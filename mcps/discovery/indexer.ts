import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isRetiredPayTo } from "../../shared/constants.js";
import type {
  CatalogEntry,
  EndpointValidationResult,
} from "../../shared/types.js";
import {
  validateEndpoint,
  type ValidateEndpointOptions,
} from "./validator.js";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_CATALOG_PATH = path.resolve(
  MODULE_DIR,
  "../../registry/catalog.json"
);
export const DEFAULT_MANIFESTS_DIR = path.resolve(
  MODULE_DIR,
  "../../registry/manifests"
);

const INTEGER_STRING_REGEX = /^\d+$/;

export interface CatalogIndexerOptions {
  catalogPath?: string;
  manifestsDir?: string;
}

export interface RegisterEndpointInput {
  id?: string;
  name: string;
  title?: string;
  description?: string;
  url: string;
  mcpEndpoint?: string;
  wellKnownUrl?: string;
  paidEndpoint?: string;
  vendor: string;
  networks?: string[];
  schemes?: string[];
  payTo?: string;
  priceMicroUsd?: string;
  validateFirst?: boolean;
  allowUnverified?: boolean;
  writeManifest?: boolean;
  validationOptions?: ValidateEndpointOptions;
}

export interface SearchResourcesFilter {
  query?: string;
  network?: string;
  scheme?: string;
  maxPriceMicroUsd?: string | bigint;
  onlyValid?: boolean;
  vendor?: string;
}

export function parseMicroUsdInteger(value: string | bigint): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error(`Micro-USD value cannot be negative: ${value.toString()}`);
    }
    return value;
  }
  const trimmed = value.trim();
  if (!INTEGER_STRING_REGEX.test(trimmed)) {
    throw new Error(
      `Invalid integer micro-USD value "${value}". Floats and non-digits are forbidden.`
    );
  }
  return BigInt(trimmed);
}

function slugifyId(raw: string): string {
  const slug = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || `endpoint-${crypto.randomBytes(4).toString("hex")}`;
}

function matchesNetworkFilter(entryNetworks: string[], filterNetwork: string): boolean {
  const target = filterNetwork.trim().toLowerCase();
  if (!target) return true;
  if (target.endsWith(":*")) {
    const prefix = target.slice(0, -1);
    return entryNetworks.some((n) => n.toLowerCase().startsWith(prefix));
  }
  return entryNetworks.some((n) => n.toLowerCase() === target);
}

function atomicWriteJson(filePath: string, data: unknown): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2) + "\n", "utf8");
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {
      // Best-effort cleanup
    }
    throw err;
  }
}

export class CatalogIndexer {
  public readonly catalogPath: string;
  public readonly manifestsDir: string;

  constructor(options: CatalogIndexerOptions = {}) {
    this.catalogPath = path.resolve(options.catalogPath ?? DEFAULT_CATALOG_PATH);
    this.manifestsDir = path.resolve(options.manifestsDir ?? DEFAULT_MANIFESTS_DIR);
  }

  public loadCatalog(): CatalogEntry[] {
    if (!fs.existsSync(this.catalogPath)) {
      return [];
    }
    const raw = fs.readFileSync(this.catalogPath, "utf8").trim();
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (Array.isArray(parsed)) {
      return parsed as CatalogEntry[];
    }
    if (
      parsed &&
      typeof parsed === "object" &&
      Array.isArray((parsed as { entries?: unknown }).entries)
    ) {
      return (parsed as { entries: CatalogEntry[] }).entries;
    }
    throw new Error(`Malformed catalog JSON at ${this.catalogPath}`);
  }

  public saveCatalog(entries: CatalogEntry[]): void {
    atomicWriteJson(this.catalogPath, entries);
  }

  public loadManifests(): CatalogEntry[] {
    if (!fs.existsSync(this.manifestsDir)) {
      return [];
    }
    const files = fs
      .readdirSync(this.manifestsDir)
      .filter((f) => f.endsWith(".json"))
      .sort();

    const manifests: CatalogEntry[] = [];
    for (const file of files) {
      const fullPath = path.join(this.manifestsDir, file);
      const parsed = JSON.parse(fs.readFileSync(fullPath, "utf8")) as CatalogEntry;
      manifests.push(parsed);
    }
    return manifests;
  }

  public saveManifest(entry: CatalogEntry, filename?: string): string {
    const safeName = filename ?? `${slugifyId(entry.id)}.json`;
    const targetPath = path.join(this.manifestsDir, safeName);
    atomicWriteJson(targetPath, entry);
    return targetPath;
  }

  public seedFromManifests(): CatalogEntry[] {
    const manifests = this.loadManifests();
    for (const entry of manifests) {
      if (isRetiredPayTo(entry.payTo)) {
        throw new Error(
          `Seed manifest "${entry.id}" contains retired payee ${entry.payTo}`
        );
      }
    }
    this.saveCatalog(manifests);
    return manifests;
  }

  public async registerEndpoint(
    input: RegisterEndpointInput
  ): Promise<CatalogEntry> {
    const parsedUrl = new URL(input.url);
    const origin = parsedUrl.origin;

    const id = input.id ? slugifyId(input.id) : slugifyId(input.name);
    const mcpEndpoint = input.mcpEndpoint
      ? new URL(input.mcpEndpoint, origin).toString()
      : new URL("/mcp", origin).toString();
    const wellKnownUrl = input.wellKnownUrl
      ? new URL(input.wellKnownUrl, origin).toString()
      : new URL("/.well-known/x402", origin).toString();
    const paidEndpoint = input.paidEndpoint
      ? new URL(input.paidEndpoint, origin).toString()
      : undefined;

    const shouldValidate = input.validateFirst !== false;
    let validation: EndpointValidationResult | undefined;

    if (shouldValidate) {
      validation = await validateEndpoint(input.url, {
        ...input.validationOptions,
        mcpPath: input.mcpEndpoint ?? input.validationOptions?.mcpPath,
        paidPath: input.paidEndpoint ?? input.validationOptions?.paidPath,
      });
    }

    const inputPayToRetired = isRetiredPayTo(input.payTo);
    const validationPayToRetired = Boolean(
      validation?.payTo.some((addr) => isRetiredPayTo(addr))
    );
    const hasRetiredPayee = inputPayToRetired || validationPayToRetired;

    let status: CatalogEntry["status"];
    if (hasRetiredPayee) {
      // Never register a retired payee as verified or unverified.
      status = "failed";
    } else if (shouldValidate) {
      if (validation?.valid) {
        status = "verified";
      } else {
        status = input.allowUnverified ? "unverified" : "failed";
      }
    } else {
      status = "unverified";
    }

    const resolvedPayTo =
      validation?.payTo[0] ?? (input.payTo ? input.payTo.trim() : "");

    const resolvedPrice =
      validation?.priceMicroUsd ??
      (input.priceMicroUsd !== undefined
        ? parseMicroUsdInteger(input.priceMicroUsd).toString()
        : "0");

    const entry: CatalogEntry = {
      id,
      name: input.name,
      title: input.title ?? input.name,
      description: input.description ?? "",
      url: input.url,
      mcpEndpoint,
      wellKnownUrl,
      ...(paidEndpoint ? { paidEndpoint } : {}),
      vendor: input.vendor,
      networks:
        validation && validation.networks.length > 0
          ? validation.networks
          : input.networks ?? [],
      schemes:
        validation && validation.schemes.length > 0
          ? validation.schemes
          : input.schemes ?? [],
      payTo: resolvedPayTo,
      priceMicroUsd: resolvedPrice,
      status,
      ...(validation ? { validation } : {}),
      updatedAt: new Date().toISOString(),
    };

    const existing = this.loadCatalog();
    const idx = existing.findIndex((item) => item.id === entry.id);
    if (idx >= 0) {
      existing[idx] = entry;
    } else {
      existing.push(entry);
    }
    this.saveCatalog(existing);

    if (input.writeManifest) {
      this.saveManifest(entry);
    }

    return entry;
  }

  public searchResources(filter: SearchResourcesFilter = {}): CatalogEntry[] {
    const entries = this.loadCatalog();
    const maxPrice =
      filter.maxPriceMicroUsd !== undefined && filter.maxPriceMicroUsd !== ""
        ? parseMicroUsdInteger(filter.maxPriceMicroUsd)
        : undefined;

    const queryTokens = (filter.query ?? "")
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);

    const schemeTarget = filter.scheme?.trim().toLowerCase();
    const vendorTarget = filter.vendor?.trim().toLowerCase();

    const filtered = entries.filter((entry) => {
      if (filter.onlyValid) {
        if (entry.status !== "verified") return false;
        if (isRetiredPayTo(entry.payTo)) return false;
        if (entry.validation?.payTo.some((addr) => isRetiredPayTo(addr))) {
          return false;
        }
      }

      if (filter.network && !matchesNetworkFilter(entry.networks, filter.network)) {
        return false;
      }

      if (
        schemeTarget &&
        !entry.schemes.some((s) => s.toLowerCase() === schemeTarget)
      ) {
        return false;
      }

      if (vendorTarget && !entry.vendor.toLowerCase().includes(vendorTarget)) {
        return false;
      }

      if (maxPrice !== undefined) {
        const entryPrice = parseMicroUsdInteger(entry.priceMicroUsd || "0");
        if (entryPrice > maxPrice) {
          return false;
        }
      }

      if (queryTokens.length > 0) {
        const haystack = [
          entry.id,
          entry.name,
          entry.title,
          entry.description,
          entry.vendor,
          entry.url,
          ...entry.networks,
          ...entry.schemes,
        ]
          .join(" ")
          .toLowerCase();
        for (const token of queryTokens) {
          if (!haystack.includes(token)) {
            return false;
          }
        }
      }

      return true;
    });

    const statusOrder: Record<CatalogEntry["status"], number> = {
      verified: 0,
      unverified: 1,
      seeded_pending_live_probe: 2,
      failed: 3,
    };

    return filtered.sort((a, b) => {
      const rankDiff = statusOrder[a.status] - statusOrder[b.status];
      if (rankDiff !== 0) return rankDiff;
      return a.name.localeCompare(b.name);
    });
  }
}
