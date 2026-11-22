import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CatalogIndexer } from "../mcps/discovery/indexer.js";
import { validateEndpoint } from "../mcps/discovery/validator.js";
import type { CatalogEntry, EndpointValidationResult } from "../shared/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");
const FLEET_REPORT_PATH = path.join(REPO_ROOT, "registry", "fleet-probe-report.json");

interface FleetProbeEntryReport {
  id: string;
  url: string;
  status: CatalogEntry["status"];
  score: number;
  latencyMs: number;
  wellKnownTrustTxtStatus: number | null;
  checks: EndpointValidationResult["checks"];
  networks: string[];
  schemes: string[];
  payTo: string[];
  priceMicroUsd: string | null;
}

async function probeTrustTxt(originUrl: string): Promise<number | null> {
  try {
    const trustUrl = new URL("/.well-known/x402-trust.txt", originUrl).toString();
    const res = await fetch(trustUrl, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    return res.status;
  } catch {
    return null;
  }
}

async function main() {
  const indexer = new CatalogIndexer();
  const manifests = indexer.loadManifests();
  const existing = new Map(indexer.loadCatalog().map((e) => [e.id, e]));

  const merged: CatalogEntry[] = manifests.map((m) => {
    const prev = existing.get(m.id);
    if (prev && prev.validation) {
      return { ...m, ...prev };
    }
    return m;
  });

  const fleetReports: FleetProbeEntryReport[] = [];

  for (let i = 0; i < merged.length; i++) {
    const entry = merged[i];
    if (!entry.url.startsWith("https://")) {
      continue;
    }

    const [validation, trustStatus] = await Promise.all([
      validateEndpoint(entry.url, {
        ...(entry.paidEndpoint ? { paidPath: entry.paidEndpoint } : {}),
        timeoutMs: 15_000,
        allowOptionalWellKnown: true,
      }),
      probeTrustTxt(entry.url),
    ]);

    const updated: CatalogEntry = {
      ...entry,
      status: validation.valid ? "verified" : "failed",
      networks: validation.networks.length > 0 ? validation.networks : entry.networks,
      schemes: validation.schemes.length > 0 ? validation.schemes : entry.schemes,
      payTo: validation.payTo[0] ?? entry.payTo,
      priceMicroUsd: validation.priceMicroUsd ?? entry.priceMicroUsd,
      validation,
      updatedAt: validation.checkedAt,
    };
    merged[i] = updated;

    fleetReports.push({
      id: updated.id,
      url: updated.url,
      status: updated.status,
      score: validation.score,
      latencyMs: validation.latencyMs,
      wellKnownTrustTxtStatus: trustStatus,
      checks: validation.checks,
      networks: updated.networks,
      schemes: updated.schemes,
      payTo: validation.payTo,
      priceMicroUsd: validation.priceMicroUsd,
    });
  }

  indexer.saveCatalog(merged);

  const report = {
    probedAt: new Date().toISOString(),
    catalogCount: merged.length,
    fleetHostsProbed: fleetReports.length,
    verifiedCount: fleetReports.filter((f) => f.status === "verified").length,
    failedCount: fleetReports.filter((f) => f.status === "failed").length,
    fleet: fleetReports,
  };

  fs.writeFileSync(FLEET_REPORT_PATH, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(JSON.stringify(report, null, 2));
}

main().catch((err) => {
  console.error("Fleet probe failed:", err);
  process.exit(1);
});
