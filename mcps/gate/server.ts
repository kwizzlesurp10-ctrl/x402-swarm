import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  DEFAULT_KEYSTORE_PATH,
  TESTNET_FACILITATOR_URL,
  resolvePayTo,
} from "../../shared/constants.js";
import { getKeyId, signDsse } from "../../shared/keystore.js";
import {
  type RunningMcpServer,
  startMcpHttpServer,
} from "../../shared/mcp-http.js";
import type { FacilitatorClient } from "../../shared/x402-adapter.js";
import {
  type GatewayTool,
  type PaidMcpGateway,
  type PaidToolMetaEntry,
  createPaidMcpGateway,
  freeTool,
  paidTool,
} from "./adapter.js";

export interface GateServerOptions {
  port?: number;
  host?: string;
  facilitatorUrl?: string;
  facilitatorClient?: FacilitatorClient;
  payTo?: string;
  intentLogPath?: string;
  ledgerPath?: string;
  keystorePath?: string;
  network?: string;
  asset?: string;
  extraTools?: GatewayTool[];
}

export interface RunningGateServer extends RunningMcpServer {
  payTo: string;
  facilitatorUrl: string;
  keystorePath: string;
  getPricingManifest: () => PaidToolMetaEntry[];
  getIntentCount: () => number;
}

export interface CanonicalizeOptions {
  sortArrays?: boolean;
  stripNulls?: boolean;
}

export function canonicalizeJsonValue(
  value: unknown,
  options: CanonicalizeOptions = {}
): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return String(value);
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    const normalizedItems = value.map((item) =>
      canonicalizeJsonValue(item, options)
    );
    if (options.sortArrays) {
      return [...normalizedItems].sort((a, b) => {
        const sa = JSON.stringify(a);
        const sb = JSON.stringify(b);
        return sa < sb ? -1 : sa > sb ? 1 : 0;
      });
    }
    return normalizedItems;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0
    );
    const out: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      const raw = obj[key];
      if (raw === undefined) continue;
      if (options.stripNulls && raw === null) continue;
      out[key] = canonicalizeJsonValue(raw, options);
    }
    return out;
  }
  return String(value);
}

function countJsonKeys(value: unknown): number {
  if (!value || typeof value !== "object") return 0;
  if (Array.isArray(value)) {
    return value.reduce((sum, item) => sum + countJsonKeys(item), 0);
  }
  const entries = Object.entries(value as Record<string, unknown>);
  return entries.reduce(
    (sum, [, v]) => sum + 1 + countJsonKeys(v),
    0
  );
}

export async function startGateServer(
  options: GateServerOptions = {}
): Promise<RunningGateServer> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const payTo = resolvePayTo(options.payTo);
  const facilitatorUrl = (
    options.facilitatorUrl ?? TESTNET_FACILITATOR_URL
  ).replace(/\/+$/, "");
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const network = options.network ?? BASE_SEPOLIA_NETWORK;
  const asset = options.asset ?? BASE_SEPOLIA_USDC;

  let gatewayRef: PaidMcpGateway | null = null;

  const manifestTool = freeTool(
    {
      name: "gate_pricing_manifest",
      description:
        "Free pricing manifest listing registered paid tools and strict integer micro-USD prices.",
      inputSchema: {
        type: "object",
        properties: {
          tool: {
            type: "string",
            description: "Optional paid tool name filter",
          },
        },
        additionalProperties: false,
      },
    },
    (args) => {
      const manifest = gatewayRef ? gatewayRef.getPricingManifest() : [];
      const filterName =
        typeof args.tool === "string" && args.tool.trim()
          ? args.tool.trim()
          : null;
      const filtered = filterName
        ? manifest.filter((entry) => entry.name === filterName)
        : manifest;

      return {
        ok: true,
        server: "x402-gate",
        x402Version: 2,
        pricingUnit: "micro_usd_integer",
        payTo,
        facilitatorUrl,
        network,
        asset,
        paidToolsCount: filtered.length,
        paidTools: filtered.map((entry) => ({
          name: entry.name,
          description: entry.description,
          amountMicroUsd: entry.amountMicroUsd,
          amountUsd: entry.amountUsd,
          scheme: entry.scheme,
          network: entry.network,
          asset: entry.asset,
          payTo: entry.payTo,
          httpPath: entry.httpPath,
          httpUrl: entry.httpUrl,
        })),
      };
    }
  );

  const jsonTransformTool = paidTool(
    {
      name: "paid_json_transform",
      description:
        "Paid ($0.001 / 1000 micro-USD) deterministic JSON canonicalizer, key sorter, and SHA-256 hash generator.",
      amountMicroUsd: 1000n,
      inputSchema: {
        type: "object",
        properties: {
          input: { description: "JSON value to normalize and hash" },
          data: { description: "Alias for input" },
          sortArrays: { type: "boolean" },
          stripNulls: { type: "boolean" },
        },
        additionalProperties: true,
      },
    },
    (args) => {
      const target =
        args.input !== undefined
          ? args.input
          : args.data !== undefined
            ? args.data
            : args;
      const sortArrays = args.sortArrays === true;
      const stripNulls = args.stripNulls === true;
      const normalized = canonicalizeJsonValue(target, {
        sortArrays,
        stripNulls,
      });
      const canonicalJson = JSON.stringify(normalized);
      const sha256 = crypto
        .createHash("sha256")
        .update(canonicalJson, "utf8")
        .digest("hex");

      return {
        normalized,
        canonicalJson,
        sha256,
        keyCount: countJsonKeys(normalized),
        byteLength: Buffer.byteLength(canonicalJson, "utf8"),
      };
    }
  );

  const hashAttestTool = paidTool(
    {
      name: "paid_hash_attest",
      description:
        "Paid ($0.0015 / 1500 micro-USD) SHA-256 digest and persisted Ed25519 DSSE payload attestation.",
      amountMicroUsd: 1500n,
      inputSchema: {
        type: "object",
        properties: {
          payload: { description: "Payload to digest and DSSE-attest" },
          input: { description: "Alias for payload" },
          data: { description: "Alias for payload" },
          subject: { type: "string" },
        },
        additionalProperties: true,
      },
    },
    (args) => {
      const target =
        args.payload !== undefined
          ? args.payload
          : args.input !== undefined
            ? args.input
            : args.data !== undefined
              ? args.data
              : args;
      const encoding =
        typeof target === "string" ? "utf8-string" : "canonical-json";
      const canonicalText =
        typeof target === "string"
          ? target
          : JSON.stringify(canonicalizeJsonValue(target));
      const canonicalBytes = Buffer.from(canonicalText, "utf8");
      const sha256 = crypto
        .createHash("sha256")
        .update(canonicalBytes)
        .digest("hex");

      const claim = {
        type: "x402.gate.hash-attestation.v1",
        ...(typeof args.subject === "string" && args.subject.trim()
          ? { subject: args.subject.trim() }
          : {}),
        algorithm: "sha256",
        digestHex: sha256,
        encoding,
        byteLength: canonicalBytes.byteLength,
        attestedAt: new Date().toISOString(),
        keyid: getKeyId(keystorePath),
      };

      const attestation = signDsse(
        "application/vnd.x402.hash-attestation+json",
        claim,
        keystorePath
      );

      return {
        algorithm: "sha256",
        digestHex: sha256,
        encoding,
        byteLength: canonicalBytes.byteLength,
        claim,
        attestation,
      };
    }
  );

  const gateway = createPaidMcpGateway({
    name: "x402-gate",
    title: "402-Gate Universal x402 MCP Server",
    version: "0.1.0",
    description:
      "Universal x402 v2 paidTool adapter and REST/MCP paywall gateway with EIP-3009 and DSSE receipts.",
    payTo,
    facilitatorUrl,
    facilitatorClient: options.facilitatorClient,
    intentLogPath: options.intentLogPath,
    ledgerPath: options.ledgerPath,
    keystorePath,
    network,
    asset,
    tools: [
      manifestTool,
      jsonTransformTool,
      hashAttestTool,
      ...(options.extraTools ?? []),
    ],
  });
  gatewayRef = gateway;

  const running = await startMcpHttpServer({
    port,
    host,
    name: "x402-gate",
    title: "402-Gate Universal x402 MCP Server",
    version: "0.1.0",
    description:
      "Universal x402 v2 paidTool adapter and REST/MCP paywall gateway with EIP-3009 and DSSE receipts.",
    tools: gateway.tools,
    handlers: gateway.handlers,
    extraRoutes: gateway.extraRoutes,
    wellKnownX402: gateway.wellKnownX402,
    serverCardExtras: gateway.serverCardExtras,
  });

  gateway.setBaseUrl(running.baseUrl);

  return {
    ...running,
    payTo: gateway.payTo,
    facilitatorUrl: gateway.facilitatorUrl,
    keystorePath: gateway.keystorePath,
    getPricingManifest: gateway.getPricingManifest,
    getIntentCount: gateway.getIntentCount,
  };
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const port = Number(process.env.PORT ?? "4020");
  const host = process.env.HOST ?? "127.0.0.1";
  startGateServer({ port, host })
    .then((srv) => {
      console.log(`402-Gate MCP server listening on ${srv.baseUrl} (MCP: ${srv.mcpUrl})`);
    })
    .catch((err) => {
      console.error("Failed to start 402-Gate MCP server:", err);
      process.exit(1);
    });
}
