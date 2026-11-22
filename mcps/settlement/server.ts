import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  BRANDING,
  DEFAULT_KEYSTORE_PATH,
  DEFAULT_X402_PAY_TO,
} from "../../shared/constants.js";
import { getKeyId } from "../../shared/keystore.js";
import {
  startMcpHttpServer,
  type McpToolDefinition,
  type McpToolHandler,
  type RunningMcpServer,
} from "../../shared/mcp-http.js";
import type { SettlementReceipt } from "../../shared/types.js";
import {
  DEFAULT_LEDGER_PATH,
  createSettlementBatch,
  ingestSettlement,
  reconcileSettlements,
  verifySettlementReceipt,
  type ExpectedReceiptRef,
} from "./ledger.js";

export interface SettlementServerOptions {
  port?: number;
  host?: string;
  ledgerPath?: string;
  keystorePath?: string;
}

export const SETTLEMENT_TOOLS: McpToolDefinition[] = [
  {
    name: "ingest_settlement",
    description:
      "Validate, DSSE-verify or sign, deduplicate by (network, txHash), and append a settlement receipt.",
    inputSchema: {
      type: "object",
      required: ["receipt"],
      properties: {
        receipt: {
          type: "object",
          description: "SettlementReceipt JSON object",
        },
        requireValidDsse: {
          type: "boolean",
          description: "Require pre-existing valid DSSE envelope on receipt",
        },
        ledgerPath: {
          type: "string",
          description: "Optional JSONL ledger path override",
        },
      },
    },
  },
  {
    name: "reconcile_settlements",
    description:
      "Reconcile JSONL settlement receipts with exact integer bigint micro-USD and msat totals.",
    inputSchema: {
      type: "object",
      properties: {
        ledgerPath: {
          type: "string",
          description: "Optional JSONL ledger path override",
        },
        expectedReceipts: {
          type: "array",
          description: "Optional expected receipts to compare against the ledger",
          items: { type: "object" },
        },
        feeBps: {
          type: ["string", "integer"],
          description: "Optional fee in basis points (0-10000), integer floor math",
        },
      },
    },
  },
  {
    name: "create_settlement_batch",
    description:
      "Group unbatched receipts, tag batchId, and sign a Merkle batch manifest with Ed25519 DSSE.",
    inputSchema: {
      type: "object",
      properties: {
        ledgerPath: {
          type: "string",
          description: "Optional JSONL ledger path override",
        },
        batchId: {
          type: "string",
          description: "Optional deterministic batch identifier",
        },
        network: {
          type: "string",
          description: "Optional CAIP-2 network filter",
        },
        feeBps: {
          type: ["string", "integer"],
          description: "Optional fee in basis points (0-10000), integer floor math",
        },
      },
    },
  },
  {
    name: "verify_receipt",
    description:
      "Verify a settlement receipt's Ed25519 DSSE signature, payload integrity, and payee policy.",
    inputSchema: {
      type: "object",
      required: ["receipt"],
      properties: {
        receipt: {
          type: "object",
          description: "SettlementReceipt JSON object to verify",
        },
        expectedPublicKeyPem: {
          type: "string",
          description: "Optional SPKI PEM public key override",
        },
      },
    },
  },
];

export function startSettlementServer(
  options: SettlementServerOptions = {}
): Promise<RunningMcpServer> {
  const defaultLedgerPath = options.ledgerPath ?? DEFAULT_LEDGER_PATH;
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const keyid = getKeyId(keystorePath);

  const handlers: Record<string, McpToolHandler> = {
    ingest_settlement: (args) => {
      if (!args.receipt || typeof args.receipt !== "object") {
        throw new Error("receipt argument must be a SettlementReceipt object");
      }
      const ledgerPath =
        typeof args.ledgerPath === "string" && args.ledgerPath.trim()
          ? args.ledgerPath
          : defaultLedgerPath;
      const requireValidDsse =
        typeof args.requireValidDsse === "boolean" ? args.requireValidDsse : false;

      const res = ingestSettlement({
        ledgerPath,
        receipt: args.receipt as SettlementReceipt,
        requireValidDsse,
        keystorePath,
      });
      return { data: res };
    },

    reconcile_settlements: (args) => {
      const ledgerPath =
        typeof args.ledgerPath === "string" && args.ledgerPath.trim()
          ? args.ledgerPath
          : defaultLedgerPath;
      const expectedReceipts = Array.isArray(args.expectedReceipts)
        ? (args.expectedReceipts as ExpectedReceiptRef[])
        : undefined;
      const feeBps =
        args.feeBps !== undefined
          ? (args.feeBps as string | number | bigint)
          : undefined;

      const res = reconcileSettlements({
        ledgerPath,
        expectedReceipts,
        feeBps,
      });
      return { data: res };
    },

    create_settlement_batch: (args) => {
      const ledgerPath =
        typeof args.ledgerPath === "string" && args.ledgerPath.trim()
          ? args.ledgerPath
          : defaultLedgerPath;
      const batchId =
        typeof args.batchId === "string" && args.batchId.trim()
          ? args.batchId
          : undefined;
      const network =
        typeof args.network === "string" && args.network.trim()
          ? args.network
          : undefined;
      const feeBps =
        args.feeBps !== undefined
          ? (args.feeBps as string | number | bigint)
          : undefined;

      const res = createSettlementBatch({
        ledgerPath,
        batchId,
        network,
        feeBps,
        keystorePath,
      });
      return { data: res };
    },

    verify_receipt: (args) => {
      if (!args.receipt || typeof args.receipt !== "object") {
        throw new Error("receipt argument must be a SettlementReceipt object");
      }
      const expectedPublicKeyPem =
        typeof args.expectedPublicKeyPem === "string" && args.expectedPublicKeyPem.trim()
          ? args.expectedPublicKeyPem
          : undefined;
      const res = verifySettlementReceipt(
        args.receipt as SettlementReceipt,
        expectedPublicKeyPem,
        keystorePath
      );
      return { data: res };
    },
  };

  return startMcpHttpServer({
    port: options.port ?? 0,
    host: options.host ?? "127.0.0.1",
    name: "x402-settlement-ops",
    title: "x402 Batch-Settlement Ops MCP",
    version: "0.1.0",
    description:
      "Integer micro-USD x402 settlement ingestion, reconciliation, and DSSE batch manifests.",
    tools: SETTLEMENT_TOOLS,
    handlers,
    wellKnownX402: () => ({
      x402Version: 2,
      name: "x402-settlement-ops",
      title: "x402 Batch-Settlement Ops MCP",
      description:
        "Integer micro-USD x402 settlement ingestion, reconciliation, and DSSE batch manifests.",
      payTo: DEFAULT_X402_PAY_TO,
      schemes: ["exact", "lightning"],
      networks: ["eip155:84532", "eip155:8453", "lightning:testnet", "lightning:mainnet"],
      keystoreKeyId: keyid,
      tools: SETTLEMENT_TOOLS.map((t) => t.name),
      branding: BRANDING,
    }),
    serverCardExtras: () => ({
      payTo: DEFAULT_X402_PAY_TO,
      keyid,
      ledgerPath: defaultLedgerPath,
      author: BRANDING.author,
      organization: BRANDING.organization,
      website: BRANDING.website,
      contact: BRANDING.contact,
    }),
  });
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const port = Number(process.env.PORT ?? 4023);
  const host = process.env.HOST ?? "127.0.0.1";
  startSettlementServer({ port, host }).then((srv) => {
    console.log(`x402-settlement-ops listening on ${srv.mcpUrl}`);
  });
}
