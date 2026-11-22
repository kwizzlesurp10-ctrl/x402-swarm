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
import { DEFAULT_LEDGER_PATH } from "../settlement/ledger.js";
import {
  exportTaxLedger,
  generateAuditBundle,
  verifyAuditBundle,
  type TaxAuditBundle,
  type TaxExportFormat,
} from "./exporter.js";

export interface TaxServerOptions {
  port?: number;
  host?: string;
  ledgerPath?: string;
  keystorePath?: string;
}

export const TAX_TOOLS: McpToolDefinition[] = [
  {
    name: "export_tax_ledger",
    description:
      "Export settled x402 micropayments as RFC 4180 CSV, JSONL, or DSSE-signed Form 8949 summary.",
    inputSchema: {
      type: "object",
      required: ["format"],
      properties: {
        format: {
          type: "string",
          enum: ["csv", "jsonl", "form8949_summary"],
          description: "Output export format",
        },
        taxYear: {
          type: "integer",
          description: "Optional UTC tax year filter (e.g. 2026)",
        },
        feeBps: {
          type: ["string", "integer"],
          description: "Optional fee in basis points (0-10000), integer floor math",
        },
        ledgerPath: {
          type: "string",
          description: "Optional JSONL ledger path override",
        },
      },
    },
  },
  {
    name: "generate_audit_bundle",
    description:
      "Generate a complete Ed25519 DSSE-signed tax audit bundle with CSV, Form 8949 summary, and SHA-256 chain digest.",
    inputSchema: {
      type: "object",
      properties: {
        taxYear: {
          type: "integer",
          description: "Optional UTC tax year filter (e.g. 2026)",
        },
        feeBps: {
          type: ["string", "integer"],
          description: "Optional fee in basis points (0-10000), integer floor math",
        },
        ledgerPath: {
          type: "string",
          description: "Optional JSONL ledger path override",
        },
      },
    },
  },
  {
    name: "verify_audit_bundle",
    description:
      "Verify Ed25519 DSSE signature, SHA-256 chain digests, and CSV reconciliation on a tax audit bundle.",
    inputSchema: {
      type: "object",
      required: ["bundle"],
      properties: {
        bundle: {
          type: "object",
          description: "TaxAuditBundle JSON object to verify",
        },
        expectedPublicKeyPem: {
          type: "string",
          description: "Optional SPKI PEM public key override",
        },
      },
    },
  },
];

export function startTaxServer(
  options: TaxServerOptions = {}
): Promise<RunningMcpServer> {
  const defaultLedgerPath = options.ledgerPath ?? DEFAULT_LEDGER_PATH;
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const keyid = getKeyId(keystorePath);

  const handlers: Record<string, McpToolHandler> = {
    export_tax_ledger: (args) => {
      if (typeof args.format !== "string") {
        throw new Error('format argument must be "csv", "jsonl", or "form8949_summary"');
      }
      const ledgerPath =
        typeof args.ledgerPath === "string" && args.ledgerPath.trim()
          ? args.ledgerPath
          : defaultLedgerPath;
      const taxYear =
        typeof args.taxYear === "number" ? args.taxYear : undefined;
      const feeBps =
        args.feeBps !== undefined
          ? (args.feeBps as string | number | bigint)
          : undefined;

      const res = exportTaxLedger({
        ledgerPath,
        format: args.format as TaxExportFormat,
        taxYear,
        feeBps,
        keystorePath,
      });
      return { data: res };
    },

    generate_audit_bundle: (args) => {
      const ledgerPath =
        typeof args.ledgerPath === "string" && args.ledgerPath.trim()
          ? args.ledgerPath
          : defaultLedgerPath;
      const taxYear =
        typeof args.taxYear === "number" ? args.taxYear : undefined;
      const feeBps =
        args.feeBps !== undefined
          ? (args.feeBps as string | number | bigint)
          : undefined;

      const res = generateAuditBundle({
        ledgerPath,
        taxYear,
        feeBps,
        keystorePath,
      });
      return { data: res };
    },

    verify_audit_bundle: (args) => {
      if (!args.bundle || typeof args.bundle !== "object") {
        throw new Error("bundle argument must be a TaxAuditBundle object");
      }
      const expectedPublicKeyPem =
        typeof args.expectedPublicKeyPem === "string" && args.expectedPublicKeyPem.trim()
          ? args.expectedPublicKeyPem
          : undefined;

      const res = verifyAuditBundle(
        args.bundle as TaxAuditBundle,
        expectedPublicKeyPem,
        keystorePath
      );
      return { data: res };
    },
  };

  return startMcpHttpServer({
    port: options.port ?? 0,
    host: options.host ?? "127.0.0.1",
    name: "x402-tax-ledger",
    title: "x402 Tax-Ledger MCP",
    version: "0.1.0",
    description:
      "Micropayment Form 8949 tax export, RFC 4180 CSV, and Ed25519 DSSE audit bundles.",
    tools: TAX_TOOLS,
    handlers,
    wellKnownX402: () => ({
      x402Version: 2,
      name: "x402-tax-ledger",
      title: "x402 Tax-Ledger MCP",
      description:
        "Micropayment Form 8949 tax export, RFC 4180 CSV, and Ed25519 DSSE audit bundles.",
      payTo: DEFAULT_X402_PAY_TO,
      schemes: ["exact", "lightning"],
      networks: ["eip155:84532", "eip155:8453", "lightning:testnet", "lightning:mainnet"],
      keystoreKeyId: keyid,
      tools: TAX_TOOLS.map((t) => t.name),
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
  const port = Number(process.env.PORT ?? 4024);
  const host = process.env.HOST ?? "127.0.0.1";
  startTaxServer({ port, host }).then((srv) => {
    console.log(`x402-tax-ledger listening on ${srv.mcpUrl}`);
  });
}
