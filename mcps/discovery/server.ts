import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  BASE_MAINNET_NETWORK,
  BASE_SEPOLIA_NETWORK,
  BRANDING,
  LIGHTNING_TESTNET_NETWORK,
  resolvePayTo,
} from "../../shared/constants.js";
import {
  startMcpHttpServer,
  type McpToolDefinition,
  type RunningMcpServer,
} from "../../shared/mcp-http.js";
import {
  CatalogIndexer,
  DEFAULT_CATALOG_PATH,
  DEFAULT_MANIFESTS_DIR,
} from "./indexer.js";
import { validateEndpoint } from "./validator.js";

export interface DiscoveryServerOptions {
  port?: number;
  host?: string;
  catalogPath?: string;
  manifestsDir?: string;
  payTo?: string;
}

export interface RunningDiscoveryServer extends RunningMcpServer {
  indexer: CatalogIndexer;
}

const ValidateEndpointSchema = z.object({
  url: z.string().url(),
  paidPath: z.string().optional(),
  mcpPath: z.string().optional(),
  paidMethod: z.enum(["GET", "POST"]).optional(),
  paidToolName: z.string().optional(),
  timeoutMs: z.number().int().positive().max(60_000).optional(),
  allowOptionalWellKnown: z.boolean().optional(),
});

const RegisterEndpointSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1),
  title: z.string().optional(),
  description: z.string().optional(),
  url: z.string().url(),
  mcpEndpoint: z.string().optional(),
  wellKnownUrl: z.string().optional(),
  paidEndpoint: z.string().optional(),
  vendor: z.string().min(1),
  networks: z.array(z.string()).optional(),
  schemes: z.array(z.string()).optional(),
  payTo: z.string().optional(),
  priceMicroUsd: z.string().regex(/^\d+$/).optional(),
  validateFirst: z.boolean().optional(),
  allowUnverified: z.boolean().optional(),
  paidPath: z.string().optional(),
  paidMethod: z.enum(["GET", "POST"]).optional(),
  paidToolName: z.string().optional(),
});

const SearchResourcesSchema = z.object({
  query: z.string().optional(),
  network: z.string().optional(),
  scheme: z.string().optional(),
  maxPriceMicroUsd: z.string().regex(/^\d+$/).optional(),
  onlyValid: z.boolean().optional(),
  vendor: z.string().optional(),
});

const ListCatalogSchema = z.object({
  status: z
    .enum(["verified", "failed", "seeded_pending_live_probe", "unverified"])
    .optional(),
});

const TOOLS: McpToolDefinition[] = [
  {
    name: "validate_endpoint",
    description:
      "Probe an x402 v2 / MCP endpoint for GET /mcp 200, /.well-known/x402, JSON-RPC initialize/tools, 402 challenge, and retired-payee safety.",
    inputSchema: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string", description: "Target origin, /mcp URL, or paid endpoint URL" },
        paidPath: { type: "string", description: "Optional paid HTTP path override or mcp://tool/<name>" },
        mcpPath: { type: "string", description: "Optional MCP path override (default /mcp)" },
        paidMethod: { type: "string", enum: ["GET", "POST"] },
        paidToolName: { type: "string", description: "Optional paid MCP tool name to probe" },
        timeoutMs: { type: "number", description: "Request timeout in milliseconds" },
        allowOptionalWellKnown: { type: "boolean", description: "Allow missing /.well-known/x402 when 402 challenge passes" },
      },
    },
  },
  {
    name: "register_endpoint",
    description:
      "Validate and atomically register an x402 paid MCP service into registry/catalog.json.",
    inputSchema: {
      type: "object",
      required: ["name", "url", "vendor"],
      properties: {
        id: { type: "string" },
        name: { type: "string" },
        title: { type: "string" },
        description: { type: "string" },
        url: { type: "string" },
        mcpEndpoint: { type: "string" },
        wellKnownUrl: { type: "string" },
        paidEndpoint: { type: "string" },
        vendor: { type: "string" },
        networks: { type: "array", items: { type: "string" } },
        schemes: { type: "array", items: { type: "string" } },
        payTo: { type: "string" },
        priceMicroUsd: { type: "string", description: "Integer micro-USD string (1 USD = 1000000)" },
        validateFirst: { type: "boolean" },
        allowUnverified: { type: "boolean" },
        paidPath: { type: "string" },
        paidMethod: { type: "string", enum: ["GET", "POST"] },
        paidToolName: { type: "string" },
      },
    },
  },
  {
    name: "search_resources",
    description:
      "Search indexed x402 catalog entries by keyword, CAIP-2 network, scheme, integer maxPriceMicroUsd, and validation status.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string" },
        network: { type: "string" },
        scheme: { type: "string" },
        maxPriceMicroUsd: { type: "string", description: "Maximum price in integer micro-USD" },
        onlyValid: { type: "boolean" },
        vendor: { type: "string" },
      },
    },
  },
  {
    name: "list_catalog",
    description:
      "Return the full discovery catalog summary grouped by verification status.",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["verified", "failed", "seeded_pending_live_probe", "unverified"],
        },
      },
    },
  },
];

export async function startDiscoveryServer(
  options: DiscoveryServerOptions = {}
): Promise<RunningDiscoveryServer> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const catalogPath = options.catalogPath ?? DEFAULT_CATALOG_PATH;
  const manifestsDir = options.manifestsDir ?? DEFAULT_MANIFESTS_DIR;
  const payTo = resolvePayTo(options.payTo);
  const indexer = new CatalogIndexer({ catalogPath, manifestsDir });

  let resolvedBaseUrl = `http://${host}:${port}`;

  const running = await startMcpHttpServer({
    port,
    host,
    name: "x402-discovery-registrar",
    title: "x402 Swarm Discovery & Validation Registrar",
    version: "0.1.0",
    description:
      "Validates x402 v2 paid MCP endpoints, enforces retired-payee blocks, and manages registry/catalog.json.",
    tools: TOOLS,
    wellKnownX402: () => ({
      x402Version: 2,
      name: "x402-discovery-registrar",
      title: "x402 Swarm Discovery & Validation Registrar",
      description:
        "Validates x402 v2 paid MCP endpoints, enforces retired-payee blocks, and manages registry/catalog.json.",
      mcpEndpoint: `${resolvedBaseUrl}/mcp`,
      wellKnownUrl: `${resolvedBaseUrl}/.well-known/x402`,
      payTo,
      networks: [
        BASE_SEPOLIA_NETWORK,
        BASE_MAINNET_NETWORK,
        LIGHTNING_TESTNET_NETWORK,
      ],
      schemes: ["exact", "lightning"],
      tools: TOOLS.map((t) => t.name),
      branding: BRANDING,
    }),
    serverCardExtras: () => ({
      catalogPath: indexer.catalogPath,
      capabilities: ["validate_endpoint", "register_endpoint", "search_resources", "list_catalog"],
    }),
    handlers: {
      validate_endpoint: async (rawArgs) => {
        const parsed = ValidateEndpointSchema.safeParse(rawArgs);
        if (!parsed.success) {
          return {
            isError: true,
            data: { error: "Invalid arguments", issues: parsed.error.issues },
          };
        }
        const { url, ...opts } = parsed.data;
        const result = await validateEndpoint(url, opts);
        return { data: result };
      },
      register_endpoint: async (rawArgs) => {
        const parsed = RegisterEndpointSchema.safeParse(rawArgs);
        if (!parsed.success) {
          return {
            isError: true,
            data: { error: "Invalid arguments", issues: parsed.error.issues },
          };
        }
        const { paidPath, paidMethod, paidToolName, ...rest } = parsed.data;
        const entry = await indexer.registerEndpoint({
          ...rest,
          validationOptions: {
            ...(paidPath ? { paidPath } : {}),
            ...(paidMethod ? { paidMethod } : {}),
            ...(paidToolName ? { paidToolName } : {}),
          },
        });
        return { data: entry };
      },
      search_resources: async (rawArgs) => {
        const parsed = SearchResourcesSchema.safeParse(rawArgs);
        if (!parsed.success) {
          return {
            isError: true,
            data: { error: "Invalid arguments", issues: parsed.error.issues },
          };
        }
        const entries = indexer.searchResources(parsed.data);
        return {
          data: {
            count: entries.length,
            entries,
          },
        };
      },
      list_catalog: async (rawArgs) => {
        const parsed = ListCatalogSchema.safeParse(rawArgs);
        if (!parsed.success) {
          return {
            isError: true,
            data: { error: "Invalid arguments", issues: parsed.error.issues },
          };
        }
        const allEntries = indexer.loadCatalog();
        const entries = parsed.data.status
          ? allEntries.filter((e) => e.status === parsed.data.status)
          : allEntries;

        const byStatus: Record<string, number> = {
          verified: 0,
          failed: 0,
          seeded_pending_live_probe: 0,
          unverified: 0,
        };
        for (const entry of allEntries) {
          byStatus[entry.status] = (byStatus[entry.status] ?? 0) + 1;
        }

        return {
          data: {
            total: entries.length,
            catalogTotal: allEntries.length,
            byStatus,
            entries,
          },
        };
      },
    },
  });

  resolvedBaseUrl = running.baseUrl;

  return {
    ...running,
    indexer,
  };
}

const isMain =
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const port = process.env.PORT ? Number(process.env.PORT) : 4022;
  const host = process.env.HOST ?? "127.0.0.1";
  const server = await startDiscoveryServer({ port, host });
  console.log(
    JSON.stringify({
      status: "listening",
      name: "x402-discovery-registrar",
      baseUrl: server.baseUrl,
      mcpUrl: server.mcpUrl,
      catalogPath: server.indexer.catalogPath,
    })
  );
}
