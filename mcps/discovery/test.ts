import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import {
  BASE_MAINNET_NETWORK,
  BASE_MAINNET_USDC,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  DEFAULT_X402_PAY_TO,
  LIGHTNING_TESTNET_NETWORK,
  MCP_REGISTRY_SCHEMA,
  RETIRED_X402_PAY_TO,
} from "../../shared/constants.js";
import type {
  CatalogEntry,
  EndpointValidationResult,
  X402PaymentRequiredEnvelope,
} from "../../shared/types.js";
import { encodePaymentRequiredHeader } from "../../shared/x402-adapter.js";
import { CatalogIndexer, parseMicroUsdInteger } from "./indexer.js";
import { startDiscoveryServer } from "./server.js";
import { validateEndpoint } from "./validator.js";

interface MockServerHandle {
  baseUrl: string;
  close: () => Promise<void>;
}

async function startMockHttpServer(
  handler: http.RequestListener
): Promise<MockServerHandle> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function writeJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {}
): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers,
  });
  res.end(JSON.stringify(body));
}

async function mcpRpcCall(
  mcpUrl: string,
  method: string,
  params: Record<string, unknown>,
  id: number = 1
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params,
    }),
  });
  const json = (await res.json()) as Record<string, unknown>;
  return { status: res.status, json };
}

function extractToolResult<T>(rpcJson: Record<string, unknown>): T {
  const result = rpcJson.result as {
    isError?: boolean;
    content?: Array<{ type: string; text?: string }>;
  };
  assert.ok(result, "Expected JSON-RPC result object");
  assert.notEqual(result.isError, true, `Unexpected tool error: ${JSON.stringify(result)}`);
  assert.ok(Array.isArray(result.content) && result.content.length > 0, "Expected MCP content array");
  const text = result.content[0].text;
  assert.equal(typeof text, "string", "Expected text content item");
  return JSON.parse(text!) as T;
}

function createMockMcpAndPaidHandler(options: {
  payTo: string;
  priceMicroUsd?: string;
  network?: string;
  asset?: string;
  includeLightning?: boolean;
  mcpGetMode?: "ok" | "redirect307_to_404" | "not_found";
  includeWellKnown?: boolean;
  paidPath?: string;
  wellKnownItemsFormat?: boolean;
  paidMethodOnlyPost?: boolean;
}): http.RequestListener {
  const paidPath = options.paidPath ?? "/api/v1/oracle";
  const priceMicroUsd = options.priceMicroUsd ?? "1000";
  const network = options.network ?? BASE_SEPOLIA_NETWORK;
  const asset = options.asset ?? BASE_SEPOLIA_USDC;

  return async (req, res) => {
    const method = (req.method ?? "GET").toUpperCase();
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);

    if (method === "GET" && url.pathname === "/.well-known/x402") {
      if (options.includeWellKnown === false) {
        writeJson(res, 404, { error: "Not found" });
        return;
      }
      if (options.wellKnownItemsFormat) {
        writeJson(res, 200, {
          x402Version: 2,
          items: [
            {
              resource: `http://${req.headers.host ?? "127.0.0.1"}${paidPath}`,
              scheme: "exact",
              network,
              payTo: options.payTo,
            },
          ],
        });
        return;
      }
      writeJson(res, 200, {
        x402Version: 2,
        name: "mock-paid-mcp",
        mcpEndpoint: "/mcp",
        paidEndpoint: paidPath,
        payTo: options.payTo,
        schemes: options.includeLightning ? ["exact", "lightning"] : ["exact"],
        networks: options.includeLightning
          ? [network, LIGHTNING_TESTNET_NETWORK]
          : [network],
      });
      return;
    }

    if (url.pathname === "/mcp" || url.pathname === "/mcp/") {
      if (method === "GET") {
        if (options.mcpGetMode === "redirect307_to_404") {
          if (url.pathname === "/mcp") {
            res.writeHead(307, { Location: "/mcp/" });
            res.end();
          } else {
            writeJson(res, 404, { error: "Trailing slash /mcp/ not found" });
          }
          return;
        }
        if (options.mcpGetMode === "not_found") {
          writeJson(res, 404, { error: "MCP GET card not implemented" });
          return;
        }
        writeJson(res, 200, {
          name: "mock-paid-mcp",
          transport: "streamable-http",
          protocolVersion: "2025-03-26",
          toolsCount: 1,
          status: "ONLINE",
        });
        return;
      }

      if (method === "POST") {
        const raw = await readBody(req);
        const rpc = JSON.parse(raw) as { id: number | string; method: string };
        if (rpc.method === "initialize") {
          writeJson(res, 200, {
            jsonrpc: "2.0",
            id: rpc.id,
            result: {
              protocolVersion: "2025-03-26",
              capabilities: { tools: { listChanged: false } },
              serverInfo: { name: "mock-paid-mcp", version: "0.1.0" },
            },
          });
          return;
        }
        if (rpc.method === "tools/list") {
          writeJson(res, 200, {
            jsonrpc: "2.0",
            id: rpc.id,
            result: {
              tools: [
                {
                  name: "paid_oracle",
                  description: "Mock paid oracle tool",
                  inputSchema: { type: "object", properties: {} },
                },
              ],
            },
          });
          return;
        }
      }
    }

    if (url.pathname === paidPath) {
      if (options.paidMethodOnlyPost && method === "GET") {
        writeJson(res, 200, {
          method: "POST",
          info: "Send POST to pay",
        });
        return;
      }
      const accepts: X402PaymentRequiredEnvelope["accepts"] = [
        {
          scheme: "exact",
          network,
          asset,
          amount: priceMicroUsd,
          payTo: options.payTo,
          maxTimeoutSeconds: 300,
          extra: { name: "USDC", version: "2", assetTransferMethod: "eip3009" },
        },
      ];
      if (options.includeLightning) {
        accepts.push({
          scheme: "lightning",
          network: LIGHTNING_TESTNET_NETWORK,
          asset: "MSAT",
          amount: "12000",
          payTo: options.payTo,
          maxTimeoutSeconds: 300,
          extra: { amountMsat: "12000" },
        });
      }

      const envelope: X402PaymentRequiredEnvelope = {
        x402Version: 2,
        resource: {
          url: `http://${req.headers.host}${paidPath}`,
          description: "Mock paid resource",
          mimeType: "application/json",
        },
        accepts,
      };

      const encodedHeader = encodePaymentRequiredHeader(
        envelope as unknown as Parameters<typeof encodePaymentRequiredHeader>[0]
      );
      writeJson(res, 402, envelope, {
        "PAYMENT-REQUIRED": encodedHeader,
      });
      return;
    }

    writeJson(res, 404, { error: "Not found" });
  };
}

async function runTests(): Promise<void> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-discovery-test-"));
  const tmpCatalogPath = path.join(tmpDir, "catalog.json");
  const tmpManifestsDir = path.join(tmpDir, "manifests");

  const validServer = await startMockHttpServer(
    createMockMcpAndPaidHandler({
      payTo: DEFAULT_X402_PAY_TO,
      priceMicroUsd: "1000",
      network: BASE_SEPOLIA_NETWORK,
      asset: BASE_SEPOLIA_USDC,
      includeLightning: true,
      mcpGetMode: "ok",
      includeWellKnown: true,
    })
  );

  const retiredServer = await startMockHttpServer(
    createMockMcpAndPaidHandler({
      payTo: RETIRED_X402_PAY_TO,
      priceMicroUsd: "1000",
      network: BASE_SEPOLIA_NETWORK,
      asset: BASE_SEPOLIA_USDC,
      mcpGetMode: "ok",
      includeWellKnown: true,
    })
  );

  const redirect307Server = await startMockHttpServer(
    createMockMcpAndPaidHandler({
      payTo: DEFAULT_X402_PAY_TO,
      priceMicroUsd: "1000",
      mcpGetMode: "redirect307_to_404",
      includeWellKnown: true,
    })
  );

  const notFound404Server = await startMockHttpServer(
    createMockMcpAndPaidHandler({
      payTo: DEFAULT_X402_PAY_TO,
      priceMicroUsd: "1000",
      mcpGetMode: "not_found",
      includeWellKnown: true,
    })
  );

  const expensiveMainnetServer = await startMockHttpServer(
    createMockMcpAndPaidHandler({
      payTo: DEFAULT_X402_PAY_TO,
      priceMicroUsd: "5000",
      network: BASE_MAINNET_NETWORK,
      asset: BASE_MAINNET_USDC,
      includeLightning: false,
      mcpGetMode: "ok",
      includeWellKnown: false,
      paidPath: "/api/v1/pro",
    })
  );

  const discovery = await startDiscoveryServer({
    port: 0,
    host: "127.0.0.1",
    catalogPath: tmpCatalogPath,
    manifestsDir: tmpManifestsDir,
  });

  try {
    // 1. Verify Discovery server GET /mcp, GET /mcp/, GET /.well-known/x402, and POST /mcp MCP handshake.
    const [cardNoSlash, cardSlash, wellKnown] = await Promise.all([
      fetch(`${discovery.baseUrl}/mcp`, { headers: { Accept: "application/json" } }),
      fetch(`${discovery.baseUrl}/mcp/`, { headers: { Accept: "application/json" } }),
      fetch(`${discovery.baseUrl}/.well-known/x402`, { headers: { Accept: "application/json" } }),
    ]);
    assert.equal(cardNoSlash.status, 200, "GET /mcp must return 200");
    assert.equal(cardSlash.status, 200, "GET /mcp/ must return 200");
    assert.equal(wellKnown.status, 200, "GET /.well-known/x402 must return 200");

    const cardJson = (await cardNoSlash.json()) as { name: string; toolsCount: number };
    assert.equal(cardJson.name, "x402-discovery-registrar");
    assert.equal(cardJson.toolsCount, 4);

    const initRpc = await mcpRpcCall(discovery.mcpUrl, "initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "discovery-test", version: "0.1.0" },
    });
    assert.equal(initRpc.status, 200);
    assert.equal(initRpc.json.jsonrpc, "2.0");

    const listRpc = await mcpRpcCall(discovery.mcpUrl, "tools/list", {}, 2);
    assert.equal(listRpc.status, 200);
    const listedTools = (listRpc.json.result as { tools: Array<{ name: string }> }).tools;
    assert.deepEqual(
      listedTools.map((t) => t.name).sort(),
      ["list_catalog", "register_endpoint", "search_resources", "validate_endpoint"]
    );

    // 2. Valid 402 + GET /mcp 200 endpoint -> validate_endpoint passes (valid: true).
    const validRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "validate_endpoint",
        arguments: { url: validServer.baseUrl },
      },
      3
    );
    const validRes = extractToolResult<EndpointValidationResult>(validRpc.json);
    assert.equal(validRes.valid, true, `Expected valid endpoint: ${JSON.stringify(validRes)}`);
    assert.equal(validRes.score, 100);
    assert.equal(validRes.priceMicroUsd, "1000");
    assert.ok(validRes.schemes.includes("exact"));
    assert.ok(validRes.schemes.includes("lightning"));
    assert.ok(validRes.networks.includes(BASE_SEPOLIA_NETWORK));
    assert.ok(validRes.networks.includes(LIGHTNING_TESTNET_NETWORK));
    assert.deepEqual(validRes.payTo, [DEFAULT_X402_PAY_TO]);
    assert.ok(validRes.checks.every((c) => c.passed));

    // 3. Retired payee 0xAB745e5F576667037696e78ba7dA28E193E4423D -> validate_endpoint FAILS.
    const retiredRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "validate_endpoint",
        arguments: { url: retiredServer.baseUrl },
      },
      4
    );
    const retiredRes = extractToolResult<EndpointValidationResult>(retiredRpc.json);
    assert.equal(retiredRes.valid, false, "Retired payee MUST fail validation");
    assert.equal(retiredRes.score, 0, "Retired payee MUST drop score to 0");
    const retiredGuard = retiredRes.checks.find((c) => c.name === "retired_payee_guard");
    assert.equal(retiredGuard?.passed, false, "retired_payee_guard check must fail");

    // 4. 307 -> 404 on GET /mcp AND direct 404 on GET /mcp -> flags mcp_get_card failure.
    const redirectRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "validate_endpoint",
        arguments: { url: redirect307Server.baseUrl },
      },
      5
    );
    const redirectRes = extractToolResult<EndpointValidationResult>(redirectRpc.json);
    assert.equal(redirectRes.valid, false);
    assert.equal(
      redirectRes.checks.find((c) => c.name === "mcp_get_card")?.passed,
      false,
      "307->404 on GET /mcp must fail mcp_get_card"
    );

    const notFoundRes = await validateEndpoint(notFound404Server.baseUrl);
    assert.equal(notFoundRes.valid, false);
    assert.equal(
      notFoundRes.checks.find((c) => c.name === "mcp_get_card")?.passed,
      false,
      "404 on GET /mcp must fail mcp_get_card"
    );

    // 5. Endpoint without /.well-known/x402 (404 optional) with explicit paidPath passes with score 80.
    const mainnetRes = await validateEndpoint(expensiveMainnetServer.baseUrl, {
      paidPath: "/api/v1/pro",
    });
    assert.equal(mainnetRes.valid, true);
    assert.equal(mainnetRes.score, 80);
    assert.equal(mainnetRes.priceMicroUsd, "5000");
    assert.equal(
      mainnetRes.checks.find((c) => c.name === "well_known_x402")?.passed,
      false
    );

    // 5b. MCP-only paid tool challenge (isError: true + _meta["x402/payment-required"]) & object-map discovery.
    const mcpPaidToolServer = await startMockHttpServer(async (req, res) => {
      const method = (req.method ?? "GET").toUpperCase();
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
      if (method === "GET" && url.pathname === "/.well-known/x402") {
        writeJson(res, 200, {
          x402Version: 2,
          mcpEndpoint: "/mcp",
          paidTools: ["paid_lightning_echo"],
        });
        return;
      }
      if (url.pathname === "/mcp" || url.pathname === "/mcp/") {
        if (method === "GET") {
          writeJson(res, 200, { name: "mcp-paid-tool-server", status: "ONLINE" });
          return;
        }
        if (method === "POST") {
          const rpc = JSON.parse(await readBody(req)) as {
            id: number | string;
            method: string;
          };
          if (rpc.method === "initialize") {
            writeJson(res, 200, {
              jsonrpc: "2.0",
              id: rpc.id,
              result: {
                protocolVersion: "2025-03-26",
                capabilities: { tools: {} },
                serverInfo: { name: "mcp-paid-tool-server", version: "0.1.0" },
              },
            });
            return;
          }
          if (rpc.method === "tools/list") {
            writeJson(res, 200, {
              jsonrpc: "2.0",
              id: rpc.id,
              result: {
                tools: [
                  {
                    name: "paid_lightning_echo",
                    description: "Paid MCP tool",
                    inputSchema: { type: "object", properties: {} },
                  },
                ],
              },
            });
            return;
          }
          if (rpc.method === "tools/call") {
            const challenge: X402PaymentRequiredEnvelope = {
              x402Version: 2,
              error: "PaymentRequired",
              accepts: [
                {
                  scheme: "exact",
                  network: BASE_SEPOLIA_NETWORK,
                  asset: BASE_SEPOLIA_USDC,
                  amount: "2000",
                  payTo: DEFAULT_X402_PAY_TO,
                  maxTimeoutSeconds: 300,
                },
              ],
            };
            writeJson(res, 200, {
              jsonrpc: "2.0",
              id: rpc.id,
              result: {
                isError: true,
                content: [{ type: "text", text: JSON.stringify(challenge) }],
                _meta: { "x402/payment-required": challenge },
              },
            });
            return;
          }
        }
      }
      writeJson(res, 404, { error: "Not found" });
    });

    try {
      const mcpToolRes = await validateEndpoint(mcpPaidToolServer.baseUrl);
      assert.equal(mcpToolRes.valid, true, `Expected MCP paid tool server valid: ${JSON.stringify(mcpToolRes)}`);
      assert.equal(mcpToolRes.priceMicroUsd, "2000");
      assert.equal(mcpToolRes.score, 100);
    } finally {
      await mcpPaidToolServer.close();
    }

    // 6. register_endpoint via HTTP POST /mcp (verified, failed retired payee, unverified fallback).
    const regValidRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "register_endpoint",
        arguments: {
          id: "mock-lightning-oracle",
          name: "mock-lightning-oracle",
          title: "Mock Lightning Oracle",
          description: "Valid dual-rail test oracle",
          url: validServer.baseUrl,
          vendor: "TestVendor",
        },
      },
      6
    );
    const regValid = extractToolResult<CatalogEntry>(regValidRpc.json);
    assert.equal(regValid.status, "verified");
    assert.equal(regValid.priceMicroUsd, "1000");

    const regMainnetRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "register_endpoint",
        arguments: {
          id: "mock-pro-mainnet",
          name: "mock-pro-mainnet",
          title: "Mock Pro Mainnet",
          description: "Higher-cost Base mainnet endpoint",
          url: expensiveMainnetServer.baseUrl,
          paidEndpoint: "/api/v1/pro",
          paidPath: "/api/v1/pro",
          vendor: "MainnetVendor",
        },
      },
      7
    );
    const regMainnet = extractToolResult<CatalogEntry>(regMainnetRpc.json);
    assert.equal(regMainnet.status, "verified");
    assert.equal(regMainnet.priceMicroUsd, "5000");

    // Attempt to register retired payee even with allowUnverified: true -> MUST still be "failed".
    const regRetiredRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "register_endpoint",
        arguments: {
          id: "retired-endpoint",
          name: "retired-endpoint",
          url: retiredServer.baseUrl,
          vendor: "BadVendor",
          allowUnverified: true,
        },
      },
      8
    );
    const regRetired = extractToolResult<CatalogEntry>(regRetiredRpc.json);
    assert.equal(
      regRetired.status,
      "failed",
      "Retired payee MUST NEVER be registered as verified or unverified"
    );

    const regUnverifiedRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "register_endpoint",
        arguments: {
          id: "broken-redirect-endpoint",
          name: "broken-redirect-endpoint",
          url: redirect307Server.baseUrl,
          vendor: "BrokenVendor",
          allowUnverified: true,
        },
      },
      9
    );
    const regUnverified = extractToolResult<CatalogEntry>(regUnverifiedRpc.json);
    assert.equal(regUnverified.status, "unverified");

    // 7. search_resources with integer maxPriceMicroUsd, scheme, network, onlyValid.
    const searchCheapRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "search_resources",
        arguments: {
          maxPriceMicroUsd: "1000",
          onlyValid: true,
        },
      },
      10
    );
    const searchCheap = extractToolResult<{ count: number; entries: CatalogEntry[] }>(
      searchCheapRpc.json
    );
    assert.equal(searchCheap.count, 1);
    assert.equal(searchCheap.entries[0].id, "mock-lightning-oracle");

    const searchTooLowRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "search_resources",
        arguments: {
          maxPriceMicroUsd: "999",
          onlyValid: true,
        },
      },
      11
    );
    const searchTooLow = extractToolResult<{ count: number; entries: CatalogEntry[] }>(
      searchTooLowRpc.json
    );
    assert.equal(searchTooLow.count, 0);

    const searchLightningRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "search_resources",
        arguments: {
          scheme: "lightning",
          network: LIGHTNING_TESTNET_NETWORK,
          onlyValid: true,
        },
      },
      12
    );
    const searchLightning = extractToolResult<{ count: number; entries: CatalogEntry[] }>(
      searchLightningRpc.json
    );
    assert.equal(searchLightning.count, 1);
    assert.equal(searchLightning.entries[0].id, "mock-lightning-oracle");

    const searchMainnetRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "search_resources",
        arguments: {
          network: BASE_MAINNET_NETWORK,
          maxPriceMicroUsd: "5000",
          onlyValid: true,
        },
      },
      13
    );
    const searchMainnet = extractToolResult<{ count: number; entries: CatalogEntry[] }>(
      searchMainnetRpc.json
    );
    assert.equal(searchMainnet.count, 1);
    assert.equal(searchMainnet.entries[0].id, "mock-pro-mainnet");

    // Integer parser rejects floating point strings.
    assert.throws(() => parseMicroUsdInteger("0.001"));
    assert.throws(() => parseMicroUsdInteger("-10"));

    // 8. list_catalog verifies total counts by status.
    const listCatRpc = await mcpRpcCall(
      discovery.mcpUrl,
      "tools/call",
      {
        name: "list_catalog",
        arguments: {},
      },
      14
    );
    const listCat = extractToolResult<{
      total: number;
      byStatus: Record<string, number>;
      entries: CatalogEntry[];
    }>(listCatRpc.json);
    assert.equal(listCat.total, 4);
    assert.equal(listCat.byStatus.verified, 2);
    assert.equal(listCat.byStatus.failed, 1);
    assert.equal(listCat.byStatus.unverified, 1);

    // 9. Verify real repo registry/catalog.json, registry/manifests/, and server.json compliance.
    const itemsResourceServer = await startMockHttpServer(
      createMockMcpAndPaidHandler({
        payTo: DEFAULT_X402_PAY_TO,
        paidPath: "/api/swarm",
        wellKnownItemsFormat: true,
        paidMethodOnlyPost: true,
      })
    );
    try {
      const itemsRes = await validateEndpoint(itemsResourceServer.baseUrl);
      assert.equal(itemsRes.valid, true, "items[].resource paid target must validate cleanly");
      assert.equal(itemsRes.score, 100);
    } finally {
      await itemsResourceServer.close();
    }

    const repoIndexer = new CatalogIndexer();
    const repoManifests = repoIndexer.loadManifests();
    assert.ok(repoManifests.length >= 10, "Expected at least 10 manifests in registry/manifests/");
    for (const manifest of repoManifests) {
      assert.equal(
        manifest.status,
        "seeded_pending_live_probe",
        `Seeded manifest ${manifest.id} must have status seeded_pending_live_probe`
      );
      assert.notEqual(
        manifest.payTo.toLowerCase(),
        RETIRED_X402_PAY_TO.toLowerCase(),
        `Seeded manifest ${manifest.id} must never use retired payee`
      );
    }

    const repoCatalog = repoIndexer.loadCatalog();
    assert.equal(
      repoCatalog.length,
      repoManifests.length,
      "Expected registry/catalog.json entry count to match registry/manifests/"
    );
    for (const entry of repoCatalog) {
      assert.notEqual(
        entry.payTo.toLowerCase(),
        RETIRED_X402_PAY_TO.toLowerCase(),
        `Catalog entry ${entry.id} must never use retired payee`
      );
    }

    const serverJsonPath = path.resolve(
      path.dirname(new URL(import.meta.url).pathname),
      "server.json"
    );
    const serverJson = JSON.parse(fs.readFileSync(serverJsonPath, "utf8")) as {
      $schema: string;
      description: string;
    };
    assert.equal(serverJson.$schema, MCP_REGISTRY_SCHEMA);
    assert.ok(
      serverJson.description.length <= 100,
      `server.json description exceeds 100 chars (${serverJson.description.length})`
    );

    console.log(
      JSON.stringify({
        ok: true,
        validated_endpoints: 2,
        rejected_endpoints: 3,
        repo_catalog_seeded: repoCatalog.length,
        server_json_description_len: serverJson.description.length,
      })
    );
  } finally {
    await Promise.all([
      discovery.close(),
      validServer.close(),
      retiredServer.close(),
      redirect307Server.close(),
      notFound404Server.close(),
      expensiveMainnetServer.close(),
    ]);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
