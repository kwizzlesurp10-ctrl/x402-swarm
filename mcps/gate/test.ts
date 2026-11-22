import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { startLocalFacilitator } from "../../harness/local-facilitator.js";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  BRANDING,
  DEFAULT_X402_PAY_TO,
  MCP_REGISTRY_SCHEMA,
  RETIRED_X402_PAY_TO,
} from "../../shared/constants.js";
import { verifyDsse } from "../../shared/keystore.js";
import { startMcpHttpServer } from "../../shared/mcp-http.js";
import type {
  DsseEnvelope,
  SettlementReceipt,
  X402PaymentRequiredEnvelope,
  X402PaymentSignature,
} from "../../shared/types.js";
import {
  createX402FetchClient,
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "../../shared/x402-adapter.js";
import { createPaidMcpGateway, paidTool } from "./adapter.js";
import { startGateServer } from "./server.js";

async function callMcp(
  mcpUrl: string,
  method: string,
  params?: Record<string, unknown>,
  headers: Record<string, string> = {}
) {
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Math.floor(Math.random() * 1_000_000),
      method,
      params,
    }),
  });
  const rpc = (await res.json()) as Record<string, unknown>;
  const result = (rpc.result ?? {}) as Record<string, unknown>;
  const content = Array.isArray(result.content)
    ? (result.content as Array<{ text?: string }>)
    : [];
  const rawText = content[0]?.text ?? "";
  let parsed: unknown = rawText;
  if (rawText) {
    try {
      parsed = JSON.parse(rawText);
    } catch {
      // Keep raw string
    }
  }
  return {
    httpStatus: res.status,
    rpc,
    result,
    isError: Boolean(result.isError),
    meta:
      result._meta && typeof result._meta === "object"
        ? (result._meta as Record<string, unknown>)
        : {},
    data: parsed,
  };
}

async function runTests(): Promise<void> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-gate-test-"));
  const keystorePath = path.join(tmpDir, "ed25519.pem");
  const intentLogPath = path.join(tmpDir, "intents.jsonl");
  const ledgerPath = path.join(tmpDir, "ledger.jsonl");

  const facilitator = await startLocalFacilitator(0);
  let srv = await startGateServer({
    port: 0,
    host: "127.0.0.1",
    facilitatorUrl: facilitator.url,
    payTo: DEFAULT_X402_PAY_TO,
    intentLogPath,
    ledgerPath,
    keystorePath,
  });

  const payerKey = generatePrivateKey();
  const payerAccount = privateKeyToAccount(payerKey);
  const evmScheme = new ExactEvmScheme(payerAccount);

  try {
    // -------------------------------------------------------------------------
    // 1. server.json Official MCP Registry compliance & branding
    // -------------------------------------------------------------------------
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const serverJson = JSON.parse(
      fs.readFileSync(path.join(__dirname, "server.json"), "utf8")
    ) as {
      $schema: string;
      name: string;
      description: string;
      _meta: {
        "io.modelcontextprotocol.registry/publisher-provided": {
          author: string;
          organization: string;
          website: string;
          contact: string;
          location: string;
        };
      };
    };
    assert.equal(serverJson.$schema, MCP_REGISTRY_SCHEMA);
    assert.equal(serverJson.name, "io.github.kwizzlesurp10-ctrl/x402-gate");
    assert.ok(
      serverJson.description.length > 0 && serverJson.description.length <= 100,
      `description length must be <= 100, got ${serverJson.description.length}`
    );
    const pubMeta =
      serverJson._meta["io.modelcontextprotocol.registry/publisher-provided"];
    assert.equal(pubMeta.author, BRANDING.author);
    assert.equal(pubMeta.organization, BRANDING.organization);
    assert.equal(pubMeta.website, BRANDING.website);
    assert.equal(pubMeta.contact, BRANDING.contact);
    assert.equal(pubMeta.location, BRANDING.location);

    // -------------------------------------------------------------------------
    // 2. Strict integer bigint micro-USD pricing & retired payee startup guard
    // -------------------------------------------------------------------------
    assert.throws(
      () =>
        paidTool(
          {
            name: "bad_float_str",
            description: "Invalid float price",
            amountMicroUsd: "1.5",
          },
          () => ({})
        ),
      /floats are forbidden/
    );
    assert.throws(
      () =>
        paidTool(
          {
            name: "bad_num",
            description: "Invalid numeric price",
            amountMicroUsd: 1000 as unknown as bigint,
          },
          () => ({})
        ),
      /floats are forbidden/
    );
    assert.throws(
      () =>
        paidTool(
          {
            name: "bad_neg",
            description: "Negative bigint",
            amountMicroUsd: -1n,
          },
          () => ({})
        ),
      /non-negative/
    );
    assert.throws(
      () =>
        paidTool(
          {
            name: "bad_payee",
            description: "Retired payee",
            amountMicroUsd: "1000",
            payTo: RETIRED_X402_PAY_TO,
          },
          () => ({})
        ),
      /Retired payee address is forbidden/
    );

    // -------------------------------------------------------------------------
    // 3. Custom paidTool wrapping a caller-defined tool (standalone + gateway)
    // -------------------------------------------------------------------------
    const customIntentLog = path.join(tmpDir, "custom-intents.jsonl");
    const customLedger = path.join(tmpDir, "custom-ledger.jsonl");
    const customMultiplier = paidTool(
      {
        name: "custom_multiply",
        description: "Caller-defined multiplier wrapped with paidTool",
        amountMicroUsd: "750",
        payTo: DEFAULT_X402_PAY_TO,
        facilitatorUrl: facilitator.url,
        intentLogPath: customIntentLog,
        ledgerPath: customLedger,
        keystorePath,
        inputSchema: {
          type: "object",
          properties: {
            a: { type: "number" },
            b: { type: "number" },
          },
        },
      },
      async (args) => ({
        product: Number(args.a ?? 0) * Number(args.b ?? 0),
      })
    );

    // Direct unpaid invocation of custom paidTool
    const directUnpaid = await customMultiplier({ a: 6, b: 7 });
    assert.equal(directUnpaid.isError, true);
    const directChallenge = directUnpaid.meta?.[
      "x402/payment-required"
    ] as X402PaymentRequiredEnvelope;
    assert.ok(directChallenge);
    assert.equal(directChallenge.accepts[0].amount, "750");
    assert.deepEqual(directChallenge.accepts[0].extra, {
      name: "USDC",
      version: "2",
      assetTransferMethod: "eip3009",
    });

    // Direct paid invocation via ExactEvmScheme
    const directPartial = await evmScheme.createPaymentPayload(
      2,
      directChallenge.accepts[0] as unknown as Parameters<
        ExactEvmScheme["createPaymentPayload"]
      >[1]
    );
    const directPaid = await customMultiplier(
      { a: 6, b: 7 },
      {
        meta: {
          "x402/payment": {
            x402Version: 2,
            accepted: directChallenge.accepts[0],
            payload: directPartial.payload,
          },
        },
      }
    );
    assert.equal(Boolean(directPaid.isError), false);
    const directData = directPaid.data as {
      ok: boolean;
      tool: string;
      result: { product: number };
      settlement: SettlementReceipt;
      dsse: DsseEnvelope;
    };
    assert.equal(directData.ok, true);
    assert.equal(directData.tool, "custom_multiply");
    assert.equal(directData.result.product, 42);
    assert.equal(directData.settlement.amountMicroUsd, "750");
    assert.ok(directPaid.meta?.["x402/payment-response"]);
    assert.ok(directPaid.meta?.["x402/dsse"]);
    assert.ok(directPaid.httpHeaders?.["PAYMENT-RESPONSE"]);
    assert.equal(
      verifyDsse(directData.dsse, undefined, keystorePath).valid,
      true
    );

    // Also compose custom paidTool into createPaidMcpGateway + startMcpHttpServer
    const customGateway = createPaidMcpGateway({
      name: "custom-gate",
      payTo: DEFAULT_X402_PAY_TO,
      facilitatorUrl: facilitator.url,
      keystorePath,
      intentLogPath: customIntentLog,
      ledgerPath: customLedger,
      tools: [
        paidTool(
          {
            name: "custom_reverse",
            description: "Reverse string",
            amountMicroUsd: 500n,
          },
          (args) => ({
            reversed: String(args.text ?? "")
              .split("")
              .reverse()
              .join(""),
          })
        ),
      ],
    });
    const customSrv = await startMcpHttpServer({
      port: 0,
      host: "127.0.0.1",
      name: "custom-gate",
      title: "Custom Gate",
      version: "0.1.0",
      description: "Custom paidTool gateway",
      tools: customGateway.tools,
      handlers: customGateway.handlers,
      extraRoutes: customGateway.extraRoutes,
      wellKnownX402: customGateway.wellKnownX402,
      serverCardExtras: customGateway.serverCardExtras,
    });
    customGateway.setBaseUrl(customSrv.baseUrl);
    try {
      const customFetch = createX402FetchClient({
        evmPrivateKey: payerKey,
        preferredScheme: "exact",
        preferredNetwork: BASE_SEPOLIA_NETWORK,
      });
      const customHttpRes = await customFetch.fetchWithPayment(
        `${customSrv.baseUrl}/api/tools/custom_reverse`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: "x402" }),
        }
      );
      assert.equal(customHttpRes.status, 200);
      const customBody = (await customHttpRes.json()) as {
        ok: boolean;
        result: { reversed: string };
      };
      assert.equal(customBody.ok, true);
      assert.equal(customBody.result.reversed, "204x");
    } finally {
      await customSrv.close();
    }

    // -------------------------------------------------------------------------
    // 4. GET /mcp, GET /mcp/, GET /.well-known/x402, initialize, tools/list, manifest
    // -------------------------------------------------------------------------
    for (const mcpPath of ["/mcp", "/mcp/"]) {
      const cardRes = await fetch(`${srv.baseUrl}${mcpPath}`, {
        redirect: "manual",
        headers: { Accept: "application/json" },
      });
      assert.equal(cardRes.status, 200, `GET ${mcpPath} must return 200`);
      assert.ok(
        cardRes.headers.get("content-type")?.includes("application/json")
      );
      const card = (await cardRes.json()) as {
        name: string;
        transport: string;
        toolsCount: number;
      };
      assert.equal(card.name, "x402-gate");
      assert.equal(card.transport, "streamable-http");
      assert.equal(card.toolsCount, 3);
    }

    const wkRes = await fetch(`${srv.baseUrl}/.well-known/x402`);
    assert.equal(wkRes.status, 200);
    const wk = (await wkRes.json()) as {
      x402Version: number;
      payTo: string;
      paidEndpoints: Array<{ tool: string; url: string; amountMicroUsd: string }>;
      accepts: Array<{ extra?: Record<string, unknown> }>;
    };
    assert.equal(wk.x402Version, 2);
    assert.equal(wk.payTo, DEFAULT_X402_PAY_TO);
    assert.equal(wk.paidEndpoints.length, 2);
    assert.ok(
      wk.paidEndpoints.some(
        (e) =>
          e.tool === "paid_json_transform" &&
          e.amountMicroUsd === "1000" &&
          e.url.endsWith("/api/tools/paid_json_transform")
      )
    );
    assert.ok(
      wk.paidEndpoints.some(
        (e) =>
          e.tool === "paid_hash_attest" &&
          e.amountMicroUsd === "1500" &&
          e.url.endsWith("/api/tools/paid_hash_attest")
      )
    );
    assert.deepEqual(wk.accepts[0].extra, {
      name: "USDC",
      version: "2",
      assetTransferMethod: "eip3009",
    });

    // GET /api/tools/:name probe returns 402 + PAYMENT-REQUIRED
    const probeRes = await fetch(
      `${srv.baseUrl}/api/tools/paid_json_transform`
    );
    assert.equal(probeRes.status, 402);
    const probeHeader = probeRes.headers.get("payment-required");
    assert.ok(probeHeader, "GET /api/tools/:name must emit PAYMENT-REQUIRED");
    const decodedProbe = decodePaymentRequiredHeader(probeHeader);
    assert.equal(decodedProbe.x402Version, 2);
    assert.equal(decodedProbe.accepts[0].amount, "1000");

    // Free tool gate_pricing_manifest via MCP tools/call
    const manifestCall = await callMcp(srv.mcpUrl, "tools/call", {
      name: "gate_pricing_manifest",
      arguments: {},
    });
    assert.equal(manifestCall.isError, false);
    const manifestData = manifestCall.data as {
      ok: boolean;
      paidTools: Array<{ name: string; amountMicroUsd: string }>;
    };
    assert.equal(manifestData.ok, true);
    assert.equal(manifestData.paidTools.length, 2);

    // -------------------------------------------------------------------------
    // 5. @x402/fetch HTTP 402 -> EIP-3009 pay -> 200 on POST /api/tools/paid_json_transform
    // -------------------------------------------------------------------------
    let capturedHttpSig = "";
    const { fetchWithPayment, trace } = createX402FetchClient({
      evmPrivateKey: payerKey,
      preferredScheme: "exact",
      preferredNetwork: BASE_SEPOLIA_NETWORK,
      baseFetch: async (input, init) => {
        const req = new Request(input, init);
        const sig = req.headers.get("payment-signature");
        if (sig) capturedHttpSig = sig;
        return fetch(req);
      },
    });

    const httpPaidRes = await fetchWithPayment(
      `${srv.baseUrl}/api/tools/paid_json_transform`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input: { z: 3, a: { d: 2, b: 1 } },
        }),
      }
    );
    assert.equal(httpPaidRes.status, 200);
    assert.ok(capturedHttpSig);
    const payRespHeader = httpPaidRes.headers.get("payment-response");
    assert.ok(payRespHeader, "200 response must include PAYMENT-RESPONSE header");
    const decodedSettle = decodePaymentResponseHeader(payRespHeader);
    assert.equal(decodedSettle.success, true);
    assert.ok(decodedSettle.transaction.startsWith("local-eip3009-"));
    assert.ok(
      trace.some((t) => t.status === 402 && t.hasPaymentRequiredHeader) &&
        trace.some(
          (t) =>
            t.status === 200 &&
            t.hasPaymentSignatureHeader &&
            t.hasPaymentResponseHeader
        ),
      "Trace must record 402 PAYMENT-REQUIRED -> PAYMENT-SIGNATURE -> 200 PAYMENT-RESPONSE"
    );

    const httpBody = (await httpPaidRes.json()) as {
      ok: boolean;
      tool: string;
      result: { canonicalJson: string; sha256: string };
      settlement: SettlementReceipt;
      dsse: DsseEnvelope;
    };
    assert.equal(httpBody.ok, true);
    assert.equal(httpBody.tool, "paid_json_transform");
    assert.equal(httpBody.result.canonicalJson, '{"a":{"b":1,"d":2},"z":3}');
    assert.match(httpBody.result.sha256, /^[0-9a-f]{64}$/);
    assert.equal(httpBody.settlement.amountMicroUsd, "1000");
    assert.equal(httpBody.settlement.mode, "local_facilitator");
    assert.equal(
      verifyDsse(httpBody.dsse, undefined, keystorePath).valid,
      true,
      "Receipt DSSE signature must verify"
    );

    // Tampered DSSE must fail
    const tampered: DsseEnvelope = {
      ...httpBody.dsse,
      payload:
        (httpBody.dsse.payload[0] === "A" ? "B" : "A") +
        httpBody.dsse.payload.slice(1),
    };
    assert.equal(verifyDsse(tampered, undefined, keystorePath).valid, false);

    // Also exercise paid_hash_attest via @x402/fetch
    const attestRes = await fetchWithPayment(
      `${srv.baseUrl}/api/tools/paid_hash_attest`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subject: "gate-attest-check",
          payload: { y: 2, x: 1 },
        }),
      }
    );
    assert.equal(attestRes.status, 200);
    const attestBody = (await attestRes.json()) as {
      ok: boolean;
      result: { digestHex: string; attestation: DsseEnvelope };
      settlement: SettlementReceipt;
    };
    assert.equal(attestBody.ok, true);
    assert.equal(attestBody.settlement.amountMicroUsd, "1500");
    assert.equal(
      verifyDsse(attestBody.result.attestation, undefined, keystorePath).valid,
      true
    );

    // -------------------------------------------------------------------------
    // 6. MCP tools/call _meta["x402/payment"] unpaid isError:true -> paid retry -> _meta["x402/payment-response"]
    // -------------------------------------------------------------------------
    const mcpUnpaid = await callMcp(srv.mcpUrl, "tools/call", {
      name: "paid_json_transform",
      arguments: { input: { b: 2, a: 1 } },
    });
    assert.equal(mcpUnpaid.isError, true);
    const mcpChallenge = mcpUnpaid.meta[
      "x402/payment-required"
    ] as X402PaymentRequiredEnvelope;
    assert.ok(mcpChallenge && mcpChallenge.accepts.length === 1);
    assert.equal(mcpChallenge.accepts[0].amount, "1000");

    const mcpPartial = await evmScheme.createPaymentPayload(
      2,
      mcpChallenge.accepts[0] as unknown as Parameters<
        ExactEvmScheme["createPaymentPayload"]
      >[1]
    );
    const mcpPaymentSig: X402PaymentSignature = {
      x402Version: 2,
      accepted: mcpChallenge.accepts[0],
      payload: mcpPartial.payload,
    };

    const mcpPaid = await callMcp(srv.mcpUrl, "tools/call", {
      name: "paid_json_transform",
      arguments: { input: { b: 2, a: 1 } },
      _meta: { "x402/payment": mcpPaymentSig },
    });
    assert.equal(mcpPaid.isError, false);
    assert.ok(mcpPaid.meta["x402/payment-response"]);
    assert.ok(mcpPaid.meta["x402/dsse"]);
    const mcpPaidData = mcpPaid.data as {
      ok: boolean;
      tool: string;
      result: { canonicalJson: string };
      settlement: SettlementReceipt;
      dsse: DsseEnvelope;
    };
    assert.equal(mcpPaidData.ok, true);
    assert.equal(mcpPaidData.result.canonicalJson, '{"a":1,"b":2}');
    assert.equal(
      verifyDsse(mcpPaidData.dsse, undefined, keystorePath).valid,
      true
    );

    // -------------------------------------------------------------------------
    // 7. Replay rejection (409) across HTTP, MCP, and server restarts
    // -------------------------------------------------------------------------
    const httpReplayRes = await fetch(
      `${srv.baseUrl}/api/tools/paid_json_transform`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "PAYMENT-SIGNATURE": capturedHttpSig,
        },
        body: JSON.stringify({ input: { replay: true } }),
      }
    );
    assert.equal(httpReplayRes.status, 409, "HTTP replay must return 409");
    assert.equal(
      ((await httpReplayRes.json()) as { code: string }).code,
      "replay_rejected"
    );

    const mcpReplayRes = await callMcp(srv.mcpUrl, "tools/call", {
      name: "paid_json_transform",
      arguments: { input: { replay: true } },
      _meta: { "x402/payment": mcpPaymentSig },
    });
    assert.equal(mcpReplayRes.isError, true);
    assert.equal(
      (mcpReplayRes.data as { code: string }).code,
      "replay_rejected"
    );

    // Restart server with same intentLogPath -> replay still blocked with 409!
    await srv.close();
    srv = await startGateServer({
      port: 0,
      host: "127.0.0.1",
      facilitatorUrl: facilitator.url,
      payTo: DEFAULT_X402_PAY_TO,
      intentLogPath,
      ledgerPath,
      keystorePath,
    });
    const restartReplayRes = await fetch(
      `${srv.baseUrl}/api/tools/paid_json_transform`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "PAYMENT-SIGNATURE": capturedHttpSig,
        },
        body: JSON.stringify({ input: { restart: true } }),
      }
    );
    assert.equal(
      restartReplayRes.status,
      409,
      "Replay must remain blocked (409) after restart via intentLogPath"
    );

    // -------------------------------------------------------------------------
    // 8. Retired payee rejection (403)
    // -------------------------------------------------------------------------
    const retiredPayment: X402PaymentSignature = {
      x402Version: 2,
      accepted: {
        scheme: "exact",
        network: BASE_SEPOLIA_NETWORK,
        asset: BASE_SEPOLIA_USDC,
        amount: "1000",
        payTo: RETIRED_X402_PAY_TO,
        maxTimeoutSeconds: 300,
        extra: { name: "USDC", version: "2", assetTransferMethod: "eip3009" },
      },
      payload: {
        authorization: {
          from: payerAccount.address,
          to: RETIRED_X402_PAY_TO,
          value: "1000",
          validAfter: "0",
          validBefore: String(Math.floor(Date.now() / 1000) + 300),
          nonce: "0x" + "ab".repeat(32),
        },
        signature: "0x" + "11".repeat(65),
      },
    };
    const retiredHttpRes = await fetch(
      `${srv.baseUrl}/api/tools/paid_json_transform`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "PAYMENT-SIGNATURE": encodePaymentSignatureHeader(
            retiredPayment as unknown as Parameters<
              typeof encodePaymentSignatureHeader
            >[0]
          ),
        },
        body: JSON.stringify({ input: {} }),
      }
    );
    assert.equal(retiredHttpRes.status, 403, "Retired payee must return 403");
    assert.equal(
      ((await retiredHttpRes.json()) as { code: string }).code,
      "retired_payee_rejected"
    );

    const retiredMcpRes = await callMcp(srv.mcpUrl, "tools/call", {
      name: "paid_json_transform",
      arguments: {},
      _meta: { "x402/payment": retiredPayment },
    });
    assert.equal(retiredMcpRes.isError, true);
    assert.equal(
      (retiredMcpRes.data as { code: string }).code,
      "retired_payee_rejected"
    );

    // Expired authorization must be rejected with 402
    const expiredPayment: X402PaymentSignature = {
      x402Version: 2,
      accepted: {
        scheme: "exact",
        network: BASE_SEPOLIA_NETWORK,
        asset: BASE_SEPOLIA_USDC,
        amount: "1000",
        payTo: DEFAULT_X402_PAY_TO,
        maxTimeoutSeconds: 300,
        extra: { name: "USDC", version: "2", assetTransferMethod: "eip3009" },
      },
      payload: {
        authorization: {
          from: payerAccount.address,
          to: DEFAULT_X402_PAY_TO,
          value: "1000",
          validAfter: "0",
          validBefore: String(Math.floor(Date.now() / 1000) - 10),
          nonce: "0x" + "cd".repeat(32),
        },
        signature: "0x" + "22".repeat(65),
      },
    };
    const expiredRes = await fetch(
      `${srv.baseUrl}/api/tools/paid_json_transform`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "PAYMENT-SIGNATURE": encodePaymentSignatureHeader(
            expiredPayment as unknown as Parameters<
              typeof encodePaymentSignatureHeader
            >[0]
          ),
        },
        body: JSON.stringify({ input: {} }),
      }
    );
    assert.equal(expiredRes.status, 402);
    assert.equal(
      ((await expiredRes.json()) as { code: string }).code,
      "authorization_expired"
    );

    // MCP initialize + tools/list check
    const initCall = await callMcp(srv.mcpUrl, "initialize", {});
    assert.equal(initCall.httpStatus, 200);
    const listCall = await callMcp(srv.mcpUrl, "tools/list", {});
    assert.equal(listCall.httpStatus, 200);
    const listedTools = (listCall.result.tools ?? []) as Array<{ name: string }>;
    assert.equal(listedTools.length, 3);

    // MCP tools/call via HTTP payment-signature header must also succeed
    const headerMcpPartial = await evmScheme.createPaymentPayload(
      2,
      mcpChallenge.accepts[0] as unknown as Parameters<
        ExactEvmScheme["createPaymentPayload"]
      >[1]
    );
    const headerMcpSig: X402PaymentSignature = {
      x402Version: 2,
      accepted: mcpChallenge.accepts[0],
      payload: headerMcpPartial.payload,
    };
    const headerMcpPaid = await callMcp(
      srv.mcpUrl,
      "tools/call",
      {
        name: "paid_json_transform",
        arguments: { input: { headerMode: true, a: 1 } },
      },
      {
        "payment-signature": encodePaymentSignatureHeader(
          headerMcpSig as unknown as Parameters<
            typeof encodePaymentSignatureHeader
          >[0]
        ),
      }
    );
    assert.equal(headerMcpPaid.isError, false);
    assert.ok(headerMcpPaid.meta["x402/payment-response"]);

    // Unknown tool on REST route must return 404
    const unknownToolRes = await fetch(`${srv.baseUrl}/api/tools/no_such_tool`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(unknownToolRes.status, 404);

    // Keystore mode 0600 & persisted logs check
    assert.equal(fs.statSync(keystorePath).mode & 0o777, 0o600);
    assert.ok(fs.existsSync(intentLogPath));
    assert.ok(fs.existsSync(ledgerPath));

    console.log(
      "ALL 402-GATE TESTS PASSED:",
      JSON.stringify({
        server_path: "mcps/gate/server.ts",
        tools: 3,
        tests_passed: true,
      })
    );
  } finally {
    await srv.close();
    await facilitator.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runTests().catch((err) => {
  console.error("402-Gate tests failed:", err);
  process.exit(1);
});
