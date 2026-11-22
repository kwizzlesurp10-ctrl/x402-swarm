import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generatePrivateKey } from "viem/accounts";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  BRANDING,
  DEFAULT_X402_PAY_TO,
  LIGHTNING_MAINNET_NETWORK,
  LIGHTNING_TESTNET_NETWORK,
  MCP_REGISTRY_SCHEMA,
  RETIRED_X402_PAY_TO,
} from "../../shared/constants.js";
import { verifyDsse } from "../../shared/keystore.js";
import { readJsonBody, sendJson } from "../../shared/mcp-http.js";
import { SpendPolicyEngine, SpendPolicyError } from "../../shared/policy.js";
import type {
  DsseEnvelope,
  LightningTaskOutput,
  X402PaymentRequiredEnvelope,
  X402PaymentSignature,
} from "../../shared/types.js";
import {
  decodePaymentRequiredHeader,
  encodePaymentRequiredHeader,
  encodePaymentSignatureHeader,
} from "../../shared/x402-adapter.js";
import {
  createTestLightningSimulator,
  decodeLightningInvoice,
  encodeLightningInvoice,
  verifyLightningPreimage,
} from "./bolt11.js";
import {
  runLightning402ClientCall,
  runLightningMcpToolCall,
} from "./client.js";
import { startLightning402Server } from "./server.js";

async function startMockFacilitator(): Promise<{
  url: string;
  verifyCalls: number;
  settleCalls: number;
  close: () => Promise<void>;
}> {
  const state = { verifyCalls: 0, settleCalls: 0 };

  const server = http.createServer(async (req, res) => {
    const pathname = new URL(req.url || "/", "http://127.0.0.1").pathname;
    if (req.method === "GET" && pathname === "/supported") {
      sendJson(res, 200, {
        kinds: [
          {
            x402Version: 2,
            scheme: "exact",
            network: BASE_SEPOLIA_NETWORK,
          },
        ],
        extensions: [],
        signers: {},
      });
      return;
    }

    if (req.method === "POST" && pathname === "/verify") {
      state.verifyCalls += 1;
      const body = (await readJsonBody(req)) as Record<string, unknown>;
      const paymentPayload = body.paymentPayload as
        | { payload?: { authorization?: { from?: string } } }
        | undefined;
      sendJson(res, 200, {
        isValid: true,
        payer:
          paymentPayload?.payload?.authorization?.from ??
          "0x1111111111111111111111111111111111111111",
      });
      return;
    }

    if (req.method === "POST" && pathname === "/settle") {
      state.settleCalls += 1;
      const body = (await readJsonBody(req)) as Record<string, unknown>;
      const paymentPayload = body.paymentPayload as
        | { payload?: { authorization?: { from?: string } } }
        | undefined;
      sendJson(res, 200, {
        success: true,
        transaction: `0x${crypto.randomBytes(32).toString("hex")}`,
        network: BASE_SEPOLIA_NETWORK,
        payer:
          paymentPayload?.payload?.authorization?.from ??
          "0x1111111111111111111111111111111111111111",
      });
      return;
    }

    sendJson(res, 404, { error: "Not found" });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${addr.port}`,
    get verifyCalls() {
      return state.verifyCalls;
    },
    get settleCalls() {
      return state.settleCalls;
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function startRetiredPayeeMockServer(): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  const server = http.createServer((_req, res) => {
    const reqEnv: X402PaymentRequiredEnvelope = {
      x402Version: 2,
      error: "Payment required",
      resource: { url: "http://127.0.0.1/retired", mimeType: "application/json" },
      accepts: [
        {
          scheme: "exact",
          network: BASE_SEPOLIA_NETWORK,
          asset: BASE_SEPOLIA_USDC,
          amount: "1000",
          payTo: RETIRED_X402_PAY_TO,
          maxTimeoutSeconds: 300,
          extra: {
            name: "USDC",
            version: "2",
            assetTransferMethod: "eip3009",
          },
        },
      ],
    };
    sendJson(res, 402, reqEnv, {
      "PAYMENT-REQUIRED": encodePaymentRequiredHeader(
        reqEnv as unknown as Parameters<typeof encodePaymentRequiredHeader>[0]
      ),
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}/retired`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function runTests(): Promise<void> {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "lightning-402-test-")
  );
  const keystorePath = path.join(tmpDir, "ed25519.pem");
  const intentLogPath = path.join(tmpDir, "intents.jsonl");
  const ledgerPath = path.join(tmpDir, "ledger.jsonl");

  const facilitator = await startMockFacilitator();
  const retiredServer = await startRetiredPayeeMockServer();
  let srv = await startLightning402Server({
    port: 0,
    host: "127.0.0.1",
    facilitatorUrl: facilitator.url,
    payTo: DEFAULT_X402_PAY_TO,
    intentLogPath,
    ledgerPath,
    keystorePath,
    priceMicroUsd: "1000",
    priceMsat: "12000",
  });

  try {
    // -------------------------------------------------------------------------
    // 1. server.json compliance
    // -------------------------------------------------------------------------
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const serverJson = JSON.parse(
      fs.readFileSync(path.join(__dirname, "server.json"), "utf8")
    ) as {
      $schema: string;
      description: string;
      author: { name: string; email: string; url: string };
      organization: string;
      location: string;
    };
    assert.equal(serverJson.$schema, MCP_REGISTRY_SCHEMA);
    assert.ok(
      serverJson.description.length > 0 && serverJson.description.length <= 100,
      `server.json description length must be <= 100, got ${serverJson.description.length}`
    );
    assert.equal(serverJson.author.name, BRANDING.author);
    assert.equal(serverJson.author.email, BRANDING.contact);
    assert.equal(serverJson.organization, BRANDING.organization);
    assert.equal(serverJson.location, BRANDING.location);

    // -------------------------------------------------------------------------
    // 2. BOLT11 bech32 encode/decode (testnet, mainnet, pico-msat, amountless) & simulator
    // -------------------------------------------------------------------------
    const preimageBytes = crypto.randomBytes(32);
    const preimageHex = preimageBytes.toString("hex");
    const paymentHashHex = crypto
      .createHash("sha256")
      .update(preimageBytes)
      .digest("hex");

    const testnetBolt11 = encodeLightningInvoice({
      network: LIGHTNING_TESTNET_NETWORK,
      amountMsat: 12000n,
      paymentHash: paymentHashHex,
      description: "Testnet BOLT11 check",
      expirySeconds: 300,
    });
    assert.ok(testnetBolt11.startsWith("lntb120n1"));
    const decodedTestnet = decodeLightningInvoice(testnetBolt11);
    assert.equal(decodedTestnet.network, LIGHTNING_TESTNET_NETWORK);
    assert.equal(decodedTestnet.amountMsat, 12000n);
    assert.equal(decodedTestnet.paymentHash, paymentHashHex);
    assert.equal(decodedTestnet.description, "Testnet BOLT11 check");
    assert.ok(/^(02|03)[0-9a-f]{64}$/.test(decodedTestnet.payeePubkey));
    assert.equal(
      decodedTestnet.expiresAtUnix,
      decodedTestnet.timestampUnix + 300
    );

    const picoBolt11 = encodeLightningInvoice({
      network: LIGHTNING_TESTNET_NETWORK,
      amountMsat: 12345n,
      paymentHash: paymentHashHex,
    });
    assert.ok(picoBolt11.startsWith("lntb123450p1"));
    assert.equal(decodeLightningInvoice(picoBolt11).amountMsat, 12345n);

    const amountlessBolt11 = encodeLightningInvoice({
      network: LIGHTNING_TESTNET_NETWORK,
      amountMsat: 0n,
      paymentHash: paymentHashHex,
    });
    assert.ok(amountlessBolt11.startsWith("lntb1"));
    assert.equal(decodeLightningInvoice(amountlessBolt11).amountMsat, 0n);

    const mainnetBolt11 = encodeLightningInvoice({
      network: LIGHTNING_MAINNET_NETWORK,
      amountMsat: 100_000n,
      paymentHash: paymentHashHex,
    });
    assert.ok(mainnetBolt11.startsWith("lnbc1u1"));
    assert.equal(decodeLightningInvoice(mainnetBolt11).amountMsat, 100_000n);

    assert.equal(verifyLightningPreimage(preimageHex, paymentHashHex), true);
    assert.equal(
      verifyLightningPreimage("00".repeat(32), paymentHashHex),
      false
    );

    const lnSim = createTestLightningSimulator();
    const minted = lnSim.mintInvoice({
      amountMsat: 12000n,
      network: LIGHTNING_TESTNET_NETWORK,
    });
    assert.equal("preimage" in minted, false);
    assert.equal(lnSim.hasPreimage(minted.paymentHash), true);

    // Expired invoice must fail payer check
    const expiredBolt11 = encodeLightningInvoice({
      network: LIGHTNING_TESTNET_NETWORK,
      amountMsat: 12000n,
      paymentHash: minted.paymentHash,
      timestampUnix: Math.floor(Date.now() / 1000) - 600,
      expirySeconds: 60,
    });
    await assert.rejects(
      () =>
        lnSim.pay({
          bolt11: expiredBolt11,
          paymentHash: minted.paymentHash,
          amountMsat: 12000n,
          network: LIGHTNING_TESTNET_NETWORK,
          payTo: DEFAULT_X402_PAY_TO,
          requirements: {
            scheme: "lightning",
            network: LIGHTNING_TESTNET_NETWORK,
            asset: "MSAT",
            amount: "12000",
            payTo: DEFAULT_X402_PAY_TO,
            maxTimeoutSeconds: 300,
          },
        }),
      /expired/
    );

    // -------------------------------------------------------------------------
    // 3. GET /mcp, GET /mcp/, SSE GET /mcp, and GET /.well-known/x402
    // -------------------------------------------------------------------------
    for (const mcpPath of ["/mcp", "/mcp/"]) {
      const mcpRes = await fetch(`${srv.baseUrl}${mcpPath}`, {
        headers: { Accept: "application/json" },
      });
      assert.equal(mcpRes.status, 200, `GET ${mcpPath} should return 200`);
      assert.ok(
        mcpRes.headers.get("content-type")?.includes("application/json")
      );
      const card = (await mcpRes.json()) as {
        name: string;
        toolsCount: number;
        transport: string;
      };
      assert.equal(card.name, "lightning-402");
      assert.equal(card.toolsCount, 3);
      assert.equal(card.transport, "streamable-http");
    }

    const sseAbort = new AbortController();
    const sseRes = await fetch(`${srv.baseUrl}/mcp`, {
      headers: { Accept: "text/event-stream" },
      signal: sseAbort.signal,
    });
    assert.equal(sseRes.status, 200);
    assert.ok(sseRes.headers.get("content-type")?.includes("text/event-stream"));
    sseAbort.abort();

    const wkRes = await fetch(`${srv.baseUrl}/.well-known/x402`);
    assert.equal(wkRes.status, 200);
    const wk = (await wkRes.json()) as {
      x402Version: number;
      networks: string[];
      schemes: string[];
      payTo: string;
      accepts: Array<{ extra?: Record<string, unknown> }>;
    };
    assert.equal(wk.x402Version, 2);
    assert.ok(wk.networks.includes(BASE_SEPOLIA_NETWORK));
    assert.ok(wk.networks.includes(LIGHTNING_TESTNET_NETWORK));
    assert.ok(wk.schemes.includes("exact"));
    assert.ok(wk.schemes.includes("lightning"));
    assert.equal(wk.payTo, DEFAULT_X402_PAY_TO);
    for (const acc of wk.accepts) {
      assert.equal(acc.extra && "preimage" in acc.extra, false);
    }

    // -------------------------------------------------------------------------
    // 4. Unpaid HTTP 402 challenge verification & zero preimage exposure
    // -------------------------------------------------------------------------
    const unpaidOracle = await fetch(`${srv.baseUrl}/api/v1/oracle`);
    assert.equal(unpaidOracle.status, 402);
    const payReqHeader = unpaidOracle.headers.get("payment-required");
    assert.ok(payReqHeader, "402 response must carry PAYMENT-REQUIRED header");
    const decodedChallenge = decodePaymentRequiredHeader(payReqHeader);
    const bodyChallenge =
      (await unpaidOracle.json()) as X402PaymentRequiredEnvelope;
    assert.equal(decodedChallenge.x402Version, 2);
    assert.equal(bodyChallenge.x402Version, 2);
    assert.equal(bodyChallenge.accepts.length, 2);

    const lnAccept = bodyChallenge.accepts.find(
      (a) => a.scheme === "lightning"
    );
    assert.ok(lnAccept?.extra?.bolt11);
    assert.equal("preimage" in (lnAccept?.extra ?? {}), false);
    for (const stored of srv.getIssuedInvoices()) {
      assert.equal("preimage" in stored, false);
    }

    // -------------------------------------------------------------------------
    // 5. @x402/fetch HTTP 402 -> Lightning preimage pay -> 200 round-trip + DSSE
    // -------------------------------------------------------------------------
    let capturedReplayHeader = "";
    const trackingFetch: typeof globalThis.fetch = async (input, init) => {
      const req = new Request(input, init);
      const sigHeader = req.headers.get("payment-signature");
      if (sigHeader) capturedReplayHeader = sigHeader;
      return globalThis.fetch(req);
    };

    const paidOracle = await runLightning402ClientCall({
      url: `${srv.baseUrl}/api/v1/oracle`,
      method: "GET",
      lightningPayer: lnSim.pay,
      preferredScheme: "lightning",
      preferredNetwork: LIGHTNING_TESTNET_NETWORK,
      baseFetch: trackingFetch,
    });

    assert.equal(paidOracle.ok, true);
    assert.equal(paidOracle.status, 200);
    assert.ok(paidOracle.handshakeTx?.startsWith("ln:"));
    assert.ok(paidOracle.paymentResponse?.success);
    assert.ok(paidOracle.dsse);

    const dsseEnv = paidOracle.dsse as DsseEnvelope;
    assert.equal(
      verifyDsse(dsseEnv, undefined, keystorePath).valid,
      true,
      "Settlement DSSE signature must verify"
    );
    // Tampering 1 character in DSSE payload must fail verification
    const tamperedDsse: DsseEnvelope = {
      ...dsseEnv,
      payload:
        (dsseEnv.payload[0] === "A" ? "B" : "A") + dsseEnv.payload.slice(1),
    };
    assert.equal(
      verifyDsse(tamperedDsse, undefined, keystorePath).valid,
      false,
      "Tampered DSSE payload must fail verification"
    );

    const oracleBody = paidOracle.data as {
      quote: { btcMicroUsdPerSat: string };
      witness: DsseEnvelope;
    };
    assert.equal(
      verifyDsse(oracleBody.witness, undefined, keystorePath).valid,
      true
    );

    const paidEchoHttp = await runLightning402ClientCall({
      url: `${srv.baseUrl}/api/v1/echo`,
      method: "POST",
      body: { ping: "satoshi" },
      lightningPayer: lnSim.pay,
      preferredScheme: "lightning",
      preferredNetwork: LIGHTNING_TESTNET_NETWORK,
    });
    assert.equal(paidEchoHttp.ok, true);
    assert.deepEqual((paidEchoHttp.data as { echo: unknown }).echo, {
      ping: "satoshi",
    });

    // -------------------------------------------------------------------------
    // 6. Replay of same Lightning preimage is rejected (409)
    // -------------------------------------------------------------------------
    assert.ok(capturedReplayHeader);
    const replayRes = await fetch(`${srv.baseUrl}/api/v1/oracle`, {
      method: "GET",
      headers: { "PAYMENT-SIGNATURE": capturedReplayHeader },
    });
    assert.equal(replayRes.status, 409);
    assert.equal(
      ((await replayRes.json()) as { code: string }).code,
      "replay_rejected"
    );

    // Wrong preimage must be rejected
    const freshChallenge = (await (
      await fetch(`${srv.baseUrl}/api/v1/oracle`)
    ).json()) as X402PaymentRequiredEnvelope;
    const freshLn = freshChallenge.accepts.find(
      (a) => a.scheme === "lightning"
    )!;
    const forgedSig: X402PaymentSignature = {
      x402Version: 2,
      accepted: freshLn,
      payload: {
        bolt11: freshLn.extra?.bolt11,
        paymentHash: freshLn.extra?.paymentHash,
        preimage: "ff".repeat(32),
        payer: "attacker",
      },
    };
    const forgedRes = await fetch(`${srv.baseUrl}/api/v1/oracle`, {
      headers: {
        "PAYMENT-SIGNATURE": encodePaymentSignatureHeader(
          forgedSig as unknown as Parameters<
            typeof encodePaymentSignatureHeader
          >[0]
        ),
      },
    });
    assert.equal(forgedRes.status, 402);

    // -------------------------------------------------------------------------
    // 7. EVM eip155:84532 402 -> EIP-3009 sign -> mock facilitator -> 200 & replay guard
    // -------------------------------------------------------------------------
    const testEvmKey = generatePrivateKey();
    let capturedEvmSigHeader = "";
    const evmTrackingFetch: typeof globalThis.fetch = async (input, init) => {
      const req = new Request(input, init);
      const sigHeader = req.headers.get("payment-signature");
      if (sigHeader) capturedEvmSigHeader = sigHeader;
      return globalThis.fetch(req);
    };

    const paidEvmOracle = await runLightning402ClientCall({
      url: `${srv.baseUrl}/api/v1/oracle`,
      method: "GET",
      evmPrivateKey: testEvmKey,
      preferredScheme: "exact",
      preferredNetwork: BASE_SEPOLIA_NETWORK,
      baseFetch: evmTrackingFetch,
    });
    assert.equal(paidEvmOracle.ok, true);
    assert.equal(paidEvmOracle.status, 200);
    assert.ok(facilitator.verifyCalls >= 1);
    assert.ok(facilitator.settleCalls >= 1);
    assert.ok(paidEvmOracle.handshakeTx?.startsWith("0x"));

    const evmReplayRes = await fetch(`${srv.baseUrl}/api/v1/oracle`, {
      headers: { "PAYMENT-SIGNATURE": capturedEvmSigHeader },
    });
    assert.equal(evmReplayRes.status, 409);

    // -------------------------------------------------------------------------
    // 8. MCP tools/call _meta["x402/payment"] unpaid -> paid retry -> _meta["x402/payment-response"]
    // -------------------------------------------------------------------------
    const quoteRpcRes = await fetch(srv.mcpUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: { name: "lightning_quote_invoice", arguments: {} },
      }),
    });
    const quoteRpcJson = (await quoteRpcRes.json()) as {
      result: { isError?: boolean; content: Array<{ text: string }> };
    };
    assert.equal(Boolean(quoteRpcJson.result.isError), false);
    const quoteObj = JSON.parse(quoteRpcJson.result.content[0].text) as {
      lightning: { bolt11: string; paymentHash: string };
    };
    assert.ok(quoteObj.lightning.bolt11.startsWith("lntb"));
    assert.equal("preimage" in quoteObj.lightning, false);

    // Unpaid MCP tools/call check
    const unpaidMcpRes = await fetch(srv.mcpUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 11,
        method: "tools/call",
        params: {
          name: "paid_lightning_echo",
          arguments: { message: "hello-x402-mcp" },
        },
      }),
    });
    const unpaidMcpJson = (await unpaidMcpRes.json()) as {
      result: {
        isError?: boolean;
        _meta?: Record<string, unknown>;
        content: Array<{ text: string }>;
      };
    };
    assert.equal(unpaidMcpJson.result.isError, true);
    assert.ok(unpaidMcpJson.result._meta?.["x402/payment-required"]);

    // Full MCP unpaid -> paid retry via client helper
    const paidMcpEcho = await runLightningMcpToolCall({
      mcpUrl: srv.mcpUrl,
      toolName: "paid_lightning_echo",
      arguments: { message: "hello-x402-mcp" },
      lightningPayer: lnSim.pay,
      preferredScheme: "lightning",
      preferredNetwork: LIGHTNING_TESTNET_NETWORK,
    });
    assert.equal(paidMcpEcho.isError, false);
    assert.ok(paidMcpEcho.paymentResponse?.success);
    assert.ok(paidMcpEcho.handshakeTx?.startsWith("ln:"));
    assert.equal(
      (paidMcpEcho.parsedContent as { echo: string }).echo,
      "hello-x402-mcp"
    );

    const paidMcpOracle = await runLightningMcpToolCall({
      mcpUrl: srv.mcpUrl,
      toolName: "paid_satoshi_oracle",
      arguments: {},
      lightningPayer: lnSim.pay,
      preferredScheme: "lightning",
      preferredNetwork: LIGHTNING_TESTNET_NETWORK,
    });
    assert.equal(paidMcpOracle.isError, false);
    assert.ok(paidMcpOracle.paymentResponse?.success);
    assert.equal(
      verifyDsse(
        (paidMcpOracle.parsedContent as { witness: DsseEnvelope }).witness,
        undefined,
        keystorePath
      ).valid,
      true
    );

    // MCP replay via payment-signature header must also fail with replay_rejected
    const mcpReplayRes = await fetch(srv.mcpUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "payment-signature": capturedReplayHeader,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 12,
        method: "tools/call",
        params: {
          name: "paid_lightning_echo",
          arguments: { message: "replay" },
        },
      }),
    });
    const mcpReplayJson = (await mcpReplayRes.json()) as {
      result: { isError?: boolean; content: Array<{ text: string }> };
    };
    assert.equal(mcpReplayJson.result.isError, true);
    assert.equal(
      (JSON.parse(mcpReplayJson.result.content[0].text) as { code: string })
        .code,
      "replay_rejected"
    );

    // -------------------------------------------------------------------------
    // 9. Server restart preserves replay guard from intentLogPath
    // -------------------------------------------------------------------------
    await srv.close();
    srv = await startLightning402Server({
      port: 0,
      host: "127.0.0.1",
      facilitatorUrl: facilitator.url,
      payTo: DEFAULT_X402_PAY_TO,
      intentLogPath,
      ledgerPath,
      keystorePath,
      priceMicroUsd: "1000",
      priceMsat: "12000",
    });

    const restartLnReplay = await fetch(`${srv.baseUrl}/api/v1/oracle`, {
      headers: { "PAYMENT-SIGNATURE": capturedReplayHeader },
    });
    assert.equal(
      restartLnReplay.status,
      409,
      "Replay must remain blocked across server restarts via intentLogPath"
    );

    const restartEvmReplay = await fetch(`${srv.baseUrl}/api/v1/oracle`, {
      headers: { "PAYMENT-SIGNATURE": capturedEvmSigHeader },
    });
    assert.equal(
      restartEvmReplay.status,
      409,
      "EVM nonce replay must remain blocked across server restarts via intentLogPath"
    );

    // -------------------------------------------------------------------------
    // 10. Spend cap enforcement (maxPerCallMicroUsd < price) blocks BEFORE signing
    // -------------------------------------------------------------------------
    let signingCalls = 0;
    const spiedLightningPayer: typeof lnSim.pay = async (req) => {
      signingCalls += 1;
      return lnSim.pay(req);
    };

    let capBlocked = false;
    try {
      await runLightning402ClientCall({
        url: `${srv.baseUrl}/api/v1/oracle`,
        lightningPayer: spiedLightningPayer,
        evmPrivateKey: testEvmKey,
        preferredScheme: "exact",
        preferredNetwork: BASE_SEPOLIA_NETWORK,
        maxPerCallMicroUsd: 500n,
        maxRollingWindowMicroUsd: 10_000n,
      });
    } catch (err) {
      assert.ok(err instanceof SpendPolicyError);
      assert.equal(err.decision.capEnforced, true);
      assert.equal(err.decision.allowed, false);
      capBlocked = true;
    }
    assert.equal(capBlocked, true);
    assert.equal(signingCalls, 0);

    let lnCapBlocked = false;
    try {
      await runLightning402ClientCall({
        url: `${srv.baseUrl}/api/v1/oracle`,
        lightningPayer: spiedLightningPayer,
        preferredScheme: "lightning",
        preferredNetwork: LIGHTNING_TESTNET_NETWORK,
        policy: new SpendPolicyEngine({
          maxPerCallMicroUsd: 500_000n,
          maxRollingWindowMicroUsd: 5_000_000n,
          windowMs: 60_000,
        }),
      });
    } catch (err) {
      assert.ok(err instanceof SpendPolicyError);
      assert.equal(err.decision.capEnforced, true);
      lnCapBlocked = true;
    }
    assert.equal(lnCapBlocked, true);
    assert.equal(signingCalls, 0);

    // -------------------------------------------------------------------------
    // 11. Retired payee 0xAB745e5F576667037696e78ba7dA28E193E4423D rejected unconditionally
    // -------------------------------------------------------------------------
    let retiredBlockedClient = false;
    try {
      await runLightning402ClientCall({
        url: retiredServer.url,
        evmPrivateKey: testEvmKey,
        lightningPayer: spiedLightningPayer,
      });
    } catch (err) {
      assert.ok(err instanceof SpendPolicyError);
      assert.equal(err.decision.capEnforced, true);
      assert.ok(err.message.toLowerCase().includes("retired"));
      retiredBlockedClient = true;
    }
    assert.equal(retiredBlockedClient, true);
    assert.equal(signingCalls, 0);

    await assert.rejects(
      () =>
        startLightning402Server({
          port: 0,
          payTo: RETIRED_X402_PAY_TO,
          keystorePath,
        }),
      /Retired payee address is forbidden/
    );

    const retiredPaymentPayload: X402PaymentSignature = {
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
          from: "0x1111111111111111111111111111111111111111",
          to: RETIRED_X402_PAY_TO,
          value: "1000",
          validAfter: "0",
          validBefore: String(Math.floor(Date.now() / 1000) + 300),
          nonce: `0x${crypto.randomBytes(32).toString("hex")}`,
        },
        signature: "0x" + "11".repeat(65),
      },
    };
    const retiredPostRes = await fetch(`${srv.baseUrl}/api/v1/oracle`, {
      headers: {
        "PAYMENT-SIGNATURE": encodePaymentSignatureHeader(
          retiredPaymentPayload as unknown as Parameters<
            typeof encodePaymentSignatureHeader
          >[0]
        ),
      },
    });
    assert.equal(retiredPostRes.status, 403);
    assert.equal(
      ((await retiredPostRes.json()) as { code: string }).code,
      "retired_payee_rejected"
    );

    const ksMode = fs.statSync(keystorePath).mode & 0o777;
    assert.equal(ksMode, 0o600, "Keystore must have mode 0600");
    assert.ok(fs.existsSync(intentLogPath));
    assert.ok(fs.existsSync(ledgerPath));

    const summary: LightningTaskOutput = {
      server_path: "mcps/lightning/server.ts",
      handshake_tx: paidOracle.handshakeTx,
      cap_enforced: true,
      tests_passed: true,
    };
    console.log("ALL LIGHTNING-402 TESTS PASSED:", JSON.stringify(summary));
  } finally {
    await srv.close();
    await facilitator.close();
    await retiredServer.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runTests().catch((err) => {
  console.error("LIGHTNING-402 TESTS FAILED:", err);
  process.exit(1);
});
