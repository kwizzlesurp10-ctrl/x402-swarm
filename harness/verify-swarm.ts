import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  DEFAULT_KEYSTORE_PATH,
  DEFAULT_X402_PAY_TO,
  LIGHTNING_TESTNET_NETWORK,
  MCP_REGISTRY_SCHEMA,
  RETIRED_X402_PAY_TO,
  TESTNET_FACILITATOR_URL,
} from "../shared/constants.js";
import { loadOrCreateKeystore, verifyDsse } from "../shared/keystore.js";
import { SpendPolicyEngine } from "../shared/policy.js";
import type {
  DsseEnvelope,
  EndpointValidationResult,
  SettlementReceipt,
  X402PaymentRequiredEnvelope,
} from "../shared/types.js";
import {
  FacilitatorClient,
  createX402FetchClient,
  decodePaymentResponseHeader,
} from "../shared/x402-adapter.js";
import { startDiscoveryServer } from "../mcps/discovery/server.js";
import { startGateServer } from "../mcps/gate/server.js";
import { createTestLightningSimulator } from "../mcps/lightning/bolt11.js";
import { startLightning402Server } from "../mcps/lightning/server.js";
import { startPolicyServer } from "../mcps/policy/server.js";
import { formatMicroUsd } from "../mcps/settlement/ledger.js";
import { startSettlementServer } from "../mcps/settlement/server.js";
import { startTaxServer } from "../mcps/tax/server.js";
import { startLocalFacilitator } from "./local-facilitator.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");
const LEDGER_OUTPUT_PATH = path.join(REPO_ROOT, "registry", "testnet-ledger.jsonl");
const REPORT_OUTPUT_PATH = path.join(REPO_ROOT, "registry", "verification-report.json");
const EXPORTS_DIR = path.join(REPO_ROOT, "registry", "exports");
const BASE_CATALOG_PATH = path.join(REPO_ROOT, "registry", "catalog.json");

interface JsonRpcCallResult {
  httpStatus: number;
  rpc: Record<string, unknown>;
  resultData: unknown;
  isError: boolean;
  meta: Record<string, unknown>;
}

async function callMcp(
  mcpUrl: string,
  method: string,
  params?: Record<string, unknown>,
  headers: Record<string, string> = {}
): Promise<JsonRpcCallResult> {
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
    ? (result.content as Array<{ type?: string; text?: string }>)
    : [];
  const text = content[0]?.text ?? "";
  let resultData: unknown = text;
  try {
    if (text) resultData = JSON.parse(text);
  } catch {
    // Keep text as-is
  }
  return {
    httpStatus: res.status,
    rpc,
    resultData,
    isError: Boolean(result.isError),
    meta:
      result._meta && typeof result._meta === "object"
        ? (result._meta as Record<string, unknown>)
        : {},
  };
}

async function callMcpTool(
  mcpUrl: string,
  name: string,
  args: Record<string, unknown>,
  meta?: Record<string, unknown>
): Promise<JsonRpcCallResult> {
  return callMcp(mcpUrl, "tools/call", {
    name,
    arguments: args,
    ...(meta ? { _meta: meta } : {}),
  });
}

async function runLiveFacilitatorProbe(payTo: string) {
  const client = new FacilitatorClient(TESTNET_FACILITATOR_URL);
  const supported = await client.getSupported();
  const supportsBaseSepolia = supported.kinds.some(
    (k) => k.network === BASE_SEPOLIA_NETWORK && k.scheme === "exact"
  );

  const liveKey = (process.env.BASE_SEPOLIA_PRIVATE_KEY ||
    process.env.EVM_PRIVATE_KEY) as `0x${string}` | undefined;

  if (liveKey) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-live-"));
    const liveServer = await startLightning402Server({
      port: 0,
      facilitatorUrl: TESTNET_FACILITATOR_URL,
      payTo,
      intentLogPath: path.join(tmpDir, "intents.jsonl"),
      ledgerPath: path.join(tmpDir, "ledger.jsonl"),
      keystorePath: DEFAULT_KEYSTORE_PATH,
      priceMicroUsd: "1000",
      priceMsat: "12000",
    });

    try {
      const { fetchWithPayment, trace, evmAddress } = createX402FetchClient({
        evmPrivateKey: liveKey,
        preferredScheme: "exact",
        preferredNetwork: BASE_SEPOLIA_NETWORK,
      });

      const res = await fetchWithPayment(`${liveServer.baseUrl}/api/v1/oracle`, {
        method: "GET",
      });
      const body = (await res.json()) as Record<string, unknown>;
      const payRespHeader = res.headers.get("payment-response");
      const decoded = payRespHeader
        ? decodePaymentResponseHeader(payRespHeader)
        : undefined;

      const observed402 = trace.some((t) => t.status === 402 && t.hasPaymentRequiredHeader);
      const observed200 = res.status === 200 && Boolean(decoded?.success);

      return {
        reachable: true,
        facilitatorUrl: TESTNET_FACILITATOR_URL,
        supportsBaseSepolia,
        supportedKindsCount: supported.kinds.length,
        hasFundedTestnetKey: true,
        payerAddress: evmAddress ?? null,
        liveVerifyChecked: true,
        liveOnchainSettled: observed402 && observed200,
        handshake_tx: decoded?.transaction ?? null,
        responseStatus: res.status,
        body,
      };
    } finally {
      await liveServer.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  const ephemeralKey = generatePrivateKey();
  const account = privateKeyToAccount(ephemeralKey);
  const scheme = new ExactEvmScheme(account);
  const req = {
    scheme: "exact" as const,
    network: BASE_SEPOLIA_NETWORK as `${string}:${string}`,
    asset: BASE_SEPOLIA_USDC,
    amount: "1000",
    payTo,
    maxTimeoutSeconds: 300,
    extra: {
      name: "USDC",
      version: "2",
      assetTransferMethod: "eip3009",
    },
  };
  const partial = await scheme.createPaymentPayload(2, req);
  const paymentPayload = {
    x402Version: 2,
    accepted: req,
    payload: partial.payload,
  };
  const verifyOutcome = await client.verify(paymentPayload, req);

  return {
    reachable: true,
    facilitatorUrl: TESTNET_FACILITATOR_URL,
    supportsBaseSepolia,
    supportedKindsCount: supported.kinds.length,
    hasFundedTestnetKey: false,
    ephemeralVerifySigner: account.address,
    liveVerifyChecked: true,
    liveVerifyResponse: verifyOutcome,
    liveOnchainSettled: false,
    handshake_tx: null,
    note: "No BASE_SEPOLIA_PRIVATE_KEY / EVM_PRIVATE_KEY funded with Base Sepolia USDC in environment; live facilitator /supported and /verify wire check completed without fabricating an on-chain tx hash.",
  };
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const liveFacilitatorOnly = args.has("--live-facilitator");

  if (liveFacilitatorOnly) {
    const liveProbe = await runLiveFacilitatorProbe(DEFAULT_X402_PAY_TO);
    if (fs.existsSync(REPORT_OUTPUT_PATH)) {
      const existing = JSON.parse(fs.readFileSync(REPORT_OUTPUT_PATH, "utf8")) as Record<
        string,
        unknown
      >;
      existing.liveFacilitatorProbe = liveProbe;
      if (liveProbe.handshake_tx) {
        const t1 = existing.task1 as Record<string, unknown> | undefined;
        if (t1) t1.handshake_tx = liveProbe.handshake_tx;
      }
      fs.writeFileSync(REPORT_OUTPUT_PATH, JSON.stringify(existing, null, 2) + "\n", "utf8");
    }
    console.log(JSON.stringify({ liveFacilitatorProbe: liveProbe }, null, 2));
    return;
  }

  // Preserve any existing verified live_testnet probe + receipt from prior live run
  let preservedLiveProbe: Record<string, unknown> | undefined;
  let preservedLiveReceipt: SettlementReceipt | undefined;
  if (fs.existsSync(REPORT_OUTPUT_PATH)) {
    try {
      const prevReport = JSON.parse(fs.readFileSync(REPORT_OUTPUT_PATH, "utf8")) as Record<
        string,
        unknown
      >;
      const prevProbe = prevReport.liveFacilitatorProbe as
        | { liveOnchainSettled?: boolean; handshake_tx?: string; body?: { settlement?: SettlementReceipt } }
        | undefined;
      if (prevProbe?.liveOnchainSettled && prevProbe.handshake_tx) {
        preservedLiveProbe = prevReport.liveFacilitatorProbe as Record<string, unknown>;
        if (prevProbe.body?.settlement) {
          preservedLiveReceipt = prevProbe.body.settlement;
        }
      }
    } catch {
      // Ignore corrupt prior report
    }
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-swarm-verify-"));
  const intentLogPath = path.join(tmpDir, "lightning-intents.jsonl");
  const serverLedgerPath = path.join(tmpDir, "lightning-server-ledger.jsonl");
  const gateIntentLogPath = path.join(tmpDir, "gate-intents.jsonl");
  const gateLedgerPath = path.join(tmpDir, "gate-server-ledger.jsonl");
  const policyStatePath = path.join(tmpDir, "policy-state.json");
  const tempCatalogPath = path.join(tmpDir, "catalog.json");
  fs.copyFileSync(BASE_CATALOG_PATH, tempCatalogPath);

  fs.mkdirSync(path.dirname(LEDGER_OUTPUT_PATH), { recursive: true });
  fs.mkdirSync(EXPORTS_DIR, { recursive: true });
  fs.writeFileSync(LEDGER_OUTPUT_PATH, "", "utf8");

  const ks = loadOrCreateKeystore(DEFAULT_KEYSTORE_PATH);
  const ksStats = fs.statSync(ks.keystorePath);
  assert.equal(
    ksStats.mode & 0o777,
    0o600,
    "Persisted Ed25519 keystore must have mode 0600"
  );

  // Gate A1: Validate ALL 6 server.json files against 2025-12-11 schema & <=100 char descriptions
  const serverJsonPaths = [
    "mcps/gate/server.json",
    "mcps/lightning/server.json",
    "mcps/discovery/server.json",
    "mcps/policy/server.json",
    "mcps/settlement/server.json",
    "mcps/tax/server.json",
  ];
  const serverJsonChecks: Array<{ path: string; name: string; descriptionLen: number }> = [];
  for (const rel of serverJsonPaths) {
    const raw = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8")) as {
      $schema: string;
      name: string;
      description: string;
    };
    assert.equal(raw.$schema, MCP_REGISTRY_SCHEMA, `${rel} must use 2025-12-11 schema`);
    assert.ok(
      raw.description.length > 0 && raw.description.length <= 100,
      `${rel} description length (${raw.description.length}) must be <= 100`
    );
    serverJsonChecks.push({
      path: rel,
      name: raw.name,
      descriptionLen: raw.description.length,
    });
  }

  // Boot local EIP-3009 facilitator + ALL 6 MCP servers on ephemeral ports
  const localFacilitator = await startLocalFacilitator(0);
  const lnSimulator = createTestLightningSimulator();

  const gateServer = await startGateServer({
    port: 0,
    facilitatorUrl: localFacilitator.url,
    payTo: DEFAULT_X402_PAY_TO,
    intentLogPath: gateIntentLogPath,
    ledgerPath: gateLedgerPath,
    keystorePath: DEFAULT_KEYSTORE_PATH,
  });

  const lightningServer = await startLightning402Server({
    port: 0,
    facilitatorUrl: localFacilitator.url,
    payTo: DEFAULT_X402_PAY_TO,
    intentLogPath,
    ledgerPath: serverLedgerPath,
    keystorePath: DEFAULT_KEYSTORE_PATH,
    priceMicroUsd: "1000",
    priceMsat: "12000",
    issueInvoice: ({ amountMsat, network, description, expirySeconds }) =>
      lnSimulator.mintInvoice({
        amountMsat,
        network,
        description,
        expirySeconds,
      }),
  });

  const discoveryServer = await startDiscoveryServer({
    port: 0,
    catalogPath: tempCatalogPath,
  });

  const policyServer = await startPolicyServer({
    port: 0,
    statePath: policyStatePath,
    keystorePath: DEFAULT_KEYSTORE_PATH,
  });

  const settlementServer = await startSettlementServer({
    port: 0,
    ledgerPath: LEDGER_OUTPUT_PATH,
    keystorePath: DEFAULT_KEYSTORE_PATH,
  });

  const taxServer = await startTaxServer({
    port: 0,
    ledgerPath: LEDGER_OUTPUT_PATH,
    keystorePath: DEFAULT_KEYSTORE_PATH,
  });

  try {
    // Gate A2: Browser GET /mcp & GET /mcp/ 200 JSON + initialize + tools/list on all 6 servers
    const serverUrls = [
      { name: "gate", baseUrl: gateServer.baseUrl, mcpUrl: gateServer.mcpUrl },
      { name: "lightning", baseUrl: lightningServer.baseUrl, mcpUrl: lightningServer.mcpUrl },
      { name: "discovery", baseUrl: discoveryServer.baseUrl, mcpUrl: discoveryServer.mcpUrl },
      { name: "policy", baseUrl: policyServer.baseUrl, mcpUrl: policyServer.mcpUrl },
      { name: "settlement", baseUrl: settlementServer.baseUrl, mcpUrl: settlementServer.mcpUrl },
      { name: "tax", baseUrl: taxServer.baseUrl, mcpUrl: taxServer.mcpUrl },
    ];

    const mcpCardChecks: Array<{ name: string; statusGet: number; statusSlash: number; tools: number }> = [];
    for (const srv of serverUrls) {
      const r1 = await fetch(`${srv.baseUrl}/mcp`, { redirect: "manual" });
      assert.equal(r1.status, 200, `${srv.name} GET /mcp must return 200`);
      const card = (await r1.json()) as Record<string, unknown>;
      assert.ok(card.name && card.transport === "streamable-http");

      const r2 = await fetch(`${srv.baseUrl}/mcp/`, { redirect: "manual" });
      assert.equal(r2.status, 200, `${srv.name} GET /mcp/ must return 200`);
      await r2.json();

      const wk = await fetch(`${srv.baseUrl}/.well-known/x402`);
      assert.equal(wk.status, 200, `${srv.name} GET /.well-known/x402 must return 200`);
      await wk.json();

      const init = await callMcp(srv.mcpUrl, "initialize", {});
      assert.equal(init.httpStatus, 200);
      assert.ok((init.rpc.result as Record<string, unknown>)?.protocolVersion);

      const listed = await callMcp(srv.mcpUrl, "tools/list", {});
      assert.equal(listed.httpStatus, 200);
      const tools = ((listed.rpc.result as Record<string, unknown>)?.tools ?? []) as unknown[];
      assert.ok(tools.length > 0, `${srv.name} must expose tools`);
      mcpCardChecks.push({
        name: srv.name,
        statusGet: r1.status,
        statusSlash: r2.status,
        tools: tools.length,
      });
    }

    // Gate B: Policy/Identity MCP + client SpendPolicyEngine enforcement
    const regPolicyCall = await callMcpTool(policyServer.mcpUrl, "register_agent_policy", {
      agentId: "swarm-verify-agent",
      maxPerCallMicroUsd: "1500",
      maxRollingWindowMicroUsd: "2500",
      windowMs: 60_000,
      allowedNetworks: [BASE_SEPOLIA_NETWORK, LIGHTNING_TESTNET_NETWORK],
      allowedPayees: [DEFAULT_X402_PAY_TO],
    });
    assert.equal(regPolicyCall.isError, false);
    const policyAttestation = regPolicyCall.resultData as Record<string, unknown>;
    const verifyIdentityCall = await callMcpTool(policyServer.mcpUrl, "verify_agent_identity", {
      attestation: policyAttestation,
    });
    assert.equal(verifyIdentityCall.isError, false);
    assert.equal((verifyIdentityCall.resultData as { valid: boolean }).valid, true);

    const okEval = await callMcpTool(policyServer.mcpUrl, "evaluate_payment_request", {
      agentId: "swarm-verify-agent",
      requirement: {
        scheme: "exact",
        network: BASE_SEPOLIA_NETWORK,
        asset: BASE_SEPOLIA_USDC,
        amount: "1000",
        payTo: DEFAULT_X402_PAY_TO,
      },
    });
    assert.equal(okEval.isError, false);
    const okEvalData = okEval.resultData as { allowed: boolean; verdictDsse: DsseEnvelope };
    assert.equal(okEvalData.allowed, true);
    assert.ok(verifyDsse(okEvalData.verdictDsse, ks.publicKeyPem, ks.keystorePath).valid);

    const overCapEval = await callMcpTool(policyServer.mcpUrl, "evaluate_payment_request", {
      agentId: "swarm-verify-agent",
      requirement: {
        scheme: "exact",
        network: BASE_SEPOLIA_NETWORK,
        asset: BASE_SEPOLIA_USDC,
        amount: "2000",
        payTo: DEFAULT_X402_PAY_TO,
      },
    });
    assert.equal(overCapEval.isError, false);
    assert.equal((overCapEval.resultData as { allowed: boolean }).allowed, false);

    // Client-side SpendPolicyEngine check before signing
    const intentsBeforeCap = lightningServer.getIntentCount();
    const lowCapPolicy = new SpendPolicyEngine({
      agentId: "gate-b-verifier",
      maxPerCallMicroUsd: 500n,
      maxRollingWindowMicroUsd: 5000n,
      windowMs: 60_000,
    });

    const retiredDecision = lowCapPolicy.onPaymentRequested({
      scheme: "exact",
      network: BASE_SEPOLIA_NETWORK,
      asset: BASE_SEPOLIA_USDC,
      amount: "100",
      payTo: RETIRED_X402_PAY_TO,
      maxTimeoutSeconds: 300,
    });
    assert.equal(retiredDecision.allowed, false, "Retired payee must be unconditionally blocked");

    const evmKey = generatePrivateKey();
    const cappedClient = createX402FetchClient({
      evmPrivateKey: evmKey,
      lightningPayer: lnSimulator.pay,
      policy: lowCapPolicy,
      preferredScheme: "exact",
      preferredNetwork: BASE_SEPOLIA_NETWORK,
    });

    let capBlocked = false;
    let capBlockMessage = "";
    try {
      await cappedClient.fetchWithPayment(`${lightningServer.baseUrl}/api/v1/oracle`, {
        method: "GET",
      });
    } catch (err) {
      capBlocked = true;
      capBlockMessage = err instanceof Error ? err.message : String(err);
    }
    assert.equal(capBlocked, true, "Spend cap MUST abort payment before signing");
    assert.equal(lightningServer.getIntentCount(), intentsBeforeCap);

    // Revocation check on Policy MCP
    const revokeCall = await callMcpTool(policyServer.mcpUrl, "revoke_agent_identity", {
      agentId: "swarm-verify-agent",
      reason: "gate-b-revocation-test",
    });
    assert.equal(revokeCall.isError, false);
    const postRevokeEval = await callMcpTool(policyServer.mcpUrl, "evaluate_payment_request", {
      agentId: "swarm-verify-agent",
      requirement: {
        scheme: "exact",
        network: BASE_SEPOLIA_NETWORK,
        asset: BASE_SEPOLIA_USDC,
        amount: "1000",
        payTo: DEFAULT_X402_PAY_TO,
      },
    });
    assert.equal((postRevokeEval.resultData as { allowed: boolean; revoked: boolean }).allowed, false);
    assert.equal((postRevokeEval.resultData as { revoked: boolean }).revoked, true);

    // Gate C0: 402-Gate server HTTP 402 -> EIP-3009 pay -> 200 + 409 replay
    const gatePolicy = new SpendPolicyEngine({
      agentId: "gate-c0-402gate",
      maxPerCallMicroUsd: 5_000n,
      maxRollingWindowMicroUsd: 50_000n,
      windowMs: 60_000,
    });
    let capturedGateSig = "";
    const gateFetchClient = createX402FetchClient({
      evmPrivateKey: evmKey,
      policy: gatePolicy,
      preferredScheme: "exact",
      preferredNetwork: BASE_SEPOLIA_NETWORK,
      baseFetch: async (input, init) => {
        const req = new Request(input, init);
        const sig = req.headers.get("payment-signature");
        if (sig) capturedGateSig = sig;
        return fetch(req);
      },
    });

    const gateRes = await gateFetchClient.fetchWithPayment(
      `${gateServer.baseUrl}/api/tools/paid_json_transform`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: { z: 2, a: 1 } }),
      }
    );
    assert.equal(gateRes.status, 200, "402-Gate HTTP 402->pay->200 must succeed");
    const gateBody = (await gateRes.json()) as {
      ok: boolean;
      result: { canonicalJson: string };
      settlement: SettlementReceipt;
    };
    assert.equal(gateBody.ok, true);
    assert.equal(gateBody.result.canonicalJson, '{"a":1,"z":2}');

    const gateReplayRes = await fetch(
      `${gateServer.baseUrl}/api/tools/paid_json_transform`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "payment-signature": capturedGateSig,
        },
        body: JSON.stringify({ input: { z: 2, a: 1 } }),
      }
    );
    assert.equal(gateReplayRes.status, 409, "402-Gate replay must return 409");

    // Gate C1: Lightning BOLT11 + Preimage 402 -> pay -> 200 handshake & replay rejection
    const lnPolicy = new SpendPolicyEngine({
      agentId: "gate-c-lightning",
      maxPerCallMicroUsd: 5_000_000n,
      maxRollingWindowMicroUsd: 20_000_000n,
      windowMs: 60_000,
    });
    let capturedLnPaymentSig = "";
    const lnFetchClient = createX402FetchClient({
      lightningPayer: lnSimulator.pay,
      policy: lnPolicy,
      preferredScheme: "lightning",
      preferredNetwork: LIGHTNING_TESTNET_NETWORK,
      baseFetch: async (input, init) => {
        const req = new Request(input, init);
        const sig = req.headers.get("payment-signature");
        if (sig) capturedLnPaymentSig = sig;
        return fetch(req);
      },
    });

    const lnRes = await lnFetchClient.fetchWithPayment(
      `${lightningServer.baseUrl}/api/v1/oracle`
    );
    assert.equal(lnRes.status, 200, "Lightning 402->pay->200 must succeed");
    const lnPayRespHeader = lnRes.headers.get("payment-response");
    assert.ok(lnPayRespHeader, "PAYMENT-RESPONSE header must be present");
    const lnSettleDecoded = decodePaymentResponseHeader(lnPayRespHeader);
    assert.equal(lnSettleDecoded.success, true);
    const lnBody = (await lnRes.json()) as {
      ok: boolean;
      settlement: SettlementReceipt;
      dsse: SettlementReceipt["dsse"];
    };
    assert.equal(lnBody.ok, true);
    assert.equal(lnBody.settlement.mode, "lightning_preimage");
    assert.ok(lnBody.dsse && verifyDsse(lnBody.dsse, ks.publicKeyPem, ks.keystorePath).valid);

    const lnReplayRes = await fetch(`${lightningServer.baseUrl}/api/v1/oracle`, {
      headers: { "payment-signature": capturedLnPaymentSig },
    });
    assert.ok(
      lnReplayRes.status === 409 || lnReplayRes.status === 402,
      `Lightning replay must be rejected (got ${lnReplayRes.status})`
    );

    // Gate C1b: MCP JSON-RPC _meta["x402/payment"] handshake on paid_satoshi_oracle
    const mcpUnpaid = await callMcpTool(lightningServer.mcpUrl, "paid_satoshi_oracle", {});
    assert.equal(mcpUnpaid.isError, true);
    const mcpChallenge = mcpUnpaid.meta["x402/payment-required"] as X402PaymentRequiredEnvelope;
    const lnAccept = mcpChallenge.accepts.find((a) => a.scheme === "lightning");
    assert.ok(lnAccept && lnAccept.extra?.bolt11 && lnAccept.extra?.paymentHash);
    const paidMcpLn = await lnSimulator.pay({
      bolt11: String(lnAccept.extra.bolt11),
      paymentHash: String(lnAccept.extra.paymentHash),
      amountMsat: BigInt(String(lnAccept.extra.amountMsat ?? lnAccept.amount)),
      network: lnAccept.network,
      payTo: lnAccept.payTo,
      requirements: lnAccept,
    });
    const mcpPaid = await callMcpTool(
      lightningServer.mcpUrl,
      "paid_satoshi_oracle",
      {},
      {
        "x402/payment": {
          x402Version: 2,
          accepted: lnAccept,
          payload: {
            bolt11: lnAccept.extra.bolt11,
            paymentHash: lnAccept.extra.paymentHash,
            preimage: paidMcpLn.preimage,
            payer: paidMcpLn.payer,
          },
        },
      }
    );
    assert.equal(mcpPaid.isError, false);
    const mcpPaidData = mcpPaid.resultData as { settlement: SettlementReceipt };
    assert.ok(mcpPaid.meta["x402/payment-response"]);

    // Gate C2: Base Sepolia eip155:84532 EIP-3009 handshake on Lightning-402 via local facilitator
    const evmPolicy = new SpendPolicyEngine({
      agentId: "gate-c-evm",
      maxPerCallMicroUsd: 5_000n,
      maxRollingWindowMicroUsd: 50_000n,
      windowMs: 60_000,
    });
    let capturedEvmPaymentSig = "";
    const evmFetchClient = createX402FetchClient({
      evmPrivateKey: evmKey,
      policy: evmPolicy,
      preferredScheme: "exact",
      preferredNetwork: BASE_SEPOLIA_NETWORK,
      baseFetch: async (input, init) => {
        const req = new Request(input, init);
        const sig = req.headers.get("payment-signature");
        if (sig) capturedEvmPaymentSig = sig;
        return fetch(req);
      },
    });
    const evmRes = await evmFetchClient.fetchWithPayment(
      `${lightningServer.baseUrl}/api/v1/oracle`
    );
    assert.equal(evmRes.status, 200);
    const evmBody = (await evmRes.json()) as {
      ok: boolean;
      settlement: SettlementReceipt;
    };
    assert.equal(evmBody.settlement.mode, "local_facilitator");

    const evmReplayRes = await fetch(`${lightningServer.baseUrl}/api/v1/oracle`, {
      headers: { "payment-signature": capturedEvmPaymentSig },
    });
    assert.ok(evmReplayRes.status === 409 || evmReplayRes.status === 402);

    // Gate D: Discovery MCP validates BOTH 402-Gate and Lightning-402
    const valGateCall = await callMcpTool(discoveryServer.mcpUrl, "validate_endpoint", {
      url: gateServer.baseUrl,
      paidPath: "/api/tools/paid_json_transform",
      paidMethod: "POST",
    });
    assert.equal(valGateCall.isError, false);
    const valGate = valGateCall.resultData as EndpointValidationResult;
    assert.equal(valGate.valid, true, "402-Gate server must pass Discovery validation");

    const valLnCall = await callMcpTool(discoveryServer.mcpUrl, "validate_endpoint", {
      url: lightningServer.baseUrl,
      paidPath: "/api/v1/oracle",
    });
    assert.equal(valLnCall.isError, false);
    const valLn = valLnCall.resultData as EndpointValidationResult;
    assert.equal(valLn.valid, true, "Lightning-402 server must pass Discovery validation");

    await callMcpTool(discoveryServer.mcpUrl, "register_endpoint", {
      id: "lightning-402-live-verify",
      name: "lightning-402",
      title: "Lightning-402 MCP Server",
      url: lightningServer.baseUrl,
      paidPath: "/api/v1/oracle",
      vendor: "kwizzlesurp.com",
    });

    const searchCall = await callMcpTool(discoveryServer.mcpUrl, "search_resources", {
      scheme: "lightning",
      network: LIGHTNING_TESTNET_NETWORK,
      onlyValid: true,
    });
    const searchData = searchCall.resultData as { entries: Array<{ id: string }> };
    assert.ok(searchData.entries.some((e) => e.id === "lightning-402-live-verify"));

    // Gate E: Settlement ingestion, reconciliation, batching, and Tax export files
    const collectedReceipts: SettlementReceipt[] = [
      ...(preservedLiveReceipt ? [preservedLiveReceipt] : []),
      gateBody.settlement,
      lnBody.settlement,
      mcpPaidData.settlement,
      evmBody.settlement,
    ];

    for (const receipt of collectedReceipts) {
      const ing = await callMcpTool(settlementServer.mcpUrl, "ingest_settlement", {
        receipt,
        requireValidDsse: true,
      });
      assert.equal(ing.isError, false);
      const ingData = ing.resultData as { ingested: boolean; duplicate: boolean };
      assert.equal(ingData.ingested, true);
      assert.equal(ingData.duplicate, false);
    }

    const dupIng = await callMcpTool(settlementServer.mcpUrl, "ingest_settlement", {
      receipt: collectedReceipts[0],
      requireValidDsse: true,
    });
    assert.equal((dupIng.resultData as { duplicate: boolean }).duplicate, true);

    const expectedGrossMicroUsd = collectedReceipts.reduce(
      (sum, r) => sum + BigInt(r.amountMicroUsd),
      0n
    );

    const recCall = await callMcpTool(settlementServer.mcpUrl, "reconcile_settlements", {
      expectedReceipts: collectedReceipts.map((r) => ({
        id: r.id,
        network: r.network,
        txHash: r.txHash,
        amountMicroUsd: r.amountMicroUsd,
      })),
      feeBps: "250",
    });
    assert.equal(recCall.isError, false);
    const recData = recCall.resultData as {
      totalGrossMicroUsd: string;
      matchedIds: string[];
      missingExpectedIds: string[];
      amountMismatches: unknown[];
    };
    assert.equal(recData.totalGrossMicroUsd, expectedGrossMicroUsd.toString());
    assert.equal(recData.matchedIds.length, collectedReceipts.length);
    assert.equal(recData.missingExpectedIds.length, 0);
    assert.equal(recData.amountMismatches.length, 0);

    const batchCall = await callMcpTool(settlementServer.mcpUrl, "create_settlement_batch", {
      batchId: "batch-verify-6mcp",
      feeBps: "250",
    });
    assert.equal(batchCall.isError, false);
    const batchData = batchCall.resultData as { dsse: SettlementReceipt["dsse"] };
    assert.ok(batchData.dsse && verifyDsse(batchData.dsse, ks.publicKeyPem, ks.keystorePath).valid);

    const csvCall = await callMcpTool(taxServer.mcpUrl, "export_tax_ledger", {
      format: "csv",
      taxYear: 2026,
      feeBps: "250",
    });
    const csvData = csvCall.resultData as {
      csv: string;
      totals: { grossMicroUsd: string; grossUsd: string };
    };
    assert.equal(csvData.totals.grossMicroUsd, expectedGrossMicroUsd.toString());
    assert.equal(csvData.totals.grossUsd, formatMicroUsd(expectedGrossMicroUsd));

    const jsonlCall = await callMcpTool(taxServer.mcpUrl, "export_tax_ledger", {
      format: "jsonl",
      taxYear: 2026,
      feeBps: "250",
    });
    const jsonlData = jsonlCall.resultData as { jsonl: string };

    const bundleCall = await callMcpTool(taxServer.mcpUrl, "generate_audit_bundle", {
      taxYear: 2026,
      feeBps: "250",
    });
    const verifyBundleCall = await callMcpTool(taxServer.mcpUrl, "verify_audit_bundle", {
      bundle: bundleCall.resultData,
    });
    const verifyBundleData = verifyBundleCall.resultData as { valid: boolean };
    assert.equal(verifyBundleData.valid, true);

    fs.writeFileSync(path.join(EXPORTS_DIR, "tax-ledger-2026.csv"), csvData.csv, "utf8");
    fs.writeFileSync(path.join(EXPORTS_DIR, "tax-ledger-2026.jsonl"), jsonlData.jsonl, "utf8");
    fs.writeFileSync(
      path.join(EXPORTS_DIR, "tax-audit-bundle-2026.json"),
      JSON.stringify(bundleCall.resultData, null, 2) + "\n",
      "utf8"
    );

    const liveTx =
      typeof preservedLiveProbe?.handshake_tx === "string"
        ? preservedLiveProbe.handshake_tx
        : null;

    const report: Record<string, unknown> = {
      verifiedAt: new Date().toISOString(),
      keystore: {
        path: ks.keystorePath,
        keyid: ks.keyid,
        modeOctal: "0600",
      },
      gateA_registryAndBrowserGet: {
        serverJsonChecks,
        mcpCardChecks,
      },
      gateB_policyAndIdentity: {
        cap_enforced: capBlocked,
        evmCapBlockReason: capBlockMessage,
        policyMcpToolsVerified: true,
        policyRevocationBlocked: true,
        retiredPayeeRejectedInPolicy: !retiredDecision.allowed,
      },
      gateC_paidGateAndDualRail: {
        gate402_tx: gateBody.settlement.txHash,
        gate402_replay_rejected_status: gateReplayRes.status,
        lightning_tx: lnBody.settlement.txHash,
        lightning_mcp_tx: mcpPaidData.settlement.txHash,
        lightning_replay_rejected_status: lnReplayRes.status,
        local_eip3009_tx: evmBody.settlement.txHash,
        local_eip3009_replay_rejected_status: evmReplayRes.status,
      },
      gateD_discovery: {
        gate402Validated: valGate.valid,
        gate402Score: valGate.score,
        lightning402Validated: valLn.valid,
        lightning402Score: valLn.score,
      },
      gateE_settlementAndTax: {
        ledgerPath: "registry/testnet-ledger.jsonl",
        ingestedCount: collectedReceipts.length,
        expectedGrossMicroUsd: expectedGrossMicroUsd.toString(),
        expectedGrossUsd: formatMicroUsd(expectedGrossMicroUsd),
        reconciledGrossMicroUsd: recData.totalGrossMicroUsd,
        batchSignedAndVerified: true,
        taxAuditBundleVerified: verifyBundleData.valid,
        exports: [
          "registry/exports/tax-ledger-2026.csv",
          "registry/exports/tax-ledger-2026.jsonl",
          "registry/exports/tax-audit-bundle-2026.json",
        ],
      },
      task1: {
        server_path: "mcps/lightning/server.ts",
        handshake_tx: liveTx,
        local_eip3009_tx: evmBody.settlement.txHash,
        lightning_tx: lnBody.settlement.txHash,
        cap_enforced: capBlocked,
      },
      task2: {
        server_path: "mcps/discovery/server.ts",
        registry_path: "registry/catalog.json",
        validated_endpoints: 2,
      },
      task3: {
        settlement_server_path: "mcps/settlement/server.ts",
        tax_server_path: "mcps/tax/server.ts",
        dsse_verified: verifyBundleData.valid,
        gross_micro_usd: expectedGrossMicroUsd.toString(),
      },
      ...(preservedLiveProbe ? { liveFacilitatorProbe: preservedLiveProbe } : {}),
    };

    fs.writeFileSync(REPORT_OUTPUT_PATH, JSON.stringify(report, null, 2) + "\n", "utf8");
    console.log(JSON.stringify(report, null, 2));
  } finally {
    await Promise.allSettled([
      gateServer.close(),
      lightningServer.close(),
      discoveryServer.close(),
      policyServer.close(),
      settlementServer.close(),
      taxServer.close(),
      localFacilitator.close(),
    ]);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("Swarm verification failed:", err);
  process.exit(1);
});
