import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  BRANDING,
  DEFAULT_X402_PAY_TO,
  LIGHTNING_TESTNET_NETWORK,
  MCP_REGISTRY_SCHEMA,
  RETIRED_X402_PAY_TO,
} from "../../shared/constants.js";
import { loadOrCreateKeystore, verifyDsse } from "../../shared/keystore.js";
import type { X402PaymentRequirement } from "../../shared/types.js";
import {
  AGENT_IDENTITY_DSSE_PAYLOAD_TYPE,
  POLICY_VERDICT_DSSE_PAYLOAD_TYPE,
  PolicyIdentityStore,
  evaluatePaymentRequest,
  issueAgentIdentity,
  recordAgentSpend,
  revokeAgentIdentity,
  verifyAgentIdentity,
  type AgentIdentityAttestation,
  type PolicyEvaluationResult,
  type RecordAgentSpendResult,
  type VerifyAgentIdentityResult,
} from "./identity.js";
import { startPolicyServer } from "./server.js";

function flipChar(str: string, index = Math.floor(str.length / 2)): string {
  const ch = str[index];
  const next = ch === "A" ? "B" : "A";
  return str.slice(0, index) + next + str.slice(index + 1);
}

async function callMcp(
  mcpUrl: string,
  method: string,
  params: Record<string, unknown> = {},
  id: number = 1
): Promise<{
  status: number;
  rpc: Record<string, unknown>;
  isError: boolean;
  data: unknown;
}> {
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  const rpc = (await res.json()) as Record<string, unknown>;
  const result = (rpc.result ?? {}) as Record<string, unknown>;
  const content = Array.isArray(result.content)
    ? (result.content as Array<{ type?: string; text?: string }>)
    : [];
  const text = content[0]?.text ?? "";
  let data: unknown = text;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      // Leave raw text
    }
  }
  return {
    status: res.status,
    rpc,
    isError: Boolean(result.isError),
    data,
  };
}

async function callTool(
  mcpUrl: string,
  name: string,
  args: Record<string, unknown>,
  id: number = 1
) {
  return callMcp(mcpUrl, "tools/call", { name, arguments: args }, id);
}

function evmReq(
  amount: string,
  payTo: string = DEFAULT_X402_PAY_TO
): X402PaymentRequirement {
  return {
    scheme: "exact",
    network: BASE_SEPOLIA_NETWORK,
    asset: BASE_SEPOLIA_USDC,
    amount,
    payTo,
    maxTimeoutSeconds: 300,
  };
}

function lnReq(
  amountMsat: string,
  payTo: string = DEFAULT_X402_PAY_TO
): X402PaymentRequirement {
  return {
    scheme: "lightning",
    network: LIGHTNING_TESTNET_NETWORK,
    asset: "MSAT",
    amount: amountMsat,
    payTo,
    maxTimeoutSeconds: 300,
    extra: { amountMsat },
  };
}

async function runTests(): Promise<void> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-policy-test-"));
  const keystorePath = path.join(tmpDir, "ed25519.pem");
  const otherKeystorePath = path.join(tmpDir, "other-ed25519.pem");
  const statePath = path.join(tmpDir, "policy-state.json");

  try {
    // 1. Validate mcps/policy/server.json against 2025-12-11 schema, <=100 char description, branding
    const serverJsonRaw = fs.readFileSync(
      path.resolve(process.cwd(), "mcps/policy/server.json"),
      "utf8"
    );
    const serverJson = JSON.parse(serverJsonRaw) as {
      $schema: string;
      name: string;
      description: string;
      _meta?: Record<string, Record<string, unknown>>;
    };
    assert.equal(serverJson.$schema, MCP_REGISTRY_SCHEMA);
    assert.equal(serverJson.name, "io.github.kwizzlesurp10-ctrl/x402-policy-identity");
    assert.ok(serverJson.description.length > 0 && serverJson.description.length <= 100);
    assert.equal(
      serverJson._meta?.["io.modelcontextprotocol.registry/publisher-provided"]?.author,
      BRANDING.author
    );
    assert.equal(
      serverJson._meta?.["io.modelcontextprotocol.registry/publisher-provided"]?.organization,
      BRANDING.organization
    );

    // Ensure keystore is created with strict 0600 permissions
    const ks = loadOrCreateKeystore(keystorePath);
    const otherKs = loadOrCreateKeystore(otherKeystorePath);
    assert.equal(fs.statSync(keystorePath).mode & 0o777, 0o600);

    // 2. Unit tests on PolicyIdentityStore + DSSE attestation + tamper rejection
    const store = new PolicyIdentityStore({ statePath, keystorePath });

    // Float rejection on registration
    assert.throws(() =>
      store.issueAgentIdentity({
        agentId: "float-agent",
        maxPerCallMicroUsd: "1000.5",
        maxRollingWindowMicroUsd: "5000",
        windowMs: 60_000,
      })
    );
    assert.throws(() =>
      store.issueAgentIdentity({
        agentId: "float-num-agent",
        maxPerCallMicroUsd: 1000.25,
        maxRollingWindowMicroUsd: "5000",
        windowMs: 60_000,
      })
    );

    // Retired payee rejected during identity registration (allowedPayees)
    assert.throws(
      () =>
        store.issueAgentIdentity({
          agentId: "bad-payee-agent",
          maxPerCallMicroUsd: "1000",
          maxRollingWindowMicroUsd: "5000",
          windowMs: 60_000,
          allowedPayees: [RETIRED_X402_PAY_TO],
        }),
      /retired/i
    );
    assert.throws(
      () =>
        store.issueAgentIdentity({
          agentId: "bad-payee-lowercase",
          maxPerCallMicroUsd: "1000",
          maxRollingWindowMicroUsd: "5000",
          windowMs: 60_000,
          allowedPayees: [DEFAULT_X402_PAY_TO, RETIRED_X402_PAY_TO.toLowerCase()],
        }),
      /retired/i
    );

    // Register valid agent identity & verify DSSE attestation
    const att = store.issueAgentIdentity({
      agentId: "agent-alpha",
      evmAddress: "0x1111111111111111111111111111111111111111",
      maxPerCallMicroUsd: "1000",
      maxRollingWindowMicroUsd: "2000",
      windowMs: 60_000,
      allowedNetworks: [BASE_SEPOLIA_NETWORK, LIGHTNING_TESTNET_NETWORK],
      allowedPayees: [DEFAULT_X402_PAY_TO],
    });
    assert.equal(att.dsse.payloadType, AGENT_IDENTITY_DSSE_PAYLOAD_TYPE);
    assert.equal(att.keyid, ks.keyid);

    const verOk = store.verifyAgentIdentity(att);
    assert.equal(verOk.valid, true);
    assert.equal(verOk.signatureValid, true);
    assert.equal(verOk.integrityValid, true);
    assert.equal(verOk.revoked, false);
    assert.equal(verOk.expired, false);
    assert.equal(verOk.agentId, "agent-alpha");

    // Verify with explicit PEM and wrong PEM
    assert.equal(store.verifyAgentIdentity(att, ks.publicKeyPem).valid, true);
    const verWrongKey = store.verifyAgentIdentity(att, otherKs.publicKeyPem);
    assert.equal(verWrongKey.valid, false);
    assert.equal(verWrongKey.signatureValid, false);

    // Tamper 1: outer claim mutated without re-signing DSSE
    const tamperedClaim: AgentIdentityAttestation = {
      ...att,
      maxPerCallMicroUsd: "999999",
    };
    const verTamperClaim = store.verifyAgentIdentity(tamperedClaim);
    assert.equal(verTamperClaim.valid, false);
    assert.equal(verTamperClaim.integrityValid, false);

    // Tamper 2: DSSE signature flipped
    const tamperedSig: AgentIdentityAttestation = {
      ...att,
      dsse: {
        ...att.dsse,
        signatures: [
          {
            keyid: att.dsse.signatures[0].keyid,
            sig: flipChar(att.dsse.signatures[0].sig),
          },
        ],
      },
    };
    const verTamperSig = store.verifyAgentIdentity(tamperedSig);
    assert.equal(verTamperSig.valid, false);
    assert.equal(verTamperSig.signatureValid, false);

    // Tamper 3: DSSE base64 payload modified
    const modifiedClaims = { ...att, maxPerCallMicroUsd: "999999" };
    const tamperedPayload: AgentIdentityAttestation = {
      ...att,
      dsse: {
        ...att.dsse,
        payload: Buffer.from(JSON.stringify(modifiedClaims), "utf8").toString("base64"),
      },
    };
    const verTamperPayload = store.verifyAgentIdentity(tamperedPayload);
    assert.equal(verTamperPayload.valid, false);
    assert.equal(verTamperPayload.signatureValid, false);

    // 3. Per-call cap enforcement (1000 allowed, 2000 blocked) + DSSE verdict
    const t0 = 1_760_000_000_000;
    const eval1000 = store.evaluatePaymentRequest({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      nowMs: t0,
    });
    assert.equal(eval1000.allowed, true);
    assert.equal(eval1000.evaluatedMicroUsd, "1000");
    assert.equal(eval1000.remainingWindowMicroUsd, "1000");
    assert.equal(eval1000.revoked, false);
    assert.equal(eval1000.expired, false);
    assert.equal(eval1000.verdictDsse.payloadType, POLICY_VERDICT_DSSE_PAYLOAD_TYPE);
    assert.equal(verifyDsse(eval1000.verdictDsse, ks.publicKeyPem, keystorePath).valid, true);

    const eval2000 = store.evaluatePaymentRequest({
      agentId: "agent-alpha",
      requirement: evmReq("2000"),
      nowMs: t0,
    });
    assert.equal(eval2000.allowed, false);
    assert.equal(eval2000.capEnforced, true);
    assert.equal(eval2000.evaluatedMicroUsd, "2000");
    assert.match(eval2000.reason ?? "", /maxPerCallMicroUsd/i);
    assert.equal(verifyDsse(eval2000.verdictDsse, ks.publicKeyPem, keystorePath).valid, true);

    // 4. Rolling-window cumulative cap (2 allowed, 3rd blocked, duplicate txHash idempotent)
    const spend1 = store.recordAgentSpend({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      intentId: "intent-1",
      nowMs: t0 + 1_000,
    });
    assert.equal(spend1.recorded, true);
    assert.equal(spend1.duplicate, false);
    assert.equal(spend1.rollingSpendMicroUsd, "1000");
    assert.equal(spend1.remainingWindowMicroUsd, "1000");

    const spend2 = store.recordAgentSpend({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      txHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      intentId: "intent-2",
      nowMs: t0 + 2_000,
    });
    assert.equal(spend2.recorded, true);
    assert.equal(spend2.duplicate, false);
    assert.equal(spend2.rollingSpendMicroUsd, "2000");
    assert.equal(spend2.remainingWindowMicroUsd, "0");

    // Duplicate txHash even when rolling window is full must be idempotent & never double-count
    const dupSpend1 = store.recordAgentSpend({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      txHash: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      nowMs: t0 + 2_500,
    });
    assert.equal(dupSpend1.recorded, false);
    assert.equal(dupSpend1.duplicate, true);
    assert.equal(dupSpend1.rollingSpendMicroUsd, "2000");
    assert.equal(dupSpend1.remainingWindowMicroUsd, "0");

    // Duplicate intentId also idempotent
    const dupIntent2 = store.recordAgentSpend({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      intentId: "intent-2",
      nowMs: t0 + 2_600,
    });
    assert.equal(dupIntent2.recorded, false);
    assert.equal(dupIntent2.duplicate, true);
    assert.equal(dupIntent2.rollingSpendMicroUsd, "2000");

    // 3rd call blocked by rolling window cap
    const eval3rd = store.evaluatePaymentRequest({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      nowMs: t0 + 3_000,
    });
    assert.equal(eval3rd.allowed, false);
    assert.equal(eval3rd.capEnforced, true);
    assert.match(eval3rd.reason ?? "", /rolling window/i);
    assert.throws(() =>
      store.recordAgentSpend({
        agentId: "agent-alpha",
        requirement: evmReq("1000"),
        txHash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        nowMs: t0 + 3_000,
      })
    );

    // Reload from statePath to prove persistence preserves spendEntries & idempotency
    const reloadedStore = new PolicyIdentityStore({ statePath, keystorePath });
    const evalAfterReloadBlocked = reloadedStore.evaluatePaymentRequest({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      nowMs: t0 + 4_000,
    });
    assert.equal(evalAfterReloadBlocked.allowed, false);
    const dupAfterReload = reloadedStore.recordAgentSpend({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      nowMs: t0 + 4_000,
    });
    assert.equal(dupAfterReload.duplicate, true);
    assert.equal(dupAfterReload.rollingSpendMicroUsd, "2000");

    // Advancing past windowMs expires older entries
    const evalAfterWindow = reloadedStore.evaluatePaymentRequest({
      agentId: "agent-alpha",
      requirement: evmReq("1000"),
      nowMs: t0 + 65_000,
    });
    assert.equal(evalAfterWindow.allowed, true);
    assert.equal(evalAfterWindow.remainingWindowMicroUsd, "1000");

    // 5. Lightning integer msat cap conversion (strict integer ceiling)
    // 1 msat at 90001 microUsd/sat -> ceil(90001 / 1000) = 91 microUsd
    // 12000 msat at 90000 microUsd/sat -> 1_080_000 microUsd
    reloadedStore.issueAgentIdentity({
      agentId: "agent-ln-ceiling",
      maxPerCallMicroUsd: "91",
      maxRollingWindowMicroUsd: "500",
      windowMs: 60_000,
      btcMicroUsdPerSat: "90001",
      allowedNetworks: [LIGHTNING_TESTNET_NETWORK],
    });
    const lnCeilAllow = reloadedStore.evaluatePaymentRequest({
      agentId: "agent-ln-ceiling",
      requirement: lnReq("1"),
      nowMs: t0,
    });
    assert.equal(lnCeilAllow.allowed, true);
    assert.equal(lnCeilAllow.evaluatedMicroUsd, "91");

    // 2 msat at 90001 microUsd/sat -> ceil(180002 / 1000) = 181 > 91 -> blocked
    const lnCeilBlock = reloadedStore.evaluatePaymentRequest({
      agentId: "agent-ln-ceiling",
      requirement: lnReq("2"),
      nowMs: t0,
    });
    assert.equal(lnCeilBlock.allowed, false);
    assert.equal(lnCeilBlock.evaluatedMicroUsd, "181");

    // Float msat in requirement must be rejected
    assert.throws(() =>
      reloadedStore.evaluatePaymentRequest({
        agentId: "agent-ln-ceiling",
        requirement: {
          scheme: "lightning",
          network: LIGHTNING_TESTNET_NETWORK,
          asset: "MSAT",
          amount: "1",
          payTo: DEFAULT_X402_PAY_TO,
          maxTimeoutSeconds: 300,
          extra: { amountMsat: 1.5 },
        },
        nowMs: t0,
      })
    );

    // 6. Retired payee unconditionally rejected in evaluate_payment_request & record_agent_spend
    const retiredEval = reloadedStore.evaluatePaymentRequest({
      agentId: "agent-alpha",
      requirement: evmReq("1", RETIRED_X402_PAY_TO),
      nowMs: t0 + 65_000,
    });
    assert.equal(retiredEval.allowed, false);
    assert.equal(retiredEval.capEnforced, true);
    assert.match(retiredEval.reason ?? "", /retired/i);
    assert.equal(verifyDsse(retiredEval.verdictDsse, ks.publicKeyPem, keystorePath).valid, true);

    assert.throws(
      () =>
        reloadedStore.recordAgentSpend({
          agentId: "agent-alpha",
          requirement: evmReq("1", RETIRED_X402_PAY_TO),
          txHash: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          nowMs: t0 + 65_000,
        }),
      /retired/i
    );

    // 7. Expiration & revocation enforcement
    const expAtt = reloadedStore.issueAgentIdentity({
      agentId: "agent-expiring",
      maxPerCallMicroUsd: "1000",
      maxRollingWindowMicroUsd: "5000",
      windowMs: 60_000,
      expiresAt: new Date(t0 + 10_000).toISOString(),
    });
    assert.equal(
      reloadedStore.evaluatePaymentRequest({
        agentId: "agent-expiring",
        requirement: evmReq("500"),
        nowMs: t0 + 10_000,
      }).expired,
      true
    );
    assert.equal(
      reloadedStore.evaluatePaymentRequest({
        agentId: "agent-expiring",
        requirement: evmReq("500"),
        nowMs: t0 + 10_000,
      }).allowed,
      false
    );
    assert.equal(
      reloadedStore.verifyAgentIdentity(expAtt, undefined, keystorePath, t0 + 10_000).expired,
      true
    );

    // Revocation immediately blocks subsequent evaluate_payment_request
    const revRes = reloadedStore.revokeAgentIdentity("agent-alpha", "Key compromised");
    assert.equal(revRes.revoked, true);
    const afterRevEval = reloadedStore.evaluatePaymentRequest({
      agentId: "agent-alpha",
      requirement: evmReq("10"),
      nowMs: t0 + 65_000,
    });
    assert.equal(afterRevEval.allowed, false);
    assert.equal(afterRevEval.revoked, true);
    assert.match(afterRevEval.reason ?? "", /revoked/i);
    assert.equal(verifyDsse(afterRevEval.verdictDsse, ks.publicKeyPem, keystorePath).valid, true);
    assert.throws(() =>
      reloadedStore.recordAgentSpend({
        agentId: "agent-alpha",
        requirement: evmReq("10"),
        nowMs: t0 + 65_000,
      })
    );
    const verAfterRev = reloadedStore.verifyAgentIdentity(att);
    assert.equal(verAfterRev.valid, false);
    assert.equal(verAfterRev.revoked, true);

    // Verify revocation persists across store reload
    const postRevReload = new PolicyIdentityStore({ statePath, keystorePath });
    assert.equal(
      postRevReload.evaluatePaymentRequest({
        agentId: "agent-alpha",
        requirement: evmReq("10"),
        nowMs: t0 + 65_000,
      }).revoked,
      true
    );

    // 8. Standalone module-level helper exports sanity test
    const helperAtt = issueAgentIdentity({
      agentId: "helper-agent",
      maxPerCallMicroUsd: "1000",
      maxRollingWindowMicroUsd: "2000",
      windowMs: 60_000,
      keystorePath,
    });
    assert.equal(verifyAgentIdentity(helperAtt, undefined, keystorePath).valid, true);
    assert.equal(
      evaluatePaymentRequest({
        agentId: "helper-agent",
        requirement: evmReq("1000"),
        nowMs: t0,
        keystorePath,
      }).allowed,
      true
    );
    assert.equal(
      recordAgentSpend({
        agentId: "helper-agent",
        requirement: evmReq("1000"),
        txHash: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        nowMs: t0,
      }).rollingSpendMicroUsd,
      "1000"
    );
    assert.equal(revokeAgentIdentity("helper-agent", "cleanup").revoked, true);
    assert.equal(
      evaluatePaymentRequest({
        agentId: "helper-agent",
        requirement: evmReq("100"),
        nowMs: t0,
        keystorePath,
      }).revoked,
      true
    );

    // 9. Live HTTP MCP server tests (GET /mcp, GET /mcp/, /.well-known/x402, all 5 tools)
    const serverStatePath = path.join(tmpDir, "http-policy-state.json");
    const srv = await startPolicyServer({
      port: 0,
      host: "127.0.0.1",
      statePath: serverStatePath,
      keystorePath,
    });

    try {
      const getMcp = await fetch(`${srv.baseUrl}/mcp`, { redirect: "manual" });
      assert.equal(getMcp.status, 200);
      assert.match(getMcp.headers.get("content-type") ?? "", /application\/json/);
      const card = (await getMcp.json()) as Record<string, unknown>;
      assert.equal(card.name, "x402-policy-identity");
      assert.equal(card.transport, "streamable-http");
      assert.equal(card.toolsCount, 5);

      const getMcpSlash = await fetch(`${srv.baseUrl}/mcp/`, { redirect: "manual" });
      assert.equal(getMcpSlash.status, 200);
      assert.match(getMcpSlash.headers.get("content-type") ?? "", /application\/json/);
      const cardSlash = (await getMcpSlash.json()) as Record<string, unknown>;
      assert.equal(cardSlash.name, "x402-policy-identity");

      const wk = await fetch(`${srv.baseUrl}/.well-known/x402`);
      assert.equal(wk.status, 200);
      const wkJson = (await wk.json()) as Record<string, unknown>;
      assert.equal(wkJson.x402Version, 2);

      const listRes = await callMcp(srv.mcpUrl, "tools/list", {}, 1);
      assert.equal(listRes.status, 200);
      const tools = ((listRes.rpc.result as Record<string, unknown>).tools ??
        []) as Array<{ name: string }>;
      assert.deepEqual(tools.map((t) => t.name).sort(), [
        "evaluate_payment_request",
        "record_agent_spend",
        "register_agent_policy",
        "revoke_agent_identity",
        "verify_agent_identity",
      ]);

      // Reject retired payee via register_agent_policy MCP tool
      const regRetired = await callTool(
        srv.mcpUrl,
        "register_agent_policy",
        {
          agentId: "mcp-retired-payee",
          maxPerCallMicroUsd: "1000",
          maxRollingWindowMicroUsd: "2000",
          windowMs: 60_000,
          allowedPayees: [RETIRED_X402_PAY_TO],
        },
        2
      );
      assert.equal(regRetired.isError, true);

      // Register valid agent via MCP tool
      const regOk = await callTool(
        srv.mcpUrl,
        "register_agent_policy",
        {
          agentId: "mcp-agent-1",
          maxPerCallMicroUsd: "1000",
          maxRollingWindowMicroUsd: "2000",
          windowMs: 60_000,
          allowedNetworks: [BASE_SEPOLIA_NETWORK, LIGHTNING_TESTNET_NETWORK],
          allowedPayees: [DEFAULT_X402_PAY_TO],
        },
        3
      );
      assert.equal(regOk.isError, false);
      const mcpAtt = regOk.data as AgentIdentityAttestation;

      // Verify valid attestation & tamper rejection via MCP tool
      const verMcp = await callTool(
        srv.mcpUrl,
        "verify_agent_identity",
        { attestation: mcpAtt },
        4
      );
      assert.equal(verMcp.isError, false);
      assert.equal((verMcp.data as VerifyAgentIdentityResult).valid, true);

      const verMcpTampered = await callTool(
        srv.mcpUrl,
        "verify_agent_identity",
        { attestation: { ...mcpAtt, maxPerCallMicroUsd: "5000000" } },
        5
      );
      assert.equal(verMcpTampered.isError, false);
      assert.equal((verMcpTampered.data as VerifyAgentIdentityResult).valid, false);

      // Evaluate 1000 (allowed) & 2000 (blocked) & retired payee (blocked)
      const mcpEval1000 = await callTool(
        srv.mcpUrl,
        "evaluate_payment_request",
        {
          agentId: "mcp-agent-1",
          requirement: evmReq("1000"),
          nowMs: t0,
        },
        6
      );
      assert.equal(mcpEval1000.isError, false);
      assert.equal((mcpEval1000.data as PolicyEvaluationResult).allowed, true);

      const mcpEval2000 = await callTool(
        srv.mcpUrl,
        "evaluate_payment_request",
        {
          agentId: "mcp-agent-1",
          requirement: evmReq("2000"),
          nowMs: t0,
        },
        7
      );
      assert.equal(mcpEval2000.isError, false);
      assert.equal((mcpEval2000.data as PolicyEvaluationResult).allowed, false);

      const mcpEvalRetired = await callTool(
        srv.mcpUrl,
        "evaluate_payment_request",
        {
          agentId: "mcp-agent-1",
          requirement: evmReq("1", RETIRED_X402_PAY_TO),
          nowMs: t0,
        },
        8
      );
      assert.equal(mcpEvalRetired.isError, false);
      assert.equal((mcpEvalRetired.data as PolicyEvaluationResult).allowed, false);

      // Rolling window: 2 spends allowed, duplicate txHash idempotent, 3rd blocked
      const s1 = await callTool(
        srv.mcpUrl,
        "record_agent_spend",
        {
          agentId: "mcp-agent-1",
          requirement: evmReq("1000"),
          txHash: "0x1111",
          nowMs: t0 + 100,
        },
        9
      );
      assert.equal(s1.isError, false);
      assert.equal((s1.data as RecordAgentSpendResult).rollingSpendMicroUsd, "1000");

      const s2 = await callTool(
        srv.mcpUrl,
        "record_agent_spend",
        {
          agentId: "mcp-agent-1",
          requirement: evmReq("1000"),
          txHash: "0x2222",
          nowMs: t0 + 200,
        },
        10
      );
      assert.equal(s2.isError, false);
      assert.equal((s2.data as RecordAgentSpendResult).rollingSpendMicroUsd, "2000");
      assert.equal((s2.data as RecordAgentSpendResult).remainingWindowMicroUsd, "0");

      const sDup = await callTool(
        srv.mcpUrl,
        "record_agent_spend",
        {
          agentId: "mcp-agent-1",
          requirement: evmReq("1000"),
          txHash: "0x2222",
          nowMs: t0 + 300,
        },
        11
      );
      assert.equal(sDup.isError, false);
      assert.equal((sDup.data as RecordAgentSpendResult).duplicate, true);
      assert.equal((sDup.data as RecordAgentSpendResult).rollingSpendMicroUsd, "2000");

      const s3 = await callTool(
        srv.mcpUrl,
        "record_agent_spend",
        {
          agentId: "mcp-agent-1",
          requirement: evmReq("1000"),
          txHash: "0x3333",
          nowMs: t0 + 400,
        },
        12
      );
      assert.equal(s3.isError, true);

      // Lightning msat conversion over MCP (12000 msat @ 90000 = 1_080_000 micro-USD)
      await callTool(
        srv.mcpUrl,
        "register_agent_policy",
        {
          agentId: "mcp-ln-agent",
          maxPerCallMicroUsd: "1080000",
          maxRollingWindowMicroUsd: "2160000",
          windowMs: 60_000,
        },
        13
      );
      const lnAllow = await callTool(
        srv.mcpUrl,
        "evaluate_payment_request",
        {
          agentId: "mcp-ln-agent",
          requirement: lnReq("12000"),
          nowMs: t0,
        },
        14
      );
      assert.equal((lnAllow.data as PolicyEvaluationResult).allowed, true);
      assert.equal(
        (lnAllow.data as PolicyEvaluationResult).evaluatedMicroUsd,
        "1080000"
      );

      const lnBlock = await callTool(
        srv.mcpUrl,
        "evaluate_payment_request",
        {
          agentId: "mcp-ln-agent",
          requirement: lnReq("12001"),
          nowMs: t0,
        },
        15
      );
      assert.equal((lnBlock.data as PolicyEvaluationResult).allowed, false);
      assert.equal(
        (lnBlock.data as PolicyEvaluationResult).evaluatedMicroUsd,
        "1080090"
      );

      // Revocation via MCP immediately blocks evaluate_payment_request
      const revMcp = await callTool(
        srv.mcpUrl,
        "revoke_agent_identity",
        { agentId: "mcp-ln-agent", reason: "Emergency stop" },
        16
      );
      assert.equal(revMcp.isError, false);
      const evalRevokedMcp = await callTool(
        srv.mcpUrl,
        "evaluate_payment_request",
        {
          agentId: "mcp-ln-agent",
          requirement: lnReq("1000"),
          nowMs: t0 + 500,
        },
        17
      );
      assert.equal((evalRevokedMcp.data as PolicyEvaluationResult).allowed, false);
      assert.equal((evalRevokedMcp.data as PolicyEvaluationResult).revoked, true);
    } finally {
      await srv.close();
    }

    console.log(
      "PASS: policy tests (GET /mcp 200, DSSE attestation + tamper rejection, per-call/rolling caps, txHash idempotency, Lightning msat conversion, retired payee block, revocation)"
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
