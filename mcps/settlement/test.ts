import assert from "node:assert/strict";
import crypto from "node:crypto";
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
import { getKeyId, loadOrCreateKeystore, signDsse, verifyDsse } from "../../shared/keystore.js";
import type { SettlementReceipt } from "../../shared/types.js";
import {
  BATCH_DSSE_PAYLOAD_TYPE,
  RECEIPT_DSSE_PAYLOAD_TYPE,
  canonicalReceiptPayload,
  computeFeeMicroUsd,
  createSettlementBatch,
  formatMicroUsd,
  ingestSettlement,
  parseMicroUsd,
  readLedger,
  readSettlementBatches,
  reconcileSettlements,
  verifySettlementReceipt,
} from "./ledger.js";
import { startSettlementServer } from "./server.js";

function makeReceipt(overrides: Partial<SettlementReceipt> = {}): SettlementReceipt {
  const id = overrides.id ?? `rcpt_${crypto.randomBytes(6).toString("hex")}`;
  return {
    id,
    amountMicroUsd: "1000",
    network: BASE_SEPOLIA_NETWORK,
    scheme: "exact",
    asset: BASE_SEPOLIA_USDC,
    txHash: `0x${crypto.randomBytes(32).toString("hex")}`,
    payer: "0x1111111111111111111111111111111111111111",
    payTo: DEFAULT_X402_PAY_TO,
    resource: "http://127.0.0.1:4021/api/v1/oracle",
    toolName: "paid_satoshi_oracle",
    settledAt: "2026-11-22T01:00:00.000Z",
    facilitator: "https://x402.org/facilitator",
    mode: "local_facilitator",
    ...overrides,
  };
}

function flipOneChar(str: string, index = Math.floor(str.length / 2)): string {
  const ch = str[index];
  const replacement = ch === "A" ? "B" : "A";
  return str.slice(0, index) + replacement + str.slice(index + 1);
}

async function callMcp(
  mcpUrl: string,
  method: string,
  params: Record<string, unknown> = {},
  id: number = 1
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  const json = (await res.json()) as Record<string, unknown>;
  return { status: res.status, json };
}

async function runTests(): Promise<void> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-settlement-test-"));
  const keystorePath = path.join(tmpDir, "ed25519.pem");
  const ledgerPath = path.join(tmpDir, "ledger.jsonl");

  try {
    // 1. server.json validation
    const serverJsonRaw = fs.readFileSync(
      path.resolve(process.cwd(), "mcps/settlement/server.json"),
      "utf8"
    );
    const serverJson = JSON.parse(serverJsonRaw) as {
      $schema: string;
      description: string;
      _meta?: Record<string, Record<string, unknown>>;
    };
    assert.equal(serverJson.$schema, MCP_REGISTRY_SCHEMA);
    assert.ok(serverJson.description.length > 0 && serverJson.description.length <= 100);
    assert.equal(
      serverJson._meta?.["io.modelcontextprotocol.registry/publisher-provided"]?.author,
      BRANDING.author
    );
    assert.equal(
      serverJson._meta?.["io.modelcontextprotocol.registry/publisher-provided"]?.organization,
      BRANDING.organization
    );

    // 2. Integer money math & zero float drift across 1000 micropayments ($0.000101 * 1000 = $0.101000)
    assert.equal(formatMicroUsd(0n), "0.000000");
    assert.equal(formatMicroUsd(1000n), "0.001000");
    assert.equal(formatMicroUsd(101n), "0.000101");
    assert.equal(formatMicroUsd(101_000n), "0.101000");
    assert.equal(formatMicroUsd(-1000n), "-0.001000");
    assert.equal(parseMicroUsd("101"), 101n);
    assert.equal(parseMicroUsd(101n), 101n);

    // Beyond Number.MAX_SAFE_INTEGER precision check
    const huge = 9_007_199_254_740_993n;
    assert.equal(parseMicroUsd(huge.toString()), huge);
    assert.equal(formatMicroUsd(huge), "9007199254.740993");

    // Reject float/decimal strings and numbers
    assert.throws(() => parseMicroUsd("0.001"));
    assert.throws(() => parseMicroUsd(""));
    assert.throws(() => parseMicroUsd("   "));
    assert.throws(() => parseMicroUsd("1e6"));
    assert.throws(() => parseMicroUsd(1000 as unknown as string));

    // Integer floor fee calculation check: floor(101 * 250 / 10000) = 2
    assert.equal(computeFeeMicroUsd(101n, 250n), 2n);

    // 3. Retired payee rejection
    const retiredReceipt = makeReceipt({
      id: "retired_1",
      payTo: RETIRED_X402_PAY_TO,
    });
    assert.throws(
      () => ingestSettlement({ ledgerPath, receipt: retiredReceipt, keystorePath }),
      /retired payee/i
    );
    const retiredLower = makeReceipt({
      id: "retired_2",
      payTo: RETIRED_X402_PAY_TO.toLowerCase(),
    });
    assert.throws(
      () => ingestSettlement({ ledgerPath, receipt: retiredLower, keystorePath }),
      /retired payee/i
    );

    // 4. Persistent 0600 Ed25519 keystore + DSSE verification + 1-char tamper rejection
    const ks1 = loadOrCreateKeystore(keystorePath);
    const ksMode = fs.statSync(keystorePath).mode & 0o777;
    assert.equal(ksMode, 0o600, "Keystore must have 0600 permissions");
    const ks2 = loadOrCreateKeystore(keystorePath);
    assert.equal(ks1.keyid, ks2.keyid, "Keystore keyid must persist across loads");

    // Pre-signed receipt with requireValidDsse: true
    const rawPreSigned = makeReceipt({
      id: "presigned_1",
      amountMicroUsd: "101",
      nonce: "nonce_presigned_1",
    });
    const signedEnv = signDsse(
      RECEIPT_DSSE_PAYLOAD_TYPE,
      canonicalReceiptPayload(rawPreSigned),
      keystorePath
    );
    const preSigned: SettlementReceipt = { ...rawPreSigned, dsse: signedEnv };
    assert.equal(verifySettlementReceipt(preSigned, undefined, keystorePath).valid, true);

    // Mutate 1 char in outer amount -> fails
    assert.equal(
      verifySettlementReceipt(
        { ...preSigned, amountMicroUsd: "102" },
        undefined,
        keystorePath
      ).valid,
      false
    );
    // Mutate 1 char in DSSE payload -> fails
    assert.equal(
      verifySettlementReceipt(
        {
          ...preSigned,
          dsse: { ...signedEnv, payload: flipOneChar(signedEnv.payload) },
        },
        undefined,
        keystorePath
      ).valid,
      false
    );
    // Mutate 1 char in DSSE signature -> fails
    assert.equal(
      verifySettlementReceipt(
        {
          ...preSigned,
          dsse: {
            ...signedEnv,
            signatures: [
              {
                keyid: signedEnv.signatures[0].keyid,
                sig: flipOneChar(signedEnv.signatures[0].sig),
              },
            ],
          },
        },
        undefined,
        keystorePath
      ).valid,
      false
    );

    // requireValidDsse rejects unsigned or tampered
    assert.throws(
      () =>
        ingestSettlement({
          ledgerPath,
          receipt: makeReceipt({ id: "unsigned_strict" }),
          requireValidDsse: true,
          keystorePath,
        }),
      /missing/i
    );
    assert.throws(
      () =>
        ingestSettlement({
          ledgerPath,
          receipt: { ...preSigned, amountMicroUsd: "999" },
          requireValidDsse: true,
          keystorePath,
        }),
      /invalid receipt dsse/i
    );

    const strictIngest = ingestSettlement({
      ledgerPath,
      receipt: preSigned,
      requireValidDsse: true,
      keystorePath,
    });
    assert.equal(strictIngest.ingested, true);
    assert.equal(strictIngest.duplicate, false);

    // 5. Idempotent duplicate (network, txHash), nonce, and paymentHash ingestion
    const dupExact = ingestSettlement({
      ledgerPath,
      receipt: preSigned,
      keystorePath,
    });
    assert.equal(dupExact.ingested, false);
    assert.equal(dupExact.duplicate, true);
    assert.equal(dupExact.receipt.id, "presigned_1");

    const dupTx = ingestSettlement({
      ledgerPath,
      receipt: makeReceipt({
        id: "dup_id_ignored",
        network: preSigned.network,
        txHash: preSigned.txHash,
      }),
      keystorePath,
    });
    assert.equal(dupTx.ingested, false);
    assert.equal(dupTx.duplicate, true);
    assert.equal(dupTx.receipt.id, "presigned_1");

    const dupNonce = ingestSettlement({
      ledgerPath,
      receipt: makeReceipt({
        id: "dup_nonce",
        nonce: "nonce_presigned_1",
      }),
      keystorePath,
    });
    assert.equal(dupNonce.ingested, false);
    assert.equal(dupNonce.duplicate, true);

    // Ingest 999 more EVM micropayments at 101 micro-USD each => total 1000 EVM * 101 = 101000 micro-USD ($0.101000)
    const bulkLedgerPath = path.join(tmpDir, "bulk-ledger.jsonl");
    const expectedBulk = [];
    for (let i = 0; i < 1000; i += 1) {
      const r = makeReceipt({
        id: `bulk_${i}`,
        amountMicroUsd: "101",
        txHash: `0x${(i + 1).toString(16).padStart(64, "0")}`,
        settledAt: `2026-11-22T02:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(
          i % 60
        ).padStart(2, "0")}.000Z`,
      });
      const res = ingestSettlement({ ledgerPath: bulkLedgerPath, receipt: r, keystorePath });
      assert.equal(res.ingested, true);
      expectedBulk.push({ id: r.id, network: r.network, txHash: r.txHash, amountMicroUsd: "101" });
    }

    // Add 2 Lightning micropayments (300 micro-USD, 5000 msat each)
    const ln1 = makeReceipt({
      id: "ln_1",
      network: LIGHTNING_TESTNET_NETWORK,
      scheme: "lightning",
      asset: "MSAT",
      amountMicroUsd: "300",
      amountMsat: "5000",
      txHash: "ln_hash_1",
      paymentHash: "aa".repeat(32),
      mode: "lightning_preimage",
    });
    const ln2 = makeReceipt({
      id: "ln_2",
      network: LIGHTNING_TESTNET_NETWORK,
      scheme: "lightning",
      asset: "MSAT",
      amountMicroUsd: "300",
      amountMsat: "5000",
      txHash: "ln_hash_2",
      paymentHash: "bb".repeat(32),
      mode: "lightning_preimage",
    });
    assert.equal(
      ingestSettlement({ ledgerPath: bulkLedgerPath, receipt: ln1, keystorePath }).ingested,
      true
    );
    assert.equal(
      ingestSettlement({ ledgerPath: bulkLedgerPath, receipt: ln2, keystorePath }).ingested,
      true
    );
    // Duplicate paymentHash rejection
    assert.equal(
      ingestSettlement({
        ledgerPath: bulkLedgerPath,
        receipt: { ...ln1, id: "ln_dup", txHash: "ln_hash_different" },
        keystorePath,
      }).duplicate,
      true
    );

    assert.equal(readLedger(bulkLedgerPath).length, 1002);

    // 6. Reconciliation totals & discrepancy detection
    const exactRecon = reconcileSettlements({
      ledgerPath: bulkLedgerPath,
      feeBps: 250,
    });
    assert.equal(exactRecon.totalGrossMicroUsd, "101600");
    assert.equal(exactRecon.totalGrossUsd, "0.101600");
    // 1000 * floor(101*250/10000 = 2) + 2 * floor(300*250/10000 = 7) = 2000 + 14 = 2014
    assert.equal(exactRecon.totalFeeMicroUsd, "2014");
    assert.equal(exactRecon.totalNetMicroUsd, "99586");
    assert.equal(exactRecon.totalNetUsd, "0.099586");
    assert.equal(exactRecon.totalMsat, "10000");
    assert.equal(exactRecon.byNetwork[BASE_SEPOLIA_NETWORK].grossUsd, "0.101000");
    assert.equal(exactRecon.byNetwork[LIGHTNING_TESTNET_NETWORK].msat, "10000");
    assert.equal(exactRecon.byScheme.exact.count, 1000);
    assert.equal(exactRecon.byScheme.lightning.count, 2);

    // Reconciliation discrepancy checks: missingExpectedIds, unexpectedLedgerIds, amountMismatches
    const discrepancyExpected = [
      ...expectedBulk.slice(0, 998),
      {
        id: "bulk_998",
        network: BASE_SEPOLIA_NETWORK,
        txHash: expectedBulk[998].txHash,
        amountMicroUsd: "999", // mismatch!
      },
      {
        id: "missing_expected_tx",
        network: BASE_SEPOLIA_NETWORK,
        txHash: `0x${"ff".repeat(32)}`,
        amountMicroUsd: "500",
      },
    ];
    const discRecon = reconcileSettlements({
      ledgerPath: bulkLedgerPath,
      expectedReceipts: discrepancyExpected,
    });
    assert.equal(discRecon.reconciled, false);
    assert.equal(discRecon.matchedIds.length, 998);
    assert.deepEqual(discRecon.missingExpectedIds, ["missing_expected_tx"]);
    assert.equal(discRecon.amountMismatches.length, 1);
    assert.equal(discRecon.amountMismatches[0].id, "bulk_998");
    assert.equal(discRecon.amountMismatches[0].expectedMicroUsd, "999");
    assert.equal(discRecon.amountMismatches[0].actualMicroUsd, "101");
    assert.equal(discRecon.amountMismatches[0].differenceMicroUsd, "-898");
    assert.ok(discRecon.unexpectedLedgerIds.includes("bulk_999"));
    assert.ok(discRecon.unexpectedLedgerIds.includes("ln_1"));
    assert.ok(discRecon.unexpectedLedgerIds.includes("ln_2"));

    // 7. Settlement Batch creation + Merkle + DSSE + post-batch receipt DSSE survival
    const lnBatch = createSettlementBatch({
      ledgerPath: bulkLedgerPath,
      batchId: "batch_ln_001",
      network: LIGHTNING_TESTNET_NETWORK,
      feeBps: 250,
      keystorePath,
    });
    assert.equal(lnBatch.created, true);
    assert.equal(lnBatch.receiptCount, 2);
    assert.equal(lnBatch.totalGrossMicroUsd, "600");
    assert.equal(lnBatch.totalFeeMicroUsd, "14");
    assert.equal(lnBatch.totalNetMicroUsd, "586");
    assert.equal(lnBatch.totalMsat, "10000");
    assert.equal(lnBatch.dsse.payloadType, BATCH_DSSE_PAYLOAD_TYPE);
    assert.equal(verifyDsse(lnBatch.dsse, undefined, keystorePath).valid, true);
    assert.equal(readSettlementBatches(bulkLedgerPath).length, 1);

    // Calling batch again for lightning must find 0 unbatched receipts
    const lnBatchEmpty = createSettlementBatch({
      ledgerPath: bulkLedgerPath,
      network: LIGHTNING_TESTNET_NETWORK,
      keystorePath,
    });
    assert.equal(lnBatchEmpty.created, false);
    assert.equal(lnBatchEmpty.receiptCount, 0);

    // Verify receipt DSSE remains valid even after batchId was assigned!
    const batchedReceipts = readLedger(bulkLedgerPath).filter(
      (r) => r.network === LIGHTNING_TESTNET_NETWORK
    );
    assert.equal(batchedReceipts.length, 2);
    for (const r of batchedReceipts) {
      assert.equal(r.batchId, "batch_ln_001");
      assert.equal(verifySettlementReceipt(r, undefined, keystorePath).valid, true);
    }

    // 8. Live MCP HTTP server + GET /mcp + GET /.well-known/x402 + POST /mcp JSON-RPC tools/call
    const mcpLedgerPath = path.join(tmpDir, "mcp-ledger.jsonl");
    const srv = await startSettlementServer({
      port: 0,
      host: "127.0.0.1",
      ledgerPath: mcpLedgerPath,
      keystorePath,
    });
    try {
      const cardRes = await fetch(`${srv.baseUrl}/mcp`);
      assert.equal(cardRes.status, 200);
      assert.ok((cardRes.headers.get("content-type") ?? "").includes("application/json"));
      const card = (await cardRes.json()) as Record<string, unknown>;
      assert.equal(card.name, "x402-settlement-ops");
      assert.equal(card.keyid, getKeyId(keystorePath));

      const cardSlashRes = await fetch(`${srv.baseUrl}/mcp/`);
      assert.equal(cardSlashRes.status, 200);

      const wkRes = await fetch(`${srv.baseUrl}/.well-known/x402`);
      assert.equal(wkRes.status, 200);
      const wk = (await wkRes.json()) as Record<string, unknown>;
      assert.equal(wk.x402Version, 2);
      assert.equal(wk.payTo, DEFAULT_X402_PAY_TO);

      const initRes = await callMcp(srv.mcpUrl, "initialize", {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "settlement-test", version: "1.0.0" },
      });
      assert.equal(initRes.status, 200);

      const listRes = await callMcp(srv.mcpUrl, "tools/list", {}, 2);
      assert.equal(listRes.status, 200);
      const tools = ((listRes.json.result as Record<string, unknown>).tools ??
        []) as Array<{ name: string }>;
      assert.deepEqual(
        tools.map((t) => t.name).sort(),
        [
          "create_settlement_batch",
          "ingest_settlement",
          "reconcile_settlements",
          "verify_receipt",
        ]
      );

      // Ingest via MCP tools/call
      const mcpReceipt = makeReceipt({ id: "mcp_r1", amountMicroUsd: "2500" });
      const ingCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        { name: "ingest_settlement", arguments: { receipt: mcpReceipt } },
        3
      );
      assert.equal(ingCall.status, 200);
      const ingContent = (
        (ingCall.json.result as Record<string, unknown>).content as Array<{
          type: string;
          text: string;
        }>
      )[0];
      const ingParsed = JSON.parse(ingContent.text) as {
        ingested: boolean;
        duplicate: boolean;
        receipt: SettlementReceipt;
      };
      assert.equal(ingParsed.ingested, true);
      assert.equal(ingParsed.duplicate, false);

      // Verify receipt via MCP tools/call (valid + tampered)
      const verCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        { name: "verify_receipt", arguments: { receipt: ingParsed.receipt } },
        4
      );
      const verParsed = JSON.parse(
        (
          (verCall.json.result as Record<string, unknown>).content as Array<{
            text: string;
          }>
        )[0].text
      ) as { valid: boolean };
      assert.equal(verParsed.valid, true);

      const badVerCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        {
          name: "verify_receipt",
          arguments: { receipt: { ...ingParsed.receipt, amountMicroUsd: "2501" } },
        },
        5
      );
      const badVerParsed = JSON.parse(
        (
          (badVerCall.json.result as Record<string, unknown>).content as Array<{
            text: string;
          }>
        )[0].text
      ) as { valid: boolean };
      assert.equal(badVerParsed.valid, false);

      // Reconcile & Batch via MCP tools/call
      const reconCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        { name: "reconcile_settlements", arguments: { feeBps: 100 } },
        6
      );
      const reconParsed = JSON.parse(
        (
          (reconCall.json.result as Record<string, unknown>).content as Array<{
            text: string;
          }>
        )[0].text
      ) as { totalGrossMicroUsd: string; totalFeeMicroUsd: string; totalNetMicroUsd: string };
      assert.equal(reconParsed.totalGrossMicroUsd, "2500");
      assert.equal(reconParsed.totalFeeMicroUsd, "25");
      assert.equal(reconParsed.totalNetMicroUsd, "2475");

      const batchCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        { name: "create_settlement_batch", arguments: { batchId: "mcp_batch_1" } },
        7
      );
      const batchParsed = JSON.parse(
        (
          (batchCall.json.result as Record<string, unknown>).content as Array<{
            text: string;
          }>
        )[0].text
      ) as { created: boolean; receiptCount: number };
      assert.equal(batchParsed.created, true);
      assert.equal(batchParsed.receiptCount, 1);

      // Retired payee via MCP returns isError: true cleanly without crashing pipe
      const retCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        {
          name: "ingest_settlement",
          arguments: {
            receipt: makeReceipt({ id: "mcp_ret", payTo: RETIRED_X402_PAY_TO }),
          },
        },
        8
      );
      assert.equal(retCall.status, 200);
      assert.equal((retCall.json.result as Record<string, unknown>).isError, true);
    } finally {
      await srv.close();
    }

    console.log("PASS: settlement tests (bigint arithmetic, idempotency, DSSE, reconciliation, batching, MCP HTTP)");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
