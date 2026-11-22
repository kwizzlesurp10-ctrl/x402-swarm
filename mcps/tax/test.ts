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
} from "../../shared/constants.js";
import { getKeyId, loadOrCreateKeystore, verifyDsse } from "../../shared/keystore.js";
import type { SettlementReceipt } from "../../shared/types.js";
import { createSettlementBatch, ingestSettlement } from "../settlement/ledger.js";
import {
  TAX_AUDIT_DSSE_PAYLOAD_TYPE,
  TAX_CSV_HEADERS,
  TAX_FORM8949_DSSE_PAYLOAD_TYPE,
  exportTaxLedger,
  generateAuditBundle,
  parseCsvRfc4180,
  verifyAuditBundle,
  type TaxAuditBundle,
} from "./exporter.js";
import { startTaxServer } from "./server.js";

function makeReceipt(overrides: Partial<SettlementReceipt> = {}): SettlementReceipt {
  const id = overrides.id ?? `tax_${crypto.randomBytes(6).toString("hex")}`;
  return {
    id,
    amountMicroUsd: "101",
    network: BASE_SEPOLIA_NETWORK,
    scheme: "exact",
    asset: BASE_SEPOLIA_USDC,
    txHash: `0x${crypto.randomBytes(32).toString("hex")}`,
    payer: "0x2222222222222222222222222222222222222222",
    payTo: DEFAULT_X402_PAY_TO,
    resource: "http://127.0.0.1:4021/api/v1/echo",
    toolName: "paid_lightning_echo",
    settledAt: "2026-11-22T01:15:00.000Z",
    facilitator: "https://x402.org/facilitator",
    mode: "live_testnet",
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-tax-test-"));
  const keystorePath = path.join(tmpDir, "ed25519.pem");
  const otherKeystorePath = path.join(tmpDir, "other-ed25519.pem");
  const ledgerPath = path.join(tmpDir, "tax-ledger.jsonl");

  try {
    // 1. server.json validation
    const serverJsonRaw = fs.readFileSync(
      path.resolve(process.cwd(), "mcps/tax/server.json"),
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

    // 2. Seed 1000 EVM micropayments ($0.000101 * 1000 = $0.101000) + 2 Lightning + 1 prior-year 2025 receipt
    for (let i = 0; i < 1000; i += 1) {
      const r = makeReceipt({
        id: `evm_2026_${i}`,
        amountMicroUsd: "101",
        txHash: `0x${(i + 1).toString(16).padStart(64, "0")}`,
        settledAt: `2026-06-15T${String(Math.floor(i / 60)).padStart(2, "0")}:${String(
          i % 60
        ).padStart(2, "0")}:00.000Z`,
      });
      ingestSettlement({ ledgerPath, receipt: r, keystorePath });
    }
    ingestSettlement({
      ledgerPath,
      receipt: makeReceipt({
        id: "ln_2026_1",
        network: LIGHTNING_TESTNET_NETWORK,
        scheme: "lightning",
        asset: "MSAT",
        amountMicroUsd: "500",
        amountMsat: "12000",
        txHash: "ln_tx_1",
        paymentHash: "11".repeat(32),
        mode: "lightning_preimage",
        settledAt: "2026-07-01T12:00:00.000Z",
      }),
      keystorePath,
    });
    ingestSettlement({
      ledgerPath,
      receipt: makeReceipt({
        id: "ln_2026_2",
        network: LIGHTNING_TESTNET_NETWORK,
        scheme: "lightning",
        asset: "MSAT",
        amountMicroUsd: "500",
        amountMsat: "12000",
        txHash: "ln_tx_2",
        paymentHash: "22".repeat(32),
        mode: "lightning_preimage",
        settledAt: "2026-07-02T12:00:00.000Z",
      }),
      keystorePath,
    });
    ingestSettlement({
      ledgerPath,
      receipt: makeReceipt({
        id: "evm_2025_1",
        amountMicroUsd: "2500",
        txHash: `0x${"ab".repeat(32)}`,
        settledAt: "2025-12-31T23:59:59.000Z",
      }),
      keystorePath,
    });

    // Batch Lightning receipts to verify batch_id propagates into CSV export
    createSettlementBatch({
      ledgerPath,
      batchId: "batch_tax_ln_2026",
      network: LIGHTNING_TESTNET_NETWORK,
      feeBps: 250,
      keystorePath,
    });

    // 3. Export CSV for taxYear 2026 with feeBps = 250
    const csvExport = exportTaxLedger({
      ledgerPath,
      format: "csv",
      taxYear: 2026,
      feeBps: 250,
      keystorePath,
    });
    assert.equal(csvExport.recordCount, 1002);
    // 1000 * 101 + 2 * 500 = 101000 + 1000 = 102000 micro-USD = $0.102000
    assert.equal(csvExport.totals.grossMicroUsd, "102000");
    assert.equal(csvExport.totals.grossUsd, "0.102000");
    // Fees: 1000 * floor(101*250/10000 = 2) + 2 * floor(500*250/10000 = 12) = 2000 + 24 = 2024
    assert.equal(csvExport.totals.feeMicroUsd, "2024");
    assert.equal(csvExport.totals.netMicroUsd, "99976");
    assert.equal(csvExport.totals.netUsd, "0.099976");
    assert.equal(csvExport.totals.amountMsat, "24000");
    assert.equal(csvExport.totals.verifiedCount, 1002);
    assert.equal(csvExport.totals.unverifiedCount, 0);

    const parsedCsv = parseCsvRfc4180(csvExport.content);
    assert.deepEqual(parsedCsv[0], [...TAX_CSV_HEADERS]);
    assert.equal(parsedCsv.length, 1003); // 1 header + 1002 rows
    const lnRow = parsedCsv.find((cells) => cells[1] === "ln_tx_1");
    assert.ok(lnRow);
    assert.equal(lnRow[7], "500"); // gross_micro_usd
    assert.equal(lnRow[8], "0.000500"); // gross_usd
    assert.equal(lnRow[9], "12000"); // amount_msat
    assert.equal(lnRow[10], "12"); // fee_micro_usd
    assert.equal(lnRow[11], "488"); // net_micro_usd
    assert.equal(lnRow[12], "0.000488"); // net_usd
    assert.equal(lnRow[14], "batch_tax_ln_2026"); // batch_id
    assert.equal(lnRow[15], "true"); // receipt_verified

    // 4. Export JSONL for 2026
    const jsonlExport = exportTaxLedger({
      ledgerPath,
      format: "jsonl",
      taxYear: 2026,
      feeBps: 250,
      keystorePath,
    });
    const jsonlLines = jsonlExport.content.trim().split("\n");
    assert.equal(jsonlLines.length, 1002);
    const firstJsonl = JSON.parse(jsonlLines[0]) as Record<string, string>;
    assert.equal(firstJsonl.gross_usd, "0.000101");
    assert.equal(firstJsonl.receipt_verified, "true");

    // 5. Export Form 8949 summary (all years -> 3 groups: 2025 evm, 2026 evm, 2026 lightning)
    const formExport = exportTaxLedger({
      ledgerPath,
      format: "form8949_summary",
      feeBps: 250,
      keystorePath,
    });
    assert.equal(formExport.recordCount, 1003);
    assert.equal(formExport.groups?.length, 3);
    assert.equal(formExport.totals.grossMicroUsd, "104500");
    assert.equal(formExport.totals.grossUsd, "0.104500");
    assert.equal(formExport.dsse.payloadType, TAX_FORM8949_DSSE_PAYLOAD_TYPE);
    const formVerify = verifyDsse(formExport.dsse, undefined, keystorePath);
    assert.equal(formVerify.valid, true);

    // 6. Generate & verify Audit Bundle + tamper detection (1 char in CSV, Form8949, DSSE, wrong key)
    const bundle = generateAuditBundle({
      ledgerPath,
      taxYear: 2026,
      feeBps: 250,
      keystorePath,
    });
    assert.equal(bundle.payloadType, TAX_AUDIT_DSSE_PAYLOAD_TYPE);
    assert.equal(bundle.keyid, getKeyId(keystorePath));
    const okVerify = verifyAuditBundle(bundle, undefined, keystorePath);
    assert.equal(okVerify.valid, true);
    assert.equal(okVerify.dsseValid, true);
    assert.equal(okVerify.digestValid, true);

    // Verify using explicit PEM (without keystore path)
    const { publicKeyPem } = loadOrCreateKeystore(keystorePath);
    assert.equal(verifyAuditBundle(bundle, publicKeyPem).valid, true);

    // Reject with wrong public key
    const { publicKeyPem: wrongPubPem } = loadOrCreateKeystore(otherKeystorePath);
    const wrongKeyVerify = verifyAuditBundle(bundle, wrongPubPem);
    assert.equal(wrongKeyVerify.valid, false);
    assert.equal(wrongKeyVerify.dsseValid, false);

    // Tamper 1 char in CSV -> fails!
    const tamperedCsvBundle: TaxAuditBundle = {
      ...bundle,
      csv: bundle.csv.replace("0.000500", "0.000501"),
    };
    const csvTamperRes = verifyAuditBundle(tamperedCsvBundle, undefined, keystorePath);
    assert.equal(csvTamperRes.valid, false);
    assert.equal(csvTamperRes.digestValid, false);

    // Tamper 1 char in Form 8949 totals -> fails!
    const tamperedFormBundle: TaxAuditBundle = {
      ...bundle,
      form8949Summary: {
        ...bundle.form8949Summary,
        totals: {
          ...bundle.form8949Summary.totals,
          grossMicroUsd: "102001",
        },
      },
    };
    assert.equal(verifyAuditBundle(tamperedFormBundle, undefined, keystorePath).valid, false);

    // Tamper 1 char in bundleDigest -> fails!
    const tamperedDigestBundle: TaxAuditBundle = {
      ...bundle,
      bundleDigest: flipOneChar(bundle.bundleDigest),
    };
    assert.equal(verifyAuditBundle(tamperedDigestBundle, undefined, keystorePath).valid, false);

    // Tamper 1 char in DSSE signature -> fails!
    const tamperedSigBundle: TaxAuditBundle = {
      ...bundle,
      dsse: {
        ...bundle.dsse,
        signatures: [
          {
            keyid: bundle.dsse.signatures[0].keyid,
            sig: flipOneChar(bundle.dsse.signatures[0].sig),
          },
        ],
      },
    };
    assert.equal(verifyAuditBundle(tamperedSigBundle, undefined, keystorePath).valid, false);

    // 7. Live Tax MCP HTTP server + JSON-RPC tools/call
    const srv = await startTaxServer({
      port: 0,
      host: "127.0.0.1",
      ledgerPath,
      keystorePath,
    });
    try {
      const cardRes = await fetch(`${srv.baseUrl}/mcp`);
      assert.equal(cardRes.status, 200);
      const card = (await cardRes.json()) as Record<string, unknown>;
      assert.equal(card.name, "x402-tax-ledger");

      const wkRes = await fetch(`${srv.baseUrl}/.well-known/x402`);
      assert.equal(wkRes.status, 200);

      const listRes = await callMcp(srv.mcpUrl, "tools/list", {}, 1);
      const tools = ((listRes.json.result as Record<string, unknown>).tools ??
        []) as Array<{ name: string }>;
      assert.deepEqual(
        tools.map((t) => t.name).sort(),
        ["export_tax_ledger", "generate_audit_bundle", "verify_audit_bundle"]
      );

      const expCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        {
          name: "export_tax_ledger",
          arguments: { format: "form8949_summary", taxYear: 2026, feeBps: 250 },
        },
        2
      );
      const expParsed = JSON.parse(
        (
          (expCall.json.result as Record<string, unknown>).content as Array<{
            text: string;
          }>
        )[0].text
      ) as { totals: { grossUsd: string }; dsse: unknown };
      assert.equal(expParsed.totals.grossUsd, "0.102000");

      const bundleCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        {
          name: "generate_audit_bundle",
          arguments: { taxYear: 2026, feeBps: 250 },
        },
        3
      );
      const mcpBundle = JSON.parse(
        (
          (bundleCall.json.result as Record<string, unknown>).content as Array<{
            text: string;
          }>
        )[0].text
      ) as TaxAuditBundle;

      const verCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        {
          name: "verify_audit_bundle",
          arguments: { bundle: mcpBundle },
        },
        4
      );
      const verParsed = JSON.parse(
        (
          (verCall.json.result as Record<string, unknown>).content as Array<{
            text: string;
          }>
        )[0].text
      ) as { valid: boolean; dsseValid: boolean; digestValid: boolean };
      assert.equal(verParsed.valid, true);
      assert.equal(verParsed.dsseValid, true);
      assert.equal(verParsed.digestValid, true);

      const badVerCall = await callMcp(
        srv.mcpUrl,
        "tools/call",
        {
          name: "verify_audit_bundle",
          arguments: {
            bundle: { ...mcpBundle, csv: flipOneChar(mcpBundle.csv, mcpBundle.csv.length - 10) },
          },
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
    } finally {
      await srv.close();
    }

    console.log("PASS: tax tests (RFC 4180 CSV, JSONL, Form 8949 summary, audit bundle DSSE + tamper rejection, MCP HTTP)");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
