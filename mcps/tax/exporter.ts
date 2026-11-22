import crypto from "node:crypto";
import { DEFAULT_KEYSTORE_PATH } from "../../shared/constants.js";
import { getKeyId, signDsse, verifyDsse } from "../../shared/keystore.js";
import type { DsseEnvelope, SettlementReceipt } from "../../shared/types.js";
import {
  DEFAULT_LEDGER_PATH,
  canonicalJson,
  computeFeeMicroUsd,
  formatMicroUsd,
  parseFeeBps,
  parseMicroUsd,
  parseNonNegativeBigInt,
  readLedger,
  sha256Hex,
  verifySettlementReceipt,
} from "../settlement/ledger.js";

export const TAX_FORM8949_DSSE_PAYLOAD_TYPE =
  "application/vnd.x402.tax-form8949+json" as const;
export const TAX_AUDIT_DSSE_PAYLOAD_TYPE =
  "application/vnd.x402.tax-audit+json" as const;

export const TAX_CSV_HEADERS = [
  "date_utc",
  "tx_hash",
  "network",
  "scheme",
  "asset",
  "payer",
  "pay_to",
  "gross_micro_usd",
  "gross_usd",
  "amount_msat",
  "fee_micro_usd",
  "net_micro_usd",
  "net_usd",
  "tax_category",
  "batch_id",
  "receipt_verified",
] as const;

export type TaxExportFormat = "csv" | "jsonl" | "form8949_summary";

export interface NormalizedTaxRow {
  date_utc: string;
  tx_hash: string;
  network: string;
  scheme: string;
  asset: string;
  payer: string;
  pay_to: string;
  gross_micro_usd: string;
  gross_usd: string;
  amount_msat: string;
  fee_micro_usd: string;
  net_micro_usd: string;
  net_usd: string;
  tax_category: string;
  batch_id: string;
  receipt_verified: string;
}

export interface TaxExportTotals {
  transactionCount: number;
  grossMicroUsd: string;
  grossUsd: string;
  feeMicroUsd: string;
  netMicroUsd: string;
  netUsd: string;
  amountMsat: string;
  verifiedCount: number;
  unverifiedCount: number;
}

export interface Form8949Group {
  taxYear: number;
  network: string;
  asset: string;
  scheme: string;
  transactionCount: number;
  grossMicroUsd: string;
  grossUsd: string;
  feeMicroUsd: string;
  netMicroUsd: string;
  netUsd: string;
  amountMsat: string;
  verifiedCount: number;
  unverifiedCount: number;
  firstSettledAt: string;
  lastSettledAt: string;
}

export interface Form8949SummaryData {
  taxYear: number | null;
  feeBps: string;
  recordCount: number;
  groups: Form8949Group[];
  totals: TaxExportTotals;
}

export interface TaxExportResult {
  format: TaxExportFormat;
  taxYear: number | null;
  feeBps: string;
  recordCount: number;
  content: string;
  csv?: string;
  jsonl?: string;
  groups?: Form8949Group[];
  totals: TaxExportTotals;
  recordChainDigest: string;
  sha256Digest: string;
  keyid: string;
  dsse: DsseEnvelope;
}

export interface TaxAuditBundle {
  version: string;
  payloadType: typeof TAX_AUDIT_DSSE_PAYLOAD_TYPE;
  taxYear: number | null;
  feeBps: string;
  generatedAt: string;
  recordCount: number;
  csv: string;
  form8949Summary: Form8949SummaryData;
  recordChainDigest: string;
  bundleDigest: string;
  keyid: string;
  dsse: DsseEnvelope;
}

export interface AuditBundleVerificationResult {
  valid: boolean;
  dsseValid: boolean;
  digestValid: boolean;
  keyid?: string;
  recordCount?: number;
  bundleDigest?: string;
  recordChainDigest?: string;
  error?: string;
}

function escapeCsvField(field: string): string {
  if (/[",\r\n]/.test(field)) {
    return `"${field.replace(/"/g, '""')}"`;
  }
  return field;
}

/** Parses RFC 4180 CSV text (supporting CRLF/LF and quoted fields). */
export function parseCsvRfc4180(csvText: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;

  while (i < csvText.length) {
    const ch = csvText[i];
    if (inQuotes) {
      if (ch === '"') {
        if (csvText[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += ch;
      i += 1;
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
      i += 1;
    } else if (ch === ",") {
      row.push(field);
      field = "";
      i += 1;
    } else if (ch === "\r" && csvText[i + 1] === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      i += 2;
    } else if (ch === "\n" || ch === "\r") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      i += 1;
    } else {
      field += ch;
      i += 1;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function deriveTaxCategory(receipt: SettlementReceipt): string {
  if (receipt.scheme === "lightning" || receipt.network.startsWith("lightning:")) {
    return "x402_lightning_micropayment_revenue";
  }
  return "x402_evm_micropayment_revenue";
}

function buildNormalizedRows(
  receipts: SettlementReceipt[],
  taxYear: number | undefined,
  feeBps: bigint,
  keystorePath: string,
  expectedPublicKeyPem?: string
): Array<{ row: NormalizedTaxRow; receipt: SettlementReceipt; year: number }> {
  if (taxYear !== undefined && (!Number.isInteger(taxYear) || taxYear < 1970 || taxYear > 9999)) {
    throw new Error(`Invalid taxYear: ${taxYear}`);
  }

  const sorted = [...receipts].sort((a, b) =>
    `${a.settledAt}|${a.network}|${a.txHash}|${a.id}`.localeCompare(
      `${b.settledAt}|${b.network}|${b.txHash}|${b.id}`
    )
  );

  const items: Array<{ row: NormalizedTaxRow; receipt: SettlementReceipt; year: number }> = [];

  for (const r of sorted) {
    const dt = new Date(r.settledAt);
    if (Number.isNaN(dt.getTime())) {
      throw new Error(`Invalid settledAt timestamp on receipt ${r.id}: ${r.settledAt}`);
    }
    const year = dt.getUTCFullYear();
    if (taxYear !== undefined && year !== taxYear) {
      continue;
    }

    const gross = parseMicroUsd(r.amountMicroUsd);
    const fee = computeFeeMicroUsd(gross, feeBps);
    const net = gross - fee;
    const msat = parseNonNegativeBigInt(r.amountMsat, "amountMsat");
    const verification = r.dsse
      ? verifySettlementReceipt(r, expectedPublicKeyPem, keystorePath)
      : { valid: false };

    items.push({
      receipt: r,
      year,
      row: {
        date_utc: dt.toISOString(),
        tx_hash: r.txHash,
        network: r.network,
        scheme: r.scheme,
        asset: r.asset,
        payer: r.payer,
        pay_to: r.payTo,
        gross_micro_usd: gross.toString(),
        gross_usd: formatMicroUsd(gross),
        amount_msat: msat.toString(),
        fee_micro_usd: fee.toString(),
        net_micro_usd: net.toString(),
        net_usd: formatMicroUsd(net),
        tax_category: deriveTaxCategory(r),
        batch_id: r.batchId ?? "",
        receipt_verified: verification.valid ? "true" : "false",
      },
    });
  }

  return items;
}

function renderCsv(rows: NormalizedTaxRow[]): string {
  const headerLine = TAX_CSV_HEADERS.join(",");
  const lines = rows.map((row) =>
    TAX_CSV_HEADERS.map((col) => escapeCsvField(row[col])).join(",")
  );
  return `${[headerLine, ...lines].join("\r\n")}\r\n`;
}

function computeRowChainDigest(rows: NormalizedTaxRow[]): string {
  let chain = sha256Hex("x402-tax-chain-v1");
  for (const row of rows) {
    const serialized = JSON.stringify(TAX_CSV_HEADERS.map((col) => row[col]));
    chain = sha256Hex(`${chain}\n${serialized}`);
  }
  return chain;
}

interface MutableForm8949Acc {
  taxYear: number;
  network: string;
  asset: string;
  scheme: string;
  count: number;
  gross: bigint;
  fee: bigint;
  net: bigint;
  msat: bigint;
  verifiedCount: number;
  unverifiedCount: number;
  firstSettledAt: string;
  lastSettledAt: string;
}

function summarizeRows(
  rows: NormalizedTaxRow[],
  taxYear: number | undefined,
  feeBps: bigint
): Form8949SummaryData {
  let totalGross = 0n;
  let totalFee = 0n;
  let totalNet = 0n;
  let totalMsat = 0n;
  let verifiedCount = 0;
  let unverifiedCount = 0;

  const groupMap = new Map<string, MutableForm8949Acc>();

  for (const row of rows) {
    const year = new Date(row.date_utc).getUTCFullYear();
    const gross = parseMicroUsd(row.gross_micro_usd);
    const fee = parseMicroUsd(row.fee_micro_usd);
    const net = parseMicroUsd(row.net_micro_usd);
    const msat = parseNonNegativeBigInt(row.amount_msat, "amount_msat");
    const isVerified = row.receipt_verified === "true";

    totalGross += gross;
    totalFee += fee;
    totalNet += net;
    totalMsat += msat;
    if (isVerified) verifiedCount += 1;
    else unverifiedCount += 1;

    const groupKey = `${year}|${row.network}|${row.asset}|${row.scheme}`;
    const existing = groupMap.get(groupKey);
    if (!existing) {
      groupMap.set(groupKey, {
        taxYear: year,
        network: row.network,
        asset: row.asset,
        scheme: row.scheme,
        count: 1,
        gross,
        fee,
        net,
        msat,
        verifiedCount: isVerified ? 1 : 0,
        unverifiedCount: isVerified ? 0 : 1,
        firstSettledAt: row.date_utc,
        lastSettledAt: row.date_utc,
      });
    } else {
      existing.count += 1;
      existing.gross += gross;
      existing.fee += fee;
      existing.net += net;
      existing.msat += msat;
      if (isVerified) existing.verifiedCount += 1;
      else existing.unverifiedCount += 1;
      if (row.date_utc < existing.firstSettledAt) existing.firstSettledAt = row.date_utc;
      if (row.date_utc > existing.lastSettledAt) existing.lastSettledAt = row.date_utc;
    }
  }

  const groups: Form8949Group[] = Array.from(groupMap.keys())
    .sort()
    .map((key) => {
      const g = groupMap.get(key)!;
      return {
        taxYear: g.taxYear,
        network: g.network,
        asset: g.asset,
        scheme: g.scheme,
        transactionCount: g.count,
        grossMicroUsd: g.gross.toString(),
        grossUsd: formatMicroUsd(g.gross),
        feeMicroUsd: g.fee.toString(),
        netMicroUsd: g.net.toString(),
        netUsd: formatMicroUsd(g.net),
        amountMsat: g.msat.toString(),
        verifiedCount: g.verifiedCount,
        unverifiedCount: g.unverifiedCount,
        firstSettledAt: g.firstSettledAt,
        lastSettledAt: g.lastSettledAt,
      };
    });

  return {
    taxYear: taxYear ?? null,
    feeBps: feeBps.toString(),
    recordCount: rows.length,
    groups,
    totals: {
      transactionCount: rows.length,
      grossMicroUsd: totalGross.toString(),
      grossUsd: formatMicroUsd(totalGross),
      feeMicroUsd: totalFee.toString(),
      netMicroUsd: totalNet.toString(),
      netUsd: formatMicroUsd(totalNet),
      amountMsat: totalMsat.toString(),
      verifiedCount,
      unverifiedCount,
    },
  };
}

export interface ExportTaxLedgerParams {
  ledgerPath: string;
  format: TaxExportFormat;
  taxYear?: number;
  feeBps?: bigint | number | string;
  keystorePath?: string;
  expectedPublicKeyPem?: string;
}

/**
 * Exports settled micropayments in RFC 4180 `"csv"`, `"jsonl"`, or signed
 * `"form8949_summary"` format using strictly `bigint` arithmetic.
 */
export function exportTaxLedger(params: ExportTaxLedgerParams): TaxExportResult {
  const ledgerPath = params.ledgerPath || DEFAULT_LEDGER_PATH;
  const keystorePath = params.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const feeBps = parseFeeBps(params.feeBps);

  if (!["csv", "jsonl", "form8949_summary"].includes(params.format)) {
    throw new Error(`Unsupported tax export format: ${String(params.format)}`);
  }

  const receipts = readLedger(ledgerPath);
  const items = buildNormalizedRows(
    receipts,
    params.taxYear,
    feeBps,
    keystorePath,
    params.expectedPublicKeyPem
  );
  const rows = items.map((item) => item.row);
  const summary = summarizeRows(rows, params.taxYear, feeBps);
  const recordChainDigest = computeRowChainDigest(rows);

  if (params.format === "csv") {
    const csv = renderCsv(rows);
    const sha256Digest = sha256Hex(csv);
    const dsse = signDsse(
      TAX_FORM8949_DSSE_PAYLOAD_TYPE,
      { format: "csv", summary, recordChainDigest, sha256Digest },
      keystorePath
    );
    const keyid = dsse.signatures[0]?.keyid ?? getKeyId(keystorePath);
    return {
      format: "csv",
      taxYear: params.taxYear ?? null,
      feeBps: feeBps.toString(),
      recordCount: rows.length,
      content: csv,
      csv,
      totals: summary.totals,
      recordChainDigest,
      sha256Digest,
      keyid,
      dsse,
    };
  }

  if (params.format === "jsonl") {
    const jsonl =
      rows.length === 0 ? "" : `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`;
    const sha256Digest = sha256Hex(jsonl);
    const dsse = signDsse(
      TAX_FORM8949_DSSE_PAYLOAD_TYPE,
      { format: "jsonl", summary, recordChainDigest, sha256Digest },
      keystorePath
    );
    const keyid = dsse.signatures[0]?.keyid ?? getKeyId(keystorePath);
    return {
      format: "jsonl",
      taxYear: params.taxYear ?? null,
      feeBps: feeBps.toString(),
      recordCount: rows.length,
      content: jsonl,
      jsonl,
      totals: summary.totals,
      recordChainDigest,
      sha256Digest,
      keyid,
      dsse,
    };
  }

  // "form8949_summary"
  const canonicalPayload = {
    ...summary,
    recordChainDigest,
  };
  const sha256Digest = sha256Hex(canonicalJson(canonicalPayload));
  const dsse = signDsse(
    TAX_FORM8949_DSSE_PAYLOAD_TYPE,
    { ...canonicalPayload, sha256Digest },
    keystorePath
  );
  const keyid = dsse.signatures[0]?.keyid ?? getKeyId(keystorePath);

  return {
    format: "form8949_summary",
    taxYear: params.taxYear ?? null,
    feeBps: feeBps.toString(),
    recordCount: rows.length,
    content: JSON.stringify(
      { ...canonicalPayload, sha256Digest, keyid, dsse },
      null,
      2
    ),
    groups: summary.groups,
    totals: summary.totals,
    recordChainDigest,
    sha256Digest,
    keyid,
    dsse,
  };
}

export interface GenerateAuditBundleParams {
  ledgerPath: string;
  taxYear?: number;
  feeBps?: bigint | number | string;
  keystorePath?: string;
  expectedPublicKeyPem?: string;
}

/**
 * Generates a complete, tamper-evident tax audit bundle containing RFC 4180 CSV,
 * Form 8949 summary, canonical SHA-256 record chain digest, and an Ed25519 DSSE envelope.
 */
export function generateAuditBundle(params: GenerateAuditBundleParams): TaxAuditBundle {
  const ledgerPath = params.ledgerPath || DEFAULT_LEDGER_PATH;
  const keystorePath = params.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const feeBps = parseFeeBps(params.feeBps);
  const generatedAt = new Date().toISOString();

  const receipts = readLedger(ledgerPath);
  const items = buildNormalizedRows(
    receipts,
    params.taxYear,
    feeBps,
    keystorePath,
    params.expectedPublicKeyPem
  );
  const rows = items.map((item) => item.row);
  const csv = renderCsv(rows);
  const form8949Summary = summarizeRows(rows, params.taxYear, feeBps);
  const recordChainDigest = computeRowChainDigest(rows);

  const bundleCore = {
    version: "1.0.0",
    taxYear: params.taxYear ?? null,
    feeBps: feeBps.toString(),
    generatedAt,
    recordCount: rows.length,
    csv,
    form8949Summary,
    recordChainDigest,
  };
  const bundleDigest = sha256Hex(canonicalJson(bundleCore));
  const csvDigest = sha256Hex(csv);

  const dsse = signDsse(
    TAX_AUDIT_DSSE_PAYLOAD_TYPE,
    {
      version: bundleCore.version,
      taxYear: bundleCore.taxYear,
      feeBps: bundleCore.feeBps,
      generatedAt,
      recordCount: bundleCore.recordCount,
      csvDigest,
      form8949Summary,
      recordChainDigest,
      bundleDigest,
    },
    keystorePath
  );
  const keyid = dsse.signatures[0]?.keyid ?? getKeyId(keystorePath);

  return {
    version: bundleCore.version,
    payloadType: TAX_AUDIT_DSSE_PAYLOAD_TYPE,
    taxYear: bundleCore.taxYear,
    feeBps: bundleCore.feeBps,
    generatedAt,
    recordCount: bundleCore.recordCount,
    csv,
    form8949Summary,
    recordChainDigest,
    bundleDigest,
    keyid,
    dsse,
  };
}

/**
 * Verifies both the Ed25519 DSSE signature AND all canonical SHA-256 digests
 * and CSV-to-Form-8949 reconciliation invariants of a `TaxAuditBundle`.
 */
export function verifyAuditBundle(
  bundle: TaxAuditBundle,
  expectedPublicKeyPem?: string,
  keystorePath: string = DEFAULT_KEYSTORE_PATH
): AuditBundleVerificationResult {
  try {
    if (
      !bundle ||
      typeof bundle !== "object" ||
      typeof bundle.csv !== "string" ||
      !bundle.form8949Summary ||
      !bundle.dsse ||
      typeof bundle.bundleDigest !== "string" ||
      typeof bundle.recordChainDigest !== "string"
    ) {
      return {
        valid: false,
        dsseValid: false,
        digestValid: false,
        error: "Malformed tax audit bundle",
      };
    }

    if (bundle.dsse.payloadType !== TAX_AUDIT_DSSE_PAYLOAD_TYPE) {
      return {
        valid: false,
        dsseValid: false,
        digestValid: false,
        error: `Unexpected DSSE payloadType: ${bundle.dsse.payloadType}`,
      };
    }

    const dsseRes = verifyDsse(bundle.dsse, expectedPublicKeyPem, keystorePath);
    if (!dsseRes.valid) {
      return {
        valid: false,
        dsseValid: false,
        digestValid: false,
        error: dsseRes.error ?? "DSSE signature verification failed",
      };
    }

    if (bundle.keyid && dsseRes.keyid && bundle.keyid !== dsseRes.keyid) {
      return {
        valid: false,
        dsseValid: false,
        digestValid: false,
        error: `Bundle keyid ${bundle.keyid} does not match signature keyid ${dsseRes.keyid}`,
      };
    }

    const bundleCore = {
      version: bundle.version,
      taxYear: bundle.taxYear,
      feeBps: bundle.feeBps,
      generatedAt: bundle.generatedAt,
      recordCount: bundle.recordCount,
      csv: bundle.csv,
      form8949Summary: bundle.form8949Summary,
      recordChainDigest: bundle.recordChainDigest,
    };
    const recomputedBundleDigest = sha256Hex(canonicalJson(bundleCore));
    if (recomputedBundleDigest !== bundle.bundleDigest) {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: "Bundle SHA-256 digest mismatch (bundle content modified)",
      };
    }

    const decoded = dsseRes.decodedPayload as Record<string, unknown> | undefined;
    if (!decoded || typeof decoded !== "object") {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: "Decoded DSSE payload is not an object",
      };
    }

    const recomputedCsvDigest = sha256Hex(bundle.csv);
    if (
      decoded.bundleDigest !== bundle.bundleDigest ||
      decoded.csvDigest !== recomputedCsvDigest ||
      decoded.recordChainDigest !== bundle.recordChainDigest ||
      decoded.recordCount !== bundle.recordCount ||
      canonicalJson(decoded.form8949Summary) !== canonicalJson(bundle.form8949Summary)
    ) {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: "Signed DSSE payload does not match bundle fields",
      };
    }

    // Re-parse CSV rows and verify canonical chain digest + exact integer totals.
    const parsedCsv = parseCsvRfc4180(bundle.csv);
    if (parsedCsv.length === 0) {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: "CSV missing header row",
      };
    }
    const header = parsedCsv[0];
    if (
      header.length !== TAX_CSV_HEADERS.length ||
      TAX_CSV_HEADERS.some((col, idx) => header[idx] !== col)
    ) {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: "CSV header columns do not match expected schema",
      };
    }

    const csvRows: NormalizedTaxRow[] = [];
    for (let i = 1; i < parsedCsv.length; i += 1) {
      const cells = parsedCsv[i];
      if (cells.length === 1 && cells[0] === "") continue;
      if (cells.length !== TAX_CSV_HEADERS.length) {
        return {
          valid: false,
          dsseValid: true,
          digestValid: false,
          keyid: dsseRes.keyid,
          error: `Malformed CSV row at line ${i + 1}`,
        };
      }
      const rowObj = {} as Record<(typeof TAX_CSV_HEADERS)[number], string>;
      for (let c = 0; c < TAX_CSV_HEADERS.length; c += 1) {
        rowObj[TAX_CSV_HEADERS[c]] = cells[c];
      }
      csvRows.push(rowObj as NormalizedTaxRow);
    }

    if (csvRows.length !== bundle.recordCount) {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: `CSV row count ${csvRows.length} does not match bundle recordCount ${bundle.recordCount}`,
      };
    }

    const recomputedChain = computeRowChainDigest(csvRows);
    if (recomputedChain !== bundle.recordChainDigest) {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: "CSV record SHA-256 chain digest mismatch",
      };
    }

    const recomputedSummary = summarizeRows(
      csvRows,
      bundle.taxYear ?? undefined,
      parseFeeBps(bundle.feeBps)
    );
    if (
      canonicalJson(recomputedSummary.totals) !==
        canonicalJson(bundle.form8949Summary.totals) ||
      canonicalJson(recomputedSummary.groups) !==
        canonicalJson(bundle.form8949Summary.groups)
    ) {
      return {
        valid: false,
        dsseValid: true,
        digestValid: false,
        keyid: dsseRes.keyid,
        error: "CSV totals do not match Form 8949 summary totals",
      };
    }

    return {
      valid: true,
      dsseValid: true,
      digestValid: true,
      keyid: dsseRes.keyid,
      recordCount: bundle.recordCount,
      bundleDigest: bundle.bundleDigest,
      recordChainDigest: bundle.recordChainDigest,
    };
  } catch (err) {
    return {
      valid: false,
      dsseValid: false,
      digestValid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
