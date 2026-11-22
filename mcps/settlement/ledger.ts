import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import {
  DEFAULT_KEYSTORE_PATH,
  MICRO_USD_PER_USD,
  RETIRED_X402_PAY_TO,
  isRetiredPayTo,
} from "../../shared/constants.js";
import {
  getKeyId,
  signDsse,
  verifyDsse,
} from "../../shared/keystore.js";
import type { DsseEnvelope, SettlementReceipt } from "../../shared/types.js";

export const RECEIPT_DSSE_PAYLOAD_TYPE =
  "application/vnd.x402.settlement-receipt+json" as const;
export const BATCH_DSSE_PAYLOAD_TYPE =
  "application/vnd.x402.settlement-batch+json" as const;

export const DEFAULT_LEDGER_PATH = path.resolve(
  process.cwd(),
  "registry/testnet-ledger.jsonl"
);

const NON_NEGATIVE_INT_STR = /^\d+$/;
const SIGNED_INT_STR = /^-?\d+$/;

const DsseEnvelopeSchema = z.object({
  payloadType: z.string().min(1),
  payload: z.string().min(1),
  signatures: z
    .array(
      z.object({
        keyid: z.string().min(1),
        sig: z.string().min(1),
      })
    )
    .min(1),
});

export const SettlementReceiptSchema = z.object({
  id: z.string().min(1),
  amountMicroUsd: z
    .string()
    .regex(NON_NEGATIVE_INT_STR, "amountMicroUsd must be a non-negative integer string"),
  amountMsat: z
    .string()
    .regex(NON_NEGATIVE_INT_STR, "amountMsat must be a non-negative integer string")
    .optional(),
  network: z.string().min(1),
  scheme: z.string().min(1),
  asset: z.string().min(1),
  txHash: z.string().min(1),
  payer: z.string().min(1),
  payTo: z.string().min(1),
  resource: z.string().min(1),
  toolName: z.string().min(1),
  settledAt: z
    .string()
    .min(1)
    .refine((val) => !Number.isNaN(Date.parse(val)), {
      message: "settledAt must be a valid ISO timestamp",
    }),
  facilitator: z.string().min(1),
  mode: z.enum(["live_testnet", "local_facilitator", "lightning_preimage"]),
  nonce: z.string().min(1).optional(),
  paymentHash: z.string().min(1).optional(),
  batchId: z.string().min(1).optional(),
  dsse: DsseEnvelopeSchema.optional(),
});

/**
 * Formats an exact integer micro-USD amount (`1 USD = 1_000_000n`) as a
 * fixed 6-decimal USD string without floating-point arithmetic.
 */
export function formatMicroUsd(microUsd: bigint): string {
  if (typeof microUsd !== "bigint") {
    throw new TypeError("formatMicroUsd requires a bigint value");
  }
  const negative = microUsd < 0n;
  const abs = negative ? -microUsd : microUsd;
  const whole = abs / MICRO_USD_PER_USD;
  const frac = abs % MICRO_USD_PER_USD;
  return `${negative ? "-" : ""}${whole.toString()}.${frac.toString().padStart(6, "0")}`;
}

/**
 * Parses an integer micro-USD value from a `bigint` or integer string.
 * Rejects floating-point numbers and decimal strings to prevent precision drift.
 */
export function parseMicroUsd(val: string | bigint): bigint {
  if (typeof val === "bigint") {
    return val;
  }
  if (typeof val !== "string") {
    throw new TypeError("parseMicroUsd requires a bigint or integer string");
  }
  const trimmed = val.trim();
  if (!SIGNED_INT_STR.test(trimmed)) {
    throw new Error(`Invalid integer micro-USD value: "${val}"`);
  }
  return BigInt(trimmed);
}

/** Parses non-negative integer basis points (`0`..`10000`). */
export function parseFeeBps(feeBps?: bigint | number | string): bigint {
  if (feeBps === undefined) return 0n;
  let parsed: bigint;
  if (typeof feeBps === "bigint") {
    parsed = feeBps;
  } else if (typeof feeBps === "number") {
    if (!Number.isInteger(feeBps)) {
      throw new Error(`feeBps must be an integer, got: ${feeBps}`);
    }
    parsed = BigInt(feeBps);
  } else if (typeof feeBps === "string") {
    const trimmed = feeBps.trim();
    if (!NON_NEGATIVE_INT_STR.test(trimmed)) {
      throw new Error(`Invalid feeBps string: "${feeBps}"`);
    }
    parsed = BigInt(trimmed);
  } else {
    throw new TypeError("Invalid feeBps type");
  }

  if (parsed < 0n || parsed > 10_000n) {
    throw new Error(`feeBps out of range [0, 10000]: ${parsed.toString()}`);
  }
  return parsed;
}

/** Parses an optional non-negative integer string or bigint into bigint. */
export function parseNonNegativeBigInt(
  val: string | bigint | undefined,
  fieldName = "value"
): bigint {
  if (val === undefined) return 0n;
  if (typeof val === "bigint") {
    if (val < 0n) {
      throw new Error(`${fieldName} must be non-negative`);
    }
    return val;
  }
  if (typeof val !== "string") {
    throw new TypeError(`${fieldName} must be a bigint or integer string`);
  }
  const trimmed = val.trim();
  if (!NON_NEGATIVE_INT_STR.test(trimmed)) {
    throw new Error(`Invalid non-negative integer ${fieldName}: "${val}"`);
  }
  return BigInt(trimmed);
}

/** Integer floor fee calculation: `(amount * feeBps) / 10_000n`. */
export function computeFeeMicroUsd(amountMicroUsd: bigint, feeBps: bigint): bigint {
  if (amountMicroUsd < 0n || feeBps < 0n || feeBps > 10_000n) {
    throw new Error("Invalid amountMicroUsd or feeBps for fee calculation");
  }
  return (amountMicroUsd * feeBps) / 10_000n;
}

/** Produces deterministic JSON with sorted object keys for hashing and signing. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",")}}`;
}

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function sortKeysDeep(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    if (obj[key] !== undefined) {
      out[key] = obj[key];
    }
  }
  return out;
}

/**
 * Extracts the immutable canonical fields of a `SettlementReceipt` for DSSE signing.
 * `batchId` and `dsse` are excluded so post-ingestion batch assignment does not
 * invalidate the original receipt signature.
 */
export function canonicalReceiptPayload(
  receipt: SettlementReceipt
): Record<string, unknown> {
  return sortKeysDeep({
    amountMicroUsd: receipt.amountMicroUsd,
    amountMsat: receipt.amountMsat,
    asset: receipt.asset,
    facilitator: receipt.facilitator,
    id: receipt.id,
    mode: receipt.mode,
    network: receipt.network,
    nonce: receipt.nonce,
    payTo: receipt.payTo,
    payer: receipt.payer,
    paymentHash: receipt.paymentHash,
    resource: receipt.resource,
    scheme: receipt.scheme,
    settledAt: receipt.settledAt,
    toolName: receipt.toolName,
    txHash: receipt.txHash,
  });
}

function identifiersEqual(a: string, b: string): boolean {
  if (a === b) return true;
  if (/^0x[0-9a-fA-F]+$/.test(a) && /^0x[0-9a-fA-F]+$/.test(b)) {
    return a.toLowerCase() === b.toLowerCase();
  }
  return false;
}

function isDuplicateReceipt(
  existing: SettlementReceipt,
  candidate: SettlementReceipt
): boolean {
  if (
    existing.network === candidate.network &&
    identifiersEqual(existing.txHash, candidate.txHash)
  ) {
    return true;
  }
  if (
    candidate.nonce &&
    existing.nonce &&
    existing.network === candidate.network &&
    existing.nonce === candidate.nonce
  ) {
    return true;
  }
  if (
    candidate.paymentHash &&
    existing.paymentHash &&
    existing.network === candidate.network &&
    identifiersEqual(existing.paymentHash, candidate.paymentHash)
  ) {
    return true;
  }
  return false;
}

function validateCanonicalFieldsMatch(
  receipt: SettlementReceipt,
  decodedPayload: unknown,
  payloadType: string
): string | null {
  if (!decodedPayload || typeof decodedPayload !== "object" || Array.isArray(decodedPayload)) {
    return "Decoded DSSE payload is not a JSON object";
  }
  const decoded = decodedPayload as Record<string, unknown>;
  const expected = canonicalReceiptPayload(receipt);

  if (payloadType === RECEIPT_DSSE_PAYLOAD_TYPE) {
    for (const key of Object.keys(expected)) {
      if (decoded[key] !== expected[key]) {
        return `DSSE payload mismatch on field "${key}"`;
      }
    }
    for (const key of Object.keys(decoded)) {
      if (!(key in expected)) {
        return `Unexpected field "${key}" in DSSE receipt payload`;
      }
    }
    return null;
  }

  // External receipt DSSE envelopes: verify every overlapping canonical field matches.
  for (const key of Object.keys(expected)) {
    if (key in decoded && decoded[key] !== expected[key]) {
      return `DSSE payload mismatch on field "${key}"`;
    }
  }
  return null;
}

export interface ReceiptVerificationResult {
  valid: boolean;
  keyid?: string;
  payloadType?: string;
  error?: string;
}

/**
 * Verifies a receipt's retired-payee guard, Ed25519 DSSE signature, and
 * consistency between outer receipt fields and the signed DSSE payload.
 */
export function verifySettlementReceipt(
  receipt: SettlementReceipt,
  expectedPublicKeyPem?: string,
  keystorePath: string = DEFAULT_KEYSTORE_PATH
): ReceiptVerificationResult {
  if (isRetiredPayTo(receipt.payTo)) {
    return {
      valid: false,
      error: `Retired payee address is forbidden: ${receipt.payTo}`,
    };
  }
  if (!receipt.dsse) {
    return { valid: false, error: "Receipt does not contain a DSSE envelope" };
  }

  const dsseRes = verifyDsse(receipt.dsse, expectedPublicKeyPem, keystorePath);
  if (!dsseRes.valid) {
    return { valid: false, error: dsseRes.error ?? "DSSE signature verification failed" };
  }

  const mismatch = validateCanonicalFieldsMatch(
    receipt,
    dsseRes.decodedPayload,
    receipt.dsse.payloadType
  );
  if (mismatch) {
    return { valid: false, keyid: dsseRes.keyid, error: mismatch };
  }

  return {
    valid: true,
    keyid: dsseRes.keyid,
    payloadType: receipt.dsse.payloadType,
  };
}

/** Reads an append-only JSONL settlement ledger safely; returns `[]` if missing. */
export function readLedger(ledgerPath: string = DEFAULT_LEDGER_PATH): SettlementReceipt[] {
  if (!fs.existsSync(ledgerPath)) {
    return [];
  }
  const raw = fs.readFileSync(ledgerPath, "utf8");
  if (!raw.trim()) {
    return [];
  }
  const receipts: SettlementReceipt[] = [];
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line) continue;
    const parsed = JSON.parse(line) as Record<string, unknown>;
    if (parsed.recordType === "settlement_batch") {
      continue;
    }
    receipts.push(parsed as unknown as SettlementReceipt);
  }
  return receipts;
}

function atomicWriteFile(filePath: string, content: string): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = path.join(
    dir,
    `.${path.basename(filePath)}.tmp.${process.pid}.${crypto.randomBytes(6).toString("hex")}`
  );
  fs.writeFileSync(tmpPath, content, "utf8");
  fs.renameSync(tmpPath, filePath);
}

export interface IngestSettlementParams {
  ledgerPath: string;
  receipt: SettlementReceipt;
  requireValidDsse?: boolean;
  keystorePath?: string;
  expectedPublicKeyPem?: string;
}

export interface IngestSettlementResult {
  ingested: boolean;
  duplicate: boolean;
  receipt: SettlementReceipt;
  keyid?: string;
}

/**
 * Validates, verifies or signs, deduplicates, and appends a settlement receipt
 * to an append-only JSONL ledger.
 */
export function ingestSettlement(params: IngestSettlementParams): IngestSettlementResult {
  const ledgerPath = params.ledgerPath || DEFAULT_LEDGER_PATH;
  const keystorePath = params.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const requireValidDsse = params.requireValidDsse ?? false;

  const parsedResult = SettlementReceiptSchema.safeParse(params.receipt);
  if (!parsedResult.success) {
    const detail = parsedResult.error.issues
      .map((iss) => `${iss.path.join(".") || "receipt"}: ${iss.message}`)
      .join("; ");
    throw new Error(`Invalid settlement receipt schema: ${detail}`);
  }
  const validated = parsedResult.data as SettlementReceipt;

  if (isRetiredPayTo(validated.payTo)) {
    throw new Error(
      `Rejected settlement for retired payee ${RETIRED_X402_PAY_TO}: ${validated.payTo}`
    );
  }

  // Validate integer money parsing explicitly via BigInt.
  const gross = parseMicroUsd(validated.amountMicroUsd);
  if (gross < 0n) {
    throw new Error("amountMicroUsd must be non-negative");
  }
  if (validated.amountMsat !== undefined) {
    parseNonNegativeBigInt(validated.amountMsat, "amountMsat");
  }

  let finalReceipt: SettlementReceipt;
  let keyid: string | undefined;

  if (validated.dsse) {
    const verification = verifySettlementReceipt(
      validated,
      params.expectedPublicKeyPem,
      keystorePath
    );
    if (!verification.valid) {
      throw new Error(`Invalid receipt DSSE signature: ${verification.error}`);
    }
    keyid = verification.keyid;
    finalReceipt = validated;
  } else {
    if (requireValidDsse) {
      throw new Error("requireValidDsse is true but receipt.dsse is missing");
    }
    const dsse = signDsse(
      RECEIPT_DSSE_PAYLOAD_TYPE,
      canonicalReceiptPayload(validated),
      keystorePath
    );
    keyid = dsse.signatures[0]?.keyid ?? getKeyId(keystorePath);
    finalReceipt = { ...validated, dsse };
  }

  const existingReceipts = readLedger(ledgerPath);
  const existingMatch = existingReceipts.find((r) => isDuplicateReceipt(r, finalReceipt));
  if (existingMatch) {
    return {
      ingested: false,
      duplicate: true,
      receipt: existingMatch,
      keyid: existingMatch.dsse?.signatures[0]?.keyid ?? keyid,
    };
  }

  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  fs.appendFileSync(ledgerPath, `${JSON.stringify(finalReceipt)}\n`, "utf8");

  return {
    ingested: true,
    duplicate: false,
    receipt: finalReceipt,
    keyid,
  };
}

export interface ExpectedReceiptRef {
  id?: string;
  network?: string;
  txHash?: string;
  amountMicroUsd: string;
  amountMsat?: string;
}

export interface BreakdownTotals {
  count: number;
  grossMicroUsd: string;
  grossUsd: string;
  feeMicroUsd: string;
  netMicroUsd: string;
  netUsd: string;
  msat: string;
}

export interface AmountMismatch {
  id: string;
  expectedId: string;
  network: string;
  txHash: string;
  expectedMicroUsd: string;
  actualMicroUsd: string;
  differenceMicroUsd: string;
  expectedMsat?: string;
  actualMsat?: string;
}

export interface ReconciliationResult {
  ledgerPath: string;
  reconciled: boolean;
  feeBps: string;
  totalGrossMicroUsd: string;
  totalGrossUsd: string;
  totalFeeMicroUsd: string;
  totalNetMicroUsd: string;
  totalNetUsd: string;
  totalMsat: string;
  counts: {
    ledger: number;
    expected: number;
    matched: number;
    missingExpected: number;
    unexpectedLedger: number;
    amountMismatches: number;
    batched: number;
    unbatched: number;
    dsseSigned: number;
  };
  byNetwork: Record<string, BreakdownTotals>;
  byScheme: Record<string, BreakdownTotals>;
  matchedIds: string[];
  missingExpectedIds: string[];
  unexpectedLedgerIds: string[];
  amountMismatches: AmountMismatch[];
  reconciledAt: string;
}

interface MutableBreakdown {
  count: number;
  gross: bigint;
  fee: bigint;
  net: bigint;
  msat: bigint;
}

function addBreakdown(
  map: Map<string, MutableBreakdown>,
  key: string,
  gross: bigint,
  fee: bigint,
  net: bigint,
  msat: bigint
): void {
  const cur = map.get(key) ?? { count: 0, gross: 0n, fee: 0n, net: 0n, msat: 0n };
  cur.count += 1;
  cur.gross += gross;
  cur.fee += fee;
  cur.net += net;
  cur.msat += msat;
  map.set(key, cur);
}

function finalizeBreakdowns(
  map: Map<string, MutableBreakdown>
): Record<string, BreakdownTotals> {
  const out: Record<string, BreakdownTotals> = {};
  for (const key of Array.from(map.keys()).sort()) {
    const b = map.get(key)!;
    out[key] = {
      count: b.count,
      grossMicroUsd: b.gross.toString(),
      grossUsd: formatMicroUsd(b.gross),
      feeMicroUsd: b.fee.toString(),
      netMicroUsd: b.net.toString(),
      netUsd: formatMicroUsd(b.net),
      msat: b.msat.toString(),
    };
  }
  return out;
}

export interface ReconcileSettlementsParams {
  ledgerPath: string;
  expectedReceipts?: ExpectedReceiptRef[];
  feeBps?: bigint | number | string;
}

/**
 * Reconciles ledger receipts against optional expected receipts using strictly
 * integer `bigint` micro-USD and msat math.
 */
export function reconcileSettlements(
  params: ReconcileSettlementsParams
): ReconciliationResult {
  const ledgerPath = params.ledgerPath || DEFAULT_LEDGER_PATH;
  const feeBps = parseFeeBps(params.feeBps);
  const receipts = readLedger(ledgerPath);

  let totalGross = 0n;
  let totalFee = 0n;
  let totalNet = 0n;
  let totalMsat = 0n;
  let batched = 0;
  let unbatched = 0;
  let dsseSigned = 0;

  const networkMap = new Map<string, MutableBreakdown>();
  const schemeMap = new Map<string, MutableBreakdown>();

  for (const r of receipts) {
    const gross = parseMicroUsd(r.amountMicroUsd);
    const fee = computeFeeMicroUsd(gross, feeBps);
    const net = gross - fee;
    const msat = parseNonNegativeBigInt(r.amountMsat, "amountMsat");

    totalGross += gross;
    totalFee += fee;
    totalNet += net;
    totalMsat += msat;

    if (r.batchId) batched += 1;
    else unbatched += 1;
    if (r.dsse) dsseSigned += 1;

    addBreakdown(networkMap, r.network, gross, fee, net, msat);
    addBreakdown(schemeMap, r.scheme, gross, fee, net, msat);
  }

  const matchedIds: string[] = [];
  const missingExpectedIds: string[] = [];
  const unexpectedLedgerIds: string[] = [];
  const amountMismatches: AmountMismatch[] = [];

  if (params.expectedReceipts !== undefined) {
    const matchedLedgerIndices = new Set<number>();

    for (const exp of params.expectedReceipts) {
      const expId = exp.id ?? `${exp.network ?? ""}:${exp.txHash ?? ""}`;
      let matchIdx = -1;

      if (exp.network && exp.txHash) {
        matchIdx = receipts.findIndex(
          (r) =>
            r.network === exp.network && identifiersEqual(r.txHash, exp.txHash!)
        );
      }
      if (matchIdx === -1 && exp.id) {
        matchIdx = receipts.findIndex((r) => r.id === exp.id);
      }

      if (matchIdx === -1) {
        missingExpectedIds.push(expId);
        continue;
      }

      matchedLedgerIndices.add(matchIdx);
      const actual = receipts[matchIdx];
      const expectedMicro = parseMicroUsd(exp.amountMicroUsd);
      const actualMicro = parseMicroUsd(actual.amountMicroUsd);
      const expectedMsat =
        exp.amountMsat !== undefined
          ? parseNonNegativeBigInt(exp.amountMsat, "expected.amountMsat")
          : undefined;
      const actualMsat = parseNonNegativeBigInt(actual.amountMsat, "actual.amountMsat");

      const microMismatch = expectedMicro !== actualMicro;
      const msatMismatch = expectedMsat !== undefined && expectedMsat !== actualMsat;

      if (microMismatch || msatMismatch) {
        amountMismatches.push({
          id: actual.id,
          expectedId: expId,
          network: actual.network,
          txHash: actual.txHash,
          expectedMicroUsd: expectedMicro.toString(),
          actualMicroUsd: actualMicro.toString(),
          differenceMicroUsd: (actualMicro - expectedMicro).toString(),
          ...(expectedMsat !== undefined
            ? {
                expectedMsat: expectedMsat.toString(),
                actualMsat: actualMsat.toString(),
              }
            : {}),
        });
      } else {
        matchedIds.push(actual.id);
      }
    }

    for (let i = 0; i < receipts.length; i += 1) {
      if (!matchedLedgerIndices.has(i)) {
        unexpectedLedgerIds.push(receipts[i].id);
      }
    }
  }

  const reconciled =
    params.expectedReceipts === undefined ||
    (missingExpectedIds.length === 0 &&
      unexpectedLedgerIds.length === 0 &&
      amountMismatches.length === 0);

  return {
    ledgerPath,
    reconciled,
    feeBps: feeBps.toString(),
    totalGrossMicroUsd: totalGross.toString(),
    totalGrossUsd: formatMicroUsd(totalGross),
    totalFeeMicroUsd: totalFee.toString(),
    totalNetMicroUsd: totalNet.toString(),
    totalNetUsd: formatMicroUsd(totalNet),
    totalMsat: totalMsat.toString(),
    counts: {
      ledger: receipts.length,
      expected: params.expectedReceipts?.length ?? 0,
      matched: matchedIds.length,
      missingExpected: missingExpectedIds.length,
      unexpectedLedger: unexpectedLedgerIds.length,
      amountMismatches: amountMismatches.length,
      batched,
      unbatched,
      dsseSigned,
    },
    byNetwork: finalizeBreakdowns(networkMap),
    byScheme: finalizeBreakdowns(schemeMap),
    matchedIds,
    missingExpectedIds,
    unexpectedLedgerIds,
    amountMismatches,
    reconciledAt: new Date().toISOString(),
  };
}

/** Computes a deterministic binary SHA-256 Merkle root over hex leaf hashes. */
export function computeMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) {
    return sha256Hex("");
  }
  let level = [...leafHashes];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? left;
      next.push(sha256Hex(`${left}${right}`));
    }
    level = next;
  }
  return level[0];
}

export function hashReceiptLeaf(receipt: SettlementReceipt): string {
  return sha256Hex(canonicalJson(canonicalReceiptPayload(receipt)));
}

export interface SettlementBatchManifest {
  created: boolean;
  batchId: string;
  createdAt: string;
  network: string | null;
  feeBps: string;
  receiptCount: number;
  receiptIds: string[];
  txHashes: string[];
  leafHashes: string[];
  merkleRoot: string;
  sha256Digest: string;
  totalGrossMicroUsd: string;
  totalGrossUsd: string;
  totalFeeMicroUsd: string;
  totalNetMicroUsd: string;
  totalNetUsd: string;
  totalMsat: string;
  keyid: string;
  dsse: DsseEnvelope;
}

export interface CreateSettlementBatchParams {
  ledgerPath: string;
  batchId?: string;
  network?: string;
  feeBps?: bigint | number | string;
  keystorePath?: string;
}

export function batchManifestPathFor(ledgerPath: string): string {
  return `${ledgerPath}.batches.jsonl`;
}

export function readSettlementBatches(
  ledgerPath: string = DEFAULT_LEDGER_PATH
): SettlementBatchManifest[] {
  const manifestPath = batchManifestPathFor(ledgerPath);
  if (!fs.existsSync(manifestPath)) return [];
  const raw = fs.readFileSync(manifestPath, "utf8");
  if (!raw.trim()) return [];
  return raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l) as SettlementBatchManifest);
}

/**
 * Groups unbatched receipts (optionally filtered by `network`), marks them with
 * `batchId` atomically in the ledger, and writes a DSSE-signed batch manifest
 * containing exact integer totals and a SHA-256 Merkle root over receipt hashes.
 */
export function createSettlementBatch(
  params: CreateSettlementBatchParams
): SettlementBatchManifest {
  const ledgerPath = params.ledgerPath || DEFAULT_LEDGER_PATH;
  const keystorePath = params.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const feeBps = parseFeeBps(params.feeBps);
  const allReceipts = readLedger(ledgerPath);

  const targetIndices: number[] = [];
  for (let i = 0; i < allReceipts.length; i += 1) {
    const r = allReceipts[i];
    if (r.batchId) continue;
    if (params.network && r.network !== params.network) continue;
    targetIndices.push(i);
  }

  const createdAt = new Date().toISOString();
  const unbatched = targetIndices
    .map((idx) => allReceipts[idx])
    .sort((a, b) =>
      `${a.settledAt}|${a.network}|${a.txHash}|${a.id}`.localeCompare(
        `${b.settledAt}|${b.network}|${b.txHash}|${b.id}`
      )
    );

  let totalGross = 0n;
  let totalFee = 0n;
  let totalNet = 0n;
  let totalMsat = 0n;

  const receiptIds: string[] = [];
  const txHashes: string[] = [];
  const leafHashes: string[] = [];

  for (const r of unbatched) {
    const gross = parseMicroUsd(r.amountMicroUsd);
    const fee = computeFeeMicroUsd(gross, feeBps);
    const net = gross - fee;
    const msat = parseNonNegativeBigInt(r.amountMsat, "amountMsat");

    totalGross += gross;
    totalFee += fee;
    totalNet += net;
    totalMsat += msat;

    receiptIds.push(r.id);
    txHashes.push(r.txHash);
    leafHashes.push(hashReceiptLeaf(r));
  }

  const merkleRoot = computeMerkleRoot(leafHashes);
  const resolvedBatchId =
    params.batchId ??
    `batch_${createdAt.replace(/[-:.TZ]/g, "").slice(0, 14)}_${merkleRoot.slice(0, 10)}`;

  const summaryCore = {
    batchId: resolvedBatchId,
    createdAt,
    network: params.network ?? null,
    feeBps: feeBps.toString(),
    receiptCount: unbatched.length,
    receiptIds,
    txHashes,
    leafHashes,
    merkleRoot,
    totalGrossMicroUsd: totalGross.toString(),
    totalGrossUsd: formatMicroUsd(totalGross),
    totalFeeMicroUsd: totalFee.toString(),
    totalNetMicroUsd: totalNet.toString(),
    totalNetUsd: formatMicroUsd(totalNet),
    totalMsat: totalMsat.toString(),
  };

  const sha256Digest = sha256Hex(canonicalJson(summaryCore));
  const dsse = signDsse(
    BATCH_DSSE_PAYLOAD_TYPE,
    { ...summaryCore, sha256Digest },
    keystorePath
  );
  const keyid = dsse.signatures[0]?.keyid ?? getKeyId(keystorePath);

  const manifest: SettlementBatchManifest = {
    created: unbatched.length > 0,
    ...summaryCore,
    sha256Digest,
    keyid,
    dsse,
  };

  if (unbatched.length > 0) {
    const idxSet = new Set(targetIndices);
    const updatedLines = allReceipts.map((r, i) =>
      JSON.stringify(idxSet.has(i) ? { ...r, batchId: resolvedBatchId } : r)
    );
    atomicWriteFile(ledgerPath, `${updatedLines.join("\n")}\n`);

    const manifestPath = batchManifestPathFor(ledgerPath);
    fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
    fs.appendFileSync(manifestPath, `${JSON.stringify(manifest)}\n`, "utf8");
  }

  return manifest;
}
