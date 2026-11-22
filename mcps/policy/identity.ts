import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  DEFAULT_BTC_MICRO_USD_PER_SAT,
  DEFAULT_KEYSTORE_PATH,
  MSAT_PER_SAT,
  isRetiredPayTo,
} from "../../shared/constants.js";
import { getKeyId, loadOrCreateKeystore, signDsse, verifyDsse } from "../../shared/keystore.js";
import { SpendPolicyEngine, SpendPolicyError } from "../../shared/policy.js";
import type {
  DsseEnvelope,
  SpendDecision,
  X402PaymentRequirement,
} from "../../shared/types.js";

export const AGENT_IDENTITY_DSSE_PAYLOAD_TYPE =
  "application/vnd.x402.agent-identity+json" as const;
export const POLICY_VERDICT_DSSE_PAYLOAD_TYPE =
  "application/vnd.x402.policy-verdict+json" as const;

const NON_NEGATIVE_INT_STR = /^\d+$/;

export type IntegerAmountInput = string | bigint | number;

export interface IssueAgentIdentityInput {
  agentId: string;
  evmAddress?: string;
  maxPerCallMicroUsd: IntegerAmountInput;
  maxRollingWindowMicroUsd: IntegerAmountInput;
  windowMs: number;
  allowedNetworks?: string[];
  allowedPayees?: string[];
  btcMicroUsdPerSat?: IntegerAmountInput;
  expiresAt?: string | number;
  keystorePath?: string;
}

export interface AgentIdentityClaims {
  version: 1;
  attestationId: string;
  agentId: string;
  evmAddress?: string;
  maxPerCallMicroUsd: string;
  maxRollingWindowMicroUsd: string;
  windowMs: number;
  allowedNetworks?: string[];
  allowedPayees?: string[];
  btcMicroUsdPerSat: string;
  issuedAt: string;
  expiresAt?: string;
  keyid: string;
}

export interface AgentIdentityAttestation extends AgentIdentityClaims {
  dsse: DsseEnvelope;
}

export interface VerifyAgentIdentityResult {
  valid: boolean;
  signatureValid: boolean;
  integrityValid: boolean;
  revoked: boolean;
  expired: boolean;
  agentId?: string;
  attestationId?: string;
  keyid?: string;
  revocationReason?: string;
  claims?: AgentIdentityClaims;
  error?: string;
}

export interface RevokeAgentIdentityResult {
  agentId: string;
  revoked: boolean;
  revokedAt: string;
  reason?: string;
}

export interface EvaluatePaymentRequestInput {
  agentId: string;
  requirement: X402PaymentRequirement;
  nowMs?: number;
  keystorePath?: string;
}

export interface PolicyEvaluationResult extends SpendDecision {
  agentId: string;
  revoked: boolean;
  expired: boolean;
  verdictDsse: DsseEnvelope;
}

export interface RecordAgentSpendInput {
  agentId: string;
  requirement: X402PaymentRequirement;
  txHash?: string;
  intentId?: string;
  nowMs?: number;
}

export interface RecordAgentSpendResult {
  recorded: boolean;
  duplicate: boolean;
  agentId: string;
  idempotencyKey?: string;
  txHash?: string;
  intentId?: string;
  evaluatedMicroUsd: string;
  rollingSpendMicroUsd: string;
  remainingWindowMicroUsd: string;
  network: string;
  payTo: string;
  scheme: string;
}

export interface PolicyIdentityStoreOptions {
  statePath?: string;
  keystorePath?: string;
}

interface StoredSpendEntry {
  timestampMs: number;
  amountMicroUsd: string;
  network: string;
  payTo: string;
  scheme: string;
  txHash?: string;
  intentId?: string;
}

interface CommittedSpendRecord {
  idempotencyKey: string;
  recordedAtMs: number;
  amountMicroUsd: string;
  network: string;
  payTo: string;
  scheme: string;
  txHash?: string;
  intentId?: string;
}

interface StoredAgentRecord {
  claims: AgentIdentityClaims;
  attestation: AgentIdentityAttestation;
  revoked: boolean;
  revokedAt?: string;
  revocationReason?: string;
  spendEntries: StoredSpendEntry[];
  committedKeys: Record<string, CommittedSpendRecord>;
}

interface PersistedPolicyState {
  version: 1;
  agents: Record<string, StoredAgentRecord>;
  revokedAttestationIds: string[];
}

function parseNonNegativeBigInt(
  value: IntegerAmountInput,
  fieldName: string
): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error(`${fieldName} must be non-negative`);
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(
        `${fieldName} must be a non-negative integer (floats are forbidden): ${value}`
      );
    }
    return BigInt(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!NON_NEGATIVE_INT_STR.test(trimmed)) {
      throw new Error(
        `${fieldName} must be a non-negative integer string (floats are forbidden): "${value}"`
      );
    }
    return BigInt(trimmed);
  }
  throw new Error(`${fieldName} must be a non-negative integer string, number, or bigint`);
}

function parsePositiveSafeInteger(value: number, fieldName: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return value;
}

function normalizeStringList(items?: string[]): string[] | undefined {
  if (!items || items.length === 0) return undefined;
  const cleaned = items.map((s) => s.trim()).filter((s) => s.length > 0);
  return cleaned.length > 0 ? Array.from(new Set(cleaned)) : undefined;
}

function normalizeExpiresAt(expiresAt?: string | number): string | undefined {
  if (expiresAt === undefined) return undefined;
  if (typeof expiresAt === "number") {
    if (!Number.isFinite(expiresAt)) {
      throw new Error(`Invalid expiresAt timestamp: ${expiresAt}`);
    }
    return new Date(expiresAt).toISOString();
  }
  if (typeof expiresAt === "string") {
    const trimmed = expiresAt.trim();
    if (!trimmed) return undefined;
    const ms = Date.parse(trimmed);
    if (Number.isNaN(ms)) {
      throw new Error(`Invalid expiresAt ISO timestamp: "${expiresAt}"`);
    }
    return new Date(ms).toISOString();
  }
  throw new Error("expiresAt must be an ISO string or epoch milliseconds");
}

function canonicalJson(value: unknown): string {
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

function validateAndNormalizeRequirement(
  req: X402PaymentRequirement
): X402PaymentRequirement {
  if (!req || typeof req !== "object" || Array.isArray(req)) {
    throw new Error("requirement must be an X402PaymentRequirement object");
  }
  if (typeof req.scheme !== "string" || !req.scheme.trim()) {
    throw new Error("requirement.scheme must be a non-empty string");
  }
  if (typeof req.network !== "string" || !req.network.trim()) {
    throw new Error("requirement.network must be a non-empty string");
  }
  if (typeof req.asset !== "string" || !req.asset.trim()) {
    throw new Error("requirement.asset must be a non-empty string");
  }
  if (typeof req.payTo !== "string" || !req.payTo.trim()) {
    throw new Error("requirement.payTo must be a non-empty string");
  }

  const normalizedAmount = parseNonNegativeBigInt(
    req.amount as IntegerAmountInput,
    "requirement.amount"
  ).toString();

  const maxTimeoutSeconds =
    req.maxTimeoutSeconds === undefined ? 300 : req.maxTimeoutSeconds;
  if (
    typeof maxTimeoutSeconds !== "number" ||
    !Number.isFinite(maxTimeoutSeconds) ||
    maxTimeoutSeconds < 0
  ) {
    throw new Error("requirement.maxTimeoutSeconds must be a non-negative finite number");
  }

  let normalizedExtra = req.extra;
  if (req.extra && typeof req.extra === "object" && !Array.isArray(req.extra)) {
    if (req.extra.amountMsat !== undefined) {
      const msat = parseNonNegativeBigInt(
        req.extra.amountMsat as IntegerAmountInput,
        "requirement.extra.amountMsat"
      );
      normalizedExtra = {
        ...req.extra,
        amountMsat: msat.toString(),
      };
    }
  }

  return {
    scheme: req.scheme.trim(),
    network: req.network.trim(),
    asset: req.asset.trim(),
    amount: normalizedAmount,
    payTo: req.payTo.trim(),
    maxTimeoutSeconds,
    ...(normalizedExtra !== undefined ? { extra: normalizedExtra } : {}),
  };
}

function normalizeIdentifierKey(kind: "tx" | "intent", raw: string): string {
  const trimmed = raw.trim();
  if (kind === "tx" && /^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return `${kind}:${trimmed.toLowerCase()}`;
  }
  return `${kind}:${trimmed}`;
}

function buildEngineConfig(claims: AgentIdentityClaims) {
  return {
    agentId: claims.agentId,
    maxPerCallMicroUsd: BigInt(claims.maxPerCallMicroUsd),
    maxRollingWindowMicroUsd: BigInt(claims.maxRollingWindowMicroUsd),
    windowMs: claims.windowMs,
    ...(claims.allowedNetworks ? { allowedNetworks: claims.allowedNetworks } : {}),
    ...(claims.allowedPayees ? { allowedPayees: claims.allowedPayees } : {}),
    btcMicroUsdPerSat: BigInt(claims.btcMicroUsdPerSat),
  };
}

function extractClaimsFromAttestation(
  att: Record<string, unknown>
): AgentIdentityClaims {
  return {
    version: att.version as 1,
    attestationId: att.attestationId as string,
    agentId: att.agentId as string,
    ...(att.evmAddress !== undefined ? { evmAddress: att.evmAddress as string } : {}),
    maxPerCallMicroUsd: att.maxPerCallMicroUsd as string,
    maxRollingWindowMicroUsd: att.maxRollingWindowMicroUsd as string,
    windowMs: att.windowMs as number,
    ...(att.allowedNetworks !== undefined
      ? { allowedNetworks: att.allowedNetworks as string[] }
      : {}),
    ...(att.allowedPayees !== undefined
      ? { allowedPayees: att.allowedPayees as string[] }
      : {}),
    btcMicroUsdPerSat: att.btcMicroUsdPerSat as string,
    issuedAt: att.issuedAt as string,
    ...(att.expiresAt !== undefined ? { expiresAt: att.expiresAt as string } : {}),
    keyid: att.keyid as string,
  };
}

function validateDecodedClaims(
  raw: unknown
): { ok: true; claims: AgentIdentityClaims } | { ok: false; error: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, error: "Decoded DSSE identity payload must be a JSON object" };
  }
  const obj = raw as Record<string, unknown>;
  if (obj.version !== 1) {
    return { ok: false, error: `Unsupported identity claim version: ${String(obj.version)}` };
  }
  if (typeof obj.attestationId !== "string" || !obj.attestationId.trim()) {
    return { ok: false, error: "Identity claim missing attestationId" };
  }
  if (typeof obj.agentId !== "string" || !obj.agentId.trim()) {
    return { ok: false, error: "Identity claim missing agentId" };
  }
  if (obj.evmAddress !== undefined && typeof obj.evmAddress !== "string") {
    return { ok: false, error: "Identity claim evmAddress must be a string" };
  }
  if (typeof obj.keyid !== "string" || !obj.keyid.trim()) {
    return { ok: false, error: "Identity claim missing keyid" };
  }
  if (typeof obj.issuedAt !== "string" || Number.isNaN(Date.parse(obj.issuedAt))) {
    return { ok: false, error: "Identity claim invalid issuedAt timestamp" };
  }
  if (
    obj.expiresAt !== undefined &&
    (typeof obj.expiresAt !== "string" || Number.isNaN(Date.parse(obj.expiresAt)))
  ) {
    return { ok: false, error: "Identity claim invalid expiresAt timestamp" };
  }

  try {
    parseNonNegativeBigInt(obj.maxPerCallMicroUsd as IntegerAmountInput, "maxPerCallMicroUsd");
    parseNonNegativeBigInt(
      obj.maxRollingWindowMicroUsd as IntegerAmountInput,
      "maxRollingWindowMicroUsd"
    );
    parseNonNegativeBigInt(obj.btcMicroUsdPerSat as IntegerAmountInput, "btcMicroUsdPerSat");
    parsePositiveSafeInteger(obj.windowMs as number, "windowMs");
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  if (obj.allowedPayees !== undefined) {
    if (!Array.isArray(obj.allowedPayees) || obj.allowedPayees.some((p) => typeof p !== "string")) {
      return { ok: false, error: "Identity claim allowedPayees must be string[]" };
    }
    for (const payee of obj.allowedPayees) {
      if (isRetiredPayTo(payee)) {
        return {
          ok: false,
          error: `Retired payee address is forbidden in identity allowedPayees: ${payee}`,
        };
      }
    }
  }

  if (
    obj.allowedNetworks !== undefined &&
    (!Array.isArray(obj.allowedNetworks) || obj.allowedNetworks.some((n) => typeof n !== "string"))
  ) {
    return { ok: false, error: "Identity claim allowedNetworks must be string[]" };
  }

  return { ok: true, claims: extractClaimsFromAttestation(obj) };
}

function isDsseEnvelopeLike(value: unknown): value is DsseEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  return (
    typeof obj.payloadType === "string" &&
    typeof obj.payload === "string" &&
    Array.isArray(obj.signatures) &&
    !("agentId" in obj)
  );
}

function atomicWriteJson(filePath: string, data: unknown): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = path.join(
    dir,
    `.${path.basename(filePath)}.tmp.${process.pid}.${crypto.randomBytes(6).toString("hex")}`
  );
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2) + "\n", "utf8");
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {
      // Best-effort cleanup
    }
    throw err;
  }
}

export class PolicyIdentityStore {
  public readonly statePath?: string;
  public readonly keystorePath: string;

  private readonly agents = new Map<string, StoredAgentRecord>();
  private readonly engines = new Map<string, SpendPolicyEngine>();
  private readonly revokedAttestationIds = new Set<string>();

  constructor(options: PolicyIdentityStoreOptions = {}) {
    this.statePath = options.statePath ? path.resolve(options.statePath) : undefined;
    this.keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
    this.loadFromDisk();
  }

  private loadFromDisk(): void {
    if (!this.statePath || !fs.existsSync(this.statePath)) {
      return;
    }
    const raw = fs.readFileSync(this.statePath, "utf8");
    if (!raw.trim()) return;
    const parsed = JSON.parse(raw) as PersistedPolicyState;
    if (parsed.version !== 1 || !parsed.agents || typeof parsed.agents !== "object") {
      throw new Error(`Invalid policy state file at ${this.statePath}`);
    }

    for (const id of parsed.revokedAttestationIds ?? []) {
      this.revokedAttestationIds.add(id);
    }

    for (const [agentId, record] of Object.entries(parsed.agents)) {
      this.agents.set(agentId, record);
      this.engines.set(agentId, this.rebuildEngine(record));
    }
  }

  private rebuildEngine(record: StoredAgentRecord): SpendPolicyEngine {
    const engine = new SpendPolicyEngine(buildEngineConfig(record.claims));
    const ordered = [...record.spendEntries].sort((a, b) => a.timestampMs - b.timestampMs);
    for (const entry of ordered) {
      engine.recordSpend(
        {
          scheme: entry.scheme,
          network: entry.network,
          asset: "MICRO_USD",
          amount: entry.amountMicroUsd,
          payTo: entry.payTo,
          maxTimeoutSeconds: 300,
        },
        { agentId: record.claims.agentId, nowMs: entry.timestampMs }
      );
    }
    return engine;
  }

  private persist(): void {
    if (!this.statePath) return;
    const agentsObj: Record<string, StoredAgentRecord> = {};
    for (const [agentId, record] of this.agents.entries()) {
      agentsObj[agentId] = record;
    }
    const snapshot: PersistedPolicyState = {
      version: 1,
      agents: agentsObj,
      revokedAttestationIds: Array.from(this.revokedAttestationIds),
    };
    atomicWriteJson(this.statePath, snapshot);
  }

  public issueAgentIdentity(
    input: IssueAgentIdentityInput
  ): AgentIdentityAttestation {
    if (typeof input.agentId !== "string" || !input.agentId.trim()) {
      throw new Error("agentId must be a non-empty string");
    }
    const agentId = input.agentId.trim();
    const evmAddress =
      input.evmAddress !== undefined && input.evmAddress.trim()
        ? input.evmAddress.trim()
        : undefined;

    const maxPerCall = parseNonNegativeBigInt(
      input.maxPerCallMicroUsd,
      "maxPerCallMicroUsd"
    );
    const maxRolling = parseNonNegativeBigInt(
      input.maxRollingWindowMicroUsd,
      "maxRollingWindowMicroUsd"
    );
    const windowMs = parsePositiveSafeInteger(input.windowMs, "windowMs");
    const btcMicroUsdPerSat =
      input.btcMicroUsdPerSat !== undefined
        ? parseNonNegativeBigInt(input.btcMicroUsdPerSat, "btcMicroUsdPerSat")
        : DEFAULT_BTC_MICRO_USD_PER_SAT;

    if (btcMicroUsdPerSat <= 0n) {
      throw new Error("btcMicroUsdPerSat must be greater than 0");
    }

    const allowedNetworks = normalizeStringList(input.allowedNetworks);
    const allowedPayees = normalizeStringList(input.allowedPayees);

    if (allowedPayees) {
      for (const payee of allowedPayees) {
        if (isRetiredPayTo(payee)) {
          throw new Error(
            `Retired payee address is forbidden in allowedPayees: ${payee}`
          );
        }
      }
    }

    const expiresAt = normalizeExpiresAt(input.expiresAt);
    const effectiveKeystore = input.keystorePath ?? this.keystorePath;
    const ks = loadOrCreateKeystore(effectiveKeystore);
    const issuedAt = new Date().toISOString();
    const attestationId = `att_${crypto.randomBytes(12).toString("hex")}`;

    const claims: AgentIdentityClaims = {
      version: 1,
      attestationId,
      agentId,
      ...(evmAddress !== undefined ? { evmAddress } : {}),
      maxPerCallMicroUsd: maxPerCall.toString(),
      maxRollingWindowMicroUsd: maxRolling.toString(),
      windowMs,
      ...(allowedNetworks !== undefined ? { allowedNetworks } : {}),
      ...(allowedPayees !== undefined ? { allowedPayees } : {}),
      btcMicroUsdPerSat: btcMicroUsdPerSat.toString(),
      issuedAt,
      ...(expiresAt !== undefined ? { expiresAt } : {}),
      keyid: ks.keyid,
    };

    const dsse = signDsse(AGENT_IDENTITY_DSSE_PAYLOAD_TYPE, claims, effectiveKeystore);
    const attestation: AgentIdentityAttestation = {
      ...claims,
      dsse,
    };

    const record: StoredAgentRecord = {
      claims,
      attestation,
      revoked: false,
      spendEntries: [],
      committedKeys: {},
    };

    this.agents.set(agentId, record);
    this.engines.set(agentId, new SpendPolicyEngine(buildEngineConfig(claims)));
    this.persist();

    return attestation;
  }

  public verifyAgentIdentity(
    attestation: AgentIdentityAttestation | DsseEnvelope,
    expectedPublicKeyPem?: string,
    keystorePath?: string,
    nowMs: number = Date.now()
  ): VerifyAgentIdentityResult {
    if (!attestation || typeof attestation !== "object" || Array.isArray(attestation)) {
      return {
        valid: false,
        signatureValid: false,
        integrityValid: false,
        revoked: false,
        expired: false,
        error: "Attestation must be an object",
      };
    }

    const bareEnvelope = isDsseEnvelopeLike(attestation);
    const dsse = bareEnvelope
      ? attestation
      : (attestation as AgentIdentityAttestation).dsse;

    if (!dsse || typeof dsse !== "object") {
      return {
        valid: false,
        signatureValid: false,
        integrityValid: false,
        revoked: false,
        expired: false,
        error: "Attestation missing DSSE envelope",
      };
    }

    if (dsse.payloadType !== AGENT_IDENTITY_DSSE_PAYLOAD_TYPE) {
      return {
        valid: false,
        signatureValid: false,
        integrityValid: false,
        revoked: false,
        expired: false,
        error: `Unexpected DSSE payloadType "${dsse.payloadType}", expected "${AGENT_IDENTITY_DSSE_PAYLOAD_TYPE}"`,
      };
    }

    const effectiveKeystore = keystorePath ?? this.keystorePath;
    const dsseRes = verifyDsse(dsse, expectedPublicKeyPem, effectiveKeystore);
    if (!dsseRes.valid) {
      return {
        valid: false,
        signatureValid: false,
        integrityValid: false,
        revoked: false,
        expired: false,
        error: dsseRes.error ?? "DSSE signature verification failed",
      };
    }

    const claimsRes = validateDecodedClaims(dsseRes.decodedPayload);
    if (!claimsRes.ok) {
      return {
        valid: false,
        signatureValid: true,
        integrityValid: false,
        revoked: false,
        expired: false,
        keyid: dsseRes.keyid,
        error: claimsRes.error,
      };
    }

    const claims = claimsRes.claims;
    if (claims.keyid !== dsseRes.keyid) {
      return {
        valid: false,
        signatureValid: true,
        integrityValid: false,
        revoked: false,
        expired: false,
        agentId: claims.agentId,
        attestationId: claims.attestationId,
        keyid: dsseRes.keyid,
        error: `Claim keyid (${claims.keyid}) does not match DSSE signature keyid (${dsseRes.keyid})`,
      };
    }

    if (!bareEnvelope) {
      const outerClaims = extractClaimsFromAttestation(
        attestation as unknown as Record<string, unknown>
      );
      if (canonicalJson(outerClaims) !== canonicalJson(claims)) {
        return {
          valid: false,
          signatureValid: true,
          integrityValid: false,
          revoked: false,
          expired: false,
          agentId: claims.agentId,
          attestationId: claims.attestationId,
          keyid: dsseRes.keyid,
          error: "Attestation fields tampered: outer claims do not match signed DSSE payload",
        };
      }
    }

    const expired =
      claims.expiresAt !== undefined && Date.parse(claims.expiresAt) <= nowMs;

    const stored = this.agents.get(claims.agentId);
    const revokedByAttestation = this.revokedAttestationIds.has(claims.attestationId);
    const revokedByAgent = Boolean(stored?.revoked);
    const revoked = revokedByAttestation || revokedByAgent;
    const revocationReason = revoked ? stored?.revocationReason ?? "Revoked" : undefined;

    if (revoked) {
      return {
        valid: false,
        signatureValid: true,
        integrityValid: true,
        revoked: true,
        expired,
        agentId: claims.agentId,
        attestationId: claims.attestationId,
        keyid: dsseRes.keyid,
        revocationReason,
        claims,
        error: `Agent identity "${claims.agentId}" is revoked${
          revocationReason ? `: ${revocationReason}` : ""
        }`,
      };
    }

    if (expired) {
      return {
        valid: false,
        signatureValid: true,
        integrityValid: true,
        revoked: false,
        expired: true,
        agentId: claims.agentId,
        attestationId: claims.attestationId,
        keyid: dsseRes.keyid,
        claims,
        error: `Agent identity "${claims.agentId}" expired at ${claims.expiresAt}`,
      };
    }

    return {
      valid: true,
      signatureValid: true,
      integrityValid: true,
      revoked: false,
      expired: false,
      agentId: claims.agentId,
      attestationId: claims.attestationId,
      keyid: dsseRes.keyid,
      claims,
    };
  }

  public revokeAgentIdentity(
    agentId: string,
    reason?: string
  ): RevokeAgentIdentityResult {
    if (typeof agentId !== "string" || !agentId.trim()) {
      throw new Error("agentId must be a non-empty string");
    }
    const normalizedId = agentId.trim();
    const record = this.agents.get(normalizedId);
    if (!record) {
      throw new Error(`Unknown agentId: "${normalizedId}"`);
    }

    const revokedAt = new Date().toISOString();
    const cleanReason =
      typeof reason === "string" && reason.trim() ? reason.trim() : undefined;

    record.revoked = true;
    record.revokedAt = revokedAt;
    if (cleanReason !== undefined) {
      record.revocationReason = cleanReason;
    }
    this.revokedAttestationIds.add(record.claims.attestationId);
    this.persist();

    return {
      agentId: normalizedId,
      revoked: true,
      revokedAt,
      ...(cleanReason !== undefined ? { reason: cleanReason } : {}),
    };
  }

  public evaluatePaymentRequest(
    input: EvaluatePaymentRequestInput
  ): PolicyEvaluationResult {
    if (typeof input.agentId !== "string" || !input.agentId.trim()) {
      throw new Error("agentId must be a non-empty string");
    }
    const agentId = input.agentId.trim();
    const req = validateAndNormalizeRequirement(input.requirement);
    const nowMs =
      input.nowMs !== undefined
        ? parsePositiveSafeIntegerOrZero(input.nowMs, "nowMs")
        : Date.now();
    const effectiveKeystore = input.keystorePath ?? this.keystorePath;
    const keyid = getKeyId(effectiveKeystore);

    const record = this.agents.get(agentId);
    const engine = this.engines.get(agentId);
    const revoked = Boolean(
      record &&
        (record.revoked || this.revokedAttestationIds.has(record.claims.attestationId))
    );
    const expired = Boolean(
      record?.claims.expiresAt && Date.parse(record.claims.expiresAt) <= nowMs
    );

    let decision: SpendDecision;

    if (isRetiredPayTo(req.payTo)) {
      const remaining =
        record && engine
          ? this.computeRemainingMicroUsd(record, engine, nowMs).toString()
          : "0";
      decision = {
        allowed: false,
        reason: `Payee ${req.payTo} is retired and unconditionally rejected`,
        evaluatedMicroUsd: "0",
        remainingWindowMicroUsd: remaining,
        network: req.network,
        payTo: req.payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    } else if (!record || !engine) {
      decision = {
        allowed: false,
        reason: `Agent "${agentId}" is not registered`,
        evaluatedMicroUsd: "0",
        remainingWindowMicroUsd: "0",
        network: req.network,
        payTo: req.payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    } else if (revoked) {
      const remaining = this.computeRemainingMicroUsd(record, engine, nowMs).toString();
      decision = {
        allowed: false,
        reason: `Agent "${agentId}" identity is revoked${
          record.revocationReason ? `: ${record.revocationReason}` : ""
        }`,
        evaluatedMicroUsd: "0",
        remainingWindowMicroUsd: remaining,
        network: req.network,
        payTo: req.payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    } else if (expired) {
      const remaining = this.computeRemainingMicroUsd(record, engine, nowMs).toString();
      decision = {
        allowed: false,
        reason: `Agent "${agentId}" identity expired at ${record.claims.expiresAt}`,
        evaluatedMicroUsd: "0",
        remainingWindowMicroUsd: remaining,
        network: req.network,
        payTo: req.payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    } else {
      decision = engine.onPaymentRequested(req, { agentId, nowMs });
    }

    const verdictPayload = {
      version: 1,
      agentId,
      allowed: decision.allowed,
      ...(decision.reason !== undefined ? { reason: decision.reason } : {}),
      evaluatedMicroUsd: decision.evaluatedMicroUsd,
      remainingWindowMicroUsd: decision.remainingWindowMicroUsd,
      network: decision.network,
      payTo: decision.payTo,
      scheme: decision.scheme,
      capEnforced: decision.capEnforced,
      revoked,
      expired,
      evaluatedAt: new Date(nowMs).toISOString(),
      keyid,
    };

    const verdictDsse = signDsse(
      POLICY_VERDICT_DSSE_PAYLOAD_TYPE,
      verdictPayload,
      effectiveKeystore
    );

    return {
      ...decision,
      agentId,
      revoked,
      expired,
      verdictDsse,
    };
  }

  public recordAgentSpend(input: RecordAgentSpendInput): RecordAgentSpendResult {
    if (typeof input.agentId !== "string" || !input.agentId.trim()) {
      throw new Error("agentId must be a non-empty string");
    }
    const agentId = input.agentId.trim();
    const req = validateAndNormalizeRequirement(input.requirement);
    const nowMs =
      input.nowMs !== undefined
        ? parsePositiveSafeIntegerOrZero(input.nowMs, "nowMs")
        : Date.now();

    if (isRetiredPayTo(req.payTo)) {
      throw new Error(`Payee ${req.payTo} is retired and unconditionally rejected`);
    }

    const record = this.agents.get(agentId);
    const engine = this.engines.get(agentId);
    if (!record || !engine) {
      throw new Error(`Agent "${agentId}" is not registered`);
    }
    if (
      record.revoked ||
      this.revokedAttestationIds.has(record.claims.attestationId)
    ) {
      throw new Error(
        `Agent "${agentId}" identity is revoked${
          record.revocationReason ? `: ${record.revocationReason}` : ""
        }`
      );
    }
    if (record.claims.expiresAt && Date.parse(record.claims.expiresAt) <= nowMs) {
      throw new Error(`Agent "${agentId}" identity expired at ${record.claims.expiresAt}`);
    }

    const txHash =
      typeof input.txHash === "string" && input.txHash.trim()
        ? input.txHash.trim()
        : undefined;
    const intentId =
      typeof input.intentId === "string" && input.intentId.trim()
        ? input.intentId.trim()
        : undefined;

    const lookupKeys: string[] = [];
    if (txHash) lookupKeys.push(normalizeIdentifierKey("tx", txHash));
    if (intentId) lookupKeys.push(normalizeIdentifierKey("intent", intentId));

    // Check idempotency BEFORE evaluating rolling window cap so retries never fail when cap is full.
    for (const key of lookupKeys) {
      const existing = record.committedKeys[key];
      if (existing) {
        const rollingSpend = engine.getRollingSpendMicroUsd(agentId, nowMs);
        const maxRolling = BigInt(record.claims.maxRollingWindowMicroUsd);
        const remaining = maxRolling > rollingSpend ? maxRolling - rollingSpend : 0n;
        return {
          recorded: false,
          duplicate: true,
          agentId,
          idempotencyKey: existing.idempotencyKey,
          ...(txHash !== undefined ? { txHash } : {}),
          ...(intentId !== undefined ? { intentId } : {}),
          evaluatedMicroUsd: existing.amountMicroUsd,
          rollingSpendMicroUsd: rollingSpend.toString(),
          remainingWindowMicroUsd: remaining.toString(),
          network: req.network,
          payTo: req.payTo,
          scheme: req.scheme,
        };
      }
    }

    const decision = engine.recordSpend(req, { agentId, nowMs });
    const rollingSpend = engine.getRollingSpendMicroUsd(agentId, nowMs);
    const idempotencyKey =
      lookupKeys[0] ?? `anon:${crypto.randomUUID()}`;

    record.spendEntries.push({
      timestampMs: nowMs,
      amountMicroUsd: decision.evaluatedMicroUsd,
      network: req.network,
      payTo: req.payTo,
      scheme: req.scheme,
      ...(txHash !== undefined ? { txHash } : {}),
      ...(intentId !== undefined ? { intentId } : {}),
    });

    // Prune stale spendEntries outside window so persisted snapshot stays bounded
    const cutoff = nowMs - record.claims.windowMs;
    record.spendEntries = record.spendEntries.filter((e) => e.timestampMs > cutoff);

    const committed: CommittedSpendRecord = {
      idempotencyKey,
      recordedAtMs: nowMs,
      amountMicroUsd: decision.evaluatedMicroUsd,
      network: req.network,
      payTo: req.payTo,
      scheme: req.scheme,
      ...(txHash !== undefined ? { txHash } : {}),
      ...(intentId !== undefined ? { intentId } : {}),
    };
    for (const key of lookupKeys) {
      record.committedKeys[key] = committed;
    }
    if (lookupKeys.length === 0) {
      record.committedKeys[idempotencyKey] = committed;
    }

    this.persist();

    return {
      recorded: true,
      duplicate: false,
      agentId,
      idempotencyKey,
      ...(txHash !== undefined ? { txHash } : {}),
      ...(intentId !== undefined ? { intentId } : {}),
      evaluatedMicroUsd: decision.evaluatedMicroUsd,
      rollingSpendMicroUsd: rollingSpend.toString(),
      remainingWindowMicroUsd: decision.remainingWindowMicroUsd,
      network: req.network,
      payTo: req.payTo,
      scheme: req.scheme,
    };
  }

  public getAgentStatus(agentId: string, nowMs: number = Date.now()) {
    const normalized = agentId.trim();
    const record = this.agents.get(normalized);
    const engine = this.engines.get(normalized);
    if (!record || !engine) return undefined;

    const rollingSpend = engine.getRollingSpendMicroUsd(normalized, nowMs);
    const maxRolling = BigInt(record.claims.maxRollingWindowMicroUsd);
    const remaining = maxRolling > rollingSpend ? maxRolling - rollingSpend : 0n;
    const expired = Boolean(
      record.claims.expiresAt && Date.parse(record.claims.expiresAt) <= nowMs
    );

    return {
      claims: record.claims,
      revoked: record.revoked,
      revokedAt: record.revokedAt,
      revocationReason: record.revocationReason,
      expired,
      rollingSpendMicroUsd: rollingSpend.toString(),
      remainingWindowMicroUsd: remaining.toString(),
    };
  }

  private computeRemainingMicroUsd(
    record: StoredAgentRecord,
    engine: SpendPolicyEngine,
    nowMs: number
  ): bigint {
    const current = engine.getRollingSpendMicroUsd(record.claims.agentId, nowMs);
    const cap = BigInt(record.claims.maxRollingWindowMicroUsd);
    return cap > current ? cap - current : 0n;
  }
}

function parsePositiveSafeIntegerOrZero(value: number, fieldName: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${fieldName} must be a non-negative integer`);
  }
  return value;
}

const defaultPolicyStore = new PolicyIdentityStore();

export function issueAgentIdentity(
  input: IssueAgentIdentityInput
): AgentIdentityAttestation {
  return defaultPolicyStore.issueAgentIdentity(input);
}

export function verifyAgentIdentity(
  attestation: AgentIdentityAttestation | DsseEnvelope,
  expectedPublicKeyPem?: string,
  keystorePath?: string,
  nowMs?: number
): VerifyAgentIdentityResult {
  return defaultPolicyStore.verifyAgentIdentity(
    attestation,
    expectedPublicKeyPem,
    keystorePath,
    nowMs
  );
}

export function revokeAgentIdentity(
  agentId: string,
  reason?: string
): RevokeAgentIdentityResult {
  return defaultPolicyStore.revokeAgentIdentity(agentId, reason);
}

export function evaluatePaymentRequest(
  input: EvaluatePaymentRequestInput
): PolicyEvaluationResult {
  return defaultPolicyStore.evaluatePaymentRequest(input);
}

export function recordAgentSpend(
  input: RecordAgentSpendInput
): RecordAgentSpendResult {
  return defaultPolicyStore.recordAgentSpend(input);
}

export { SpendPolicyError, MSAT_PER_SAT };
