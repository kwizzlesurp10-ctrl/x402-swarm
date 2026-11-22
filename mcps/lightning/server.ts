import crypto from "node:crypto";
import fs from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  BRANDING,
  DEFAULT_BTC_MICRO_USD_PER_SAT,
  DEFAULT_KEYSTORE_PATH,
  LIGHTNING_TESTNET_NETWORK,
  MSAT_PER_SAT,
  TESTNET_FACILITATOR_URL,
  isRetiredPayTo,
  resolvePayTo,
} from "../../shared/constants.js";
import { getKeyId, signDsse } from "../../shared/keystore.js";
import {
  type McpToolContext,
  type McpToolDefinition,
  type McpToolResult,
  type RunningMcpServer,
  readJsonBody,
  sendJson,
  startMcpHttpServer,
} from "../../shared/mcp-http.js";
import { evaluateRequirementMicroUsd } from "../../shared/policy.js";
import type {
  DsseEnvelope,
  SettlementMode,
  SettlementReceipt,
  X402PaymentRequirement,
  X402PaymentRequiredEnvelope,
  X402PaymentSignature,
  X402SettlementResponse,
} from "../../shared/types.js";
import {
  FacilitatorClient,
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
} from "../../shared/x402-adapter.js";
import {
  type IssuedLightningInvoice,
  type LightningNetworkId,
  decodeLightningInvoice,
  issueHtlcInvoice,
  normalizeHex32,
  verifyLightningPreimage,
} from "./bolt11.js";

export interface Lightning402ServerOptions {
  port?: number;
  host?: string;
  facilitatorUrl?: string;
  payTo?: string;
  intentLogPath?: string;
  ledgerPath?: string;
  keystorePath?: string;
  priceMicroUsd?: string;
  priceMsat?: string;
  evmNetwork?: string;
  lightningNetwork?: LightningNetworkId;
  btcMicroUsdPerSat?: bigint;
  invoiceExpirySeconds?: number;
  issueInvoice?: (params: {
    amountMsat: bigint;
    network: LightningNetworkId;
    description: string;
    expirySeconds: number;
  }) => IssuedLightningInvoice;
  facilitatorClient?: FacilitatorClient;
}

export interface StoredIssuedInvoice {
  bolt11: string;
  paymentHash: string;
  amountMsat: string;
  payTo: string;
  expiresAtUnix: number;
  payeePubkey: string;
  resource: string;
  createdAtUnix: number;
}

export interface RunningLightning402Server extends RunningMcpServer {
  payTo: string;
  keystorePath: string;
  facilitatorUrl: string;
  priceMicroUsd: string;
  priceMsat: string;
  getIssuedInvoices: () => StoredIssuedInvoice[];
  getIntentCount: () => number;
}

interface IntentRecord {
  kind: "intent_committed" | "intent_settled" | "intent_failed";
  intentId: string;
  scheme: string;
  network: string;
  replayKeys: string[];
  payTo: string;
  amount: string;
  resource: string;
  txHash?: string;
  error?: string;
  timestamp: string;
}

type PaymentGateFailure = {
  ok: false;
  httpStatus: number;
  code: string;
  error: string;
  paymentRequired?: X402PaymentRequiredEnvelope;
};

type PaymentGateSuccess = {
  ok: true;
  receipt: SettlementReceipt;
  dsse: DsseEnvelope;
  settleResponse: X402SettlementResponse;
};

type PaymentGateResult = PaymentGateFailure | PaymentGateSuccess;

interface ValidatedSubmission {
  replayKeys: string[];
  payerIdentity: string;
  cleanPaymentHash?: string;
  cleanPreimage?: string;
  evmNonce?: string;
  serverRequirements: X402PaymentRequirement;
}

function formatMicroUsd(microUsd: bigint): string {
  const negative = microUsd < 0n;
  const abs = negative ? -microUsd : microUsd;
  const whole = abs / 1_000_000n;
  const frac = (abs % 1_000_000n).toString().padStart(6, "0");
  return `${negative ? "-" : ""}${whole.toString()}.${frac}`;
}

function appendJsonLine(filePath: string | undefined, record: unknown): void {
  if (!filePath) return;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`, "utf8");
}

function loadConsumedKeysFromIntentLog(
  intentLogPath: string | undefined,
  consumedKeys: Set<string>
): number {
  if (!intentLogPath || !fs.existsSync(intentLogPath)) return 0;
  const content = fs.readFileSync(intentLogPath, "utf8");
  let count = 0;
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as Partial<IntentRecord>;
      if (parsed.kind === "intent_committed" && Array.isArray(parsed.replayKeys)) {
        count += 1;
        for (const k of parsed.replayKeys) {
          if (typeof k === "string" && k) consumedKeys.add(k);
        }
      }
    } catch {
      // Ignore truncated trailing line on crash recovery
    }
  }
  return count;
}

function extractPaymentSignatureFromInput(
  rawHeader?: string,
  metaPayment?: unknown
): X402PaymentSignature | null {
  if (metaPayment !== undefined && metaPayment !== null) {
    if (typeof metaPayment === "string" && metaPayment.trim()) {
      try {
        return decodePaymentSignatureHeader(
          metaPayment.trim()
        ) as unknown as X402PaymentSignature;
      } catch {
        return JSON.parse(metaPayment) as X402PaymentSignature;
      }
    }
    if (typeof metaPayment === "object" && !Array.isArray(metaPayment)) {
      return metaPayment as X402PaymentSignature;
    }
  }

  if (rawHeader && rawHeader.trim()) {
    const trimmed = rawHeader.trim();
    try {
      return decodePaymentSignatureHeader(
        trimmed
      ) as unknown as X402PaymentSignature;
    } catch {
      return JSON.parse(trimmed) as X402PaymentSignature;
    }
  }

  return null;
}

function parseNonNegativeBigInt(raw: unknown): bigint | null {
  if (typeof raw === "bigint") return raw >= 0n ? raw : null;
  if (typeof raw !== "string" && typeof raw !== "number") return null;
  const s = String(raw).trim();
  if (!/^\d+$/.test(s)) return null;
  return BigInt(s);
}

function buildSatoshiOracleQuote(btcMicroUsdPerSat: bigint) {
  const satsPerBtc = 100_000_000n;
  const btcMicroUsd = satsPerBtc * btcMicroUsdPerSat;
  const satsPerUsd = 1_000_000n / btcMicroUsdPerSat;
  const msatPerUsd = (1_000_000n * MSAT_PER_SAT) / btcMicroUsdPerSat;

  return {
    pair: "BTC/USD",
    btcMicroUsdPerSat: btcMicroUsdPerSat.toString(),
    btcMicroUsd: btcMicroUsd.toString(),
    btcUsdFormatted: formatMicroUsd(btcMicroUsd),
    satsPerUsd: satsPerUsd.toString(),
    msatPerUsd: msatPerUsd.toString(),
    msatNumeratorPerMicroUsd: MSAT_PER_SAT.toString(),
    precision: "integer_micro_usd",
    observedAt: new Date().toISOString(),
  };
}

export async function startLightning402Server(
  options: Lightning402ServerOptions = {}
): Promise<RunningLightning402Server> {
  const payTo = resolvePayTo(options.payTo);
  if (isRetiredPayTo(payTo)) {
    throw new Error(`Retired payee address is forbidden: ${payTo}`);
  }

  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const facilitatorUrl = (
    options.facilitatorUrl ?? TESTNET_FACILITATOR_URL
  ).replace(/\/+$/, "");
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const priceMicroUsd = String(BigInt(options.priceMicroUsd ?? "1000"));
  const priceMsat = String(BigInt(options.priceMsat ?? "12000"));
  const evmNetwork = options.evmNetwork ?? BASE_SEPOLIA_NETWORK;
  const lightningNetwork: LightningNetworkId =
    options.lightningNetwork ?? LIGHTNING_TESTNET_NETWORK;
  const btcMicroUsdPerSat =
    options.btcMicroUsdPerSat ?? DEFAULT_BTC_MICRO_USD_PER_SAT;
  const invoiceExpirySeconds = options.invoiceExpirySeconds ?? 300;
  const facilitator =
    options.facilitatorClient ?? new FacilitatorClient(facilitatorUrl);

  // Server invoice table stores ONLY public invoice metadata — NEVER preimages!
  const issuedInvoices = new Map<string, StoredIssuedInvoice>();
  const consumedKeys = new Set<string>();
  let intentCount = loadConsumedKeysFromIntentLog(
    options.intentLogPath,
    consumedKeys
  );

  // Ensure keystore exists & has 0600 permissions on startup
  const keyid = getKeyId(keystorePath);
  let actualBaseUrl = `http://${host}:${port}`;

  const buildEvmRequirement = (): X402PaymentRequirement => ({
    scheme: "exact",
    network: evmNetwork,
    asset: BASE_SEPOLIA_USDC,
    amount: priceMicroUsd,
    payTo,
    maxTimeoutSeconds: invoiceExpirySeconds,
    extra: {
      name: "USDC",
      version: "2",
      assetTransferMethod: "eip3009",
    },
  });

  const issueAndStoreInvoice = (
    resource: string,
    description: string
  ): StoredIssuedInvoice => {
    const issued = options.issueInvoice
      ? options.issueInvoice({
          amountMsat: BigInt(priceMsat),
          network: lightningNetwork,
          description,
          expirySeconds: invoiceExpirySeconds,
        })
      : issueHtlcInvoice({
          amountMsat: BigInt(priceMsat),
          network: lightningNetwork,
          description,
          expirySeconds: invoiceExpirySeconds,
        });

    const record: StoredIssuedInvoice = {
      bolt11: issued.bolt11,
      paymentHash: normalizeHex32(issued.paymentHash, "paymentHash"),
      amountMsat: issued.amountMsat.toString(),
      payTo,
      expiresAtUnix: issued.expiresAtUnix,
      payeePubkey: issued.payeePubkey,
      resource,
      createdAtUnix: issued.timestampUnix,
    };
    issuedInvoices.set(record.paymentHash, record);
    return record;
  };

  const buildLightningRequirement = (
    invoice: StoredIssuedInvoice
  ): X402PaymentRequirement => ({
    scheme: "lightning",
    network: lightningNetwork,
    asset: "MSAT",
    amount: priceMsat,
    payTo,
    maxTimeoutSeconds: invoiceExpirySeconds,
    extra: {
      bolt11: invoice.bolt11,
      paymentHash: invoice.paymentHash,
      amountMsat: priceMsat,
      expiresAt: invoice.expiresAtUnix,
      payeePubkey: invoice.payeePubkey,
    },
  });

  const buildPaymentRequired = (
    resourceUrl: string,
    description: string,
    errorMessage = "Payment required"
  ): X402PaymentRequiredEnvelope => {
    const invoice = issueAndStoreInvoice(resourceUrl, description);
    return {
      x402Version: 2,
      error: errorMessage,
      resource: {
        url: resourceUrl,
        description,
        mimeType: "application/json",
      },
      accepts: [buildEvmRequirement(), buildLightningRequirement(invoice)],
    };
  };

  const failChallenge = (
    code: string,
    error: string,
    resourceUrl: string,
    description: string,
    challengeError = error
  ): PaymentGateFailure => ({
    ok: false,
    httpStatus: 402,
    code,
    error,
    paymentRequired: buildPaymentRequired(
      resourceUrl,
      description,
      challengeError
    ),
  });

  const validateLightningSubmission = (
    accepted: X402PaymentRequirement,
    payload: Record<string, unknown>,
    nowSec: number,
    resourceUrl: string,
    description: string
  ): ValidatedSubmission | PaymentGateFailure => {
    if (
      accepted.network !== lightningNetwork ||
      accepted.asset.toUpperCase() !== "MSAT"
    ) {
      return failChallenge(
        "invalid_lightning_requirements",
        `Unsupported Lightning network/asset: ${accepted.network}/${accepted.asset}`,
        resourceUrl,
        description
      );
    }

    const acceptedAmount = parseNonNegativeBigInt(accepted.amount);
    if (acceptedAmount === null || acceptedAmount < BigInt(priceMsat)) {
      return failChallenge(
        "insufficient_amount",
        `Lightning amount ${accepted.amount} invalid or below required ${priceMsat} msat`,
        resourceUrl,
        description
      );
    }

    const rawBolt11 = String(
      payload.bolt11 ?? accepted.extra?.bolt11 ?? ""
    ).trim();
    const rawHash = String(
      payload.paymentHash ?? accepted.extra?.paymentHash ?? ""
    ).trim();
    const rawPreimage = String(payload.preimage ?? "").trim();

    if (!rawBolt11 || !rawHash || !rawPreimage) {
      return failChallenge(
        "missing_lightning_fields",
        "Lightning payment payload requires bolt11, paymentHash, and preimage",
        resourceUrl,
        description
      );
    }

    let cleanPaymentHash: string;
    let cleanPreimage: string;
    let decodedBolt11;
    try {
      cleanPaymentHash = normalizeHex32(rawHash, "paymentHash");
      cleanPreimage = normalizeHex32(rawPreimage, "preimage");
      decodedBolt11 = decodeLightningInvoice(rawBolt11);
    } catch (err) {
      return failChallenge(
        "invalid_bolt11",
        err instanceof Error ? err.message : String(err),
        resourceUrl,
        description
      );
    }

    if (decodedBolt11.paymentHash !== cleanPaymentHash) {
      return failChallenge(
        "bolt11_hash_mismatch",
        "BOLT11 paymentHash does not match payload paymentHash",
        resourceUrl,
        description
      );
    }

    if (decodedBolt11.expiresAtUnix <= nowSec) {
      return failChallenge(
        "invoice_expired",
        `Lightning invoice expired at ${decodedBolt11.expiresAtUnix}`,
        resourceUrl,
        description,
        "Invoice expired"
      );
    }

    const storedInvoice = issuedInvoices.get(cleanPaymentHash);
    if (!storedInvoice) {
      if (
        consumedKeys.has(`ln:hash:${cleanPaymentHash}`) ||
        consumedKeys.has(`ln:preimage:${cleanPreimage}`)
      ) {
        return {
          ok: false,
          httpStatus: 409,
          code: "replay_rejected",
          error: `Replay detected for consumed Lightning payment credential (${cleanPaymentHash})`,
        };
      }
      return failChallenge(
        "unknown_invoice",
        `Unknown paymentHash ${cleanPaymentHash}: invoice was not issued by this server`,
        resourceUrl,
        description,
        "Unknown invoice"
      );
    }

    if (storedInvoice.expiresAtUnix <= nowSec) {
      return failChallenge(
        "invoice_expired",
        `Server-issued invoice expired at ${storedInvoice.expiresAtUnix}`,
        resourceUrl,
        description,
        "Invoice expired"
      );
    }

    if (
      BigInt(storedInvoice.amountMsat) < BigInt(priceMsat) ||
      decodedBolt11.amountMsat < BigInt(storedInvoice.amountMsat) ||
      storedInvoice.payTo.toLowerCase() !== payTo.toLowerCase() ||
      storedInvoice.bolt11 !== decodedBolt11.bolt11
    ) {
      return failChallenge(
        "invoice_terms_mismatch",
        "Submitted Lightning invoice does not match server-issued terms",
        resourceUrl,
        description
      );
    }

    const payerIdentity =
      typeof payload.payer === "string" && payload.payer.trim()
        ? payload.payer.trim()
        : "lightning:payer";

    return {
      replayKeys: [
        `ln:hash:${cleanPaymentHash}`,
        `ln:preimage:${cleanPreimage}`,
      ],
      payerIdentity,
      cleanPaymentHash,
      cleanPreimage,
      serverRequirements: buildLightningRequirement(storedInvoice),
    };
  };

  const validateEvmSubmission = (
    accepted: X402PaymentRequirement,
    payload: Record<string, unknown>,
    nowSec: number,
    resourceUrl: string,
    description: string
  ): ValidatedSubmission | PaymentGateFailure => {
    if (
      accepted.network !== evmNetwork ||
      accepted.asset.toLowerCase() !== BASE_SEPOLIA_USDC.toLowerCase()
    ) {
      return failChallenge(
        "invalid_evm_requirements",
        `Unsupported EVM network/asset: ${accepted.network}/${accepted.asset}`,
        resourceUrl,
        description
      );
    }

    const acceptedAmount = parseNonNegativeBigInt(accepted.amount);
    if (acceptedAmount === null || acceptedAmount < BigInt(priceMicroUsd)) {
      return failChallenge(
        "insufficient_amount",
        `EVM amount ${accepted.amount} invalid or below required ${priceMicroUsd}`,
        resourceUrl,
        description
      );
    }

    const innerAuth =
      payload.authorization && typeof payload.authorization === "object"
        ? (payload.authorization as Record<string, unknown>)
        : undefined;
    const innerPermit2 =
      payload.permit2Authorization &&
      typeof payload.permit2Authorization === "object"
        ? (payload.permit2Authorization as Record<string, unknown>)
        : undefined;
    const nowBig = BigInt(nowSec);

    if (innerAuth) {
      const from = String(innerAuth.from ?? "").trim();
      const to = String(innerAuth.to ?? "").trim();
      const valueBig = parseNonNegativeBigInt(innerAuth.value);
      const validAfterBig = parseNonNegativeBigInt(innerAuth.validAfter ?? "0");
      const validBeforeBig = parseNonNegativeBigInt(innerAuth.validBefore);
      const nonceStr = String(innerAuth.nonce ?? "").trim();

      if (
        !from ||
        !to ||
        !nonceStr ||
        valueBig === null ||
        validAfterBig === null ||
        validBeforeBig === null
      ) {
        return failChallenge(
          "invalid_eip3009_authorization",
          "Missing or malformed EIP-3009 authorization fields",
          resourceUrl,
          description
        );
      }

      if (to.toLowerCase() !== payTo.toLowerCase()) {
        return failChallenge(
          "authorization_payee_mismatch",
          `Authorization recipient ${to} does not match ${payTo}`,
          resourceUrl,
          description
        );
      }

      if (nowBig < validAfterBig || nowBig >= validBeforeBig) {
        return failChallenge(
          "authorization_expired",
          `EIP-3009 authorization outside validity window [${validAfterBig.toString()}, ${validBeforeBig.toString()}) at ${nowSec}`,
          resourceUrl,
          description,
          "Authorization expired"
        );
      }

      if (valueBig < BigInt(priceMicroUsd)) {
        return failChallenge(
          "insufficient_authorization_value",
          `EIP-3009 value ${valueBig.toString()} below ${priceMicroUsd}`,
          resourceUrl,
          description
        );
      }

      const evmNonce = nonceStr.toLowerCase();
      return {
        replayKeys: [`evm:${evmNetwork}:${from.toLowerCase()}:${evmNonce}`],
        payerIdentity: from,
        evmNonce,
        serverRequirements: buildEvmRequirement(),
      };
    }

    if (innerPermit2) {
      const from = String(innerPermit2.from ?? "").trim();
      const deadlineBig = parseNonNegativeBigInt(innerPermit2.deadline);
      const nonceStr = String(innerPermit2.nonce ?? "").trim();
      const permitted =
        innerPermit2.permitted && typeof innerPermit2.permitted === "object"
          ? (innerPermit2.permitted as Record<string, unknown>)
          : undefined;
      const witness =
        innerPermit2.witness && typeof innerPermit2.witness === "object"
          ? (innerPermit2.witness as Record<string, unknown>)
          : undefined;
      const amountBig = parseNonNegativeBigInt(permitted?.amount);

      if (
        !from ||
        !nonceStr ||
        deadlineBig === null ||
        nowBig >= deadlineBig ||
        amountBig === null
      ) {
        return failChallenge(
          "permit2_expired_or_invalid",
          "Permit2 authorization invalid or expired",
          resourceUrl,
          description
        );
      }

      if (
        typeof witness?.to === "string" &&
        witness.to.trim().toLowerCase() !== payTo.toLowerCase()
      ) {
        return failChallenge(
          "permit2_payee_mismatch",
          `Permit2 recipient ${witness.to} does not match ${payTo}`,
          resourceUrl,
          description
        );
      }

      if (amountBig < BigInt(priceMicroUsd)) {
        return failChallenge(
          "insufficient_permit2_amount",
          `Permit2 amount ${amountBig.toString()} below ${priceMicroUsd}`,
          resourceUrl,
          description
        );
      }

      const evmNonce = nonceStr.toLowerCase();
      return {
        replayKeys: [`evm:${evmNetwork}:${from.toLowerCase()}:${evmNonce}`],
        payerIdentity: from,
        evmNonce,
        serverRequirements: buildEvmRequirement(),
      };
    }

    return failChallenge(
      "unsupported_evm_payload",
      "EVM exact payload missing authorization / permit2Authorization",
      resourceUrl,
      description
    );
  };

  const settleEvmWithFacilitator = async (
    submitted: X402PaymentSignature,
    serverRequirements: X402PaymentRequirement,
    payerFallback: string,
    recordIntentFailure: (error: string) => void,
    resourceUrl: string,
    description: string
  ): Promise<
    | { ok: true; txHash: string; payer: string }
    | { ok: false; failure: PaymentGateFailure }
  > => {
    let verifyResult: { isValid: boolean; invalidReason?: string; payer?: string };
    try {
      verifyResult = await facilitator.verify(submitted, serverRequirements);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      recordIntentFailure(`Facilitator verify error: ${msg}`);
      return {
        ok: false,
        failure: failChallenge(
          "facilitator_verify_error",
          `Facilitator verify failed: ${msg}`,
          resourceUrl,
          description
        ),
      };
    }

    if (!verifyResult.isValid) {
      const reason = verifyResult.invalidReason ?? "invalid_payment";
      recordIntentFailure(reason);
      return {
        ok: false,
        failure: failChallenge(
          "facilitator_verify_rejected",
          verifyResult.invalidReason ?? "Facilitator rejected payment",
          resourceUrl,
          description
        ),
      };
    }

    let settleResult;
    try {
      settleResult = await facilitator.settle(submitted, serverRequirements);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      recordIntentFailure(`Facilitator settle error: ${msg}`);
      return {
        ok: false,
        failure: failChallenge(
          "facilitator_settle_error",
          `Facilitator settle failed: ${msg}`,
          resourceUrl,
          description
        ),
      };
    }

    if (!settleResult.success || !settleResult.transaction) {
      const reason = settleResult.errorReason ?? "settle_failed";
      recordIntentFailure(reason);
      return {
        ok: false,
        failure: failChallenge(
          "facilitator_settle_rejected",
          settleResult.errorReason ?? "Facilitator settlement failed",
          resourceUrl,
          description
        ),
      };
    }

    return {
      ok: true,
      txHash: settleResult.transaction,
      payer: settleResult.payer ?? verifyResult.payer ?? payerFallback,
    };
  };

  /**
   * Strict 4-step order of operations on payment submission:
   * (1) Validate payload structure, expiry window, and reject retired payee.
   * (2) Commit append-only intent record and reject duplicate EVM nonce or consumed paymentHash/preimage.
   * (3) Verify & settle (Lightning SHA256(preimage)===paymentHash + server invoice check; EVM facilitator verify+settle).
   * (4) Emit DSSE-signed SettlementReceipt + PAYMENT-RESPONSE header.
   */
  const processPaymentSubmission = async (params: {
    rawHeader?: string;
    metaPayment?: unknown;
    resourceUrl: string;
    toolName: string;
    description: string;
  }): Promise<PaymentGateResult> => {
    let submitted: X402PaymentSignature | null;
    try {
      submitted = extractPaymentSignatureFromInput(
        params.rawHeader,
        params.metaPayment
      );
    } catch (err) {
      return failChallenge(
        "malformed_payment_signature",
        `Malformed payment signature: ${err instanceof Error ? err.message : String(err)}`,
        params.resourceUrl,
        params.description,
        "Malformed payment signature"
      );
    }

    if (!submitted) {
      return failChallenge(
        "payment_required",
        "Payment required",
        params.resourceUrl,
        params.description
      );
    }

    // STEP (1): Validate payload structure, expiry window, and reject retired payee
    if (
      typeof submitted !== "object" ||
      submitted.x402Version !== 2 ||
      !submitted.accepted ||
      typeof submitted.accepted !== "object" ||
      !submitted.payload ||
      typeof submitted.payload !== "object"
    ) {
      return failChallenge(
        "invalid_payment_payload",
        "Payment payload must be x402Version 2 with accepted and payload",
        params.resourceUrl,
        params.description,
        "Invalid payment payload structure"
      );
    }

    const accepted = submitted.accepted;
    const payload = submitted.payload;
    const nowSec = Math.floor(Date.now() / 1000);

    const innerAuth =
      payload.authorization && typeof payload.authorization === "object"
        ? (payload.authorization as Record<string, unknown>)
        : undefined;
    const innerPermit2Witness =
      payload.permit2Authorization &&
      typeof payload.permit2Authorization === "object" &&
      (payload.permit2Authorization as Record<string, unknown>).witness &&
      typeof (payload.permit2Authorization as Record<string, unknown>)
        .witness === "object"
        ? ((payload.permit2Authorization as Record<string, unknown>)
            .witness as Record<string, unknown>)
        : undefined;

    for (const candidate of [
      accepted.payTo,
      typeof innerAuth?.to === "string" ? innerAuth.to : undefined,
      typeof innerPermit2Witness?.to === "string"
        ? innerPermit2Witness.to
        : undefined,
    ]) {
      if (isRetiredPayTo(candidate)) {
        return {
          ok: false,
          httpStatus: 403,
          code: "retired_payee_rejected",
          error: `Retired payee address is unconditionally rejected: ${candidate}`,
        };
      }
    }

    if (accepted.payTo.trim().toLowerCase() !== payTo.toLowerCase()) {
      return failChallenge(
        "payee_mismatch",
        `Accepted payTo ${accepted.payTo} does not match server payee ${payTo}`,
        params.resourceUrl,
        params.description,
        "Payee address mismatch"
      );
    }

    let validated: ValidatedSubmission | PaymentGateFailure;
    if (accepted.scheme === "lightning") {
      validated = validateLightningSubmission(
        accepted,
        payload,
        nowSec,
        params.resourceUrl,
        params.description
      );
    } else if (accepted.scheme === "exact") {
      validated = validateEvmSubmission(
        accepted,
        payload,
        nowSec,
        params.resourceUrl,
        params.description
      );
    } else {
      return failChallenge(
        "unsupported_scheme",
        `Unsupported payment scheme: ${accepted.scheme}`,
        params.resourceUrl,
        params.description
      );
    }

    if ("ok" in validated) return validated;

    // STEP (2): Commit append-only intent record & block duplicate nonce/preimage
    for (const key of validated.replayKeys) {
      if (consumedKeys.has(key)) {
        return {
          ok: false,
          httpStatus: 409,
          code: "replay_rejected",
          error: `Replay detected for consumed payment credential (${key})`,
        };
      }
    }

    const intentId = `intent_${crypto.randomUUID()}`;
    for (const key of validated.replayKeys) {
      consumedKeys.add(key);
    }
    intentCount += 1;

    appendJsonLine(options.intentLogPath, {
      kind: "intent_committed",
      intentId,
      scheme: accepted.scheme,
      network: accepted.network,
      replayKeys: validated.replayKeys,
      payTo,
      amount: accepted.amount,
      resource: params.resourceUrl,
      timestamp: new Date().toISOString(),
    } satisfies IntentRecord);

    const recordIntentFailure = (error: string): void => {
      appendJsonLine(options.intentLogPath, {
        kind: "intent_failed",
        intentId,
        scheme: accepted.scheme,
        network: accepted.network,
        replayKeys: validated.replayKeys,
        payTo,
        amount: accepted.amount,
        resource: params.resourceUrl,
        error,
        timestamp: new Date().toISOString(),
      } satisfies IntentRecord);
    };

    // STEP (3): Verify & Settle
    let txHash: string;
    let settlementMode: SettlementMode;
    let settledPayer = validated.payerIdentity;
    let facilitatorLabel = "lightning:htlc-preimage";

    if (accepted.scheme === "lightning") {
      if (
        !validated.cleanPreimage ||
        !validated.cleanPaymentHash ||
        !verifyLightningPreimage(
          validated.cleanPreimage,
          validated.cleanPaymentHash
        )
      ) {
        recordIntentFailure("SHA256(preimage) !== paymentHash");
        return failChallenge(
          "invalid_preimage",
          "Lightning preimage verification failed: SHA256(preimage) !== paymentHash",
          params.resourceUrl,
          params.description,
          "Invalid Lightning preimage"
        );
      }
      txHash = `ln:${validated.cleanPaymentHash}`;
      settlementMode = "lightning_preimage";
    } else {
      const evmRes = await settleEvmWithFacilitator(
        submitted,
        validated.serverRequirements,
        validated.payerIdentity,
        recordIntentFailure,
        params.resourceUrl,
        params.description
      );
      if (!evmRes.ok) return evmRes.failure;
      txHash = evmRes.txHash;
      settledPayer = evmRes.payer;
      facilitatorLabel = facilitatorUrl;
      settlementMode =
        facilitatorUrl.includes("127.0.0.1") ||
        facilitatorUrl.includes("localhost")
          ? "local_facilitator"
          : "live_testnet";
    }

    // STEP (4): Emit DSSE-signed SettlementReceipt + PAYMENT-RESPONSE header
    const settledAt = new Date().toISOString();
    const evaluatedMicroUsd = evaluateRequirementMicroUsd(
      validated.serverRequirements,
      btcMicroUsdPerSat
    ).toString();

    const receiptBase: Omit<SettlementReceipt, "dsse"> = {
      id: intentId,
      amountMicroUsd:
        accepted.scheme === "exact" ? priceMicroUsd : evaluatedMicroUsd,
      ...(accepted.scheme === "lightning" ? { amountMsat: priceMsat } : {}),
      network: accepted.network,
      scheme: accepted.scheme,
      asset: accepted.asset,
      txHash,
      payer: settledPayer,
      payTo,
      resource: params.resourceUrl,
      toolName: params.toolName,
      settledAt,
      facilitator: facilitatorLabel,
      mode: settlementMode,
      ...(validated.evmNonce ? { nonce: validated.evmNonce } : {}),
      ...(validated.cleanPaymentHash
        ? { paymentHash: validated.cleanPaymentHash }
        : {}),
    };

    const dsse = signDsse(
      "application/vnd.x402.settlement+json",
      receiptBase,
      keystorePath
    );
    const receipt: SettlementReceipt = { ...receiptBase, dsse };

    appendJsonLine(options.intentLogPath, {
      kind: "intent_settled",
      intentId,
      scheme: accepted.scheme,
      network: accepted.network,
      replayKeys: validated.replayKeys,
      payTo,
      amount: accepted.amount,
      resource: params.resourceUrl,
      txHash,
      timestamp: settledAt,
    } satisfies IntentRecord);

    appendJsonLine(options.ledgerPath, receipt);

    const settleResponse: X402SettlementResponse = {
      success: true,
      transaction: txHash,
      network: accepted.network,
      payer: settledPayer,
      requirements: validated.serverRequirements,
      mode: settlementMode,
    };

    return { ok: true, receipt, dsse, settleResponse };
  };

  const formatPaymentResponseHeaders = (
    gate: PaymentGateSuccess
  ): Record<string, string> => ({
    "PAYMENT-RESPONSE": encodePaymentResponseHeader({
      success: gate.settleResponse.success,
      transaction: gate.settleResponse.transaction,
      network: gate.settleResponse.network as `${string}:${string}`,
      payer: gate.settleResponse.payer,
      extra: {
        settlementId: gate.receipt.id,
        mode: gate.receipt.mode,
        receipt: gate.receipt,
        dsse: gate.dsse,
      },
    }),
    "X-Verified-Payer": gate.receipt.payer,
    "X-Settlement-Tx": gate.receipt.txHash,
  });

  const formatMcpGateFailure = (gate: PaymentGateFailure): McpToolResult => ({
    isError: true,
    data: gate.paymentRequired
      ? { ...gate.paymentRequired, code: gate.code, error: gate.error }
      : { code: gate.code, error: gate.error },
    ...(gate.paymentRequired
      ? { meta: { "x402/payment-required": gate.paymentRequired } }
      : {}),
  });

  const formatMcpGateSuccess = (
    gate: PaymentGateSuccess,
    payload: Record<string, unknown>
  ): McpToolResult => ({
    data: {
      ...payload,
      settlement: gate.receipt,
      dsse: gate.dsse,
    },
    meta: {
      "x402/payment-response": {
        ...gate.settleResponse,
        extra: {
          settlementId: gate.receipt.id,
          dsse: gate.dsse,
        },
      },
    },
    httpHeaders: formatPaymentResponseHeaders(gate),
  });

  const sendHttpGateFailure = (
    res: ServerResponse,
    gate: PaymentGateFailure
  ): void => {
    const extraHeaders: Record<string, string> = {};
    if (gate.paymentRequired) {
      extraHeaders["PAYMENT-REQUIRED"] = encodePaymentRequiredHeader(
        gate.paymentRequired as unknown as Parameters<
          typeof encodePaymentRequiredHeader
        >[0]
      );
      extraHeaders["Cache-Control"] = "no-store";
    }
    sendJson(
      res,
      gate.httpStatus,
      gate.paymentRequired ?? { error: gate.error, code: gate.code },
      extraHeaders
    );
  };

  const tools: McpToolDefinition[] = [
    {
      name: "lightning_quote_invoice",
      description:
        "Free x402 v2 quote returning a fresh BOLT11 testnet invoice and Base Sepolia USDC requirements.",
      inputSchema: {
        type: "object",
        properties: {
          resource: { type: "string" },
          memo: { type: "string" },
        },
        additionalProperties: false,
      },
    },
    {
      name: "paid_lightning_echo",
      description:
        "Paid x402 v2 echo tool accepting Base Sepolia USDC or Lightning BOLT11 preimage.",
      inputSchema: {
        type: "object",
        properties: {
          message: { type: "string" },
        },
        additionalProperties: true,
      },
    },
    {
      name: "paid_satoshi_oracle",
      description:
        "Paid x402 v2 BTC/USD integer micro-USD oracle with Ed25519 DSSE witness.",
      inputSchema: {
        type: "object",
        properties: {
          includeWitness: { type: "boolean" },
        },
        additionalProperties: true,
      },
    },
  ];

  const handlers: Record<
    string,
    (args: Record<string, unknown>, ctx: McpToolContext) => Promise<McpToolResult>
  > = {
    lightning_quote_invoice: async (args) => {
      const resourceUrl =
        typeof args.resource === "string" && args.resource.trim()
          ? args.resource.trim()
          : `${actualBaseUrl}/api/v1/oracle`;
      const memo =
        typeof args.memo === "string" && args.memo.trim()
          ? args.memo.trim()
          : "Lightning-402 x402 v2 quote";
      const invoice = issueAndStoreInvoice(resourceUrl, memo);
      return {
        data: {
          x402Version: 2,
          payTo,
          priceMicroUsd,
          priceMsat,
          lightning: {
            bolt11: invoice.bolt11,
            paymentHash: invoice.paymentHash,
            amountMsat: invoice.amountMsat,
            expiresAt: invoice.expiresAtUnix,
            payeePubkey: invoice.payeePubkey,
            network: lightningNetwork,
          },
          accepts: [buildEvmRequirement(), buildLightningRequirement(invoice)],
        },
      };
    },

    paid_lightning_echo: async (args, ctx) => {
      const gate = await processPaymentSubmission({
        rawHeader: ctx.paymentSignatureHeader,
        metaPayment: ctx.meta["x402/payment"],
        resourceUrl: `${actualBaseUrl}/mcp#tools/paid_lightning_echo`,
        toolName: "paid_lightning_echo",
        description: "Paid Lightning-402 MCP echo tool",
      });
      if (!gate.ok) return formatMcpGateFailure(gate);
      return formatMcpGateSuccess(gate, {
        ok: true,
        tool: "paid_lightning_echo",
        echo: args.message ?? "",
      });
    },

    paid_satoshi_oracle: async (_args, ctx) => {
      const gate = await processPaymentSubmission({
        rawHeader: ctx.paymentSignatureHeader,
        metaPayment: ctx.meta["x402/payment"],
        resourceUrl: `${actualBaseUrl}/mcp#tools/paid_satoshi_oracle`,
        toolName: "paid_satoshi_oracle",
        description: "Paid Lightning-402 BTC/USD integer micro-USD oracle",
      });
      if (!gate.ok) return formatMcpGateFailure(gate);
      const quote = buildSatoshiOracleQuote(btcMicroUsdPerSat);
      const witness = signDsse(
        "application/vnd.x402.satoshi-oracle+json",
        quote,
        keystorePath
      );
      return formatMcpGateSuccess(gate, {
        ok: true,
        tool: "paid_satoshi_oracle",
        quote,
        witness,
      });
    },
  };

  const extractHttpSigHeader = (req: IncomingMessage): string =>
    String(
      req.headers["payment-signature"] ??
        req.headers["x-payment-signature"] ??
        req.headers["x-payment"] ??
        ""
    );

  const extraRoutes = async (
    req: IncomingMessage,
    res: ServerResponse,
    url: URL
  ): Promise<boolean> => {
    const method = (req.method ?? "GET").toUpperCase();
    const pathname = url.pathname;

    if (method === "GET" && pathname === "/api/v1/oracle") {
      const gate = await processPaymentSubmission({
        rawHeader: extractHttpSigHeader(req),
        resourceUrl: `${actualBaseUrl}/api/v1/oracle`,
        toolName: "http:GET:/api/v1/oracle",
        description: "Lightning-402 BTC/USD integer micro-USD oracle",
      });
      if (!gate.ok) {
        sendHttpGateFailure(res, gate);
        return true;
      }
      const quote = buildSatoshiOracleQuote(btcMicroUsdPerSat);
      const witness = signDsse(
        "application/vnd.x402.satoshi-oracle+json",
        quote,
        keystorePath
      );
      sendJson(
        res,
        200,
        {
          ok: true,
          endpoint: "/api/v1/oracle",
          quote,
          witness,
          settlement: gate.receipt,
          dsse: gate.dsse,
        },
        formatPaymentResponseHeaders(gate)
      );
      return true;
    }

    if (method === "POST" && pathname === "/api/v1/echo") {
      const body = await readJsonBody(req);
      const gate = await processPaymentSubmission({
        rawHeader: extractHttpSigHeader(req),
        resourceUrl: `${actualBaseUrl}/api/v1/echo`,
        toolName: "http:POST:/api/v1/echo",
        description: "Lightning-402 dual-rail echo endpoint",
      });
      if (!gate.ok) {
        sendHttpGateFailure(res, gate);
        return true;
      }
      sendJson(
        res,
        200,
        {
          ok: true,
          endpoint: "/api/v1/echo",
          echo: body,
          settlement: gate.receipt,
          dsse: gate.dsse,
        },
        formatPaymentResponseHeaders(gate)
      );
      return true;
    }

    return false;
  };

  const running = await startMcpHttpServer({
    port,
    host,
    name: "lightning-402",
    title: "Lightning-402 MCP Server",
    version: "0.1.0",
    description:
      "Dual-rail x402 v2 MCP server supporting Base Sepolia USDC and Lightning Network BOLT11 preimages.",
    tools,
    handlers,
    extraRoutes,
    serverCardExtras: () => ({
      payTo,
      keyid,
      x402: {
        x402Version: 2,
        schemes: ["exact", "lightning"],
        networks: [evmNetwork, lightningNetwork],
        priceMicroUsd,
        priceMsat,
        paidEndpoints: [
          `${actualBaseUrl}/api/v1/oracle`,
          `${actualBaseUrl}/api/v1/echo`,
        ],
      },
    }),
    wellKnownX402: () => {
      const sampleInvoice = issueAndStoreInvoice(
        `${actualBaseUrl}/api/v1/oracle`,
        "Lightning-402 discovery probe quote"
      );
      return {
        x402Version: 2,
        name: "lightning-402",
        title: "Lightning-402 MCP Server",
        description:
          "Dual-rail x402 v2 MCP server supporting Base Sepolia USDC and Lightning Network BOLT11 preimages.",
        mcpEndpoint: `${actualBaseUrl}/mcp`,
        paidEndpoint: `${actualBaseUrl}/api/v1/oracle`,
        endpoints: [
          {
            method: "GET",
            path: "/api/v1/oracle",
            url: `${actualBaseUrl}/api/v1/oracle`,
            priceMicroUsd,
            priceMsat,
          },
          {
            method: "POST",
            path: "/api/v1/echo",
            url: `${actualBaseUrl}/api/v1/echo`,
            priceMicroUsd,
            priceMsat,
          },
        ],
        payTo,
        keyid,
        schemes: ["exact", "lightning"],
        networks: [evmNetwork, lightningNetwork],
        accepts: [buildEvmRequirement(), buildLightningRequirement(sampleInvoice)],
        branding: BRANDING,
      };
    },
  });

  actualBaseUrl = running.baseUrl;

  return {
    ...running,
    payTo,
    keystorePath,
    facilitatorUrl,
    priceMicroUsd,
    priceMsat,
    getIssuedInvoices: () => Array.from(issuedInvoices.values()),
    getIntentCount: () => intentCount,
  };
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const port = Number(process.env.PORT ?? "4021");
  startLightning402Server({ port })
    .then((srv) => {
      console.log(
        `Lightning-402 MCP server listening on ${srv.baseUrl} (MCP: ${srv.mcpUrl})`
      );
    })
    .catch((err) => {
      console.error("Failed to start Lightning-402 MCP server:", err);
      process.exit(1);
    });
}
