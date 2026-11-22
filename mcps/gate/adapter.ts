import crypto from "node:crypto";
import fs from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import path from "node:path";
import {
  BASE_MAINNET_NETWORK,
  BASE_MAINNET_USDC,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  BRANDING,
  DEFAULT_KEYSTORE_PATH,
  TESTNET_FACILITATOR_URL,
  isRetiredPayTo,
  resolvePayTo,
} from "../../shared/constants.js";
import { getKeyId, signDsse } from "../../shared/keystore.js";
import {
  type ExtraHttpRouteHandler,
  type McpToolContext,
  type McpToolDefinition,
  type McpToolHandler,
  type McpToolResult,
  readJsonBody,
  sendJson,
} from "../../shared/mcp-http.js";
import type {
  DsseEnvelope,
  SettlementMode,
  SettlementReceipt,
  X402PaymentRequiredEnvelope,
  X402PaymentRequirement,
  X402PaymentSignature,
  X402SettlementResponse,
} from "../../shared/types.js";
import {
  FacilitatorClient,
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
} from "../../shared/x402-adapter.js";

const INTEGER_STRING_REGEX = /^\d+$/;
const EVM_ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/;

export type MicroUsdInput = bigint | string;

export type RawToolHandler = (
  args: Record<string, unknown>,
  ctx: McpToolContext
) => Promise<unknown> | unknown;

export interface PaidToolConfig {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  amountMicroUsd: MicroUsdInput;
  payTo?: string;
  network?: string;
  asset?: string;
  scheme?: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
  facilitatorUrl?: string;
  facilitatorClient?: FacilitatorClient;
  intentLogPath?: string;
  ledgerPath?: string;
  keystorePath?: string;
  resourceUrl?: string;
}

export interface FreeToolConfig {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
}

export type FlexibleMcpToolHandler = (
  args: Record<string, unknown>,
  ctx?: Partial<McpToolContext>
) => Promise<McpToolResult>;

export interface FreeTool extends FlexibleMcpToolHandler {
  readonly isPaid: false;
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly definition: McpToolDefinition;
  readonly handler: McpToolHandler;
}

export interface FreeToolInput {
  isPaid?: false;
  name?: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  definition?: McpToolDefinition;
  handler: RawToolHandler;
}

export interface PaidToolContextOverrides {
  payTo?: string;
  network?: string;
  asset?: string;
  scheme?: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
  facilitatorUrl?: string;
  facilitatorClient?: FacilitatorClient;
  intentLogPath?: string;
  ledgerPath?: string;
  keystorePath?: string;
  getBaseUrl?: () => string;
  replayGuard?: ReplayGuard;
}

export interface BoundPaidToolRuntime {
  definition: McpToolDefinition;
  amountMicroUsd: bigint;
  payTo: string;
  network: string;
  asset: string;
  scheme: string;
  maxTimeoutSeconds: number;
  extra: Record<string, unknown>;
  facilitatorUrl: string;
  keystorePath: string;
  buildRequirement: () => X402PaymentRequirement;
  handleMcp: McpToolHandler;
  handleHttp: (
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    args: Record<string, unknown>
  ) => Promise<void>;
}

export interface PaidTool extends FlexibleMcpToolHandler {
  readonly isPaid: true;
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly amountMicroUsd: bigint;
  readonly definition: McpToolDefinition;
  readonly handler: McpToolHandler;
  readonly config: PaidToolConfig;
  readonly rawHandler: RawToolHandler;
  readonly bindRuntime: (overrides?: PaidToolContextOverrides) => BoundPaidToolRuntime;
}

export type GatewayTool = PaidTool | FreeTool | FreeToolInput;

export interface PaidMcpGatewayOptions {
  name?: string;
  title?: string;
  version?: string;
  description?: string;
  baseUrl?: string;
  payTo?: string;
  facilitatorUrl?: string;
  facilitatorClient?: FacilitatorClient;
  network?: string;
  asset?: string;
  scheme?: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
  intentLogPath?: string;
  ledgerPath?: string;
  keystorePath?: string;
  tools?: GatewayTool[];
  freeTools?: FreeToolInput[];
  paidTools?: PaidTool[];
}

export interface PaidToolMetaEntry {
  name: string;
  description: string;
  amountMicroUsd: string;
  amountUsd: string;
  scheme: string;
  network: string;
  asset: string;
  payTo: string;
  httpPath: string;
  httpUrl: string;
  requirement: X402PaymentRequirement;
}

export interface PaidMcpGateway {
  tools: McpToolDefinition[];
  handlers: Record<string, McpToolHandler>;
  extraRoutes: ExtraHttpRouteHandler;
  wellKnownX402: () => Record<string, unknown>;
  serverCardExtras: () => Record<string, unknown>;
  setBaseUrl: (baseUrl: string) => void;
  getPricingManifest: () => PaidToolMetaEntry[];
  getIntentCount: () => number;
  payTo: string;
  facilitatorUrl: string;
  keystorePath: string;
}

interface IntentRecord {
  kind: "intent_committed" | "intent_settled" | "intent_failed";
  intentId: string;
  scheme: string;
  network: string;
  replayKey: string;
  payTo: string;
  amount: string;
  resource: string;
  txHash?: string;
  error?: string;
  timestamp: string;
}

export class ReplayGuard {
  private readonly consumedKeys = new Set<string>();
  private readonly intentLogPath?: string;
  private intentCount = 0;

  constructor(intentLogPath?: string) {
    this.intentLogPath = intentLogPath;
    this.hydrateFromLog();
  }

  private hydrateFromLog(): void {
    if (!this.intentLogPath || !fs.existsSync(this.intentLogPath)) return;
    const raw = fs.readFileSync(this.intentLogPath, "utf8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed) as Partial<IntentRecord>;
        if (parsed.kind === "intent_committed" && typeof parsed.replayKey === "string") {
          this.consumedKeys.add(parsed.replayKey);
          this.intentCount += 1;
        }
      } catch {
        // Ignore truncated trailing lines from crash recovery
      }
    }
  }

  public has(replayKey: string): boolean {
    return this.consumedKeys.has(replayKey);
  }

  public commit(record: Omit<IntentRecord, "kind" | "timestamp">): void {
    this.consumedKeys.add(record.replayKey);
    this.intentCount += 1;
    appendJsonLine(this.intentLogPath, {
      ...record,
      kind: "intent_committed",
      timestamp: new Date().toISOString(),
    } satisfies IntentRecord);
  }

  public markSettled(record: Omit<IntentRecord, "kind" | "timestamp">): void {
    appendJsonLine(this.intentLogPath, {
      ...record,
      kind: "intent_settled",
      timestamp: new Date().toISOString(),
    } satisfies IntentRecord);
  }

  public markFailed(record: Omit<IntentRecord, "kind" | "timestamp">): void {
    appendJsonLine(this.intentLogPath, {
      ...record,
      kind: "intent_failed",
      timestamp: new Date().toISOString(),
    } satisfies IntentRecord);
  }

  public getIntentCount(): number {
    return this.intentCount;
  }
}

export function parseMicroUsdAmount(
  value: MicroUsdInput,
  label = "amountMicroUsd"
): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error(`${label} must be a non-negative integer bigint`);
    }
    return value;
  }
  if (typeof value === "string") {
    if (!INTEGER_STRING_REGEX.test(value)) {
      throw new Error(
        `${label} must match /^\\d+$/ integer string (floats are forbidden), got: ${value}`
      );
    }
    return BigInt(value);
  }
  throw new Error(
    `${label} must be an integer bigint or /^\\d+$/ string (numbers/floats are forbidden)`
  );
}

export function formatMicroUsd(microUsd: bigint): string {
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

function defaultAssetForNetwork(network: string): string {
  if (network === BASE_MAINNET_NETWORK) return BASE_MAINNET_USDC;
  return BASE_SEPOLIA_USDC;
}

function defaultExtraForAsset(
  network: string,
  asset: string
): Record<string, unknown> {
  if (
    network === BASE_SEPOLIA_NETWORK ||
    network === BASE_MAINNET_NETWORK ||
    asset.toLowerCase() === BASE_SEPOLIA_USDC.toLowerCase() ||
    asset.toLowerCase() === BASE_MAINNET_USDC.toLowerCase()
  ) {
    return {
      name: "USDC",
      version: "2",
      assetTransferMethod: "eip3009",
    };
  }
  return {};
}

function parseNonNegativeIntegerString(raw: unknown): bigint | null {
  if (typeof raw === "bigint") return raw >= 0n ? raw : null;
  if (typeof raw !== "string") return null;
  if (!INTEGER_STRING_REGEX.test(raw)) return null;
  return BigInt(raw);
}

function extractPaymentSignatureHeader(
  headers?: IncomingMessage["headers"]
): string {
  if (!headers) return "";
  const raw =
    headers["payment-signature"] ??
    headers["x-payment-signature"] ??
    headers["x-payment"] ??
    headers["x402-authorization"] ??
    "";
  return Array.isArray(raw) ? raw[0] ?? "" : String(raw);
}

function parseSubmittedPayment(
  rawHeader?: string,
  metaPayment?: unknown
): X402PaymentSignature | null {
  if (metaPayment !== undefined && metaPayment !== null) {
    if (typeof metaPayment === "string" && metaPayment.trim()) {
      const trimmed = metaPayment.trim();
      try {
        return decodePaymentSignatureHeader(
          trimmed
        ) as unknown as X402PaymentSignature;
      } catch {
        return JSON.parse(trimmed) as X402PaymentSignature;
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

function normalizeMcpContext(ctx?: Partial<McpToolContext>): McpToolContext {
  const req = ctx?.req ?? ({ headers: {} } as IncomingMessage);
  const headers = ctx?.headers ?? req.headers ?? {};
  const meta =
    ctx?.meta && typeof ctx.meta === "object" && !Array.isArray(ctx.meta)
      ? ctx.meta
      : {};
  const paymentSignatureHeader =
    ctx?.paymentSignatureHeader ?? extractPaymentSignatureHeader(headers);

  return {
    req,
    headers,
    meta,
    paymentSignatureHeader,
  };
}

function resolveOriginFromContext(
  ctx: McpToolContext,
  fallbackBaseUrl: () => string
): string {
  const hostHeader = ctx.headers?.host ?? ctx.req?.headers?.host;
  if (typeof hostHeader === "string" && hostHeader.trim()) {
    return `http://${hostHeader.trim()}`;
  }
  return fallbackBaseUrl().replace(/\/+$/, "");
}

type PaymentGateFailure = {
  ok: false;
  httpStatus: 402 | 403 | 409;
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

type PaymentGateOutcome = PaymentGateFailure | PaymentGateSuccess;

interface ValidatedEvmSubmission {
  replayKey: string;
  payerIdentity: string;
  nonce: string;
}

function buildToolResultFromOutcome(
  toolName: string,
  gate: PaymentGateSuccess,
  result: unknown,
  toolError?: string
): McpToolResult {
  const encodedResponse = encodePaymentResponseHeader({
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
  });

  const httpHeaders: Record<string, string> = {
    "PAYMENT-RESPONSE": encodedResponse,
    "X-Verified-Payer": gate.receipt.payer,
    "X-Settlement-Tx": gate.receipt.txHash,
  };

  const settleWithExtra = {
    ...gate.settleResponse,
    extra: {
      settlementId: gate.receipt.id,
      dsse: gate.dsse,
    },
  };

  if (toolError) {
    return {
      isError: true,
      data: {
        ok: false,
        tool: toolName,
        code: "tool_execution_error",
        error: toolError,
        settlement: gate.receipt,
        dsse: gate.dsse,
      },
      meta: {
        "x402/payment-response": settleWithExtra,
        "x402/dsse": gate.dsse,
      },
      httpHeaders,
    };
  }

  return {
    data: {
      ok: true,
      tool: toolName,
      result,
      settlement: gate.receipt,
      dsse: gate.dsse,
    },
    meta: {
      "x402/payment-response": settleWithExtra,
      "x402/dsse": gate.dsse,
    },
    httpHeaders,
  };
}

function formatMcpFailure(gate: PaymentGateFailure): McpToolResult {
  if (gate.paymentRequired) {
    return {
      isError: true,
      data: {
        ...gate.paymentRequired,
        code: gate.code,
        error: gate.error,
      },
      meta: {
        "x402/payment-required": gate.paymentRequired,
      },
    };
  }
  return {
    isError: true,
    data: {
      code: gate.code,
      error: gate.error,
    },
  };
}

function sendHttpGateFailure(
  res: ServerResponse,
  gate: PaymentGateFailure
): void {
  const extraHeaders: Record<string, string> = {};
  if (gate.paymentRequired) {
    extraHeaders["PAYMENT-REQUIRED"] = encodePaymentRequiredHeader(
      gate.paymentRequired as unknown as Parameters<
        typeof encodePaymentRequiredHeader
      >[0]
    );
    extraHeaders["Cache-Control"] = "no-store";
  }
  const body = gate.paymentRequired
    ? { ...gate.paymentRequired, code: gate.code, error: gate.error }
    : { code: gate.code, error: gate.error };
  sendJson(res, gate.httpStatus, body, extraHeaders);
}

function attachToolMetadata<
  TFn extends FlexibleMcpToolHandler,
  TProps extends Record<string, unknown>,
>(fn: TFn, name: string, props: TProps): TFn & TProps & { readonly name: string } {
  Object.defineProperty(fn, "name", { value: name, configurable: true });
  return Object.assign(fn, props) as unknown as TFn &
    TProps & { readonly name: string };
}

export function freeTool(
  config: FreeToolConfig,
  handler: RawToolHandler
): FreeTool {
  const inputSchema = config.inputSchema ?? {
    type: "object",
    additionalProperties: true,
  };
  const definition: McpToolDefinition = {
    name: config.name,
    description: config.description,
    inputSchema,
  };
  const mcpHandler: FlexibleMcpToolHandler = async (args, ctx) => {
    const result = await handler(args, normalizeMcpContext(ctx));
    if (
      result &&
      typeof result === "object" &&
      !Array.isArray(result) &&
      "data" in result &&
      (Object.keys(result).every((k) =>
        ["data", "isError", "meta", "httpStatus", "httpHeaders"].includes(k)
      ))
    ) {
      return result as McpToolResult;
    }
    return { data: result };
  };

  return attachToolMetadata(mcpHandler, config.name, {
    isPaid: false as const,
    description: config.description,
    inputSchema,
    definition,
    handler: mcpHandler as McpToolHandler,
  });
}

export function paidTool(
  config: PaidToolConfig,
  handler: RawToolHandler
): PaidTool {
  if (!config.name || !config.name.trim()) {
    throw new Error("paidTool config.name is required");
  }
  const amountMicroUsd = parseMicroUsdAmount(config.amountMicroUsd);
  // Validate explicit payTo immediately if provided.
  if (config.payTo !== undefined) {
    resolvePayTo(config.payTo);
  }

  const inputSchema = config.inputSchema ?? {
    type: "object",
    additionalProperties: true,
  };
  const definition: McpToolDefinition = {
    name: config.name,
    description: config.description,
    inputSchema,
  };

  const bindRuntime = (
    overrides: PaidToolContextOverrides = {}
  ): BoundPaidToolRuntime => {
    const payTo = resolvePayTo(config.payTo ?? overrides.payTo);
    const network = config.network ?? overrides.network ?? BASE_SEPOLIA_NETWORK;
    const asset =
      config.asset ?? overrides.asset ?? defaultAssetForNetwork(network);
    const scheme = config.scheme ?? overrides.scheme ?? "exact";
    const maxTimeoutSeconds =
      config.maxTimeoutSeconds ?? overrides.maxTimeoutSeconds ?? 300;
    const extra = {
      ...defaultExtraForAsset(network, asset),
      ...(overrides.extra ?? {}),
      ...(config.extra ?? {}),
    };
    const facilitatorUrl = (
      config.facilitatorUrl ??
      overrides.facilitatorUrl ??
      TESTNET_FACILITATOR_URL
    ).replace(/\/+$/, "");
    const facilitator =
      config.facilitatorClient ??
      overrides.facilitatorClient ??
      new FacilitatorClient(facilitatorUrl);
    const intentLogPath = config.intentLogPath ?? overrides.intentLogPath;
    const ledgerPath = config.ledgerPath ?? overrides.ledgerPath;
    const keystorePath =
      config.keystorePath ?? overrides.keystorePath ?? DEFAULT_KEYSTORE_PATH;
    const replayGuard = overrides.replayGuard ?? new ReplayGuard(intentLogPath);
    const getBaseUrl = overrides.getBaseUrl ?? (() => "http://127.0.0.1");

    // Ensure 0600 keystore exists on bind.
    getKeyId(keystorePath);

    const buildRequirement = (): X402PaymentRequirement => ({
      scheme,
      network,
      asset,
      amount: amountMicroUsd.toString(),
      payTo,
      maxTimeoutSeconds,
      extra,
    });

    const buildPaymentRequired = (
      resourceUrl: string,
      errorMessage = "Payment required"
    ): X402PaymentRequiredEnvelope => ({
      x402Version: 2,
      error: errorMessage,
      resource: {
        url: resourceUrl,
        description: config.description,
        mimeType: "application/json",
      },
      accepts: [buildRequirement()],
    });

    const failChallenge = (
      code: string,
      error: string,
      resourceUrl: string,
      challengeError = error
    ): PaymentGateFailure => ({
      ok: false,
      httpStatus: 402,
      code,
      error,
      paymentRequired: buildPaymentRequired(resourceUrl, challengeError),
    });

    const validateStep1 = (
      submitted: X402PaymentSignature,
      resourceUrl: string
    ): ValidatedEvmSubmission | PaymentGateFailure => {
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
          resourceUrl,
          "Invalid payment payload structure"
        );
      }

      const accepted = submitted.accepted;
      const payload = submitted.payload;
      const innerAuth =
        payload.authorization && typeof payload.authorization === "object"
          ? (payload.authorization as Record<string, unknown>)
          : undefined;
      const innerPermit2 =
        payload.permit2Authorization &&
        typeof payload.permit2Authorization === "object"
          ? (payload.permit2Authorization as Record<string, unknown>)
          : undefined;
      const innerPermit2Witness =
        innerPermit2?.witness && typeof innerPermit2.witness === "object"
          ? (innerPermit2.witness as Record<string, unknown>)
          : undefined;

      // Unconditional retired payee rejection (HTTP 403) BEFORE any other checks.
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

      if (accepted.scheme !== scheme) {
        return failChallenge(
          "unsupported_scheme",
          `Unsupported payment scheme: ${accepted.scheme} (expected ${scheme})`,
          resourceUrl
        );
      }

      if (
        accepted.network !== network ||
        accepted.asset.trim().toLowerCase() !== asset.toLowerCase()
      ) {
        return failChallenge(
          "invalid_evm_requirements",
          `Unsupported network/asset: ${accepted.network}/${accepted.asset}`,
          resourceUrl
        );
      }

      if (accepted.payTo.trim().toLowerCase() !== payTo.toLowerCase()) {
        return failChallenge(
          "payee_mismatch",
          `Accepted payTo ${accepted.payTo} does not match server payee ${payTo}`,
          resourceUrl,
          "Payee address mismatch"
        );
      }

      const acceptedAmount = parseNonNegativeIntegerString(accepted.amount);
      if (acceptedAmount === null || acceptedAmount < amountMicroUsd) {
        return failChallenge(
          "insufficient_amount",
          `Accepted amount ${accepted.amount} invalid or below required ${amountMicroUsd.toString()}`,
          resourceUrl
        );
      }

      const nowBig = BigInt(Math.floor(Date.now() / 1000));
      const signature =
        typeof payload.signature === "string" ? payload.signature.trim() : "";

      if (innerAuth) {
        const from = String(innerAuth.from ?? "").trim();
        const to = String(innerAuth.to ?? "").trim();
        const valueBig = parseNonNegativeIntegerString(innerAuth.value);
        const validAfterBig = parseNonNegativeIntegerString(
          innerAuth.validAfter ?? "0"
        );
        const validBeforeBig = parseNonNegativeIntegerString(
          innerAuth.validBefore
        );
        const nonceRaw = String(innerAuth.nonce ?? "").trim();

        if (
          !EVM_ADDRESS_REGEX.test(from) ||
          !EVM_ADDRESS_REGEX.test(to) ||
          !nonceRaw ||
          !signature ||
          valueBig === null ||
          validAfterBig === null ||
          validBeforeBig === null
        ) {
          return failChallenge(
            "invalid_eip3009_authorization",
            "Missing or malformed EIP-3009 authorization fields",
            resourceUrl
          );
        }

        if (to.toLowerCase() !== payTo.toLowerCase()) {
          return failChallenge(
            "authorization_payee_mismatch",
            `Authorization recipient ${to} does not match ${payTo}`,
            resourceUrl
          );
        }

        if (nowBig < validAfterBig) {
          return failChallenge(
            "authorization_not_yet_valid",
            `EIP-3009 authorization not valid until ${validAfterBig.toString()}`,
            resourceUrl,
            "Authorization not yet valid"
          );
        }

        if (nowBig >= validBeforeBig) {
          return failChallenge(
            "authorization_expired",
            `EIP-3009 authorization expired at ${validBeforeBig.toString()}`,
            resourceUrl,
            "Authorization expired"
          );
        }

        if (valueBig < amountMicroUsd) {
          return failChallenge(
            "insufficient_authorization_value",
            `EIP-3009 value ${valueBig.toString()} below ${amountMicroUsd.toString()}`,
            resourceUrl
          );
        }

        const nonce = nonceRaw.toLowerCase();
        return {
          replayKey: `evm:${network.toLowerCase()}:${from.toLowerCase()}:${nonce}`,
          payerIdentity: from,
          nonce,
        };
      }

      if (innerPermit2) {
        const from = String(innerPermit2.from ?? "").trim();
        const deadlineBig = parseNonNegativeIntegerString(innerPermit2.deadline);
        const nonceRaw = String(innerPermit2.nonce ?? "").trim();
        const permitted =
          innerPermit2.permitted && typeof innerPermit2.permitted === "object"
            ? (innerPermit2.permitted as Record<string, unknown>)
            : undefined;
        const amountBig = parseNonNegativeIntegerString(permitted?.amount);

        if (
          !EVM_ADDRESS_REGEX.test(from) ||
          !nonceRaw ||
          !signature ||
          deadlineBig === null ||
          amountBig === null
        ) {
          return failChallenge(
            "invalid_permit2_authorization",
            "Permit2 authorization missing required fields",
            resourceUrl
          );
        }

        if (nowBig >= deadlineBig) {
          return failChallenge(
            "authorization_expired",
            `Permit2 authorization expired at ${deadlineBig.toString()}`,
            resourceUrl,
            "Authorization expired"
          );
        }

        if (
          typeof innerPermit2Witness?.to === "string" &&
          innerPermit2Witness.to.trim().toLowerCase() !== payTo.toLowerCase()
        ) {
          return failChallenge(
            "permit2_payee_mismatch",
            `Permit2 recipient ${innerPermit2Witness.to} does not match ${payTo}`,
            resourceUrl
          );
        }

        if (amountBig < amountMicroUsd) {
          return failChallenge(
            "insufficient_permit2_amount",
            `Permit2 amount ${amountBig.toString()} below ${amountMicroUsd.toString()}`,
            resourceUrl
          );
        }

        const nonce = nonceRaw.toLowerCase();
        return {
          replayKey: `evm:${network.toLowerCase()}:${from.toLowerCase()}:${nonce}`,
          payerIdentity: from,
          nonce,
        };
      }

      return failChallenge(
        "unsupported_evm_payload",
        "Payment payload missing EIP-3009 authorization or permit2Authorization",
        resourceUrl
      );
    };

    /**
     * Strict 4-step order of operations:
     * (1) validate payload + expiry + reject retired payee (HTTP 403)
     * (2) commit intent & reject duplicate (network, from, nonce) replay (HTTP 409)
     * (3) verify + settle via FacilitatorClient
     * (4) emit persisted 0600 Ed25519 DSSE-signed SettlementReceipt + PAYMENT-RESPONSE
     */
    const processPayment = async (params: {
      rawHeader?: string;
      metaPayment?: unknown;
      resourceUrl: string;
    }): Promise<PaymentGateOutcome> => {
      let submitted: X402PaymentSignature | null;
      try {
        submitted = parseSubmittedPayment(params.rawHeader, params.metaPayment);
      } catch (err) {
        return failChallenge(
          "malformed_payment_signature",
          `Malformed payment signature: ${err instanceof Error ? err.message : String(err)}`,
          params.resourceUrl,
          "Malformed payment signature"
        );
      }

      if (!submitted) {
        return failChallenge(
          "payment_required",
          "Payment required",
          params.resourceUrl,
          "Payment required"
        );
      }

      // STEP (1): Validate payload + expiry + reject retired payee (HTTP 403)
      const step1 = validateStep1(submitted, params.resourceUrl);
      if ("ok" in step1) return step1;

      // STEP (2): Commit intent & reject duplicate (network, from, nonce) replay (HTTP 409)
      if (replayGuard.has(step1.replayKey)) {
        return {
          ok: false,
          httpStatus: 409,
          code: "replay_rejected",
          error: `Replay detected for consumed authorization (${step1.replayKey})`,
        };
      }

      const intentId = `intent_${crypto.randomUUID()}`;
      const serverRequirements = buildRequirement();
      replayGuard.commit({
        intentId,
        scheme,
        network,
        replayKey: step1.replayKey,
        payTo,
        amount: serverRequirements.amount,
        resource: params.resourceUrl,
      });

      // STEP (3): Verify + settle via FacilitatorClient(facilitatorUrl)
      let verifyResult: { isValid: boolean; invalidReason?: string; payer?: string };
      try {
        verifyResult = await facilitator.verify(submitted, serverRequirements);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        replayGuard.markFailed({
          intentId,
          scheme,
          network,
          replayKey: step1.replayKey,
          payTo,
          amount: serverRequirements.amount,
          resource: params.resourceUrl,
          error: `Facilitator verify error: ${msg}`,
        });
        return failChallenge(
          "facilitator_verify_error",
          `Facilitator verify failed: ${msg}`,
          params.resourceUrl
        );
      }

      if (!verifyResult.isValid) {
        const reason = verifyResult.invalidReason ?? "invalid_payment";
        replayGuard.markFailed({
          intentId,
          scheme,
          network,
          replayKey: step1.replayKey,
          payTo,
          amount: serverRequirements.amount,
          resource: params.resourceUrl,
          error: reason,
        });
        return failChallenge(
          "facilitator_verify_rejected",
          reason,
          params.resourceUrl
        );
      }

      let settleResult;
      try {
        settleResult = await facilitator.settle(submitted, serverRequirements);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        replayGuard.markFailed({
          intentId,
          scheme,
          network,
          replayKey: step1.replayKey,
          payTo,
          amount: serverRequirements.amount,
          resource: params.resourceUrl,
          error: `Facilitator settle error: ${msg}`,
        });
        return failChallenge(
          "facilitator_settle_error",
          `Facilitator settle failed: ${msg}`,
          params.resourceUrl
        );
      }

      if (!settleResult.success || !settleResult.transaction) {
        const reason = settleResult.errorReason ?? "settle_failed";
        replayGuard.markFailed({
          intentId,
          scheme,
          network,
          replayKey: step1.replayKey,
          payTo,
          amount: serverRequirements.amount,
          resource: params.resourceUrl,
          error: reason,
        });
        return failChallenge(
          "facilitator_settle_rejected",
          reason,
          params.resourceUrl
        );
      }

      // STEP (4): Emit persisted 0600 Ed25519 DSSE-signed SettlementReceipt + PAYMENT-RESPONSE
      const settledAt = new Date().toISOString();
      const txHash = settleResult.transaction;
      const settledPayer =
        settleResult.payer ?? verifyResult.payer ?? step1.payerIdentity;
      const mode: SettlementMode =
        facilitatorUrl.includes("127.0.0.1") ||
        facilitatorUrl.includes("localhost")
          ? "local_facilitator"
          : "live_testnet";

      const receiptBase: Omit<SettlementReceipt, "dsse"> = {
        id: intentId,
        amountMicroUsd: amountMicroUsd.toString(),
        network,
        scheme,
        asset,
        txHash,
        payer: settledPayer,
        payTo,
        resource: params.resourceUrl,
        toolName: config.name,
        settledAt,
        facilitator: facilitatorUrl,
        mode,
        nonce: step1.nonce,
      };

      const dsse = signDsse(
        "application/vnd.x402.settlement+json",
        receiptBase,
        keystorePath
      );
      const receipt: SettlementReceipt = { ...receiptBase, dsse };

      replayGuard.markSettled({
        intentId,
        scheme,
        network,
        replayKey: step1.replayKey,
        payTo,
        amount: serverRequirements.amount,
        resource: params.resourceUrl,
        txHash,
      });
      appendJsonLine(ledgerPath, receipt);

      const settleResponse: X402SettlementResponse = {
        success: true,
        transaction: txHash,
        network,
        payer: settledPayer,
        requirements: serverRequirements,
        mode,
      };

      return { ok: true, receipt, dsse, settleResponse };
    };

    const handleMcp: McpToolHandler = async (args, rawCtx) => {
      const ctx = normalizeMcpContext(rawCtx);
      const origin = resolveOriginFromContext(ctx, getBaseUrl);
      const resourceUrl =
        config.resourceUrl ?? `${origin}/mcp#tools/${config.name}`;

      const gate = await processPayment({
        rawHeader: ctx.paymentSignatureHeader,
        metaPayment: ctx.meta["x402/payment"],
        resourceUrl,
      });

      if (!gate.ok) {
        return formatMcpFailure(gate);
      }

      try {
        const result = await handler(args, ctx);
        return buildToolResultFromOutcome(config.name, gate, result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return buildToolResultFromOutcome(config.name, gate, undefined, msg);
      }
    };

    const handleHttp = async (
      req: IncomingMessage,
      res: ServerResponse,
      url: URL,
      args: Record<string, unknown>
    ): Promise<void> => {
      const origin =
        url.origin || resolveOriginFromContext(normalizeMcpContext({ req }), getBaseUrl);
      const resourceUrl = `${origin}/api/tools/${encodeURIComponent(config.name)}`;
      const rawHeader = extractPaymentSignatureHeader(req.headers);

      const gate = await processPayment({
        rawHeader,
        resourceUrl,
      });

      if (!gate.ok) {
        sendHttpGateFailure(res, gate);
        return;
      }

      const ctx = normalizeMcpContext({
        req,
        headers: req.headers,
        meta: {},
        paymentSignatureHeader: rawHeader,
      });

      try {
        const result = await handler(args, ctx);
        const outcome = buildToolResultFromOutcome(config.name, gate, result);
        sendJson(res, 200, outcome.data, outcome.httpHeaders ?? {});
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const outcome = buildToolResultFromOutcome(
          config.name,
          gate,
          undefined,
          msg
        );
        sendJson(res, 500, outcome.data, outcome.httpHeaders ?? {});
      }
    };

    return {
      definition,
      amountMicroUsd,
      payTo,
      network,
      asset,
      scheme,
      maxTimeoutSeconds,
      extra,
      facilitatorUrl,
      keystorePath,
      buildRequirement,
      handleMcp,
      handleHttp,
    };
  };

  let standaloneRuntime: BoundPaidToolRuntime | null = null;
  const getStandaloneRuntime = (): BoundPaidToolRuntime => {
    if (!standaloneRuntime) {
      standaloneRuntime = bindRuntime();
    }
    return standaloneRuntime;
  };

  const standaloneHandler: FlexibleMcpToolHandler = async (args, ctx) => {
    return getStandaloneRuntime().handleMcp(args, normalizeMcpContext(ctx));
  };

  return attachToolMetadata(standaloneHandler, config.name, {
    isPaid: true as const,
    description: config.description,
    inputSchema,
    amountMicroUsd,
    definition,
    handler: standaloneHandler as McpToolHandler,
    config,
    rawHandler: handler,
    bindRuntime,
  });
}

function isPaidTool(tool: GatewayTool): tool is PaidTool {
  return tool.isPaid === true;
}

function isFreeToolObject(input: FreeTool | FreeToolInput): input is FreeTool {
  return (
    typeof input === "function" &&
    "isPaid" in input &&
    input.isPaid === false &&
    "definition" in input
  );
}

function normalizeFreeTool(input: FreeTool | FreeToolInput): {
  definition: McpToolDefinition;
  handler: McpToolHandler;
  rawHandler: RawToolHandler;
} {
  if (isFreeToolObject(input)) {
    return {
      definition: input.definition,
      handler: input.handler,
      rawHandler: input.handler,
    };
  }
  const name = input.definition?.name ?? input.name;
  const description = input.definition?.description ?? input.description ?? "";
  const inputSchema = input.definition?.inputSchema ??
    input.inputSchema ?? {
      type: "object",
      additionalProperties: true,
    };
  if (!name || !name.trim()) {
    throw new Error("Free tool definition must include a non-empty name");
  }
  const wrapped = freeTool({ name, description, inputSchema }, input.handler);
  return {
    definition: wrapped.definition,
    handler: wrapped.handler,
    rawHandler: input.handler,
  };
}

function parseQueryArgs(url: URL): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  for (const [k, v] of url.searchParams.entries()) {
    const trimmed = v.trim();
    if (
      (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
      try {
        args[k] = JSON.parse(trimmed);
        continue;
      } catch {
        // Keep string value
      }
    }
    args[k] = v;
  }
  return args;
}

export function createPaidMcpGateway(
  options: PaidMcpGatewayOptions = {}
): PaidMcpGateway {
  const name = options.name ?? "x402-gate";
  const title = options.title ?? "402-Gate Universal x402 MCP Server";
  const version = options.version ?? "0.1.0";
  const description =
    options.description ??
    "Universal x402 v2 paidTool adapter and REST/MCP paywall gateway.";

  const payTo = resolvePayTo(options.payTo);
  const facilitatorUrl = (
    options.facilitatorUrl ?? TESTNET_FACILITATOR_URL
  ).replace(/\/+$/, "");
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const keyid = getKeyId(keystorePath);
  const replayGuard = new ReplayGuard(options.intentLogPath);

  let currentBaseUrl = (options.baseUrl ?? "http://127.0.0.1").replace(
    /\/+$/,
    ""
  );

  const allInputs: GatewayTool[] = [
    ...(options.tools ?? []),
    ...(options.freeTools ?? []),
    ...(options.paidTools ?? []),
  ];

  const tools: McpToolDefinition[] = [];
  const handlers: Record<string, McpToolHandler> = {};
  const freeToolMap = new Map<
    string,
    { definition: McpToolDefinition; handler: McpToolHandler }
  >();
  const paidToolMap = new Map<string, BoundPaidToolRuntime>();

  const overrides: PaidToolContextOverrides = {
    payTo,
    network: options.network,
    asset: options.asset,
    scheme: options.scheme,
    maxTimeoutSeconds: options.maxTimeoutSeconds,
    extra: options.extra,
    facilitatorUrl,
    facilitatorClient: options.facilitatorClient,
    intentLogPath: options.intentLogPath,
    ledgerPath: options.ledgerPath,
    keystorePath,
    replayGuard,
    getBaseUrl: () => currentBaseUrl,
  };

  for (const item of allInputs) {
    if (isPaidTool(item)) {
      if (handlers[item.name]) {
        throw new Error(`Duplicate tool registration: ${item.name}`);
      }
      const bound = item.bindRuntime(overrides);
      tools.push(bound.definition);
      handlers[item.name] = bound.handleMcp;
      paidToolMap.set(item.name, bound);
    } else {
      const free = normalizeFreeTool(item);
      if (handlers[free.definition.name]) {
        throw new Error(`Duplicate tool registration: ${free.definition.name}`);
      }
      tools.push(free.definition);
      handlers[free.definition.name] = free.handler;
      freeToolMap.set(free.definition.name, {
        definition: free.definition,
        handler: free.handler,
      });
    }
  }

  const getPricingManifest = (): PaidToolMetaEntry[] => {
    const entries: PaidToolMetaEntry[] = [];
    for (const [toolName, bound] of paidToolMap.entries()) {
      const httpPath = `/api/tools/${encodeURIComponent(toolName)}`;
      entries.push({
        name: toolName,
        description: bound.definition.description,
        amountMicroUsd: bound.amountMicroUsd.toString(),
        amountUsd: formatMicroUsd(bound.amountMicroUsd),
        scheme: bound.scheme,
        network: bound.network,
        asset: bound.asset,
        payTo: bound.payTo,
        httpPath,
        httpUrl: `${currentBaseUrl}${httpPath}`,
        requirement: bound.buildRequirement(),
      });
    }
    return entries;
  };

  const extraRoutes: ExtraHttpRouteHandler = async (req, res, url) => {
    const method = (req.method ?? "GET").toUpperCase();
    const pathname = url.pathname;

    if (!pathname.startsWith("/api/tools/")) {
      return false;
    }

    const rawName = pathname.slice("/api/tools/".length);
    if (!rawName || rawName.includes("/")) {
      sendJson(res, 404, { error: "Tool not found", path: pathname });
      return true;
    }

    let toolName: string;
    try {
      toolName = decodeURIComponent(rawName);
    } catch {
      sendJson(res, 400, { error: "Invalid tool name encoding" });
      return true;
    }

    if (method !== "GET" && method !== "POST") {
      sendJson(res, 405, { error: `Method ${method} not allowed` });
      return true;
    }

    const paidBound = paidToolMap.get(toolName);
    const freeBound = freeToolMap.get(toolName);

    if (!paidBound && !freeBound) {
      sendJson(res, 404, { error: `Unknown tool: ${toolName}` });
      return true;
    }

    let args: Record<string, unknown> = {};
    if (method === "POST") {
      try {
        const parsed = await readJsonBody(req);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          args = parsed as Record<string, unknown>;
        } else {
          args = { value: parsed };
        }
      } catch {
        sendJson(res, 400, { error: "Invalid JSON request body" });
        return true;
      }
    } else {
      args = parseQueryArgs(url);
    }

    if (paidBound) {
      await paidBound.handleHttp(req, res, url, args);
      return true;
    }

    if (freeBound) {
      const ctx = normalizeMcpContext({ req, headers: req.headers, meta: {} });
      try {
        const outcome = await freeBound.handler(args, ctx);
        if (outcome.isError) {
          sendJson(res, outcome.httpStatus ?? 400, {
            ok: false,
            tool: toolName,
            error: outcome.data,
          });
          return true;
        }
        sendJson(res, 200, {
          ok: true,
          tool: toolName,
          result: outcome.data,
        });
      } catch (err) {
        sendJson(res, 500, {
          ok: false,
          tool: toolName,
          error: err instanceof Error ? err.message : String(err),
        });
      }
      return true;
    }

    return false;
  };

  const wellKnownX402 = (): Record<string, unknown> => {
    const manifest = getPricingManifest();
    const schemes = Array.from(new Set(manifest.map((m) => m.scheme)));
    const networks = Array.from(new Set(manifest.map((m) => m.network)));
    const paidEndpoints = manifest.map((m) => ({
      tool: m.name,
      name: m.name,
      description: m.description,
      method: "POST",
      probeMethod: "GET",
      path: m.httpPath,
      url: m.httpUrl,
      amountMicroUsd: m.amountMicroUsd,
      amountUsd: m.amountUsd,
      scheme: m.scheme,
      network: m.network,
      asset: m.asset,
      payTo: m.payTo,
    }));

    return {
      x402Version: 2,
      name,
      title,
      description,
      mcpEndpoint: `${currentBaseUrl}/mcp`,
      ...(paidEndpoints[0] ? { paidEndpoint: paidEndpoints[0].url } : {}),
      paidEndpoints,
      paidTools: manifest.map((m) => ({
        name: m.name,
        amountMicroUsd: m.amountMicroUsd,
        amountUsd: m.amountUsd,
        url: m.httpUrl,
      })),
      payTo,
      keyid,
      schemes: schemes.length > 0 ? schemes : [options.scheme ?? "exact"],
      networks:
        networks.length > 0 ? networks : [options.network ?? BASE_SEPOLIA_NETWORK],
      accepts: manifest.map((m) => m.requirement),
      branding: BRANDING,
    };
  };

  const serverCardExtras = (): Record<string, unknown> => {
    const manifest = getPricingManifest();
    return {
      payTo,
      keyid,
      author: BRANDING.author,
      organization: BRANDING.organization,
      website: BRANDING.website,
      contact: BRANDING.contact,
      x402: {
        x402Version: 2,
        schemes: Array.from(new Set(manifest.map((m) => m.scheme))),
        networks: Array.from(new Set(manifest.map((m) => m.network))),
        paidTools: manifest.map((m) => ({
          name: m.name,
          amountMicroUsd: m.amountMicroUsd,
          amountUsd: m.amountUsd,
        })),
        paidEndpoints: manifest.map((m) => m.httpUrl),
      },
    };
  };

  return {
    tools,
    handlers,
    extraRoutes,
    wellKnownX402,
    serverCardExtras,
    setBaseUrl: (baseUrl: string) => {
      currentBaseUrl = baseUrl.replace(/\/+$/, "");
    },
    getPricingManifest,
    getIntentCount: () => replayGuard.getIntentCount(),
    payTo,
    facilitatorUrl,
    keystorePath,
  };
}
