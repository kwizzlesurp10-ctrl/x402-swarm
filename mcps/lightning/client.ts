import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import {
  BASE_SEPOLIA_NETWORK,
  DEFAULT_BTC_MICRO_USD_PER_SAT,
  LIGHTNING_MAINNET_NETWORK,
  LIGHTNING_TESTNET_NETWORK,
} from "../../shared/constants.js";
import { SpendPolicyEngine, SpendPolicyError } from "../../shared/policy.js";
import type {
  DsseEnvelope,
  SettlementReceipt,
  SpendDecision,
  X402PaymentRequiredEnvelope,
  X402PaymentRequirement,
  X402PaymentSignature,
} from "../../shared/types.js";
import {
  type HandshakeTraceEvent,
  type LightningPayerFn,
  LightningSchemeClient,
  type SettleResponse,
  createX402FetchClient,
  decodePaymentResponseHeader,
  toLocalRequirement,
} from "../../shared/x402-adapter.js";

export interface Lightning402ClientCallOptions {
  url: string;
  method?: "GET" | "POST" | "PUT" | "DELETE";
  headers?: Record<string, string>;
  body?: unknown;
  evmPrivateKey?: `0x${string}`;
  lightningPayer?: LightningPayerFn;
  policy?: SpendPolicyEngine;
  maxPerCallMicroUsd?: bigint;
  maxRollingWindowMicroUsd?: bigint;
  windowMs?: number;
  btcMicroUsdPerSat?: bigint;
  allowedNetworks?: string[];
  allowedPayees?: string[];
  agentId?: string;
  preferredScheme?: string;
  preferredNetwork?: string;
  baseFetch?: typeof globalThis.fetch;
  throwOnPolicyBlock?: boolean;
}

export interface Lightning402ClientCallResult {
  ok: boolean;
  status: number;
  data: unknown;
  paymentResponse?: SettleResponse;
  receipt?: SettlementReceipt;
  dsse?: DsseEnvelope;
  handshakeTx: string | null;
  capEnforced: boolean;
  blockedByPolicy: boolean;
  policyDecision?: SpendDecision;
  trace: HandshakeTraceEvent[];
}

function buildEffectivePolicy(
  options: Pick<
    Lightning402ClientCallOptions,
    | "policy"
    | "maxPerCallMicroUsd"
    | "maxRollingWindowMicroUsd"
    | "windowMs"
    | "btcMicroUsdPerSat"
    | "allowedNetworks"
    | "allowedPayees"
    | "agentId"
  >
): SpendPolicyEngine {
  if (options.policy) return options.policy;
  return new SpendPolicyEngine({
    agentId: options.agentId ?? "lightning-402-client",
    maxPerCallMicroUsd: options.maxPerCallMicroUsd ?? 10_000_000n,
    maxRollingWindowMicroUsd:
      options.maxRollingWindowMicroUsd ?? 100_000_000n,
    windowMs: options.windowMs ?? 3_600_000,
    btcMicroUsdPerSat:
      options.btcMicroUsdPerSat ?? DEFAULT_BTC_MICRO_USD_PER_SAT,
    allowedNetworks: options.allowedNetworks,
    allowedPayees: options.allowedPayees,
  });
}

function resolvePreferredRail(options: {
  preferredScheme?: string;
  preferredNetwork?: string;
  evmPrivateKey?: `0x${string}`;
  lightningPayer?: LightningPayerFn;
}): { preferredScheme?: string; preferredNetwork?: string } {
  if (options.preferredScheme || options.preferredNetwork) {
    return {
      preferredScheme: options.preferredScheme,
      preferredNetwork: options.preferredNetwork,
    };
  }
  if (options.lightningPayer && !options.evmPrivateKey) {
    return {
      preferredScheme: "lightning",
      preferredNetwork: LIGHTNING_TESTNET_NETWORK,
    };
  }
  if (options.evmPrivateKey && !options.lightningPayer) {
    return {
      preferredScheme: "exact",
      preferredNetwork: BASE_SEPOLIA_NETWORK,
    };
  }
  return {};
}

export async function runLightning402ClientCall(
  options: Lightning402ClientCallOptions
): Promise<Lightning402ClientCallResult> {
  const policy = buildEffectivePolicy(options);
  const { preferredScheme, preferredNetwork } = resolvePreferredRail(options);

  let latestBlockedDecision: SpendDecision | undefined;
  const wrappedPolicy = {
    onPaymentRequested: (
      req: X402PaymentRequirement,
      reqOpts?: { agentId?: string; nowMs?: number }
    ) => {
      const decision = policy.onPaymentRequested(req, reqOpts);
      if (!decision.allowed) {
        latestBlockedDecision = decision;
      }
      return decision;
    },
    recordSpend: (
      req: X402PaymentRequirement,
      reqOpts?: { agentId?: string; nowMs?: number }
    ) => policy.recordSpend(req, reqOpts),
    assertAllowed: (
      req: X402PaymentRequirement,
      reqOpts?: { agentId?: string; nowMs?: number }
    ) => policy.assertAllowed(req, reqOpts),
    getRollingSpendMicroUsd: (agentId?: string, nowMs?: number) =>
      policy.getRollingSpendMicroUsd(agentId, nowMs),
  } as unknown as SpendPolicyEngine;

  const { fetchWithPayment, trace } = createX402FetchClient({
    evmPrivateKey: options.evmPrivateKey,
    lightningPayer: options.lightningPayer,
    policy: wrappedPolicy,
    agentId: options.agentId,
    preferredScheme,
    preferredNetwork,
    baseFetch: options.baseFetch,
  });

  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers ?? {}),
  };
  let bodyPayload: string | undefined;
  if (options.body !== undefined) {
    bodyPayload =
      typeof options.body === "string"
        ? options.body
        : JSON.stringify(options.body);
    if (!headers["Content-Type"] && !headers["content-type"]) {
      headers["Content-Type"] = "application/json";
    }
  }

  let response: Response;
  try {
    response = await fetchWithPayment(options.url, {
      method: options.method ?? (bodyPayload !== undefined ? "POST" : "GET"),
      headers,
      ...(bodyPayload !== undefined ? { body: bodyPayload } : {}),
    });
  } catch (err) {
    if (latestBlockedDecision) {
      if (options.throwOnPolicyBlock === false) {
        return {
          ok: false,
          status: 403,
          data: { error: latestBlockedDecision.reason },
          handshakeTx: null,
          capEnforced: true,
          blockedByPolicy: true,
          policyDecision: latestBlockedDecision,
          trace,
        };
      }
      throw new SpendPolicyError(
        latestBlockedDecision.reason ?? "Payment blocked by SpendPolicyEngine",
        latestBlockedDecision
      );
    }
    throw err;
  }

  const rawText = await response.text();
  let parsedData: unknown = rawText;
  if (rawText) {
    try {
      parsedData = JSON.parse(rawText);
    } catch {
      // Keep text payload
    }
  }

  const paymentRespHeader = response.headers.get("payment-response");
  let paymentResponse: SettleResponse | undefined;
  if (paymentRespHeader) {
    paymentResponse = decodePaymentResponseHeader(paymentRespHeader);
  }

  const extraRecord =
    paymentResponse?.extra && typeof paymentResponse.extra === "object"
      ? (paymentResponse.extra as Record<string, unknown>)
      : undefined;
  const dataRecord =
    parsedData && typeof parsedData === "object" && !Array.isArray(parsedData)
      ? (parsedData as Record<string, unknown>)
      : undefined;

  const receipt =
    (extraRecord?.receipt as SettlementReceipt | undefined) ??
    (dataRecord?.settlement as SettlementReceipt | undefined);
  const dsse =
    (extraRecord?.dsse as DsseEnvelope | undefined) ??
    (dataRecord?.dsse as DsseEnvelope | undefined);

  return {
    ok: response.ok,
    status: response.status,
    data: parsedData,
    paymentResponse,
    receipt,
    dsse,
    handshakeTx: paymentResponse?.transaction ?? receipt?.txHash ?? null,
    capEnforced: true,
    blockedByPolicy: false,
    trace,
  };
}

export interface LightningMcpToolCallOptions {
  mcpUrl: string;
  toolName: string;
  arguments?: Record<string, unknown>;
  evmPrivateKey?: `0x${string}`;
  lightningPayer?: LightningPayerFn;
  policy?: SpendPolicyEngine;
  maxPerCallMicroUsd?: bigint;
  maxRollingWindowMicroUsd?: bigint;
  windowMs?: number;
  btcMicroUsdPerSat?: bigint;
  allowedNetworks?: string[];
  allowedPayees?: string[];
  agentId?: string;
  preferredScheme?: string;
  preferredNetwork?: string;
  throwOnPolicyBlock?: boolean;
}

export interface LightningMcpToolCallResult {
  isError: boolean;
  result: Record<string, unknown>;
  parsedContent: unknown;
  paymentRequired?: X402PaymentRequiredEnvelope;
  paymentResponse?: SettleResponse;
  handshakeTx: string | null;
  capEnforced: boolean;
  blockedByPolicy: boolean;
  policyDecision?: SpendDecision;
}

async function postMcpRpc(
  mcpUrl: string,
  method: string,
  params: Record<string, unknown>,
  id: number
): Promise<Record<string, unknown>> {
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params,
    }),
  });
  return (await res.json()) as Record<string, unknown>;
}

export async function runLightningMcpToolCall(
  options: LightningMcpToolCallOptions
): Promise<LightningMcpToolCallResult> {
  const policy = buildEffectivePolicy(options);
  const { preferredScheme, preferredNetwork } = resolvePreferredRail(options);

  const firstRpc = await postMcpRpc(
    options.mcpUrl,
    "tools/call",
    {
      name: options.toolName,
      arguments: options.arguments ?? {},
    },
    1
  );

  const firstResult = (firstRpc.result ?? {}) as Record<string, unknown>;
  const firstMeta = (firstResult._meta ?? {}) as Record<string, unknown>;
  const challenge = firstMeta["x402/payment-required"] as
    | X402PaymentRequiredEnvelope
    | undefined;

  if (!firstResult.isError || !challenge) {
    const firstContent = Array.isArray(firstResult.content)
      ? (firstResult.content[0] as { text?: string } | undefined)?.text
      : undefined;
    let parsedContent: unknown = firstContent;
    if (typeof firstContent === "string") {
      try {
        parsedContent = JSON.parse(firstContent);
      } catch {
        // Keep raw string
      }
    }
    return {
      isError: Boolean(firstResult.isError),
      result: firstResult,
      parsedContent,
      handshakeTx: null,
      capEnforced: true,
      blockedByPolicy: false,
    };
  }

  // Build x402Client to sign only after SpendPolicyEngine approves.
  const selector = (
    _version: number,
    accepts: X402PaymentRequirement[]
  ) => {
    if (preferredScheme || preferredNetwork) {
      const match = accepts.find((a) => {
        const sOk = !preferredScheme || a.scheme === preferredScheme;
        const nOk = !preferredNetwork || a.network === preferredNetwork;
        return sOk && nOk;
      });
      if (match) return match;
    }
    return accepts[0];
  };

  const client = new x402Client(
    selector as ConstructorParameters<typeof x402Client>[0]
  );
  client.setSpendControls(false);

  if (options.evmPrivateKey) {
    const account = privateKeyToAccount(options.evmPrivateKey);
    client.register("eip155:*", new ExactEvmScheme(account));
  }
  if (options.lightningPayer) {
    const lnClient = new LightningSchemeClient(options.lightningPayer);
    client.register("lightning:*", lnClient);
    client.register(LIGHTNING_TESTNET_NETWORK, lnClient);
    client.register(LIGHTNING_MAINNET_NETWORK, lnClient);
  }

  let blockedDecision: SpendDecision | undefined;
  client.onBeforePaymentCreation(async ({ selectedRequirements }) => {
    const decision = policy.onPaymentRequested(
      toLocalRequirement(selectedRequirements),
      { agentId: options.agentId }
    );
    if (!decision.allowed) {
      blockedDecision = decision;
      return {
        abort: true,
        reason: decision.reason ?? "Blocked by SpendPolicyEngine",
      };
    }
  });
  client.onAfterPaymentCreation(async ({ selectedRequirements }) => {
    policy.recordSpend(toLocalRequirement(selectedRequirements), {
      agentId: options.agentId,
    });
  });

  let paymentPayload: X402PaymentSignature;
  try {
    paymentPayload = (await client.createPaymentPayload(
      challenge as unknown as Parameters<x402Client["createPaymentPayload"]>[0]
    )) as unknown as X402PaymentSignature;
  } catch (err) {
    if (blockedDecision) {
      if (options.throwOnPolicyBlock === false) {
        return {
          isError: true,
          result: firstResult,
          parsedContent: { error: blockedDecision.reason },
          paymentRequired: challenge,
          handshakeTx: null,
          capEnforced: true,
          blockedByPolicy: true,
          policyDecision: blockedDecision,
        };
      }
      throw new SpendPolicyError(
        blockedDecision.reason ?? "Payment blocked by SpendPolicyEngine",
        blockedDecision
      );
    }
    throw err;
  }

  const paidRpc = await postMcpRpc(
    options.mcpUrl,
    "tools/call",
    {
      name: options.toolName,
      arguments: options.arguments ?? {},
      _meta: {
        "x402/payment": paymentPayload,
      },
    },
    2
  );

  const paidResult = (paidRpc.result ?? {}) as Record<string, unknown>;
  const paidMeta = (paidResult._meta ?? {}) as Record<string, unknown>;
  const paymentResponse = paidMeta["x402/payment-response"] as
    | SettleResponse
    | undefined;
  const paidContentText = Array.isArray(paidResult.content)
    ? (paidResult.content[0] as { text?: string } | undefined)?.text
    : undefined;
  let parsedContent: unknown = paidContentText;
  if (typeof paidContentText === "string") {
    try {
      parsedContent = JSON.parse(paidContentText);
    } catch {
      // Keep raw string
    }
  }

  return {
    isError: Boolean(paidResult.isError),
    result: paidResult,
    parsedContent,
    paymentRequired: challenge,
    paymentResponse,
    handshakeTx: paymentResponse?.transaction ?? null,
    capEnforced: true,
    blockedByPolicy: false,
  };
}
