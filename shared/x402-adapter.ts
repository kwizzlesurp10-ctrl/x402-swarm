import crypto from "node:crypto";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import type {
  PaymentPayloadResult,
  PaymentRequired,
  PaymentRequirements,
  SchemeNetworkClient,
  SettleResponse,
} from "@x402/core/types";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { wrapFetchWithPayment } from "@x402/fetch";
import { privateKeyToAccount } from "viem/accounts";
import {
  LIGHTNING_MAINNET_NETWORK,
  LIGHTNING_TESTNET_NETWORK,
  TESTNET_FACILITATOR_URL,
} from "./constants.js";
import type { SpendPolicyEngine } from "./policy.js";
import type { X402PaymentRequirement } from "./types.js";

export {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
  encodePaymentSignatureHeader,
};

export interface LightningPaymentRequest {
  bolt11: string;
  paymentHash: string;
  amountMsat: bigint;
  network: string;
  payTo: string;
  requirements: X402PaymentRequirement;
}

export type LightningPayerFn = (
  req: LightningPaymentRequest
) => Promise<{ preimage: string; payer?: string }>;

export class LightningSchemeClient implements SchemeNetworkClient {
  public readonly scheme = "lightning";
  private readonly payer: LightningPayerFn;

  constructor(payer: LightningPayerFn) {
    this.payer = payer;
  }

  public async createPaymentPayload(
    x402Version: number,
    paymentRequirements: PaymentRequirements
  ): Promise<PaymentPayloadResult> {
    const extra = paymentRequirements.extra ?? {};
    const bolt11 = String(extra.bolt11 ?? "");
    const paymentHash = String(extra.paymentHash ?? "");
    const amountMsatRaw =
      typeof extra.amountMsat === "string" || typeof extra.amountMsat === "number"
        ? String(extra.amountMsat)
        : paymentRequirements.amount;

    if (!bolt11 || !paymentHash) {
      throw new Error(
        "Lightning payment requirements missing extra.bolt11 or extra.paymentHash"
      );
    }

    const paid = await this.payer({
      bolt11,
      paymentHash,
      amountMsat: BigInt(amountMsatRaw),
      network: paymentRequirements.network,
      payTo: paymentRequirements.payTo,
      requirements: toLocalRequirement(paymentRequirements),
    });

    const computedHash = crypto
      .createHash("sha256")
      .update(Buffer.from(paid.preimage.replace(/^0x/, ""), "hex"))
      .digest("hex");

    if (computedHash !== paymentHash.replace(/^0x/, "").toLowerCase()) {
      throw new Error("Lightning payer returned preimage that does not match paymentHash");
    }

    return {
      x402Version,
      payload: {
        bolt11,
        paymentHash,
        preimage: paid.preimage,
        payer: paid.payer ?? "lightning:client",
      },
    };
  }
}

export function toLocalRequirement(req: PaymentRequirements): X402PaymentRequirement {
  return {
    scheme: req.scheme,
    network: req.network,
    asset: req.asset,
    amount: req.amount,
    payTo: req.payTo,
    maxTimeoutSeconds: req.maxTimeoutSeconds,
    extra: req.extra,
  };
}

export interface HandshakeTraceEvent {
  url: string;
  method: string;
  status: number;
  hasPaymentRequiredHeader: boolean;
  hasPaymentSignatureHeader: boolean;
  hasPaymentResponseHeader: boolean;
  decodedSettleResponse?: SettleResponse;
  policyDecision?: { allowed: boolean; reason?: string; evaluatedMicroUsd: string };
}

export interface CreateX402FetchOptions {
  evmPrivateKey?: `0x${string}`;
  lightningPayer?: LightningPayerFn;
  policy?: SpendPolicyEngine;
  agentId?: string;
  preferredScheme?: string;
  preferredNetwork?: string;
  baseFetch?: typeof globalThis.fetch;
}

export function createX402FetchClient(options: CreateX402FetchOptions) {
  const trace: HandshakeTraceEvent[] = [];

  const selector = (_version: number, accepts: PaymentRequirements[]): PaymentRequirements => {
    if (options.preferredScheme || options.preferredNetwork) {
      const exactMatch = accepts.find((a) => {
        const schemeOk = !options.preferredScheme || a.scheme === options.preferredScheme;
        const netOk = !options.preferredNetwork || a.network === options.preferredNetwork;
        return schemeOk && netOk;
      });
      if (exactMatch) return exactMatch;
    }
    return accepts[0];
  };

  const client = new x402Client(selector);
  // Use our explicit SpendPolicyEngine for consistent integer micro-USD & Lightning caps.
  client.setSpendControls(false);

  let evmAddress: `0x${string}` | undefined;
  if (options.evmPrivateKey) {
    const account = privateKeyToAccount(options.evmPrivateKey);
    evmAddress = account.address;
    client.register("eip155:*", new ExactEvmScheme(account));
  }

  if (options.lightningPayer) {
    const lnClient = new LightningSchemeClient(options.lightningPayer);
    client.register("lightning:*", lnClient);
    client.register(LIGHTNING_TESTNET_NETWORK, lnClient);
    client.register(LIGHTNING_MAINNET_NETWORK, lnClient);
  }

  if (options.policy) {
    const policy = options.policy;
    client.onBeforePaymentCreation(async ({ selectedRequirements }) => {
      const decision = policy.onPaymentRequested(
        toLocalRequirement(selectedRequirements),
        { agentId: options.agentId }
      );
      trace.push({
        url: "policy://onBeforePaymentCreation",
        method: "CHECK",
        status: decision.allowed ? 200 : 403,
        hasPaymentRequiredHeader: false,
        hasPaymentSignatureHeader: false,
        hasPaymentResponseHeader: false,
        policyDecision: {
          allowed: decision.allowed,
          reason: decision.reason,
          evaluatedMicroUsd: decision.evaluatedMicroUsd,
        },
      });
      if (!decision.allowed) {
        return {
          abort: true,
          reason: decision.reason ?? "Rejected by SpendPolicyEngine",
        };
      }
    });

    client.onAfterPaymentCreation(async ({ selectedRequirements }) => {
      policy.recordSpend(toLocalRequirement(selectedRequirements), {
        agentId: options.agentId,
      });
    });
  }

  const underlyingFetch = options.baseFetch ?? globalThis.fetch;
  const tracedFetch: typeof globalThis.fetch = async (input, init) => {
    const req = new Request(input, init);
    const res = await underlyingFetch(req);
    const payRespHeader = res.headers.get("payment-response");
    let decodedSettleResponse: SettleResponse | undefined;
    if (payRespHeader) {
      try {
        decodedSettleResponse = decodePaymentResponseHeader(payRespHeader);
      } catch {
        // Ignore malformed settlement header in trace
      }
    }
    trace.push({
      url: req.url,
      method: req.method,
      status: res.status,
      hasPaymentRequiredHeader: res.headers.has("payment-required"),
      hasPaymentSignatureHeader:
        req.headers.has("payment-signature") || req.headers.has("x-payment"),
      hasPaymentResponseHeader: res.headers.has("payment-response"),
      decodedSettleResponse,
    });
    return res;
  };

  const httpClient = new x402HTTPClient(client);
  const fetchWithPayment = wrapFetchWithPayment(tracedFetch, httpClient);

  return {
    fetchWithPayment,
    x402Client: client,
    httpClient,
    evmAddress,
    trace,
  };
}

export class FacilitatorClient {
  public readonly baseUrl: string;

  constructor(baseUrl: string = TESTNET_FACILITATOR_URL) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  public async getSupported(): Promise<{
    kinds: Array<{
      x402Version: number;
      scheme: string;
      network: string;
      extra?: Record<string, unknown>;
    }>;
    extensions?: string[];
    signers?: Record<string, string[]>;
  }> {
    const res = await fetch(`${this.baseUrl}/supported`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`Facilitator GET /supported failed: ${res.status} ${await res.text()}`);
    }
    return (await res.json()) as {
      kinds: Array<{
        x402Version: number;
        scheme: string;
        network: string;
        extra?: Record<string, unknown>;
      }>;
      extensions?: string[];
      signers?: Record<string, string[]>;
    };
  }

  public async verify(
    paymentPayload: unknown,
    paymentRequirements: PaymentRequirements | X402PaymentRequirement
  ): Promise<{ isValid: boolean; invalidReason?: string; payer?: string }> {
    const payload =
      paymentPayload && typeof paymentPayload === "object"
        ? (paymentPayload as Record<string, unknown>)
        : {};
    const res = await fetch(`${this.baseUrl}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        x402Version: (payload.x402Version as number | undefined) ?? 2,
        paymentPayload,
        paymentRequirements,
      }),
    });
    const text = await res.text();
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error(`Facilitator /verify non-JSON (${res.status}): ${text}`);
    }
    if (!res.ok && typeof parsed.isValid !== "boolean") {
      throw new Error(`Facilitator /verify HTTP ${res.status}: ${text}`);
    }
    return parsed as { isValid: boolean; invalidReason?: string; payer?: string };
  }

  public async settle(
    paymentPayload: unknown,
    paymentRequirements: PaymentRequirements | X402PaymentRequirement
  ): Promise<SettleResponse> {
    const payload =
      paymentPayload && typeof paymentPayload === "object"
        ? (paymentPayload as Record<string, unknown>)
        : {};
    const res = await fetch(`${this.baseUrl}/settle`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        x402Version: (payload.x402Version as number | undefined) ?? 2,
        paymentPayload,
        paymentRequirements,
      }),
    });
    const text = await res.text();
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error(`Facilitator /settle non-JSON (${res.status}): ${text}`);
    }
    if (!res.ok && typeof parsed.success !== "boolean") {
      throw new Error(`Facilitator /settle HTTP ${res.status}: ${text}`);
    }
    return parsed as unknown as SettleResponse;
  }
}

export type { PaymentRequired, PaymentRequirements, SettleResponse };
