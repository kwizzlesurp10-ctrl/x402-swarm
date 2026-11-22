import {
  DEFAULT_BTC_MICRO_USD_PER_SAT,
  MSAT_PER_SAT,
  isRetiredPayTo,
} from "./constants.js";
import type {
  SpendDecision,
  SpendPolicyConfig,
  X402PaymentRequirement,
} from "./types.js";

interface SpendEntry {
  timestampMs: number;
  amountMicroUsd: bigint;
}

export class SpendPolicyError extends Error {
  public readonly decision: SpendDecision;

  constructor(message: string, decision: SpendDecision) {
    super(message);
    this.name = "SpendPolicyError";
    this.decision = decision;
  }
}

export function evaluateRequirementMicroUsd(
  req: X402PaymentRequirement,
  btcMicroUsdPerSat: bigint = DEFAULT_BTC_MICRO_USD_PER_SAT
): bigint {
  const rawAmount = BigInt(req.amount);
  if (rawAmount < 0n) {
    throw new Error(`Negative payment requirement amount: ${req.amount}`);
  }

  const assetUpper = req.asset.toUpperCase();
  const isLightning =
    req.scheme === "lightning" ||
    req.network.startsWith("lightning:") ||
    assetUpper === "BTC_SAT" ||
    assetUpper === "SAT" ||
    assetUpper === "MSAT";

  if (!isLightning) {
    // EVM USDC / USD-pegged 6-decimal base units == integer micro-USD.
    return rawAmount;
  }

  // Lightning requirement `amount` may be in msats (preferred via extra.amountMsat) or sats.
  const explicitMsat =
    req.extra && typeof req.extra.amountMsat === "string"
      ? BigInt(req.extra.amountMsat)
      : req.extra && typeof req.extra.amountMsat === "number"
        ? BigInt(Math.trunc(req.extra.amountMsat))
        : assetUpper === "MSAT"
          ? rawAmount
          : rawAmount * MSAT_PER_SAT;

  // Deterministic integer ceiling conversion: ceil(msat * microUsdPerSat / 1000)
  return (explicitMsat * btcMicroUsdPerSat + (MSAT_PER_SAT - 1n)) / MSAT_PER_SAT;
}

export class SpendPolicyEngine {
  private readonly config: SpendPolicyConfig;
  private readonly spendHistory = new Map<string, SpendEntry[]>();

  constructor(config: SpendPolicyConfig) {
    if (config.maxPerCallMicroUsd < 0n || config.maxRollingWindowMicroUsd < 0n) {
      throw new Error("Spend limits must be non-negative integers");
    }
    this.config = config;
  }

  private pruneAndSum(agentId: string, nowMs: number): bigint {
    const entries = this.spendHistory.get(agentId) ?? [];
    const cutoff = nowMs - this.config.windowMs;
    const active = entries.filter((e) => e.timestampMs > cutoff);
    this.spendHistory.set(agentId, active);
    return active.reduce((acc, e) => acc + e.amountMicroUsd, 0n);
  }

  public onPaymentRequested(
    req: X402PaymentRequirement,
    options?: { agentId?: string; nowMs?: number }
  ): SpendDecision {
    const agentId = options?.agentId ?? this.config.agentId ?? "default-agent";
    const nowMs = options?.nowMs ?? Date.now();
    const payTo = req.payTo.trim();

    const currentWindowSpend = this.pruneAndSum(agentId, nowMs);
    const remainingBefore =
      this.config.maxRollingWindowMicroUsd > currentWindowSpend
        ? this.config.maxRollingWindowMicroUsd - currentWindowSpend
        : 0n;

    if (isRetiredPayTo(payTo)) {
      return {
        allowed: false,
        reason: `Payee ${payTo} is retired and unconditionally rejected`,
        evaluatedMicroUsd: "0",
        remainingWindowMicroUsd: remainingBefore.toString(),
        network: req.network,
        payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    }

    if (
      this.config.allowedNetworks &&
      this.config.allowedNetworks.length > 0 &&
      !this.config.allowedNetworks.includes(req.network)
    ) {
      return {
        allowed: false,
        reason: `Network ${req.network} is not in allowedNetworks`,
        evaluatedMicroUsd: "0",
        remainingWindowMicroUsd: remainingBefore.toString(),
        network: req.network,
        payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    }

    if (this.config.allowedPayees && this.config.allowedPayees.length > 0) {
      const normalized = payTo.toLowerCase();
      const allowed = this.config.allowedPayees.some(
        (p) => p.trim().toLowerCase() === normalized
      );
      if (!allowed) {
        return {
          allowed: false,
          reason: `Payee ${payTo} is not in allowedPayees`,
          evaluatedMicroUsd: "0",
          remainingWindowMicroUsd: remainingBefore.toString(),
          network: req.network,
          payTo,
          scheme: req.scheme,
          capEnforced: true,
        };
      }
    }

    const costMicroUsd = evaluateRequirementMicroUsd(
      req,
      this.config.btcMicroUsdPerSat ?? DEFAULT_BTC_MICRO_USD_PER_SAT
    );

    if (costMicroUsd > this.config.maxPerCallMicroUsd) {
      return {
        allowed: false,
        reason: `Requested ${costMicroUsd.toString()} micro-USD exceeds maxPerCallMicroUsd ${this.config.maxPerCallMicroUsd.toString()}`,
        evaluatedMicroUsd: costMicroUsd.toString(),
        remainingWindowMicroUsd: remainingBefore.toString(),
        network: req.network,
        payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    }

    if (currentWindowSpend + costMicroUsd > this.config.maxRollingWindowMicroUsd) {
      return {
        allowed: false,
        reason: `Rolling window spend ${(currentWindowSpend + costMicroUsd).toString()} micro-USD exceeds cap ${this.config.maxRollingWindowMicroUsd.toString()}`,
        evaluatedMicroUsd: costMicroUsd.toString(),
        remainingWindowMicroUsd: remainingBefore.toString(),
        network: req.network,
        payTo,
        scheme: req.scheme,
        capEnforced: true,
      };
    }

    const remainingAfter =
      this.config.maxRollingWindowMicroUsd - (currentWindowSpend + costMicroUsd);

    return {
      allowed: true,
      evaluatedMicroUsd: costMicroUsd.toString(),
      remainingWindowMicroUsd: remainingAfter.toString(),
      network: req.network,
      payTo,
      scheme: req.scheme,
      capEnforced: true,
    };
  }

  public assertAllowed(
    req: X402PaymentRequirement,
    options?: { agentId?: string; nowMs?: number }
  ): SpendDecision {
    const decision = this.onPaymentRequested(req, options);
    if (!decision.allowed) {
      throw new SpendPolicyError(decision.reason ?? "Spend policy rejected payment", decision);
    }
    return decision;
  }

  public recordSpend(
    req: X402PaymentRequirement,
    options?: { agentId?: string; nowMs?: number }
  ): SpendDecision {
    const agentId = options?.agentId ?? this.config.agentId ?? "default-agent";
    const nowMs = options?.nowMs ?? Date.now();
    const decision = this.assertAllowed(req, { agentId, nowMs });
    const entries = this.spendHistory.get(agentId) ?? [];
    entries.push({
      timestampMs: nowMs,
      amountMicroUsd: BigInt(decision.evaluatedMicroUsd),
    });
    this.spendHistory.set(agentId, entries);
    return decision;
  }

  public getRollingSpendMicroUsd(agentId?: string, nowMs: number = Date.now()): bigint {
    return this.pruneAndSum(agentId ?? this.config.agentId ?? "default-agent", nowMs);
  }
}
