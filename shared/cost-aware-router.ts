import crypto from "node:crypto";
import { MICRO_USD_PER_USD } from "./constants.js";

/**
 * Vercel AI Gateway Cost-Aware Model Routing
 *
 * Pattern: A dedicated low-cost decision model classifies incoming prompts into
 * Economy Route (router/pandaforge or $0 promotional models) vs Frontier Route
 * (GPT-5.6 / Claude 3.7 / Gemini 2.5 Pro) based on reasoning complexity.
 */

export interface DecisionModelSpec {
  id: string;
  provider: string;
  pricePerMillionInputUsd: number;
  microUsdPerMillionInput: bigint;
  contextTokens: number;
  zdr: boolean;
  noTraining: boolean;
}

export const DECISION_MODELS: Record<string, DecisionModelSpec> = {
  PERPLEXITY_FLASH: {
    id: "perplexity/pplx-decider-flash-v1.3",
    provider: "perplexity",
    pricePerMillionInputUsd: 0.01,
    microUsdPerMillionInput: 10_000n, // $0.01 = 10,000 micro-USD per 1M tokens
    contextTokens: 262_144,
    zdr: false,
    noTraining: true,
  },
  LIQUID: {
    id: "liquid/d1.2",
    provider: "liquid",
    pricePerMillionInputUsd: 0.02,
    microUsdPerMillionInput: 20_000n, // $0.02 = 20,000 micro-USD per 1M tokens
    contextTokens: 65_536,
    zdr: false,
    noTraining: true,
  },
  MICROSOFT: {
    id: "microsoft/decision-1.1",
    provider: "azure",
    pricePerMillionInputUsd: 0.04,
    microUsdPerMillionInput: 40_000n, // $0.04 = 40,000 micro-USD per 1M tokens
    contextTokens: 131_072,
    zdr: true,
    noTraining: true,
  },
} as const;

export const DEFAULT_DECISION_CHAIN = [
  DECISION_MODELS.PERPLEXITY_FLASH,
  DECISION_MODELS.LIQUID,
  DECISION_MODELS.MICROSOFT,
];

export const EXECUTION_TIERS = {
  ECONOMY: {
    primary: "router/pandaforge",
    fallbacks: ["reflection/beam-free", "deepseek/deepseek-v4.1-flash-1017"],
    description: "Economy route bundling $0 promotional models and ultra-low cost inference",
    estimatedCostMicroUsdPerCall: 0n,
  },
  FRONTIER: {
    primary: "openai/gpt-5.6-luna",
    fallbacks: ["anthropic/claude-3-7-sonnet", "deepseek/deepseek-r1"],
    description: "Frontier reasoning tier for advanced architecture, multi-step math, and high ambiguity",
    estimatedCostMicroUsdPerCall: 1500n, // ~$0.0015
  },
} as const;

export interface RoutingEvaluation {
  tier: "economy" | "frontier";
  targetModel: string;
  reason: string;
  complexityChoice: "simple" | "moderate" | "complex";
  requiresFrontierProb: number;
  deciderModelUsed: string;
  routingCostMicroUsd: bigint;
  inputTokensEstimated: number;
  sha256Prompt: string;
  timestamp: string;
}

export interface RouterOptions {
  aiGatewayApiKey?: string;
  frontierEscalationThreshold?: number; // default 0.65
  forceEconomy?: boolean;
  forceFrontier?: boolean;
  customEconomyModel?: string;
  customFrontierModel?: string;
  mockDecisionResult?: {
    complexityChoice: "simple" | "moderate" | "complex";
    requiresFrontierProb: number;
  };
}

/**
 * Estimate token count safely from string byte/character length
 */
export function estimatePromptTokens(prompt: string): number {
  if (!prompt || typeof prompt !== "string") return 0;
  // Standard rule of thumb: ~4 characters per token
  return Math.max(1, Math.ceil(prompt.trim().length / 4));
}

/**
 * Calculate micro-USD integer cost for decision tokens
 */
export function calculateDecisionCostMicroUsd(
  tokens: number,
  microUsdPerMillion: bigint
): bigint {
  if (tokens <= 0) return 0n;
  // (tokens * microUsdPerMillion) / 1,000,000
  const numerator = BigInt(tokens) * microUsdPerMillion;
  const cost = numerator / MICRO_USD_PER_USD;
  // Floor to at least 1 micro-USD if any tokens were evaluated
  return cost > 0n ? cost : 1n;
}

/**
 * Deterministic heuristic classifier when offline or no API key is supplied
 */
export function evaluateLocalHeuristic(prompt: string): {
  complexityChoice: "simple" | "moderate" | "complex";
  requiresFrontierProb: number;
} {
  const text = prompt.toLowerCase();
  const tokenCount = estimatePromptTokens(prompt);

  // Indicators of complex frontier queries
  const frontierKeywords = [
    "formal verification",
    "lock-free",
    "concurrent",
    "distributed consensus",
    "zero-knowledge",
    "algebraic topology",
    "compiler optimization",
    "kernel driver",
    "cryptographic proof",
    "assembly",
    "micro-architecture",
  ];

  let complexityScore = 0;
  for (const kw of frontierKeywords) {
    if (text.includes(kw)) {
      complexityScore += 3;
    }
  }

  if (tokenCount > 800) complexityScore += 2;
  if (text.includes("```") && (text.includes("refactor") || text.includes("debug"))) {
    complexityScore += 2;
  }

  if (complexityScore >= 3) {
    return {
      complexityChoice: "complex",
      requiresFrontierProb: Math.min(0.95, 0.65 + complexityScore * 0.05),
    };
  }

  if (complexityScore >= 1 || tokenCount > 300) {
    return {
      complexityChoice: "moderate",
      requiresFrontierProb: 0.45,
    };
  }

  return {
    complexityChoice: "simple",
    requiresFrontierProb: 0.12,
  };
}

/**
 * Core Cost-Aware Router:
 * Evaluates whether a prompt stays on the Economy Route (router/pandaforge)
 * or escalates to Frontier.
 */
export async function evaluateCostAwareRoute(
  prompt: string,
  options: RouterOptions = {}
): Promise<RoutingEvaluation> {
  const timestamp = new Date().toISOString();
  const sha256Prompt = crypto.createHash("sha256").update(prompt, "utf8").digest("hex");
  const inputTokensEstimated = estimatePromptTokens(prompt);
  const threshold = options.frontierEscalationThreshold ?? 0.65;

  if (options.forceEconomy) {
    return {
      tier: "economy",
      targetModel: options.customEconomyModel ?? EXECUTION_TIERS.ECONOMY.primary,
      reason: "Forced override to Economy Route",
      complexityChoice: "simple",
      requiresFrontierProb: 0.0,
      deciderModelUsed: "manual-override",
      routingCostMicroUsd: 0n,
      inputTokensEstimated,
      sha256Prompt,
      timestamp,
    };
  }

  if (options.forceFrontier) {
    return {
      tier: "frontier",
      targetModel: options.customFrontierModel ?? EXECUTION_TIERS.FRONTIER.primary,
      reason: "Forced override to Frontier Route",
      complexityChoice: "complex",
      requiresFrontierProb: 1.0,
      deciderModelUsed: "manual-override",
      routingCostMicroUsd: 0n,
      inputTokensEstimated,
      sha256Prompt,
      timestamp,
    };
  }

  let complexityChoice: "simple" | "moderate" | "complex" = "simple";
  let requiresFrontierProb = 0.1;
  let deciderUsed = DECISION_MODELS.PERPLEXITY_FLASH.id;
  let deciderMicroUsdRate = DECISION_MODELS.PERPLEXITY_FLASH.microUsdPerMillionInput;

  // 1. Mock decision injection (for testing)
  if (options.mockDecisionResult) {
    complexityChoice = options.mockDecisionResult.complexityChoice;
    requiresFrontierProb = options.mockDecisionResult.requiresFrontierProb;
    deciderUsed = "mock-decider-evaluation";
  } else {
    const apiKey =
      options.aiGatewayApiKey ??
      process.env.AI_GATEWAY_API_KEY ??
      process.env.VERCEL_AI_GATEWAY_KEY;

    let apiSucceeded = false;

    // 2. Try decision models via Vercel AI Gateway if credentials are available
    if (apiKey) {
      for (const decider of DEFAULT_DECISION_CHAIN) {
        try {
          const resp = await fetch("https://ai-gateway.vercel.sh/v1/decisions", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${apiKey}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              model: decider.id,
              input: prompt,
              questions: [
                {
                  id: "isComplex",
                  type: "predicate",
                  instructions:
                    "Does this prompt require multi-step deep reasoning, advanced systems programming, subtle architecture, or frontier computation?",
                },
              ],
            }),
            signal: AbortSignal.timeout(4000),
          });

          if (resp.ok) {
            const data = (await resp.json()) as any;
            if (Array.isArray(data?.answers) && data.answers.length > 0) {
              const prob =
                typeof data.answers[0]?.probability === "number"
                  ? data.answers[0].probability
                  : 0.1;
              requiresFrontierProb = prob;
              complexityChoice =
                prob >= 0.65 ? "complex" : prob >= 0.35 ? "moderate" : "simple";
              deciderUsed = decider.id;
              deciderMicroUsdRate = decider.microUsdPerMillionInput;
              apiSucceeded = true;
              break;
            }
          }
        } catch {
          // Fall through to next decider in chain
        }
      }
    }

    // 3. Fallback to calibrated local heuristic if API is unconfigured or unavailable
    if (!apiSucceeded) {
      const heuristic = evaluateLocalHeuristic(prompt);
      complexityChoice = heuristic.complexityChoice;
      requiresFrontierProb = heuristic.requiresFrontierProb;
      deciderUsed = "heuristic-calibrated-local";
      deciderMicroUsdRate = DECISION_MODELS.PERPLEXITY_FLASH.microUsdPerMillionInput;
    }
  }

  // Escalation rule
  const shouldEscalate =
    complexityChoice === "complex" || requiresFrontierProb >= threshold;

  const tier: "economy" | "frontier" = shouldEscalate ? "frontier" : "economy";
  const targetModel = shouldEscalate
    ? (options.customFrontierModel ?? EXECUTION_TIERS.FRONTIER.primary)
    : (options.customEconomyModel ?? EXECUTION_TIERS.ECONOMY.primary);

  const routingCostMicroUsd = calculateDecisionCostMicroUsd(
    inputTokensEstimated,
    deciderMicroUsdRate
  );

  const reason = shouldEscalate
    ? `Escalated to Frontier (${targetModel}): complexity="${complexityChoice}", requiresFrontierProb=${requiresFrontierProb.toFixed(2)} >= ${threshold}`
    : `Routed to Economy (${targetModel}): complexity="${complexityChoice}", requiresFrontierProb=${requiresFrontierProb.toFixed(2)} < ${threshold}`;

  return {
    tier,
    targetModel,
    reason,
    complexityChoice,
    requiresFrontierProb,
    deciderModelUsed: deciderUsed,
    routingCostMicroUsd,
    inputTokensEstimated,
    sha256Prompt,
    timestamp,
  };
}
