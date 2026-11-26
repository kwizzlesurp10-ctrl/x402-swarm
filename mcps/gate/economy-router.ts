import crypto from "node:crypto";
import {
  DEFAULT_KEYSTORE_PATH,
  DEFAULT_X402_PAY_TO,
  resolvePayTo,
} from "../../shared/constants.js";
import {
  type RoutingEvaluation,
  evaluateCostAwareRoute,
} from "../../shared/cost-aware-router.js";
import { getKeyId, signDsse } from "../../shared/keystore.js";
import {
  type GatewayTool,
  freeTool,
  paidTool,
} from "./adapter.js";

export interface EconomyRouteToolOptions {
  payTo?: string;
  amountMicroUsd?: bigint;
  facilitatorUrl?: string;
  keystorePath?: string;
  intentLogPath?: string;
  ledgerPath?: string;
}

/**
 * Creates the paid x402 Model Context Protocol tool for Vercel Cost-Aware Model Routing.
 * Evaluates incoming prompts using dedicated low-cost decision models
 * and routes to Economy (router/pandaforge) or escalates to Frontier.
 */
export function createPaidEconomyRouteTool(
  options: EconomyRouteToolOptions = {}
): GatewayTool {
  const payTo = resolvePayTo(options.payTo ?? DEFAULT_X402_PAY_TO);
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const amountMicroUsd = options.amountMicroUsd ?? 100n; // 100 micro-USD ($0.000100)

  return paidTool(
    {
      name: "paid_economy_route",
      description:
        "Paid (100 micro-USD = $0.000100) Cost-Aware Model Router: evaluates prompt complexity via dedicated decision models (perplexity/pplx-decider-flash-v1.3, liquid/d1.2, microsoft/decision-1.1), routes routine tasks to Economy (router/pandaforge), escalates complex reasoning to Frontier, and returns an Ed25519 DSSE attestation.",
      amountMicroUsd,
      payTo,
      facilitatorUrl: options.facilitatorUrl,
      intentLogPath: options.intentLogPath,
      ledgerPath: options.ledgerPath,
      keystorePath,
      inputSchema: {
        type: "object",
        properties: {
          prompt: {
            type: "string",
            description: "User prompt or agent task to evaluate and route",
          },
          forceEconomy: {
            type: "boolean",
            description: "Force routing to Economy tier (router/pandaforge)",
          },
          forceFrontier: {
            type: "boolean",
            description: "Force escalation to Frontier tier",
          },
          threshold: {
            type: "number",
            description: "Frontier escalation probability threshold (default: 0.65)",
          },
          mockComplexity: {
            type: "string",
            enum: ["simple", "moderate", "complex"],
            description: "Optional test override for complexity",
          },
          mockFrontierProb: {
            type: "number",
            description: "Optional test override for frontier probability",
          },
        },
        required: ["prompt"],
        additionalProperties: false,
      },
    },
    async (args) => {
      const prompt = String(args.prompt ?? "");
      const forceEconomy = args.forceEconomy === true;
      const forceFrontier = args.forceFrontier === true;
      const threshold = typeof args.threshold === "number" ? args.threshold : 0.65;

      const mockDecisionResult =
        typeof args.mockComplexity === "string" && typeof args.mockFrontierProb === "number"
          ? {
              complexityChoice: args.mockComplexity as "simple" | "moderate" | "complex",
              requiresFrontierProb: Number(args.mockFrontierProb),
            }
          : undefined;

      const evaluation: RoutingEvaluation = await evaluateCostAwareRoute(prompt, {
        forceEconomy,
        forceFrontier,
        frontierEscalationThreshold: threshold,
        mockDecisionResult,
      });

      const claim = {
        type: "x402.gate.economy-route.v1",
        tier: evaluation.tier,
        targetModel: evaluation.targetModel,
        complexityChoice: evaluation.complexityChoice,
        requiresFrontierProb: evaluation.requiresFrontierProb,
        deciderModelUsed: evaluation.deciderModelUsed,
        routingCostMicroUsd: evaluation.routingCostMicroUsd.toString(),
        inputTokensEstimated: evaluation.inputTokensEstimated,
        sha256Prompt: evaluation.sha256Prompt,
        evaluatedAt: evaluation.timestamp,
        keyid: getKeyId(keystorePath),
      };

      const attestation = signDsse(
        "application/vnd.x402.economy-route+json",
        claim,
        keystorePath
      );

      return {
        ok: true,
        evaluation: {
          ...evaluation,
          routingCostMicroUsd: evaluation.routingCostMicroUsd.toString(),
        },
        claim,
        attestation,
      };
    }
  );
}

/**
 * Creates the free MCP preview tool for testing routing decisions without payment.
 */
export function createFreeEconomyRouteTriageTool(
  options: { keystorePath?: string } = {}
): GatewayTool {
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;

  return freeTool(
    {
      name: "economy_route_triage",
      description:
        "Free preview of Cost-Aware Model Routing: classifies prompt complexity into Economy (router/pandaforge) vs Frontier without requiring payment.",
      inputSchema: {
        type: "object",
        properties: {
          prompt: {
            type: "string",
            description: "User prompt to classify",
          },
          threshold: {
            type: "number",
            description: "Escalation threshold (default 0.65)",
          },
        },
        required: ["prompt"],
      },
    },
    async (args) => {
      const prompt = String(args.prompt ?? "");
      const threshold = typeof args.threshold === "number" ? args.threshold : 0.65;
      const evaluation = await evaluateCostAwareRoute(prompt, {
        frontierEscalationThreshold: threshold,
      });

      return {
        ok: true,
        preview: true,
        tier: evaluation.tier,
        targetModel: evaluation.targetModel,
        reason: evaluation.reason,
        complexityChoice: evaluation.complexityChoice,
        requiresFrontierProb: evaluation.requiresFrontierProb,
        deciderModelUsed: evaluation.deciderModelUsed,
        estimatedRoutingCostMicroUsd: evaluation.routingCostMicroUsd.toString(),
        tokensEstimated: evaluation.inputTokensEstimated,
      };
    }
  );
}
