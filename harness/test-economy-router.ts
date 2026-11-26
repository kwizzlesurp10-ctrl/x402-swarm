import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  DEFAULT_X402_PAY_TO,
  MICRO_USD_PER_USD,
} from "../shared/constants.js";
import {
  DECISION_MODELS,
  DEFAULT_DECISION_CHAIN,
  EXECUTION_TIERS,
  calculateDecisionCostMicroUsd,
  estimatePromptTokens,
  evaluateCostAwareRoute,
} from "../shared/cost-aware-router.js";
import { verifyDsse } from "../shared/keystore.js";
import type { X402PaymentSignature } from "../shared/types.js";
import { startLocalFacilitator } from "./local-facilitator.js";
import {
  createFreeEconomyRouteTriageTool,
  createPaidEconomyRouteTool,
} from "../mcps/gate/economy-router.js";

async function runEconomyRouteTests(): Promise<void> {
  console.log("================================================================================");
  console.log("x402 Swarm: Economy Route & Cost-Aware Model Router Verification");
  console.log("================================================================================\n");

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-economy-route-test-"));
  const keystorePath = path.join(tmpDir, "ed25519.pem");
  const intentLogPath = path.join(tmpDir, "intents.jsonl");
  const ledgerPath = path.join(tmpDir, "ledger.jsonl");

  const facilitator = await startLocalFacilitator(0);

  try {
    // -------------------------------------------------------------------------
    // 1. Decision Model Specifications & Micro-USD Integer Rates
    // -------------------------------------------------------------------------
    console.log("1. Verifying Decision Model Specifications & micro-USD rates...");
    assert.equal(DECISION_MODELS.PERPLEXITY_FLASH.id, "perplexity/pplx-decider-flash-v1.3");
    assert.equal(DECISION_MODELS.PERPLEXITY_FLASH.pricePerMillionInputUsd, 0.01);
    assert.equal(DECISION_MODELS.PERPLEXITY_FLASH.microUsdPerMillionInput, 10_000n);

    assert.equal(DECISION_MODELS.LIQUID.id, "liquid/d1.2");
    assert.equal(DECISION_MODELS.LIQUID.pricePerMillionInputUsd, 0.02);
    assert.equal(DECISION_MODELS.LIQUID.microUsdPerMillionInput, 20_000n);

    assert.equal(DECISION_MODELS.MICROSOFT.id, "microsoft/decision-1.1");
    assert.equal(DECISION_MODELS.MICROSOFT.pricePerMillionInputUsd, 0.04);
    assert.equal(DECISION_MODELS.MICROSOFT.microUsdPerMillionInput, 40_000n);
    assert.equal(DECISION_MODELS.MICROSOFT.zdr, true);

    // Rate calculations
    const cost50TokensPerplexity = calculateDecisionCostMicroUsd(50, 10_000n);
    assert.equal(cost50TokensPerplexity, 1n, "50 tokens at $0.01/1M should round to at least 1 micro-USD floor");

    const cost500TokensPerplexity = calculateDecisionCostMicroUsd(500, 10_000n);
    assert.equal(cost500TokensPerplexity, 5n, "500 tokens at $0.01/1M = 5 micro-USD ($0.000005)");

    const cost100kTokensPerplexity = calculateDecisionCostMicroUsd(100_000, 10_000n);
    assert.equal(cost100kTokensPerplexity, 1_000n, "100k tokens at $0.01/1M = 1,000 micro-USD ($0.001)");

    console.log("   ✓ Decision model specs & micro-USD math verified.");

    // -------------------------------------------------------------------------
    // 2. Economy Route Target Configuration
    // -------------------------------------------------------------------------
    console.log("2. Verifying Economy Route target models...");
    assert.equal(EXECUTION_TIERS.ECONOMY.primary, "router/pandaforge");
    assert.ok(EXECUTION_TIERS.ECONOMY.fallbacks.includes("reflection/beam-free"));
    assert.ok(EXECUTION_TIERS.ECONOMY.fallbacks.includes("deepseek/deepseek-v4.1-flash-1017"));
    assert.equal(EXECUTION_TIERS.FRONTIER.primary, "openai/gpt-5.6-luna");
    console.log("   ✓ Economy route target (router/pandaforge) and Frontier targets verified.");

    // -------------------------------------------------------------------------
    // 3. Routing Classification Logic (Routine vs Complex)
    // -------------------------------------------------------------------------
    console.log("3. Testing prompt triage into Economy vs Frontier...");

    // Routine prompt -> Economy
    const simpleEval = await evaluateCostAwareRoute("Translate 'Hello World' to French", {
      mockDecisionResult: {
        complexityChoice: "simple",
        requiresFrontierProb: 0.05,
      },
    });
    assert.equal(simpleEval.tier, "economy");
    assert.equal(simpleEval.targetModel, "router/pandaforge");
    assert.equal(simpleEval.complexityChoice, "simple");

    // Complex prompt -> Frontier
    const complexEval = await evaluateCostAwareRoute(
      "Design a zero-knowledge succinct non-interactive argument of knowledge with formal verification",
      {
        mockDecisionResult: {
          complexityChoice: "complex",
          requiresFrontierProb: 0.92,
        },
      }
    );
    assert.equal(complexEval.tier, "frontier");
    assert.equal(complexEval.targetModel, "openai/gpt-5.6-luna");
    assert.equal(complexEval.complexityChoice, "complex");

    // Overrides
    const forceEconomyEval = await evaluateCostAwareRoute("Deep math inquiry", {
      forceEconomy: true,
    });
    assert.equal(forceEconomyEval.tier, "economy");
    assert.equal(forceEconomyEval.targetModel, "router/pandaforge");

    const forceFrontierEval = await evaluateCostAwareRoute("Say hi", {
      forceFrontier: true,
    });
    assert.equal(forceFrontierEval.tier, "frontier");
    assert.equal(forceFrontierEval.targetModel, "openai/gpt-5.6-luna");

    console.log("   ✓ Prompt triage and manual overrides verified.");

    // -------------------------------------------------------------------------
    // 4. Free Triage Tool Test
    // -------------------------------------------------------------------------
    console.log("4. Testing freeEconomyRouteTriageTool...");
    const freeTool = createFreeEconomyRouteTriageTool({ keystorePath });
    const freeRes = (await freeTool.handler(
      { prompt: "What is the time complexity of binary search?" },
      { headers: {} } as any
    )) as any;

    const freeData = freeRes.data ?? freeRes;
    assert.equal(freeData.ok, true);
    assert.equal(freeData.preview, true);
    assert.ok(freeData.tier === "economy" || freeData.tier === "frontier");
    console.log(`   ✓ Free triage preview succeeded: tier=${freeData.tier}, model=${freeData.targetModel}`);

    // -------------------------------------------------------------------------
    // 5. Paid Economy Route MCP Tool with EIP-3009 Handshake & DSSE Attestation
    // -------------------------------------------------------------------------
    console.log("5. Testing paid_economy_route (100 micro-USD) with x402 payment...");
    const paidEconomyTool = createPaidEconomyRouteTool({
      amountMicroUsd: 100n,
      payTo: DEFAULT_X402_PAY_TO,
      facilitatorUrl: facilitator.url,
      keystorePath,
      intentLogPath,
      ledgerPath,
    });

    // 5a. Unpaid invocation returns 402 challenge
    const unpaidRes = (await paidEconomyTool.handler(
      { prompt: "Write a high-performance hash map in C++" },
      { headers: {} } as any
    )) as any;
    assert.equal(unpaidRes.isError, true, "Unpaid call must trigger 402 error envelope");
    const meta402 = (unpaidRes.meta?.["x402/payment-required"] ?? unpaidRes.data) as any;
    assert.ok(meta402, "Must contain x402 payment-required envelope");
    assert.equal(meta402.x402Version, 2);
    assert.equal(meta402.accepts[0].amount, "100");
    assert.equal(meta402.accepts[0].network, BASE_SEPOLIA_NETWORK);
    assert.equal(meta402.accepts[0].asset, BASE_SEPOLIA_USDC);
    console.log("   ✓ Unpaid request challenged with HTTP 402 (100 micro-USD Base Sepolia USDC).");

    // 5b. Signed EIP-3009 payment invocation
    const payerKey = generatePrivateKey();
    const payerAccount = privateKeyToAccount(payerKey);
    const evmScheme = new ExactEvmScheme(payerAccount);

    const requirement = meta402.accepts[0];
    const mcpPartial = await evmScheme.createPaymentPayload(
      2,
      requirement as unknown as Parameters<
        ExactEvmScheme["createPaymentPayload"]
      >[1]
    );
    const paymentSig: X402PaymentSignature = {
      x402Version: 2,
      accepted: requirement,
      payload: mcpPartial.payload,
    };

    const paymentHeader = JSON.stringify(paymentSig);

    const paidRes = (await paidEconomyTool.handler(
      {
        prompt: "Write a high-performance hash map in C++",
        mockComplexity: "moderate",
        mockFrontierProb: 0.40,
      },
      {
        headers: {
          "x-payment": paymentHeader,
        },
      } as any
    )) as any;

    assert.equal(Boolean(paidRes.isError), false, "Paid call must succeed without error");
    const toolPayload = paidRes.data?.result ?? paidRes.data;
    assert.equal(toolPayload.ok, true);
    assert.equal(toolPayload.evaluation.tier, "economy");
    assert.equal(toolPayload.evaluation.targetModel, "router/pandaforge");
    assert.ok(toolPayload.attestation, "Paid result must include Ed25519 DSSE attestation");

    // 5c. Verify DSSE Attestation
    const verification = verifyDsse(toolPayload.attestation, undefined, keystorePath);
    assert.equal(verification.valid, true, "DSSE attestation must verify cleanly against keystore");
    const payload = (verification.decodedPayload as any)?.claim ?? (verification.decodedPayload as any);
    assert.equal(payload.tier, "economy");
    assert.equal(payload.targetModel, "router/pandaforge");
    console.log("   ✓ Paid settlement verified: 100 micro-USD settled, DSSE signature verified.");

    console.log("\n================================================================================");
    console.log("✓ ALL 5 ECONOMY ROUTE VERIFICATION CHECKS PASSED CLEANLY!");
    console.log("================================================================================\n");
  } finally {
    await facilitator.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runEconomyRouteTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
