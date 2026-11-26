import fs from "node:fs";
import path from "node:path";
import { evaluateCostAwareRoute } from "../shared/cost-aware-router.js";

// Read API Key from .env if present
const envPath = path.resolve(process.cwd(), ".env");
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, "utf8");
  for (const line of envContent.split("\n")) {
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) {
      const key = match[1].trim();
      const val = match[2].trim().replace(/^["']|["']$/g, "");
      process.env[key] = val;
    }
  }
}

const apiKey = process.env.AI_GATEWAY_API_KEY;
if (!apiKey) {
  console.error("Missing AI_GATEWAY_API_KEY in environment or .env file.");
  process.exit(1);
}

async function runLiveTest() {
  console.log("================================================================================");
  console.log("x402 Swarm: Live Vercel AI Gateway Cost-Aware Routing Test");
  console.log("================================================================================\n");

  // Test 1: Routine Simple Prompt
  console.log("--- TEST 1: Routine Simple Prompt ---");
  const routinePrompt = "Calculate the sum of 15 and 27, and explain in one sentence.";
  console.log(`Prompt: "${routinePrompt}"`);

  const t0 = Date.now();
  const res1 = await evaluateCostAwareRoute(routinePrompt, { aiGatewayApiKey: apiKey });
  const latency1 = Date.now() - t0;

  console.log(`Decision Model: ${res1.deciderModelUsed}`);
  console.log(`Probability of Complexity: ${(res1.requiresFrontierProb * 100).toFixed(2)}%`);
  console.log(`Complexity Choice: ${res1.complexityChoice}`);
  console.log(`Selected Tier: ${res1.tier.toUpperCase()}`);
  console.log(`Target Model: ${res1.targetModel}`);
  console.log(`Routing Step Cost: ${res1.routingCostMicroUsd.toString()} micro-USD (~$0.000001)`);
  console.log(`Routing Latency: ${latency1}ms\n`);

  // Execute Economy Route
  console.log(`Executing Economy Route on '${res1.targetModel}' via Vercel AI Gateway...`);
  const execT0 = Date.now();
  const execResp1 = await fetch("https://ai-gateway.vercel.sh/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: res1.targetModel,
      messages: [{ role: "user", content: routinePrompt }],
      max_tokens: 60,
    }),
  });

  const execLatency1 = Date.now() - execT0;
  if (execResp1.ok) {
    const execData1 = (await execResp1.json()) as any;
    const content = execData1.choices?.[0]?.message?.content || "(empty)";
    const modelUsed = execData1.model || res1.targetModel;
    const tokens = execData1.usage?.total_tokens ?? "N/A";
    const cost = execData1.usage?.cost ?? "0";
    console.log(`✓ Economy Response from ${modelUsed} (${execLatency1}ms, ${tokens} tokens, cost=$${cost}):`);
    console.log(`  "${content.trim()}"\n`);
  } else {
    console.log(`Economy execution returned status ${execResp1.status}`);
  }

  // Test 2: Complex Frontier Prompt
  console.log("--- TEST 2: Complex Frontier Prompt ---");
  const complexPrompt =
    "Synthesize a memory-safe lock-free concurrent queue in C++20 with atomic hazard pointers, formal memory order invariants, and ABA prevention.";
  console.log(`Prompt: "${complexPrompt}"`);

  const t1 = Date.now();
  const res2 = await evaluateCostAwareRoute(complexPrompt, { aiGatewayApiKey: apiKey });
  const latency2 = Date.now() - t1;

  console.log(`Decision Model: ${res2.deciderModelUsed}`);
  console.log(`Probability of Complexity: ${(res2.requiresFrontierProb * 100).toFixed(2)}%`);
  console.log(`Complexity Choice: ${res2.complexityChoice}`);
  console.log(`Selected Tier: ${res2.tier.toUpperCase()}`);
  console.log(`Target Model: ${res2.targetModel}`);
  console.log(`Routing Step Cost: ${res2.routingCostMicroUsd.toString()} micro-USD (~$0.000001)`);
  console.log(`Routing Latency: ${latency2}ms\n`);

  console.log("================================================================================");
  console.log("✓ LIVE TEST COMPLETED SUCCESSFULLY!");
  console.log("================================================================================");
}

runLiveTest().catch((err) => {
  console.error("Live test failed:", err);
  process.exit(1);
});
