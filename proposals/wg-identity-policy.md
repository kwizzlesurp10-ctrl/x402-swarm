# RFC: x402 Identity & Spend Policy Working Group

- **Document:** `x402-wg-identity-policy-01`
- **Status:** Draft Proposal (Implemented & Verified in `x402-swarm`)
- **Author:** Keith S. (`kwizzlesurp10@gmail.com`)
- **Organization:** `kwizzlesurp.com` · `Sevtech` · `Dragon&PandaDuo` (`https://kwizzlesurp.com`, Minneapolis, MN, USA)
- **Reference Modules:** `shared/constants.ts`, `shared/types.ts`, `shared/policy.ts`, `shared/keystore.ts`, `shared/x402-adapter.ts`, `mcps/policy/identity.ts`, `mcps/policy/server.ts`

---

## 1. Abstract

Autonomous AI agents paying HTTP `402` challenges without human checkout prompts cannot rely on loose floating-point budgets or post-hoc alerting. A single malformed `PAYMENT-REQUIRED` header, floating-point rounding drift, unit confusion between 6-decimal USDC and Lightning millisatoshis (`msat`), or compromised payee rotation can drain an agent wallet before a transaction settles.

This RFC specifies the identity and spend-control architecture implemented in `x402-swarm`:
1. A mandatory pre-sign `onPaymentRequested` hook executed prior to wallet/HTLC signing.
2. Strictly integer `bigint` micro-USD evaluation with deterministic integer ceiling conversion for Lightning `msat`/`sat` challenges.
3. Per-call and sliding rolling-window spend caps with idempotent spend accounting.
4. Persisted mode `0600` Ed25519 DSSE capability attestations and policy verdict envelopes.
5. Immediate agent identity revocation and unconditional retired-payee blocking.

---

## 2. Pre-Sign `onPaymentRequested` Policy Hook

Client payment adapters MUST evaluate spend policy **before** generating any cryptographic signature or releasing any Lightning preimage:

1. **Disabling Weak Built-In Float Controls:**
   - In `createX402FetchClient` (`shared/x402-adapter.ts`) and `runLightningMcpToolCall` (`mcps/lightning/client.ts`), default SDK spend controls are explicitly replaced (`client.setSpendControls(false)`) with a deterministic `SpendPolicyEngine` bound to `client.onBeforePaymentCreation`.
2. **Pre-Sign Interception (`onBeforePaymentCreation`):**
   - Upon receiving a `402 PAYMENT-REQUIRED` challenge (HTTP) or `_meta["x402/payment-required"]` (MCP), `client.onBeforePaymentCreation` calls `SpendPolicyEngine.onPaymentRequested(req, { agentId, nowMs })`.
   - If `decision.allowed === false`, the hook returns `{ abort: true, reason }` and throws `SpendPolicyError` (`shared/policy.ts`). Zero wallet signatures are created and zero server intents are committed.
   - Verified in `registry/verification-report.json` (`gateB_spendCapsAndRetiredPayee`):
     - `cap_enforced: true`
     - `evmCapBlockReason`: `"Failed to create payment payload: Payment creation aborted: Requested 1000 micro-USD exceeds maxPerCallMicroUsd 500"`
     - `harness/verify-swarm.ts` asserts `lightningServer.getIntentCount() === intentsBeforeCap` after both EVM and Lightning cap rejections.
3. **Evaluation Order (`SpendPolicyEngine.onPaymentRequested` in `shared/policy.ts`):**
   1. **Retired Payee Check:** `isRetiredPayTo(req.payTo)` unconditionally blocks retired payee addresses with `allowed: false`, `evaluatedMicroUsd: "0"`, `capEnforced: true`.
   2. **Network Allowlist:** If `allowedNetworks` is configured and non-empty, `req.network` MUST be listed.
   3. **Payee Allowlist:** If `allowedPayees` is configured and non-empty, `req.payTo.trim().toLowerCase()` MUST match an allowed address (and `allowedPayees` registration itself MUST reject retired payees).
   4. **Integer Cost Evaluation:** `evaluateRequirementMicroUsd(req, btcMicroUsdPerSat)`.
   5. **Per-Call Ceiling:** Reject if `costMicroUsd > config.maxPerCallMicroUsd`.
   6. **Rolling-Window Ceiling:** Reject if `currentWindowSpend + costMicroUsd > config.maxRollingWindowMicroUsd`.
4. **Post-Creation Spend Recording (`onAfterPaymentCreation`):**
   - `SpendPolicyEngine.recordSpend` re-runs `assertAllowed` and records `{ timestampMs, amountMicroUsd }` once payment payload creation succeeds.

---

## 3. Integer Micro-USD & Lightning `msat` Ceiling Conversion

All monetary math MUST use arbitrary-precision integers (`bigint`). JavaScript `Number` floats are forbidden for amounts, budgets, or exchange conversions.

- **Canonical USD Unit:** `MICRO_USD_PER_USD = 1_000_000n` (`$1.00 = 1,000,000` micro-USD; `$0.001 = 1000` micro-USD).
- **EVM USD-Pegged Assets (`eip155:*`):** 6-decimal USDC (`0x036CbD53842c5426634e7929541eC2318f3dCF7e` on Base Sepolia, `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` on Base Mainnet) maps `1:1` to integer micro-USD (`BigInt(req.amount)`).
- **Lightning (`scheme === "lightning"`, `network.startsWith("lightning:")`, or `asset` in `{"MSAT", "SAT", "BTC_SAT"}`):**
  1. Resolve `explicitMsat` (`bigint`) from `req.extra.amountMsat` if present, else `rawAmount` when `asset === "MSAT"`, else `rawAmount * MSAT_PER_SAT` (`1_000n`).
  2. Convert to micro-USD using **integer ceiling division** (`evaluateRequirementMicroUsd` in `shared/policy.ts`, lines 59–60):
     ```ts
     (explicitMsat * btcMicroUsdPerSat + (MSAT_PER_SAT - 1n)) / MSAT_PER_SAT
     ```
     With `DEFAULT_BTC_MICRO_USD_PER_SAT = 90_000n` (`shared/constants.ts`), a `12000` msat invoice (`12` sats) evaluates to `1_080_000n` micro-USD (`$1.080000`), matching the verified `Lightning-402` settlement records in `registry/testnet-ledger.jsonl`.
  3. **Rationale for Ceiling Rounding:** Integer floor division could let an attacker charge fractional micro-USD amounts repeatedly while reporting `0` policy cost; integer ceiling division guarantees conservative upper-bound budget enforcement.

---

## 4. Rolling-Window Spend Caps & Idempotent Accounting

`SpendPolicyConfig` (`shared/types.ts`) defines:
- `agentId?: string`
- `maxPerCallMicroUsd: bigint`
- `maxRollingWindowMicroUsd: bigint`
- `windowMs: number`
- `allowedNetworks?: string[]`
- `allowedPayees?: string[]`
- `btcMicroUsdPerSat?: bigint`

`SpendPolicyEngine.pruneAndSum(agentId, nowMs)` computes `cutoff = nowMs - windowMs`, retains only entries where `entry.timestampMs > cutoff`, and accumulates `amountMicroUsd` via `bigint` addition.

In the `Policy / Identity` MCP service (`mcps/policy/identity.ts`, `mcps/policy/server.ts`, manifest `registry/manifests/policy-identity.json`, port `4025`):
- `PolicyIdentityStore` persists agent policies, spend history, committed idempotency keys, and revocations to `statePath` when configured.
- `recordAgentSpend` (exposed via MCP tool `record_agent_spend`) deduplicates spend commits idempotently by `(agentId, txHash / intentId)` so retried tool calls or facilitator callbacks never double-count against an agent's rolling window budget.

---

## 5. Ed25519 DSSE Capability Attestations & Verdict Envelopes

Every policy issuer and verification boundary MUST persist its signing key rather than generating ephemeral in-memory keys (`shared/keystore.ts`):
- **Persisted `0600` Keystore:** `loadOrCreateKeystore(DEFAULT_KEYSTORE_PATH)` stores PKCS#8 Ed25519 private keys at `/home/keef/x402-swarm/.keystore/ed25519.pem` with directory mode `0o700` and file mode `0o600` (verified in `registry/verification-report.json`: `keyid: "ed25519:76921d7540c827b1"`, `modeOctal: "0600"`).
- **Key ID Derivation:** `keyid = "ed25519:" + sha256(spkiDer).slice(0, 16)`.
- **DSSE v1 Pre-Authentication Encoding (`dssePae`):**
  ```text
  "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payloadBytes) + " " + payloadBytes
  ```
- **Standardized Payload Types (`mcps/policy/identity.ts`):**
  - `AGENT_IDENTITY_DSSE_PAYLOAD_TYPE` (`"application/vnd.x402.agent-identity+json"`): Signed capability attestation (`issueAgentIdentity` / `register_agent_policy`) binding `version: 1`, `attestationId`, `agentId`, optional `evmAddress`, integer caps (`maxPerCallMicroUsd`, `maxRollingWindowMicroUsd`, `windowMs`), `allowedNetworks`, `allowedPayees`, `btcMicroUsdPerSat`, `issuedAt`, `expiresAt`, and `keyid`.
  - `POLICY_VERDICT_DSSE_PAYLOAD_TYPE` (`"application/vnd.x402.policy-verdict+json"`): Signed `PolicyEvaluationResult` (`evaluatePaymentRequest` / `evaluate_payment_request`) wrapping `SpendDecision` (`allowed`, `reason`, `evaluatedMicroUsd`, `remainingWindowMicroUsd`, `network`, `payTo`, `scheme`, `capEnforced`, `agentId`, `revoked`, `expired`).

---

## 6. Revocation & Unconditional Retired-Payee Rejection

1. **Immediate Revocation (`mcps/policy/identity.ts` & `mcps/policy/server.ts`):** Calling `revokeAgentIdentity` (`revoke_agent_identity`) marks the `agentId` revoked immediately (recording `revokedAt`, optional `reason`, and adding `attestationId` to `revokedAttestationIds`). Subsequent `verifyAgentIdentity` (`verify_agent_identity`) and `evaluatePaymentRequest` (`evaluate_payment_request`) calls return `revoked: true` and `allowed: false` regardless of remaining window budget or `expiresAt`.
2. **Expiration Enforcement:** Attestations past `expiresAt` MUST be rejected (`expired: true`, `allowed: false`).
3. **Retired Payee Block:** Both identity registration (`allowedPayees`) and runtime evaluation (`onPaymentRequested` in `shared/policy.ts` and `evaluatePaymentRequest` in `mcps/policy/identity.ts`) unconditionally reject retired payees via `isRetiredPayTo`, while servers enforce HTTP `403` (`retired_payee_rejected`) at the boundary (`mcps/lightning/server.ts`, `mcps/gate/adapter.ts`, `harness/local-facilitator.ts`).
