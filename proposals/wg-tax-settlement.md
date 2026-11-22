# RFC: x402 Tax & Settlement Working Group

- **Document:** `x402-wg-tax-settlement-01`
- **Status:** Draft Proposal (Implemented & Verified in `x402-swarm`)
- **Author:** Keith S. (`kwizzlesurp10@gmail.com`)
- **Organization:** `kwizzlesurp.com` · `Sevtech` · `Dragon&PandaDuo` (`https://kwizzlesurp.com`, Minneapolis, MN, USA)
- **Reference Modules:** `shared/types.ts`, `shared/constants.ts`, `shared/keystore.ts`, `mcps/gate/adapter.ts`, `mcps/lightning/server.ts`, `mcps/lightning/bolt11.ts`, `mcps/settlement/ledger.ts`, `mcps/settlement/server.ts`, `mcps/tax/exporter.ts`, `mcps/tax/server.ts`

---

## 1. Abstract

High-frequency x402 micropayments across EVM L2 USDC (`eip155:84532` / `eip155:8453`) and Bitcoin Lightning (`lightning:testnet` / `lightning:mainnet`) break traditional floating-point accounting, naive retry logic, and unsigned CSV exports. Sub-cent micropayments (`$0.001 = 1000` micro-USD) accumulate float drift over thousands of transactions, while verify-then-serve-then-settle flows enable crash/replay double-spends or preimage leakage.

This RFC standardizes the settlement and tax-compliance architecture verified in `x402-swarm`:
1. Strict integer `bigint` micro-USD and `msat` `SettlementReceipt` ledger schema.
2. Idempotent `(network, txHash)` ingestion with `(network, nonce)` and `(network, paymentHash)` replay protection.
3. Strict 4-step replay-safe order of operations for paid HTTP and MCP tool execution.
4. Integer floor `feeBps` reconciliation and Merkle-rooted DSSE settlement batches.
5. RFC 4180 CSV, Form 8949 grouped summaries, SHA-256 chain digests, and self-verifying Ed25519 DSSE tax audit bundles.

---

## 2. Strict Integer Micro-USD / `msat` Ledger Schema

All ledger records MUST represent monetary quantities as non-negative integer strings (`/^\d+$/`) and perform all arithmetic in `bigint` (`mcps/settlement/ledger.ts`):

- **Forbidden Floats:** `parseMicroUsd(val)` rejects any decimal or floating-point input; `formatMicroUsd(microUsd)` formats `1 USD = 1_000_000n` as exact 6-decimal strings (e.g., `1000n -> "0.001000"`, `2161000n -> "2.161000"`) using `bigint` division and modulo (`/` and `%`).
- **`SettlementReceipt` Schema (`SettlementReceiptSchema` in `mcps/settlement/ledger.ts` & `shared/types.ts`):**
  - `id`: unique intent identifier (e.g., `"intent_019e5562-64b1-46d9-b301-b763ad7ab75c"`)
  - `amountMicroUsd`: non-negative integer string (`/^\d+$/`)
  - `amountMsat`: optional non-negative integer string (`/^\d+$/`) for Lightning rails
  - `network`: CAIP-2 chain identifier (`"eip155:84532"`, `"lightning:testnet"`, etc.)
  - `scheme`: `"exact"` | `"lightning"`
  - `asset`: token contract (`"0x036CbD53842c5426634e7929541eC2318f3dCF7e"`) or `"MSAT"`
  - `txHash`: on-chain tx hash (e.g., `"0x4d4f49caf594e8264b63d5f2da5d44c0477da26c53beeb173673c4d4e2cd6340"`), local facilitator hash (`"local-eip3009-..."`), or `"ln:<paymentHash>"`
  - `payer`: verified payer address or Lightning payer ID
  - `payTo`: verified payee address (never `RETIRED_X402_PAY_TO`)
  - `resource`, `toolName`, `settledAt` (valid ISO-8601 UTC timestamp), `facilitator`
  - `mode`: `"live_testnet" | "local_facilitator" | "lightning_preimage"`
  - Optional `nonce`, `paymentHash`, `batchId`, `dsse` (`DsseEnvelope`)
- **Immutable Canonical Payload (`canonicalReceiptPayload`):** Extracts sorted-key fields excluding `batchId` and `dsse`, ensuring post-ingestion batch assignment (`batchId`) never invalidates the receipt's original Ed25519 DSSE signature.
- **Storage Format:** Append-only JSONL (`registry/testnet-ledger.jsonl`).

---

## 3. `(network, txHash)` Idempotency & Duplicate Prevention

`ingestSettlement` in `mcps/settlement/ledger.ts` enforces:
1. **Schema & Integer Validation:** Validates `SettlementReceiptSchema`, `BigInt` micro-USD / `msat` bounds, and rejects `RETIRED_X402_PAY_TO` (`0xAB745e5F576667037696e78ba7dA28E193E4423D`).
2. **DSSE Integrity:** If `receipt.dsse` is present, `verifySettlementReceipt` validates the Ed25519 DSSE signature and exact field consistency against `canonicalReceiptPayload` (or requires valid DSSE when `requireValidDsse: true`); otherwise signs with the persisted `0600` keystore (`RECEIPT_DSSE_PAYLOAD_TYPE = "application/vnd.x402.settlement-receipt+json"`).
3. **Multi-Key Deduplication (`isDuplicateReceipt`):** Rejects duplicate insertion idempotently (`{ ingested: false, duplicate: true, receipt: existingMatch }`) whenever:
   - `(existing.network === candidate.network && identifiersEqual(existing.txHash, candidate.txHash))` (case-insensitive for `0x...` hex identifiers), OR
   - `(existing.network === candidate.network && existing.nonce === candidate.nonce)` when `nonce` is present, OR
   - `(existing.network === candidate.network && identifiersEqual(existing.paymentHash, candidate.paymentHash))` when `paymentHash` is present.

---

## 4. Strict 4-Step Replay-Safe Order of Operations

Paid servers MUST NOT use verify-then-serve-then-settle. Reference servers (`processPaymentSubmission` in `mcps/lightning/server.ts` and `paidTool` / `ReplayGuard` in `mcps/gate/adapter.ts`) enforce the strict 4-step sequence:

1. **Step 1 — Validate Structure, Authorization Window, and Payee Policy:**
   - Require `x402Version === 2`, non-empty `accepted` and `payload`.
   - Check `isRetiredPayTo` across `accepted.payTo`, `authorization.to`, and `permit2Authorization.witness.to`; reject retired payees immediately with HTTP `403` (`retired_payee_rejected`).
   - Verify `accepted.payTo` matches server `payTo`, `amount >= requiredPrice`, and validity window (`validAfter <= now < validBefore` for EIP-3009, `now < deadline` for Permit2, or `expiresAtUnix > now` for BOLT11).
   - For Lightning, verify `BOLT11` decoding (`decodeLightningInvoice`), `paymentHash` match, and match against the server's `issuedInvoices` table (which NEVER stores preimages; `issueHtlcInvoice` keeps preimages isolated from HTTP `402` responses and server invoice tables).
2. **Step 2 — Commit Append-Only Intent Record (Replay Gate):**
   - Check in-memory and log-recovered `consumedKeys` (`evm:<network>:<from>:<nonce>` or `ln:hash:<paymentHash>` / `ln:preimage:<preimage>`).
   - If any replay key exists, abort immediately with HTTP `409` (`replay_rejected`) — verified in `registry/verification-report.json` (`lightning_replay_rejected_status: 409`, `local_eip3009_replay_rejected_status: 409`).
   - Otherwise add keys to `consumedKeys` and append an `intent_committed` JSONL record BEFORE verifying/settling.
3. **Step 3 — Verify & Settle:**
   - **EVM `exact`:** Call `FacilitatorClient(facilitatorUrl).verify(submitted, serverRequirements)` followed by `.settle(submitted, serverRequirements)`. Base Sepolia USDC (`eip155:84532`, `0x036CbD53842c5426634e7929541eC2318f3dCF7e`) requirements MUST include `extra: { name: "USDC", version: "2", assetTransferMethod: "eip3009" }` for `ExactEvmScheme`.
   - **Lightning `lightning`:** Verify `verifyLightningPreimage(preimage, paymentHash)` (`crypto.timingSafeEqual` on `SHA256(preimage) === paymentHash`), producing `txHash = "ln:<paymentHash>"`.
4. **Step 4 — Emit Signed Receipt & Serve Response:**
   - Append `intent_settled` and DSSE-signed `SettlementReceipt` (`application/vnd.x402.settlement+json`), then return HTTP `200` with `PAYMENT-RESPONSE` header (`encodePaymentResponseHeader`) / `_meta["x402/payment-response"]` and the paid tool/endpoint payload.

---

## 5. Integer Floor `feeBps`, Reconciliation, & Merkle Batching

1. **Basis-Point Fee Calculation (`parseFeeBps`, `computeFeeMicroUsd` in `mcps/settlement/ledger.ts`):**
   - `feeBps` MUST be an integer in `[0, 10000]`.
   - Fee calculation uses exact integer floor division:
     ```ts
     feeMicroUsd = (amountMicroUsd * feeBps) / 10_000n
     netMicroUsd = amountMicroUsd - feeMicroUsd
     ```
2. **Reconciliation (`reconcileSettlements`):**
   - Accumulates `totalGrossMicroUsd`, `totalFeeMicroUsd`, `totalNetMicroUsd`, `totalMsat`, and deterministic sorted breakdowns `byNetwork` and `byScheme`.
   - Cross-checks against `expectedReceipts`, reporting `matchedIds`, `missingExpectedIds`, `unexpectedLedgerIds`, and `amountMismatches` (`differenceMicroUsd`).
3. **Merkle Settlement Batches (`createSettlementBatch`):**
   - Computes leaf hashes `hashReceiptLeaf(r) = sha256Hex(canonicalJson(canonicalReceiptPayload(r)))` and deterministic binary Merkle root `computeMerkleRoot(leafHashes)` (duplicating an odd trailing leaf, matching Bitcoin-style binary pairing).
   - Computes `sha256Digest` over `summaryCore`, signs `BATCH_DSSE_PAYLOAD_TYPE` (`"application/vnd.x402.settlement-batch+json"`), atomically tags included receipts with `batchId` via `atomicWriteFile`, and appends the manifest to `<ledgerPath>.batches.jsonl`.
   - Verified in `registry/testnet-ledger.jsonl.batches.jsonl`: `batch-verify-001` (`receiptCount: 3`, `feeBps: "250"`, `totalGrossMicroUsd: "2161000"`, `totalFeeMicroUsd: "54025"`, `totalNetMicroUsd: "2106975"`, `totalMsat: "24000"`, `merkleRoot: "525a1fdd654acc38f088505f75e4dd44a942e13f55034ad85e2d1cbad80b5325"`).

---

## 6. RFC 4180 CSV, Form 8949 Summary, SHA-256 Chain Digest & DSSE Audit Bundle

Implemented in `mcps/tax/exporter.ts` and exposed by `mcps/tax/server.ts`:

1. **Deterministic Ordering:** Receipts are sorted lexicographically by `${settledAt}|${network}|${txHash}|${id}` and optionally filtered by UTC `taxYear`.
2. **RFC 4180 CSV (`TAX_CSV_HEADERS`):** CRLF-delimited CSV with 16 canonical columns:
   `date_utc,tx_hash,network,scheme,asset,payer,pay_to,gross_micro_usd,gross_usd,amount_msat,fee_micro_usd,net_micro_usd,net_usd,tax_category,batch_id,receipt_verified`
   where `tax_category` is `"x402_lightning_micropayment_revenue"` or `"x402_evm_micropayment_revenue"`.
3. **Form 8949 Summary (`form8949_summary`):** Aggregates `transactionCount`, `grossMicroUsd`, `grossUsd`, `feeMicroUsd`, `netMicroUsd`, `netUsd`, `amountMsat`, `verifiedCount`, `unverifiedCount`, `firstSettledAt`, and `lastSettledAt` grouped by `(taxYear, network, asset, scheme)`.
4. **SHA-256 Record Chain Digest (`computeRowChainDigest`):**
   - Initialized to `chain = sha256Hex("x402-tax-chain-v1")`.
   - For each ordered row: `chain = sha256Hex(chain + "\n" + JSON.stringify(orderedColumnValues))`.
5. **Tamper-Evident DSSE Audit Bundle (`generateAuditBundle` & `verifyAuditBundle`):**
   - Signs `TAX_AUDIT_DSSE_PAYLOAD_TYPE` (`"application/vnd.x402.tax-audit+json"`) containing `version`, `taxYear`, `feeBps`, `generatedAt`, `recordCount`, `csvDigest`, `form8949Summary`, `recordChainDigest`, and `bundleDigest` (`sha256Hex(canonicalJson(bundleCore))`).
   - `verifyAuditBundle` validates the Ed25519 DSSE signature, matching `keyid`, `bundleDigest`, `csvDigest`, CSV header schema, row-level `recordChainDigest`, and exact CSV-to-Form-8949 `BigInt` total equivalence (failing on even a 1-character mutation).
