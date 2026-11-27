# x402 Working Group RFC Proposals

Reference specifications extracted from the production `x402-swarm` 6-server MCP implementation (`shared/`, `mcps/`, `harness/`, `registry/`).

- **Author:** Keith S. (`kwizzlesurp10@gmail.com`)
- **Organization:** `kwizzlesurp.com` · `Sevtech` · `Dragon&PandaDuo` (`https://kwizzlesurp.com`, Minneapolis, MN, USA)
- **Canonical `payTo`:** `0x0d25A44f74868eCE53B305C97139CF4B62963410`
- **Payee Integrity:** Unconditional block on retired legacy seller wallets via hash guard

## RFC Index

| RFC | Working Group | Focus | Reference Implementation |
|---|---|---|---|
| [wg-domain-discovery.md](./wg-domain-discovery.md) | x402 Domain Discovery WG | Browser `GET /mcp` 200 JSON server card, `/.well-known/x402` manifest schema, `validate_endpoint` 5-check rubric, retired-payee guard | `shared/mcp-http.ts`, `mcps/discovery/validator.ts`, `mcps/discovery/indexer.ts`, `mcps/discovery/server.ts`, `harness/probe-fleet.ts` |
| [wg-identity-policy.md](./wg-identity-policy.md) | x402 Identity & Spend Policy WG | Pre-sign `onPaymentRequested` hook, integer micro-USD & msat ceiling conversion, rolling-window caps, Ed25519 DSSE capability & verdict envelopes, immediate revocation | `shared/policy.ts`, `shared/keystore.ts`, `shared/x402-adapter.ts`, `mcps/policy/identity.ts`, `mcps/policy/server.ts` |
| [wg-tax-settlement.md](./wg-tax-settlement.md) | x402 Tax & Settlement WG | Strict `bigint` micro-USD/msat ledger, `(network, txHash)` idempotency, 4-step replay-safe settlement order, integer floor `feeBps`, RFC 4180 CSV + Form 8949 + SHA-256 chain digest + DSSE audit bundle | `mcps/settlement/ledger.ts`, `mcps/settlement/server.ts`, `mcps/tax/exporter.ts`, `mcps/tax/server.ts`, `mcps/lightning/server.ts`, `mcps/gate/adapter.ts` |

## Adoption Checklist

### 1. Domain Discovery & Registry Compliance (`wg-domain-discovery.md`)
- [x] Serve `200 OK` `application/json` server cards on plain `GET /mcp` and `GET /mcp/` when `Accept` omits `text/event-stream` (`startMcpHttpServer` in `shared/mcp-http.ts`).
- [x] Route `GET /mcp` with `Accept: text/event-stream` to SSE and `POST /mcp` to JSON-RPC 2.0 (`initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`).
- [x] Serve `GET /.well-known/x402` (`200 OK` JSON) with `x402Version: 2`, `mcpEndpoint`, `paidEndpoint`/`endpoints[]`, `schemes[]`, CAIP-2 `networks[]`, `payTo`, and `accepts[]`.
- [x] Validate `server.json` files against `MCP_REGISTRY_SCHEMA` (`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`) with `description.length <= 100` (`mcps/*/server.json`, checked by `harness/verify-swarm.ts`).
- [x] Enforce the 5-probe `validateEndpoint` rubric (`well_known_x402`, `mcp_get_card`, `mcp_initialize_and_tools`, `paid_402_challenge`, `retired_payee_guard`) and fail unconditionally (`score: 0`, `valid: false`) if any retired legacy payee appears anywhere in discovery or `402` challenges.
- [x] Keep unprobed fleet and local seed manifests explicitly tagged `"status": "seeded_pending_live_probe"` in `registry/manifests/*.json` until live probes run (`harness/probe-fleet.ts`).

### 2. Identity & Spend Policy (`wg-identity-policy.md`)
- [x] Disable unguarded client spend defaults (`client.setSpendControls(false)`) and enforce `SpendPolicyEngine.onPaymentRequested` in `onBeforePaymentCreation` before signing any EIP-3009 authorization or paying any Lightning invoice (`shared/x402-adapter.ts`, `shared/policy.ts`).
- [x] Reject retired payees unconditionally in both client policy and server admission (HTTP `403`).
- [x] Use integer `bigint` micro-USD (`1 USD = 1_000_000n`) and deterministic integer ceiling Lightning conversion (`(explicitMsat * btcMicroUsdPerSat + 999n) / 1000n`) in `evaluateRequirementMicroUsd`.
- [x] Enforce per-call (`maxPerCallMicroUsd`) and sliding-window (`maxRollingWindowMicroUsd`, `windowMs`) caps with idempotent spend recording.
- [x] Sign agent capability attestations (`application/vnd.x402.agent-identity+json`) and policy verdicts (`application/vnd.x402.policy-verdict+json`) using DSSE v1 (`dssePae`) backed by a persisted mode `0600` Ed25519 keystore (`shared/keystore.ts`, keyid `ed25519:76921d7540c827b1`), with immediate revocation (`PolicyIdentityStore` in `mcps/policy/identity.ts`, `mcps/policy/server.ts`).

### 3. Tax & Settlement Integrity (`wg-tax-settlement.md`)
- [x] Enforce the strict 4-step order of operations: (1) validate payload, time window, and payee policy; (2) commit append-only intent record and reject replays with HTTP `409`; (3) verify & settle via facilitator (`https://x402.org/facilitator` with EIP-3009 `extra: { name: "USDC", version: "2", assetTransferMethod: "eip3009" }`) or Lightning preimage (`SHA256(preimage) === paymentHash`); (4) emit DSSE-signed `SettlementReceipt` + `PAYMENT-RESPONSE` (`mcps/lightning/server.ts`, `mcps/gate/adapter.ts`).
- [x] Never expose Lightning preimages in HTTP `402` responses or server invoice stores (`issueHtlcInvoice` vs `createTestLightningSimulator` in `mcps/lightning/bolt11.ts`).
- [x] Store `SettlementReceipt` records in append-only JSONL (`registry/testnet-ledger.jsonl`) with stringified integer `amountMicroUsd` / `amountMsat` and deduplicate idempotently on `(network, txHash)`, `(network, nonce)`, and `(network, paymentHash)` (`ingestSettlement` in `mcps/settlement/ledger.ts`).
- [x] Compute fees strictly via integer floor math `(amountMicroUsd * feeBps) / 10_000n` (`computeFeeMicroUsd`) and reconcile with `reconcileSettlements` and Merkle-rooted `createSettlementBatch`.
- [x] Export RFC 4180 CSV, JSONL, Form 8949 summaries, SHA-256 row chain digests (`x402-tax-chain-v1`), and self-verifying Ed25519 DSSE audit bundles (`exportTaxLedger`, `generateAuditBundle`, `verifyAuditBundle` in `mcps/tax/exporter.ts`).
