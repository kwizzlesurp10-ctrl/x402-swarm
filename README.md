# x402 Swarm

Production 6-server x402 v2 Model Context Protocol (MCP) slate, verification harness, fleet manifests, and Working Group RFC specifications.

**Author & Maintainer:** **Keith S.** · **`kwizzlesurp.com` · `Sevtech` · `Dragon&PandaDuo`**
**Website:** <https://kwizzlesurp.com> · **Contact:** `kwizzlesurp10@gmail.com` · **Location:** Minneapolis, MN, USA

<a href="https://24klabs.ai/listing/us-city-open-data-compliance-network"><img src="https://24klabs.ai/card.svg?resource=https%3A%2F%2Fx402-mcp.onrender.com%2F.well-known%2Fx402" alt="US City Open-Data Compliance Network on the 24K Labs curated list"></a>

[![x402-index](https://x402.fuchss.app/badge.svg?resource=https%3A%2F%2Fx402-mcp.onrender.com%2F.well-known%2Fx402)](https://x402.fuchss.app/endpoint?resource=https%3A%2F%2Fx402-mcp.onrender.com%2F.well-known%2Fx402)

---

## Six-Server MCP Slate

Every server exposes Streamable HTTP MCP (`POST /mcp` JSON-RPC 2.0 + SSE `GET /mcp`), plain browser/crawler `200 OK` `application/json` server cards on `GET /mcp` and `GET /mcp/`, and `GET /.well-known/x402` metadata (`shared/mcp-http.ts`).

| Server | Path | Default Port | Manifest | Capabilities & Rails |
|---|---|---|---|---|
| **402-Gate** | `mcps/gate/` | `4020` | [402-gate.json](registry/manifests/402-gate.json) | Universal `paidTool` & `createPaidMcpGateway` paywall on Base Sepolia USDC (`eip155:84532` `exact`): `gate_pricing_manifest` (free), `paid_json_transform` (`1000` micro-USD = `$0.001`), `paid_hash_attest` (`1500` micro-USD = `$0.0015`). |
| **Lightning-402** | `mcps/lightning/` | `4021` | [lightning-402.json](registry/manifests/lightning-402.json) | Dual-rail Base Sepolia USDC (`exact`) + Bitcoin Lightning BOLT11 preimage (`lightning:testnet`) server (`/api/v1/oracle`, `/api/v1/echo`, `lightning_quote_invoice`, `paid_lightning_echo`, `paid_satoshi_oracle`). |
| **Discovery** | `mcps/discovery/` | `4022` | [discovery.json](registry/manifests/discovery.json) | Endpoint validator (`validate_endpoint`), atomic catalog registrar (`register_endpoint`), integer-price search (`search_resources`, `list_catalog`), and retired-payee guard. |
| **Settlement Ops** | `mcps/settlement/` | `4023` | [settlement-ops.json](registry/manifests/settlement-ops.json) | Idempotent `(network, txHash)` JSONL ingestion (`ingest_settlement`), integer `bigint` reconciliation (`reconcile_settlements`), Merkle batch signing (`create_settlement_batch`), `verify_receipt`. |
| **Tax-Ledger** | `mcps/tax/` | `4024` | [tax-ledger.json](registry/manifests/tax-ledger.json) | RFC 4180 CSV, JSONL, Form 8949 summaries (`export_tax_ledger`), SHA-256 chain digests, and Ed25519 DSSE audit bundles (`generate_audit_bundle`, `verify_audit_bundle`). |
| **Policy / Identity** | `mcps/policy/` | `4025` | [policy-identity.json](registry/manifests/policy-identity.json) | `PolicyIdentityStore` & `SpendPolicyEngine`: pre-sign micro-USD/msat spend caps, idempotent rolling-window tracking, Ed25519 DSSE attestations/verdicts, and revocation (`register_agent_policy`, `evaluate_payment_request`, `record_agent_spend`, `verify_agent_identity`, `revoke_agent_identity`). |

---

## Live Verification Proof

Verification artifacts live in [registry/verification-report.json](registry/verification-report.json), [registry/testnet-ledger.jsonl](registry/testnet-ledger.jsonl), and [registry/testnet-ledger.jsonl.batches.jsonl](registry/testnet-ledger.jsonl.batches.jsonl):

- **Live Base Sepolia Settlement (`https://x402.org/facilitator`):**
  - Network / Asset: `eip155:84532` · USDC (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`, EIP-3009)
  - Tx Hash: `0x4d4f49caf594e8264b63d5f2da5d44c0477da26c53beeb173673c4d4e2cd6340`
  - Amount / Status: `1000` units (`$0.001000` USDC) · HTTP `200`
  - Payer -> Canonical `payTo`: `0x41f4FFD63269FFeA16ceE2B90f1a015afA0Fb955` -> `0x0d25A44f74868eCE53B305C97139CF4B62963410`
- **Verified Lightning BOLT11 Preimage Settlement:**
  - HTTP `402 -> pay -> 200`: `ln:6ad1c5b4b04f040e9781b32b94175bdb6858ab5aa877b31242cf592606f53b43` (`lightning:testnet`, `12000` msat = `1080000` micro-USD at `90000` micro-USD/sat)
  - MCP `_meta["x402/payment"]`: `ln:51d84b73d0e0c9b7ff0cac88758c87c8af03d8135891289bd0b8b8e85698b740`
- **Local EIP-3009 Handshake & Replay Enforcement:**
  - Local facilitator tx: `local-eip3009-93224d55c296eae16575d471d00abc30ed7f0a4187c31f1259bde94b16bc2fb2`
  - Replay rejection on both Lightning and EVM rails: HTTP `409`
- **Security, Policy & Audit Guarantees:**
  - Persisted Ed25519 keystore (`mode 0600`): `keyid` `ed25519:76921d7540c827b1`
  - Pre-sign spend cap enforced (`cap_enforced: true`, blocking `1000` micro-USD > `maxPerCallMicroUsd 500` before signing)
  - Retired payee `0xAB745e5F576667037696e78ba7dA28E193E4423D` rejected in policy (`retiredPayeeRejectedInPolicy: true`), discovery (`score: 0`), and server boundary (HTTP `403`)
  - Discovery validation: `score: 100` (`["exact", "lightning"]`, `["eip155:84532", "lightning:testnet"]`)
  - Reconciled batch `batch-verify-001` (`feeBps: "250"`): `2161000` gross micro-USD (`$2.161000`), `54025` fee micro-USD, `2106975` net micro-USD, `24000` msat, Ed25519 DSSE tax audit bundle verified.

---

## Cost-Aware Model Routing (Vercel AI Gateway)

The gateway supports **Cost-Aware Model Routing** via dedicated decision models and tiered execution targets:
- **Decision Models (Complexity Classification):**
  - `perplexity/pplx-decider-flash-v1.3`: **$0.01 / 1M input tokens** (`10,000n` µUSD)
  - `liquid/d1.2`: **$0.02 / 1M input tokens** (`20,000n` µUSD)
  - `microsoft/decision-1.1`: **$0.04 / 1M input tokens** (`40,000n` µUSD, Zero Data Retention)
- **Execution Tiers:**
  - **Economy:** `router/pandaforge` (backed by zero-cost promotional `reflection/beam` router)
  - **Frontier:** `openai/gpt-5.6-luna` (for high-probability complex reasoning)
- **MCP Integration:**
  - `paid_economy_route` (`100` micro-USD = `$0.000100` Base Sepolia USDC): EIP-3009 x402 tool with Ed25519 DSSE attestation.
  - `economy_route_triage`: Free preview triage tool.
- **Harness & Verification:**
  - Offline suite: `npm run test:economy-route`
  - Live AI Gateway test: `npx tsx harness/live-gateway-test.ts`

---

## Quickstart Commands

```bash
# Install dependencies
npm install

# Typecheck and run all MCP server test suites + economy router
npm run test:all

# Run individual economy router test suite
npm run test:economy-route

# Run the full end-to-end swarm verification harness (writes verification-report.json)
npm run verify:swarm

# Probe HTTPS fleet endpoints (x402-mcp.onrender.com, Vercel fleet) and refresh catalog
npm run probe:fleet
```

Individual server suites from [package.json](package.json):
- `npm run typecheck` — `tsc --noEmit`
- `npm run test:economy-route` — `npx tsx harness/test-economy-router.ts`
- `npm run test:gate` — `npx tsx mcps/gate/test.ts`
- `npm run test:lightning` — `npx tsx mcps/lightning/test.ts`
- `npm run test:discovery` — `npx tsx mcps/discovery/test.ts`
- `npm run test:policy` — `npx tsx mcps/policy/test.ts`
- `npm run test:settlement` — `npx tsx mcps/settlement/test.ts`
- `npm run test:tax` — `npx tsx mcps/tax/test.ts`

---

## Working Group Proposals

Formal x402 Foundation Working Group specifications grounded in this codebase live in [proposals/README.md](proposals/README.md):

1. [proposals/wg-domain-discovery.md](proposals/wg-domain-discovery.md) — Browser `GET /mcp` 200 JSON server card, `/.well-known/x402` manifest schema, `validate_endpoint` 5-check rubric, and retired-payee blacklist enforcement.
2. [proposals/wg-identity-policy.md](proposals/wg-identity-policy.md) — Pre-sign `onPaymentRequested` hook, integer micro-USD & `msat` ceiling math, rolling-window spend caps, DSSE capability & verdict envelopes, and revocation.
3. [proposals/wg-tax-settlement.md](proposals/wg-tax-settlement.md) — Integer `bigint` settlement schema, `(network, txHash)` idempotency, 4-step replay-safe execution order, integer floor `feeBps`, RFC 4180 CSV, Form 8949 summary, SHA-256 chain digest, and DSSE audit bundles.

---

## Repository Structure

```text
x402-swarm/
├── shared/        # constants, types, policy engine, 0600 Ed25519 DSSE keystore, MCP HTTP, x402 adapter
├── mcps/          # gate, lightning, discovery, settlement, tax, policy MCP servers + server.json
├── harness/       # local-facilitator.ts, verify-swarm.ts, probe-fleet.ts
├── registry/      # catalog.json, manifests/*.json, testnet-ledger.jsonl, verification-report.json
├── proposals/     # Working Group RFCs (Domain Discovery, Identity & Policy, Tax & Settlement)
└── agents/        # Swarm role definitions (README.md, roles.json)
```
