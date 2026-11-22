# RFC: x402 Domain Discovery & Endpoint Validation Working Group

- **Document:** `x402-wg-domain-discovery-01`
- **Status:** Draft Proposal (Implemented & Verified in `x402-swarm`)
- **Author:** Keith S. (`kwizzlesurp10@gmail.com`)
- **Organization:** `kwizzlesurp.com` · `Sevtech` · `Dragon&PandaDuo` (`https://kwizzlesurp.com`, Minneapolis, MN, USA)
- **Reference Modules:** `shared/constants.ts`, `shared/types.ts`, `shared/mcp-http.ts`, `mcps/discovery/validator.ts`, `mcps/discovery/indexer.ts`, `mcps/discovery/server.ts`, `harness/probe-fleet.ts`

---

## 1. Abstract

Autonomous agents discovering paid Model Context Protocol (MCP) tools and x402 v2 HTTP resources require deterministic, machine-verifiable endpoint metadata before opening sessions or signing payment authorizations. In practice, remote Streamable HTTP MCP deployments frequently break discovery crawlers and browser probes by redirecting `GET /mcp` (`307` -> `404`), omitting machine-readable `/.well-known/x402` payment advertisements, mixing floating-point pricing with integer base units, or continuing to advertise retired payee addresses.

This RFC specifies four interoperable requirements derived from `x402-swarm`:
1. Mandatory `200 OK` `application/json` server cards on plain `GET /mcp` and `GET /mcp/`.
2. Canonical `/.well-known/x402` manifest and catalog entry schemas with integer micro-USD pricing.
3. A 5-probe `validate_endpoint` diagnostic and scoring rubric.
4. Unconditional enforcement of retired-payee blacklists across discovery, registration, and search.

---

## 2. Browser `GET /mcp` 200 JSON Server Card Requirement

Streamable HTTP MCP servers mounted at `/mcp` MUST distinguish plain HTTP discovery requests from SSE stream subscriptions without issuing path redirects:

1. **Plain Browser / Crawler `GET` (`GET /mcp` and `GET /mcp/`):**
   - When the `Accept` request header does NOT include `text/event-stream`, the server MUST respond with HTTP `200 OK` and `Content-Type: application/json; charset=utf-8` on **both** `/mcp` and `/mcp/`.
   - Servers MUST NOT return `307 Temporary Redirect`, `308 Permanent Redirect`, or `404 Not Found` on either trailing-slash variant.
   - Reference implementation: `startMcpHttpServer` in `shared/mcp-http.ts` handles `pathname === "/mcp" || pathname === "/mcp/"` identically and returns a JSON server card containing:
     - `name`, `title`, `version`, `description`
     - `transport`: `"streamable-http"`
     - `protocolVersion`: `"2025-03-26"`
     - `toolsCount` and `tools`: array of `{ name, description }`
     - `status`: `"ONLINE"`
     - `branding`: canonical `BRANDING` object (`shared/constants.ts`)
     - Optional `serverCardExtras()` fields (e.g., `payTo`, `keyid`, `x402` summary).
2. **SSE `GET /mcp`:**
   - When `Accept` includes `text/event-stream`, the server responds `200 OK` `text/event-stream; charset=utf-8` with `event: endpoint\ndata: /mcp\n\n`.
3. **JSON-RPC `POST /mcp`:**
   - Handles `initialize`, `notifications/initialized` (`202`), `ping`, `tools/list`, and `tools/call` returning standard MCP envelopes (`{ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }], _meta? } }`).
4. **Official MCP Registry `server.json` Alignment:**
   - Companion `server.json` descriptors MUST reference `MCP_REGISTRY_SCHEMA` (`"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"` in `shared/constants.ts`) and keep `description.length <= 100` characters so registry ingestion (`mcp-publisher`) succeeds cleanly (verified in `harness/verify-swarm.ts` Gate A1 and `registry/verification-report.json`: `97`, `90`, `81`, and `77` characters across the verified servers).

---

## 3. Canonical `/.well-known/x402` & Registry Catalog Schema

### 3.1 `GET /.well-known/x402` Discovery Document
Every x402-enabled host SHOULD expose `GET /.well-known/x402` returning `200 OK` `application/json` with:
- `x402Version`: `2`
- `name`, `title`, `description`
- `mcpEndpoint`: absolute URL to `/mcp`
- `paidEndpoint` / `endpoints[]`: concrete paid HTTP route(s) (`{ method, path, url, priceMicroUsd, priceMsat? }`) or `paidTools[]`
- `payTo`: canonical recipient address (never a retired payee)
- `schemes`: supported scheme identifiers (e.g., `["exact", "lightning"]`)
- `networks`: CAIP-2 identifiers matching `/^[a-z0-9-]{2,16}:[a-zA-Z0-9_.-]{1,64}$/` (e.g., `"eip155:84532"`, `"eip155:8453"`, `"lightning:testnet"`)
- `accepts`: array of `X402PaymentRequirement` objects (`scheme`, `network`, `asset`, integer string `amount`, `payTo`, `maxTimeoutSeconds`, `extra`)
- `branding`: `{ author, organization, website, contact, location }`

### 3.2 Domain Trust Proof (`/.well-known/x402-trust.txt`)
Production hosts verify domain ownership via `GET /.well-known/x402-trust.txt` (`text/plain`). Fleet probers (`probeTrustTxt` in `harness/probe-fleet.ts`) record the HTTP status alongside x402 endpoint checks.

### 3.3 Catalog Manifest & Honesty Statuses (`CatalogEntry`)
Catalog manifests stored in `registry/manifests/*.json` and indexed into `registry/catalog.json` (`CatalogIndexer` in `mcps/discovery/indexer.ts`, `CatalogEntry` in `shared/types.ts`) enforce:
- **Integer pricing only:** `priceMicroUsd` MUST match `/^\d+$/` and parse via `parseMicroUsdInteger` into `bigint` (`1 USD = 1_000_000n`). Floating-point prices are rejected.
- **Strict verification status enum:**
  - `"seeded_pending_live_probe"`: local or remote manifest seeded before a live validation probe completes.
  - `"unverified"`: registered with `validateFirst: false` or `allowUnverified: true` without retired-payee violations.
  - `"verified"`: passed `validateEndpoint` without retired-payee violations.
  - `"failed"`: failed validation or triggered the retired-payee guard.
- **Atomic writes:** `atomicWriteJson` in `mcps/discovery/indexer.ts` writes to a PID/UUID-suffixed temporary file and calls `fs.renameSync` so concurrent catalog readers never observe partial JSON.

---

## 4. `validate_endpoint` Diagnostic Rubric

`validateEndpoint(targetUrl, options?)` in `mcps/discovery/validator.ts` (exposed via the `validate_endpoint` MCP tool in `mcps/discovery/server.ts`) runs five manual-redirect HTTP/MCP probes with wall-clock timing (`latencyMs`):

| # | Check Name | Probe Behavior | Pass Criteria |
|---|---|---|---|
| 1 | `well_known_x402` | `GET <origin>/.well-known/x402` (`Accept: application/json`, `redirect: "manual"`) | HTTP `200` and JSON object body; extracts `mcpEndpoint`, `paidEndpoint`, `payTo`, `schemes`, `networks` (configurable optional via `allowOptionalWellKnown`). |
| 2 | `mcp_get_card` | Parallel `GET <origin>/mcp` and `GET <origin>/mcp/` (no SSE `Accept`, `redirect: "manual"`) | Both return HTTP `200` and plain JSON object server cards; any `307`/`308`/`404` fails immediately with `Location` diagnostic. |
| 3 | `mcp_initialize_and_tools` | `POST /mcp` JSON-RPC `initialize` (`protocolVersion: "2025-03-26"`), captures `Mcp-Session-Id`, then `POST /mcp` `tools/list` | HTTP `200`, `jsonrpc: "2.0"`, no `error`, and `result.tools[]` entries all have non-empty string `name`. |
| 4 | `paid_402_challenge` | Probes `paidPath` / discovered `paidEndpoint` (GET, auto-retrying POST on `405`) or `mcp://tool/<name>` without payment | HTTP target returns `402` with base64 `PAYMENT-REQUIRED` header (`decodePaymentRequiredHeader`) or JSON body; MCP tool returns `result.isError === true` with `_meta["x402/payment-required"]` or `content[0].text` JSON. `normalizeAndValidateEnvelope` verifies `x402Version` (`1` or `2`), non-empty `accepts[]`, valid CAIP-2 `network`, `scheme`, `asset`, `/^\d+$/` `amount`, non-empty `payTo`, and `/^0x[a-fA-F0-9]{40}$/` for `eip155:*` addresses. |
| 5 | `retired_payee_guard` | Recursively collects every `"payTo"` string (`collectStringsRecursive`) across `/.well-known/x402`, `GET /mcp`, `GET /mcp/`, and `accepts[]` | Case-insensitive deduplicated address set contains zero matches for `RETIRED_X402_PAY_TO`. |

### Scoring & Validity Formula
From `mcps/discovery/validator.ts` (lines 786–796):
- `valid = mcpCardPassed && (allowOptionalWellKnown ? true : checks[0].passed) && mcpInitPassed && paidCheckPassed && retiredGuardPassed`
- `score = retiredGuardPassed ? Math.round((passedCount / checks.length) * 100) : 0`
- `priceMicroUsd` is derived via `derivePriceMicroUsd(validatedRequirements)`, preferring native 6-decimal EVM USD-pegged requirements (`evaluateRequirementMicroUsd`) to avoid FX rate ambiguity when dual-rail EVM + Lightning options are present, taking the minimum across requirements.

Verified against `Lightning-402` in `registry/verification-report.json` (`gateD_discovery`): `validated: true`, `score: 100`, `schemes: ["exact", "lightning"]`, `networks: ["eip155:84532", "lightning:testnet"]`.

---

## 5. Retired-Payee Blacklist Enforcement

To prevent accidental funds loss when operators rotate wallets, `shared/constants.ts` defines:
- Canonical active payee: `DEFAULT_X402_PAY_TO = "0x0d25A44f74868eCE53B305C97139CF4B62963410"`
- Retired payee: `RETIRED_X402_PAY_TO = "0xAB745e5F576667037696e78ba7dA28E193E4423D"`
- Helper: `isRetiredPayTo(address)` (case-insensitive trimmed equality) and `resolvePayTo(override?)` (throws unconditionally if `isRetiredPayTo` matches).

Discovery enforcement rules (`mcps/discovery/validator.ts` & `mcps/discovery/indexer.ts`):
1. **Validation Gate:** Any match in `/.well-known/x402`, `/mcp`, or `402` `accepts[]` sets `retired_payee_guard.passed = false`, `valid = false`, and forces `score = 0`.
2. **Catalog Registration Gate:** `CatalogIndexer.registerEndpoint` forces `status = "failed"` whenever `input.payTo` or `validation.payTo[]` contains a retired payee, overriding `allowUnverified`.
3. **Seed Gate:** `CatalogIndexer.seedFromManifests` throws immediately if any manifest contains `RETIRED_X402_PAY_TO`.
4. **Search Gate:** `CatalogIndexer.searchResources({ onlyValid: true })` excludes any entry whose `payTo` or `validation.payTo[]` matches `isRetiredPayTo`.

---

## 6. Security Considerations

- **SSRF & Redirect Loops:** `validateEndpoint` restricts protocols to `http:` and `https:`, enforces `AbortSignal.timeout(timeoutMs)`, and sets `redirect: "manual"` so servers cannot disguise `GET /mcp` 404s or redirect probes to internal endpoints.
- **No Unverified Claims:** Catalog entries seeded prior to probing MUST declare `status: "seeded_pending_live_probe"`. Only endpoints passing `validateEndpoint` may transition to `status: "verified"`.
