# x402 Swarm Agent Roster

Canonical specialist mapping for `x402-swarm` (Keith S. · kwizzlesurp.com · Sevtech · Dragon&PandaDuo).

| Role | Swarm Lane | Owned Artifacts / Gate |
|---|---|---|
| `scout` | Ecosystem signal & open lanes | `x402-swarm-deck.html`, working-group gaps |
| `architect` | MCP wire contracts & pricing | `shared/types.ts`, `shared/constants.ts`, `mcps/*/server.json` |
| `builder` | Paid MCP server implementation | `mcps/lightning/`, `mcps/discovery/`, `mcps/settlement/`, `mcps/tax/` |
| `paymaster` | 402 -> pay -> 200 handshakes | `shared/x402-adapter.ts`, `harness/verify-swarm.ts` |
| `hardener` | Spend caps, retired payee, replay, DSSE | `shared/policy.ts`, `shared/keystore.ts`, intent log replay guard |
| `registrar` | Cross-vendor index & `validate_endpoint` | `mcps/discovery/`, `registry/catalog.json`, `registry/manifests/` |
| `ledger` | Integer reconciliation & Form 8949 tax export | `mcps/settlement/`, `mcps/tax/`, `registry/testnet-ledger.jsonl` |
