import { createHash } from "node:crypto";

export const BASE_SEPOLIA_NETWORK = "eip155:84532" as const;
export const BASE_SEPOLIA_CHAIN_ID = 84532 as const;
export const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as const;

export const BASE_MAINNET_NETWORK = "eip155:8453" as const;
export const BASE_MAINNET_CHAIN_ID = 8453 as const;
export const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;

export const LIGHTNING_TESTNET_NETWORK = "lightning:testnet" as const;
export const LIGHTNING_MAINNET_NETWORK = "lightning:mainnet" as const;

export const TESTNET_FACILITATOR_URL = "https://x402.org/facilitator" as const;

export const DEFAULT_X402_PAY_TO = "0x0d25A44f74868eCE53B305C97139CF4B62963410" as const;
export const RETIRED_X402_PAY_TO = "0xAB745e5F576667037696e78ba7dA28E193E4423D" as const;

// SHA-256 hashes of retired/forbidden seller wallets to protect funds without broadcasting addresses in public catalogs
const FORBIDDEN_PAYEE_HASHES = new Set([
  "df880fc802b194970e70bbff86e16ab0e61862d389a74870dddf0859313cfe9c",
  "6d2a78f45386d0f92fcc64b9463563f6fd91331dd1b22a19e66d11620a5bd803",
]);

export const BRANDING = {
  author: "Keith S.",
  organization: "kwizzlesurp.com · Sevtech · Dragon&PandaDuo",
  website: "https://kwizzlesurp.com",
  contact: "kwizzlesurp10@gmail.com",
  location: "Minneapolis, MN, USA",
} as const;

export const MCP_REGISTRY_SCHEMA =
  "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json" as const;

export const DEFAULT_KEYSTORE_PATH = "/home/keef/x402-swarm/.keystore/ed25519.pem" as const;

export const MICRO_USD_PER_USD = 1_000_000n;
export const MSAT_PER_SAT = 1_000n;
export const DEFAULT_BTC_MICRO_USD_PER_SAT = 90_000n;

export function isRetiredPayTo(address: string | undefined | null): boolean {
  if (!address) return false;
  const hash = createHash("sha256").update(address.trim().toLowerCase()).digest("hex");
  return FORBIDDEN_PAYEE_HASHES.has(hash);
}

export function resolvePayTo(override?: string): string {
  const raw = (override ?? process.env.X402_PAY_TO ?? DEFAULT_X402_PAY_TO).trim();
  if (isRetiredPayTo(raw)) {
    throw new Error(`Retired payee address is forbidden: ${raw}`);
  }
  return raw;
}
