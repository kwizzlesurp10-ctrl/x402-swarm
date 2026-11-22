export type SettlementMode =
  | "live_testnet"
  | "local_facilitator"
  | "lightning_preimage";

export interface X402ResourceInfo {
  url: string;
  description?: string;
  mimeType?: string;
}

export interface X402PaymentRequirement {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
}

export interface X402PaymentRequiredEnvelope {
  x402Version: 2;
  error?: string;
  resource?: X402ResourceInfo;
  accepts: X402PaymentRequirement[];
  extensions?: Record<string, unknown>;
}

export interface X402PaymentSignature {
  x402Version: 2;
  resource?: X402ResourceInfo;
  accepted: X402PaymentRequirement;
  payload: Record<string, unknown>;
  extensions?: Record<string, unknown>;
}

export interface X402SettlementResponse {
  success: boolean;
  errorReason?: string;
  transaction: string;
  network: string;
  payer?: string;
  requirements?: X402PaymentRequirement;
  mode?: SettlementMode;
}

export interface DsseSignature {
  keyid: string;
  sig: string;
}

export interface DsseEnvelope {
  payloadType: string;
  payload: string;
  signatures: DsseSignature[];
}

export interface SettlementReceipt {
  id: string;
  amountMicroUsd: string;
  amountMsat?: string;
  network: string;
  scheme: string;
  asset: string;
  txHash: string;
  payer: string;
  payTo: string;
  resource: string;
  toolName: string;
  settledAt: string;
  facilitator: string;
  mode: SettlementMode;
  nonce?: string;
  paymentHash?: string;
  batchId?: string;
  dsse?: DsseEnvelope;
}

export interface SpendPolicyConfig {
  agentId?: string;
  maxPerCallMicroUsd: bigint;
  maxRollingWindowMicroUsd: bigint;
  windowMs: number;
  allowedNetworks?: string[];
  allowedPayees?: string[];
  btcMicroUsdPerSat?: bigint;
}

export interface SpendDecision {
  allowed: boolean;
  reason?: string;
  evaluatedMicroUsd: string;
  remainingWindowMicroUsd: string;
  network: string;
  payTo: string;
  scheme: string;
  capEnforced: boolean;
}

export interface EndpointCheck {
  name: string;
  passed: boolean;
  status?: number;
  detail: string;
}

export interface EndpointValidationResult {
  url: string;
  valid: boolean;
  score: number;
  checks: EndpointCheck[];
  schemes: string[];
  networks: string[];
  payTo: string[];
  priceMicroUsd: string | null;
  latencyMs: number;
  checkedAt: string;
}

export interface CatalogEntry {
  id: string;
  name: string;
  title: string;
  description: string;
  url: string;
  mcpEndpoint: string;
  wellKnownUrl?: string;
  paidEndpoint?: string;
  vendor: string;
  networks: string[];
  schemes: string[];
  payTo: string;
  priceMicroUsd: string;
  status: "verified" | "failed" | "seeded_pending_live_probe" | "unverified";
  validation?: EndpointValidationResult;
  updatedAt: string;
}

export interface LightningTaskOutput {
  server_path: string;
  handshake_tx: string | null;
  cap_enforced: boolean;
  tests_passed?: boolean;
}

export interface DiscoveryTaskOutput {
  server_path: string;
  registry_path: string;
  validated_endpoints: number;
  tests_passed?: boolean;
}

export interface SettlementTaxTaskOutput {
  settlement_server_path: string;
  tax_server_path: string;
  dsse_verified: boolean;
  tests_passed?: boolean;
}
