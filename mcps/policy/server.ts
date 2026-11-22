import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  BASE_MAINNET_NETWORK,
  BASE_SEPOLIA_NETWORK,
  BRANDING,
  DEFAULT_KEYSTORE_PATH,
  DEFAULT_X402_PAY_TO,
  LIGHTNING_MAINNET_NETWORK,
  LIGHTNING_TESTNET_NETWORK,
} from "../../shared/constants.js";
import { getKeyId } from "../../shared/keystore.js";
import {
  startMcpHttpServer,
  type McpToolDefinition,
  type McpToolHandler,
  type RunningMcpServer,
} from "../../shared/mcp-http.js";
import { SpendPolicyError } from "../../shared/policy.js";
import type { DsseEnvelope, X402PaymentRequirement } from "../../shared/types.js";
import {
  PolicyIdentityStore,
  type AgentIdentityAttestation,
} from "./identity.js";

export interface PolicyServerOptions {
  port?: number;
  host?: string;
  statePath?: string;
  keystorePath?: string;
}

export interface RunningPolicyServer extends RunningMcpServer {
  store: PolicyIdentityStore;
}

const IntegerInputSchema = z.union([
  z.string().regex(/^\d+$/, "Must be a non-negative integer string (no floats)"),
  z.number().int().nonnegative(),
]);

const RegisterAgentPolicySchema = z.object({
  agentId: z.string().min(1),
  evmAddress: z.string().optional(),
  maxPerCallMicroUsd: IntegerInputSchema,
  maxRollingWindowMicroUsd: IntegerInputSchema,
  windowMs: z.number().int().positive(),
  allowedNetworks: z.array(z.string()).optional(),
  allowedPayees: z.array(z.string()).optional(),
  btcMicroUsdPerSat: IntegerInputSchema.optional(),
  expiresAt: z.union([z.string(), z.number()]).optional(),
});

const PaymentRequirementSchema = z.object({
  scheme: z.string().min(1),
  network: z.string().min(1),
  asset: z.string().min(1),
  amount: z.union([
    z.string().regex(/^\d+$/, "amount must be a non-negative integer string"),
    z.number().int().nonnegative(),
  ]),
  payTo: z.string().min(1),
  maxTimeoutSeconds: z.number().nonnegative().optional(),
  extra: z.record(z.unknown()).optional(),
});

const EvaluatePaymentRequestSchema = z.object({
  agentId: z.string().min(1),
  requirement: PaymentRequirementSchema,
  nowMs: z.number().int().nonnegative().optional(),
});

const RecordAgentSpendSchema = z.object({
  agentId: z.string().min(1),
  requirement: PaymentRequirementSchema,
  txHash: z.string().optional(),
  intentId: z.string().optional(),
  nowMs: z.number().int().nonnegative().optional(),
});

const VerifyAgentIdentitySchema = z.object({
  attestation: z.record(z.unknown()),
  expectedPublicKeyPem: z.string().optional(),
  nowMs: z.number().int().nonnegative().optional(),
});

const RevokeAgentIdentitySchema = z.object({
  agentId: z.string().min(1),
  reason: z.string().optional(),
});

export const POLICY_TOOLS: McpToolDefinition[] = [
  {
    name: "register_agent_policy",
    description:
      "Register an agent spend policy & identity, reject retired payees, and issue an Ed25519 DSSE capability attestation.",
    inputSchema: {
      type: "object",
      required: [
        "agentId",
        "maxPerCallMicroUsd",
        "maxRollingWindowMicroUsd",
        "windowMs",
      ],
      properties: {
        agentId: { type: "string", description: "Unique agent identifier" },
        evmAddress: { type: "string", description: "Optional agent EVM address" },
        maxPerCallMicroUsd: {
          type: ["string", "integer"],
          description: "Per-call cap in integer micro-USD (1 USD = 1000000)",
        },
        maxRollingWindowMicroUsd: {
          type: ["string", "integer"],
          description: "Rolling window spend cap in integer micro-USD",
        },
        windowMs: {
          type: "integer",
          description: "Rolling window duration in milliseconds",
        },
        allowedNetworks: {
          type: "array",
          items: { type: "string" },
          description: "Optional CAIP-2 network allowlist",
        },
        allowedPayees: {
          type: "array",
          items: { type: "string" },
          description: "Optional payee allowlist (retired payee is rejected)",
        },
        btcMicroUsdPerSat: {
          type: ["string", "integer"],
          description: "Optional integer micro-USD per satoshi conversion rate",
        },
        expiresAt: {
          type: ["string", "number"],
          description: "Optional ISO timestamp or epoch ms expiry",
        },
      },
    },
  },
  {
    name: "evaluate_payment_request",
    description:
      "Evaluate an x402 payment requirement against an agent's active policy, caps, and retired-payee block with a DSSE-signed verdict.",
    inputSchema: {
      type: "object",
      required: ["agentId", "requirement"],
      properties: {
        agentId: { type: "string" },
        requirement: {
          type: "object",
          required: ["scheme", "network", "asset", "amount", "payTo"],
          properties: {
            scheme: { type: "string" },
            network: { type: "string" },
            asset: { type: "string" },
            amount: { type: ["string", "integer"] },
            payTo: { type: "string" },
            maxTimeoutSeconds: { type: "number" },
            extra: { type: "object" },
          },
        },
        nowMs: { type: "integer", description: "Optional evaluation epoch ms" },
      },
    },
  },
  {
    name: "record_agent_spend",
    description:
      "Idempotently commit agent payment spend keyed by (agentId, txHash/intentId) and return updated rolling window spend.",
    inputSchema: {
      type: "object",
      required: ["agentId", "requirement"],
      properties: {
        agentId: { type: "string" },
        requirement: {
          type: "object",
          required: ["scheme", "network", "asset", "amount", "payTo"],
          properties: {
            scheme: { type: "string" },
            network: { type: "string" },
            asset: { type: "string" },
            amount: { type: ["string", "integer"] },
            payTo: { type: "string" },
            maxTimeoutSeconds: { type: "number" },
            extra: { type: "object" },
          },
        },
        txHash: { type: "string", description: "Optional settlement txHash idempotency key" },
        intentId: { type: "string", description: "Optional payment intentId idempotency key" },
        nowMs: { type: "integer", description: "Optional commit epoch ms" },
      },
    },
  },
  {
    name: "verify_agent_identity",
    description:
      "Verify an Ed25519 DSSE agent capability attestation, claim integrity, expiration, and revocation status.",
    inputSchema: {
      type: "object",
      required: ["attestation"],
      properties: {
        attestation: {
          type: "object",
          description: "AgentIdentityAttestation or DSSE envelope to verify",
        },
        expectedPublicKeyPem: {
          type: "string",
          description: "Optional SPKI PEM public key override",
        },
        nowMs: { type: "integer", description: "Optional verification epoch ms" },
      },
    },
  },
  {
    name: "revoke_agent_identity",
    description:
      "Immediately revoke an agent's identity so subsequent payment evaluations and spend commits are blocked.",
    inputSchema: {
      type: "object",
      required: ["agentId"],
      properties: {
        agentId: { type: "string" },
        reason: { type: "string" },
      },
    },
  },
];

function toNormalizedRequirement(
  raw: z.infer<typeof PaymentRequirementSchema>
): X402PaymentRequirement {
  return {
    scheme: raw.scheme,
    network: raw.network,
    asset: raw.asset,
    amount: String(raw.amount),
    payTo: raw.payTo,
    maxTimeoutSeconds: raw.maxTimeoutSeconds ?? 300,
    ...(raw.extra !== undefined ? { extra: raw.extra } : {}),
  };
}

export async function startPolicyServer(
  options: PolicyServerOptions = {}
): Promise<RunningPolicyServer> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const keystorePath = options.keystorePath ?? DEFAULT_KEYSTORE_PATH;
  const keyid = getKeyId(keystorePath);
  const store = new PolicyIdentityStore({
    statePath: options.statePath,
    keystorePath,
  });

  let resolvedBaseUrl = `http://${host}:${port}`;

  const handlers: Record<string, McpToolHandler> = {
    register_agent_policy: (rawArgs) => {
      const parsed = RegisterAgentPolicySchema.safeParse(rawArgs);
      if (!parsed.success) {
        return {
          isError: true,
          data: { error: "Invalid arguments", issues: parsed.error.issues },
        };
      }
      try {
        const attestation = store.issueAgentIdentity({
          ...parsed.data,
          keystorePath,
        });
        return { data: attestation };
      } catch (err) {
        return {
          isError: true,
          data: { error: err instanceof Error ? err.message : String(err) },
        };
      }
    },

    evaluate_payment_request: (rawArgs) => {
      const parsed = EvaluatePaymentRequestSchema.safeParse(rawArgs);
      if (!parsed.success) {
        return {
          isError: true,
          data: { error: "Invalid arguments", issues: parsed.error.issues },
        };
      }
      try {
        const result = store.evaluatePaymentRequest({
          agentId: parsed.data.agentId,
          requirement: toNormalizedRequirement(parsed.data.requirement),
          nowMs: parsed.data.nowMs,
          keystorePath,
        });
        return { data: result };
      } catch (err) {
        return {
          isError: true,
          data: { error: err instanceof Error ? err.message : String(err) },
        };
      }
    },

    record_agent_spend: (rawArgs) => {
      const parsed = RecordAgentSpendSchema.safeParse(rawArgs);
      if (!parsed.success) {
        return {
          isError: true,
          data: { error: "Invalid arguments", issues: parsed.error.issues },
        };
      }
      try {
        const result = store.recordAgentSpend({
          agentId: parsed.data.agentId,
          requirement: toNormalizedRequirement(parsed.data.requirement),
          txHash: parsed.data.txHash,
          intentId: parsed.data.intentId,
          nowMs: parsed.data.nowMs,
        });
        return { data: result };
      } catch (err) {
        if (err instanceof SpendPolicyError) {
          return {
            isError: true,
            data: { error: err.message, decision: err.decision },
          };
        }
        return {
          isError: true,
          data: { error: err instanceof Error ? err.message : String(err) },
        };
      }
    },

    verify_agent_identity: (rawArgs) => {
      const parsed = VerifyAgentIdentitySchema.safeParse(rawArgs);
      if (!parsed.success) {
        return {
          isError: true,
          data: { error: "Invalid arguments", issues: parsed.error.issues },
        };
      }
      const res = store.verifyAgentIdentity(
        parsed.data.attestation as unknown as AgentIdentityAttestation | DsseEnvelope,
        parsed.data.expectedPublicKeyPem,
        keystorePath,
        parsed.data.nowMs
      );
      return { data: res };
    },

    revoke_agent_identity: (rawArgs) => {
      const parsed = RevokeAgentIdentitySchema.safeParse(rawArgs);
      if (!parsed.success) {
        return {
          isError: true,
          data: { error: "Invalid arguments", issues: parsed.error.issues },
        };
      }
      try {
        const res = store.revokeAgentIdentity(
          parsed.data.agentId,
          parsed.data.reason
        );
        return { data: res };
      } catch (err) {
        return {
          isError: true,
          data: { error: err instanceof Error ? err.message : String(err) },
        };
      }
    },
  };

  const running = await startMcpHttpServer({
    port,
    host,
    name: "x402-policy-identity",
    title: "x402 Agent Policy & Identity MCP",
    version: "0.1.0",
    description:
      "Agent capability attestations, retired-payee guards, and integer micro-USD spend policy verdicts.",
    tools: POLICY_TOOLS,
    handlers,
    wellKnownX402: () => ({
      x402Version: 2,
      name: "x402-policy-identity",
      title: "x402 Agent Policy & Identity MCP",
      description:
        "Agent capability attestations, retired-payee guards, and integer micro-USD spend policy verdicts.",
      mcpEndpoint: `${resolvedBaseUrl}/mcp`,
      wellKnownUrl: `${resolvedBaseUrl}/.well-known/x402`,
      payTo: DEFAULT_X402_PAY_TO,
      schemes: ["exact", "lightning"],
      networks: [
        BASE_SEPOLIA_NETWORK,
        BASE_MAINNET_NETWORK,
        LIGHTNING_TESTNET_NETWORK,
        LIGHTNING_MAINNET_NETWORK,
      ],
      keystoreKeyId: keyid,
      tools: POLICY_TOOLS.map((t) => t.name),
      branding: BRANDING,
    }),
    serverCardExtras: () => ({
      payTo: DEFAULT_X402_PAY_TO,
      keyid,
      statePath: store.statePath ?? null,
      author: BRANDING.author,
      organization: BRANDING.organization,
      website: BRANDING.website,
      contact: BRANDING.contact,
    }),
  });

  resolvedBaseUrl = running.baseUrl;

  return {
    ...running,
    store,
  };
}

const isMain =
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const port = Number(process.env.PORT ?? 4025);
  const host = process.env.HOST ?? "127.0.0.1";
  const statePath = process.env.POLICY_STATE_PATH;
  const keystorePath = process.env.KEYSTORE_PATH ?? DEFAULT_KEYSTORE_PATH;
  const srv = await startPolicyServer({
    port,
    host,
    ...(statePath ? { statePath } : {}),
    keystorePath,
  });
  console.log(
    JSON.stringify({
      status: "listening",
      name: "x402-policy-identity",
      baseUrl: srv.baseUrl,
      mcpUrl: srv.mcpUrl,
      statePath: srv.store.statePath ?? null,
    })
  );
}
