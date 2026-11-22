import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { getAddress, verifyTypedData } from "viem";
import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  isRetiredPayTo,
} from "../shared/constants.js";
import { readJsonBody, sendJson } from "../shared/mcp-http.js";
import type { X402PaymentRequirement } from "../shared/types.js";

const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export interface LocalFacilitatorHandle {
  url: string;
  port: number;
  usedNonces: Set<string>;
  close: () => Promise<void>;
}

interface Eip3009Auth {
  from: `0x${string}`;
  to: `0x${string}`;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: `0x${string}`;
}

async function validateEip3009Payload(
  body: Record<string, unknown>,
  usedNonces: Set<string>
): Promise<{
  isValid: boolean;
  invalidReason?: string;
  payer?: string;
  nonceKey?: string;
  signature?: `0x${string}`;
  requirements?: X402PaymentRequirement;
}> {
  const paymentPayload = body.paymentPayload as Record<string, unknown> | undefined;
  const requirements = body.paymentRequirements as X402PaymentRequirement | undefined;

  if (!paymentPayload || !requirements) {
    return { isValid: false, invalidReason: "missing_payload_or_requirements" };
  }
  if (requirements.network !== BASE_SEPOLIA_NETWORK || requirements.scheme !== "exact") {
    return { isValid: false, invalidReason: "unsupported_network_or_scheme" };
  }
  if (isRetiredPayTo(requirements.payTo)) {
    return { isValid: false, invalidReason: "retired_pay_to_rejected" };
  }

  const innerPayload = paymentPayload.payload as Record<string, unknown> | undefined;
  const auth = innerPayload?.authorization as Eip3009Auth | undefined;
  const signature = innerPayload?.signature as `0x${string}` | undefined;
  if (!auth || !signature) {
    return { isValid: false, invalidReason: "missing_eip3009_authorization" };
  }

  let fromAddr: `0x${string}`;
  let toAddr: `0x${string}`;
  let expectedPayTo: `0x${string}`;
  let verifyingContract: `0x${string}`;
  try {
    fromAddr = getAddress(auth.from);
    toAddr = getAddress(auth.to);
    expectedPayTo = getAddress(requirements.payTo);
    verifyingContract = getAddress(requirements.asset || BASE_SEPOLIA_USDC);
  } catch {
    return { isValid: false, invalidReason: "invalid_address_format" };
  }

  if (toAddr !== expectedPayTo) {
    return { isValid: false, invalidReason: "pay_to_mismatch" };
  }
  if (BigInt(auth.value) < BigInt(requirements.amount)) {
    return { isValid: false, invalidReason: "insufficient_authorized_amount" };
  }

  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  if (nowSec < BigInt(auth.validAfter)) {
    return { isValid: false, invalidReason: "authorization_not_yet_valid" };
  }
  if (nowSec > BigInt(auth.validBefore)) {
    return { isValid: false, invalidReason: "authorization_expired" };
  }

  const nonceKey = `${fromAddr.toLowerCase()}:${auth.nonce.toLowerCase()}`;
  if (usedNonces.has(nonceKey)) {
    return { isValid: false, invalidReason: "nonce_already_settled" };
  }

  const extra = requirements.extra ?? {};
  const domainName = typeof extra.name === "string" ? extra.name : "USDC";
  const domainVersion = typeof extra.version === "string" ? extra.version : "2";

  const sigOk = await verifyTypedData({
    address: fromAddr,
    domain: {
      name: domainName,
      version: domainVersion,
      chainId: BASE_SEPOLIA_CHAIN_ID,
      verifyingContract,
    },
    types: EIP3009_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: fromAddr,
      to: toAddr,
      value: BigInt(auth.value),
      validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore),
      nonce: auth.nonce,
    },
    signature,
  });

  if (!sigOk) {
    return { isValid: false, invalidReason: "invalid_eip712_signature" };
  }

  return {
    isValid: true,
    payer: fromAddr,
    nonceKey,
    signature,
    requirements,
  };
}

export function startLocalFacilitator(
  port: number = 0,
  host: string = "127.0.0.1"
): Promise<LocalFacilitatorHandle> {
  const usedNonces = new Set<string>();
  const signerTag = "0x" + crypto.createHash("sha256").update("x402-swarm-local-facilitator").digest("hex").slice(0, 40);

  const server = http.createServer(async (req, res) => {
    const method = (req.method ?? "GET").toUpperCase();
    const url = new URL(req.url || "/", `http://${req.headers.host || `${host}:${port}`}`);

    if (method === "GET" && url.pathname === "/supported") {
      sendJson(res, 200, {
        kinds: [
          {
            x402Version: 2,
            scheme: "exact",
            network: BASE_SEPOLIA_NETWORK,
          },
        ],
        extensions: [],
        signers: {
          [BASE_SEPOLIA_NETWORK]: [getAddress(signerTag)],
        },
        mode: "local_facilitator",
      });
      return;
    }

    if (method === "POST" && url.pathname === "/verify") {
      try {
        const body = (await readJsonBody(req)) as Record<string, unknown>;
        const check = await validateEip3009Payload(body, usedNonces);
        sendJson(res, 200, {
          isValid: check.isValid,
          ...(check.invalidReason ? { invalidReason: check.invalidReason } : {}),
          ...(check.payer ? { payer: check.payer } : {}),
        });
      } catch (err) {
        sendJson(res, 400, {
          isValid: false,
          invalidReason: err instanceof Error ? err.message : String(err),
        });
      }
      return;
    }

    if (method === "POST" && url.pathname === "/settle") {
      try {
        const body = (await readJsonBody(req)) as Record<string, unknown>;
        const check = await validateEip3009Payload(body, usedNonces);
        if (!check.isValid || !check.nonceKey || !check.requirements) {
          sendJson(res, 200, {
            success: false,
            errorReason: check.invalidReason ?? "verification_failed",
            transaction: "",
            network: check.requirements?.network ?? BASE_SEPOLIA_NETWORK,
            payer: check.payer,
            mode: "local_facilitator",
          });
          return;
        }

        usedNonces.add(check.nonceKey);
        const txDigest = crypto
          .createHash("sha256")
          .update(`local-facilitator:${check.nonceKey}:${check.signature}`)
          .digest("hex");

        sendJson(res, 200, {
          success: true,
          transaction: `local-eip3009-${txDigest}`,
          network: check.requirements.network,
          payer: check.payer,
          mode: "local_facilitator",
        });
      } catch (err) {
        sendJson(res, 400, {
          success: false,
          errorReason: err instanceof Error ? err.message : String(err),
          transaction: "",
          network: BASE_SEPOLIA_NETWORK,
          mode: "local_facilitator",
        });
      }
      return;
    }

    sendJson(res, 404, { error: "Not found" });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address() as AddressInfo;
      resolve({
        url: `http://${host}:${addr.port}`,
        port: addr.port,
        usedNonces,
        close: () =>
          new Promise<void>((resClose, rejClose) => {
            server.close((err) => (err ? rejClose(err) : resClose()));
          }),
      });
    });
  });
}
