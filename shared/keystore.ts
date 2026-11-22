import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_KEYSTORE_PATH } from "./constants.js";
import type { DsseEnvelope } from "./types.js";

export interface PersistedKeypair {
  keystorePath: string;
  keyid: string;
  privateKeyPem: string;
  publicKeyPem: string;
}

function deriveKeyId(publicKeyPem: string): string {
  const pubObj = crypto.createPublicKey(publicKeyPem);
  const spkiDer = pubObj.export({ type: "spki", format: "der" });
  const digest = crypto.createHash("sha256").update(spkiDer).digest("hex").slice(0, 16);
  return `ed25519:${digest}`;
}

export function loadOrCreateKeystore(
  keystorePath: string = DEFAULT_KEYSTORE_PATH
): PersistedKeypair {
  const dir = path.dirname(keystorePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  let privateKeyPem: string;
  if (fs.existsSync(keystorePath)) {
    privateKeyPem = fs.readFileSync(keystorePath, "utf8");
    const stats = fs.statSync(keystorePath);
    if ((stats.mode & 0o777) !== 0o600) {
      fs.chmodSync(keystorePath, 0o600);
    }
  } else {
    const { privateKey } = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    privateKeyPem = privateKey;
    fs.writeFileSync(keystorePath, privateKeyPem, { mode: 0o600 });
    fs.chmodSync(keystorePath, 0o600);
  }

  const privKeyObj = crypto.createPrivateKey(privateKeyPem);
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const publicKeyPem = pubKeyObj.export({ type: "spki", format: "pem" }).toString();
  const keyid = deriveKeyId(publicKeyPem);

  return {
    keystorePath,
    keyid,
    privateKeyPem,
    publicKeyPem,
  };
}

export function getKeyId(keystorePath: string = DEFAULT_KEYSTORE_PATH): string {
  return loadOrCreateKeystore(keystorePath).keyid;
}

/**
 * Standard DSSE Pre-Authentication Encoding (PAE):
 * "DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
 */
export function dssePae(payloadType: string, payloadBytes: Buffer): Buffer {
  const typeBytes = Buffer.from(payloadType, "utf8");
  const header = Buffer.from(
    `DSSEv1 ${typeBytes.length} ${payloadType} ${payloadBytes.length} `,
    "utf8"
  );
  return Buffer.concat([header, payloadBytes]);
}

export function signDsse(
  payloadType: string,
  payload: unknown,
  keystorePath: string = DEFAULT_KEYSTORE_PATH
): DsseEnvelope {
  const ks = loadOrCreateKeystore(keystorePath);
  const payloadJson =
    typeof payload === "string" ? payload : JSON.stringify(payload);
  const payloadBytes = Buffer.from(payloadJson, "utf8");
  const pae = dssePae(payloadType, payloadBytes);
  const signature = crypto.sign(null, pae, crypto.createPrivateKey(ks.privateKeyPem));

  return {
    payloadType,
    payload: payloadBytes.toString("base64"),
    signatures: [
      {
        keyid: ks.keyid,
        sig: signature.toString("base64"),
      },
    ],
  };
}

export function verifyDsse(
  envelope: DsseEnvelope,
  expectedPublicKeyPem?: string,
  keystorePath: string = DEFAULT_KEYSTORE_PATH
): { valid: boolean; keyid?: string; decodedPayload?: unknown; error?: string } {
  try {
    if (
      !envelope ||
      typeof envelope.payloadType !== "string" ||
      typeof envelope.payload !== "string" ||
      !Array.isArray(envelope.signatures) ||
      envelope.signatures.length === 0
    ) {
      return { valid: false, error: "Malformed DSSE envelope" };
    }

    const publicKeyPem =
      expectedPublicKeyPem ?? loadOrCreateKeystore(keystorePath).publicKeyPem;
    const expectedKeyId = deriveKeyId(publicKeyPem);
    const pubKeyObj = crypto.createPublicKey(publicKeyPem);

    const payloadBytes = Buffer.from(envelope.payload, "base64");
    const pae = dssePae(envelope.payloadType, payloadBytes);

    for (const sigEntry of envelope.signatures) {
      if (sigEntry.keyid !== expectedKeyId) continue;
      const sigBytes = Buffer.from(sigEntry.sig, "base64");
      const ok = crypto.verify(null, pae, pubKeyObj, sigBytes);
      if (ok) {
        let decodedPayload: unknown = payloadBytes.toString("utf8");
        try {
          decodedPayload = JSON.parse(decodedPayload as string);
        } catch {
          // Keep raw string if payload isn't JSON
        }
        return { valid: true, keyid: sigEntry.keyid, decodedPayload };
      }
    }

    return {
      valid: false,
      error: `No valid DSSE signature matched expected keyid ${expectedKeyId}`,
    };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
