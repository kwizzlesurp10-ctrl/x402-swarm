import crypto from "node:crypto";
import type { LightningPayerFn, LightningPaymentRequest } from "../../shared/x402-adapter.js";
import {
  LIGHTNING_MAINNET_NETWORK,
  LIGHTNING_TESTNET_NETWORK,
} from "../../shared/constants.js";

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_POLYMOD_GEN = [
  0x3b6a57b2,
  0x26508e6d,
  0x1ea119fa,
  0x3d4233dd,
  0x2a1462b3,
];

// BOLT11 tagged field tags (5-bit integers)
const TAG_PAYMENT_HASH = 1; // 'p'
const TAG_EXPIRY = 6; // 'x'
const TAG_DESCRIPTION = 13; // 'd'
const TAG_PAYEE_PUBKEY = 19; // 'n'
const TAG_DESCRIPTION_HASH = 23; // 'h'
const TAG_MIN_FINAL_CLTV = 24; // 'c'

const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_ORDER = SECP256K1_ORDER >> 1n;

const DEFAULT_EXPIRY_SECONDS = 300;
const BOLT11_DEFAULT_EXPIRY_SECONDS = 3600;

export type LightningNetworkId =
  | "lightning:testnet"
  | "lightning:mainnet"
  | "lightning:regtest"
  | "lightning:signet";

export type Bolt11Prefix = "lntb" | "lnbc" | "lnbcrt" | "lntbs";

export interface EncodeBolt11Params {
  network?: LightningNetworkId | "testnet" | "mainnet" | "regtest" | "signet";
  amountMsat: bigint | string | number;
  paymentHash: string;
  payeePubkey?: string;
  description?: string;
  timestampUnix?: number;
  expirySeconds?: number;
  signingPrivateKeyPem?: string;
}

export interface DecodedBolt11Invoice {
  bolt11: string;
  network: LightningNetworkId;
  prefix: Bolt11Prefix;
  amountMsat: bigint;
  paymentHash: string;
  description: string;
  descriptionHash?: string;
  payeePubkey: string;
  timestampUnix: number;
  expirySeconds: number;
  expiresAtUnix: number;
  minFinalCltvExpiry?: number;
  signatureHex: string;
}

export interface IssuedLightningInvoice {
  bolt11: string;
  paymentHash: string;
  amountMsat: bigint;
  payeePubkey: string;
  timestampUnix: number;
  expiresAtUnix: number;
  expirySeconds: number;
  network: LightningNetworkId;
  description: string;
}

export interface TestLightningSimulator {
  readonly payeePubkey: string;
  readonly payerId: string;
  mintInvoice(params: {
    amountMsat: bigint | string | number;
    network?: LightningNetworkId;
    description?: string;
    expirySeconds?: number;
  }): IssuedLightningInvoice;
  registerPreimage(paymentHash: string, preimage: string): void;
  pay: LightningPayerFn;
  payer: LightningPayerFn;
  hasPreimage(paymentHash: string): boolean;
  settledCount(): number;
}

// Simulated Lightning HTLC network escrow.
// Preimages live ONLY here (never returned to server invoice store or HTTP 402 responses)
// and are revealed to the payer simulator only upon HTLC settlement.
const htlcNetworkEscrow = new Map<string, string>();

let cachedFallbackNodeKey:
  | { privateKeyPem: string; compressedPubkeyHex: string }
  | undefined;

function getFallbackNodeKey(): {
  privateKeyPem: string;
  compressedPubkeyHex: string;
} {
  if (cachedFallbackNodeKey) return cachedFallbackNodeKey;
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "secp256k1",
  });
  const privateKeyPem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  // Uncompressed EC point is the trailing 65 bytes (0x04 || X || Y) of SPKI DER
  const uncompressed = spkiDer.subarray(spkiDer.length - 65);
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new Error("Unexpected secp256k1 SPKI key encoding");
  }
  const x = uncompressed.subarray(1, 33);
  const yLastByte = uncompressed[64];
  const prefixByte = (yLastByte & 1) === 0 ? 0x02 : 0x03;
  const compressed = Buffer.concat([Buffer.from([prefixByte]), x]);
  cachedFallbackNodeKey = {
    privateKeyPem,
    compressedPubkeyHex: compressed.toString("hex"),
  };
  return cachedFallbackNodeKey;
}

export function normalizeHex32(hex: string, label: string): string {
  const clean = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`${label} must be a 32-byte (64-hex) string`);
  }
  return clean;
}

function normalizeCompressedPubkey(hex: string): string {
  const clean = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^(02|03)[0-9a-f]{64}$/.test(clean)) {
    throw new Error(
      "payeePubkey must be a 33-byte compressed secp256k1 hex key (02/03...)"
    );
  }
  return clean;
}

export function verifyLightningPreimage(
  preimageHex: string,
  paymentHashHex: string
): boolean {
  try {
    const cleanPreimage = normalizeHex32(preimageHex, "preimage");
    const cleanPaymentHash = normalizeHex32(paymentHashHex, "paymentHash");
    const computed = crypto
      .createHash("sha256")
      .update(Buffer.from(cleanPreimage, "hex"))
      .digest();
    const expected = Buffer.from(cleanPaymentHash, "hex");
    return crypto.timingSafeEqual(computed, expected);
  } catch {
    return false;
  }
}

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) {
        chk ^= BECH32_POLYMOD_GEN[i];
      }
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) >>> 5);
  }
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) & 31);
  }
  return ret;
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = bech32Polymod(values) ^ 1;
  const ret: number[] = [];
  for (let p = 0; p < 6; p++) {
    ret.push((mod >>> (5 * (5 - p))) & 31);
  }
  return ret;
}

function bech32VerifyChecksum(hrp: string, data: number[]): boolean {
  return bech32Polymod([...bech32HrpExpand(hrp), ...data]) === 1;
}

function bech32Encode(hrp: string, data: number[]): string {
  const checksum = bech32CreateChecksum(hrp, data);
  const combined = [...data, ...checksum];
  let out = `${hrp}1`;
  for (const d of combined) {
    out += BECH32_CHARSET[d];
  }
  return out;
}

function bech32Decode(str: string): { hrp: string; words: number[] } {
  if (!str || str.length < 8) {
    throw new Error("Invalid BOLT11 bech32 invoice: too short");
  }
  const hasLower = /[a-z]/.test(str);
  const hasUpper = /[A-Z]/.test(str);
  if (hasLower && hasUpper) {
    throw new Error("Invalid BOLT11 bech32 invoice: mixed case");
  }
  const lower = str.toLowerCase();
  const sepIndex = lower.lastIndexOf("1");
  if (sepIndex < 1 || sepIndex + 7 > lower.length) {
    throw new Error("Invalid BOLT11 bech32 separator position");
  }
  const hrp = lower.slice(0, sepIndex);
  const dataPart = lower.slice(sepIndex + 1);
  const words: number[] = [];
  for (let i = 0; i < dataPart.length; i++) {
    const idx = BECH32_CHARSET.indexOf(dataPart[i]);
    if (idx === -1) {
      throw new Error(`Invalid bech32 character '${dataPart[i]}'`);
    }
    words.push(idx);
  }
  if (!bech32VerifyChecksum(hrp, words)) {
    throw new Error("Invalid BOLT11 bech32 checksum");
  }
  return {
    hrp,
    words: words.slice(0, words.length - 6),
  };
}

function convertBits(
  data: Iterable<number>,
  fromBits: number,
  toBits: number,
  pad: boolean
): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) {
      throw new Error(`Invalid value ${value} for ${fromBits}-bit group`);
    }
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push((acc << (toBits - bits)) & maxv);
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error("Invalid padding bits in BOLT11 payload");
  }
  return ret;
}

function encodeTaggedField(tag: number, fieldWords: number[]): number[] {
  const len = fieldWords.length;
  if (len > 1023) {
    throw new Error(`BOLT11 tagged field ${tag} exceeds 1023 5-bit words`);
  }
  return [tag & 31, (len >>> 5) & 31, len & 31, ...fieldWords];
}

function encodeBigInt5BitWords(value: bigint): number[] {
  if (value <= 0n) return [0];
  const out: number[] = [];
  let v = value;
  while (v > 0n) {
    out.unshift(Number(v & 31n));
    v >>= 5n;
  }
  return out;
}

function decodeBigInt5BitWords(words: number[]): bigint {
  let acc = 0n;
  for (const w of words) {
    acc = (acc << 5n) | BigInt(w);
  }
  return acc;
}

function resolvePrefixAndNetwork(
  network?: EncodeBolt11Params["network"]
): { prefix: Bolt11Prefix; network: LightningNetworkId } {
  switch (network) {
    case "lightning:mainnet":
    case "mainnet":
      return { prefix: "lnbc", network: LIGHTNING_MAINNET_NETWORK };
    case "lightning:regtest":
    case "regtest":
      return { prefix: "lnbcrt", network: "lightning:regtest" };
    case "lightning:signet":
    case "signet":
      return { prefix: "lntbs", network: "lightning:signet" };
    case "lightning:testnet":
    case "testnet":
    case undefined:
      return { prefix: "lntb", network: LIGHTNING_TESTNET_NETWORK };
    default:
      throw new Error(`Unsupported Lightning network: ${String(network)}`);
  }
}

function parsePrefixAndNetwork(hrp: string): {
  prefix: Bolt11Prefix;
  network: LightningNetworkId;
  amountPart: string;
} {
  // Check lnbcrt before lnbc because lnbcrt starts with lnbc
  const prefixes: Array<{ prefix: Bolt11Prefix; network: LightningNetworkId }> = [
    { prefix: "lnbcrt", network: "lightning:regtest" },
    { prefix: "lntbs", network: "lightning:signet" },
    { prefix: "lntb", network: LIGHTNING_TESTNET_NETWORK },
    { prefix: "lnbc", network: LIGHTNING_MAINNET_NETWORK },
  ];
  for (const entry of prefixes) {
    if (hrp.startsWith(entry.prefix)) {
      return {
        ...entry,
        amountPart: hrp.slice(entry.prefix.length),
      };
    }
  }
  throw new Error(`Unsupported BOLT11 HRP prefix: ${hrp}`);
}

function encodeAmountHrpPart(amountMsat: bigint): string {
  if (amountMsat < 0n) {
    throw new Error(`BOLT11 amountMsat must be non-negative: ${amountMsat}`);
  }
  if (amountMsat === 0n) return "";
  if (amountMsat % 100_000_000_000n === 0n) {
    return `${(amountMsat / 100_000_000_000n).toString()}`;
  }
  if (amountMsat % 100_000_000n === 0n) {
    return `${(amountMsat / 100_000_000n).toString()}m`;
  }
  if (amountMsat % 100_000n === 0n) {
    return `${(amountMsat / 100_000n).toString()}u`;
  }
  if (amountMsat % 100n === 0n) {
    return `${(amountMsat / 100n).toString()}n`;
  }
  return `${(amountMsat * 10n).toString()}p`;
}

function decodeAmountHrpPart(amountPart: string): bigint {
  if (!amountPart) return 0n;
  const match = /^(\d+)([munp]?)$/.exec(amountPart);
  if (!match) {
    throw new Error(`Invalid BOLT11 amount encoding in HRP: "${amountPart}"`);
  }
  const value = BigInt(match[1]);
  const multiplier = match[2];
  switch (multiplier) {
    case "":
      return value * 100_000_000_000n;
    case "m":
      return value * 100_000_000n;
    case "u":
      return value * 100_000n;
    case "n":
      return value * 100n;
    case "p":
      if (value % 10n !== 0n) {
        throw new Error(
          `BOLT11 sub-millisatoshi amount "${amountPart}" is not an integer msat`
        );
      }
      return value / 10n;
    default:
      throw new Error(`Unsupported BOLT11 multiplier: ${multiplier}`);
  }
}

function derEcdsaToCompact65(derSig: Buffer): Buffer {
  if (derSig.length < 8 || derSig[0] !== 0x30) {
    throw new Error("Invalid DER ECDSA signature");
  }
  let offset = 2;
  if (derSig[1] & 0x80) {
    const lenBytes = derSig[1] & 0x7f;
    offset = 2 + lenBytes;
  }
  if (derSig[offset] !== 0x02) throw new Error("Expected DER integer for r");
  const rLen = derSig[offset + 1];
  const rRaw = derSig.subarray(offset + 2, offset + 2 + rLen);
  offset = offset + 2 + rLen;

  if (derSig[offset] !== 0x02) throw new Error("Expected DER integer for s");
  const sLen = derSig[offset + 1];
  const sRaw = derSig.subarray(offset + 2, offset + 2 + sLen);

  const rBig = BigInt("0x" + Buffer.from(rRaw).toString("hex"));
  let sBig = BigInt("0x" + Buffer.from(sRaw).toString("hex"));
  let recoveryId = 0;
  if (sBig > SECP256K1_HALF_ORDER) {
    sBig = SECP256K1_ORDER - sBig;
    recoveryId = 1;
  }

  const rHex = rBig.toString(16).padStart(64, "0");
  const sHex = sBig.toString(16).padStart(64, "0");
  return Buffer.concat([
    Buffer.from(rHex, "hex"),
    Buffer.from(sHex, "hex"),
    Buffer.from([recoveryId]),
  ]);
}

export function encodeLightningInvoice(params: EncodeBolt11Params): string {
  const { prefix } = resolvePrefixAndNetwork(params.network);
  const amountMsat = BigInt(params.amountMsat);
  const paymentHash = normalizeHex32(params.paymentHash, "paymentHash");
  const fallbackNode = getFallbackNodeKey();
  const payeePubkey = normalizeCompressedPubkey(
    params.payeePubkey ?? fallbackNode.compressedPubkeyHex
  );
  const timestampUnix =
    params.timestampUnix ?? Math.floor(Date.now() / 1000);
  const expirySeconds = params.expirySeconds ?? DEFAULT_EXPIRY_SECONDS;
  if (expirySeconds <= 0) {
    throw new Error(`expirySeconds must be positive, got ${expirySeconds}`);
  }
  const description = params.description ?? "x402 Lightning-402 payment";

  const hrp = `${prefix}${encodeAmountHrpPart(amountMsat)}`;

  // 35-bit timestamp (7 5-bit words)
  const tsWords: number[] = [];
  const tsBig = BigInt(timestampUnix);
  for (let i = 6; i >= 0; i--) {
    tsWords.push(Number((tsBig >> BigInt(i * 5)) & 31n));
  }

  const pWords = convertBits(Buffer.from(paymentHash, "hex"), 8, 5, true);
  const dWords = convertBits(Buffer.from(description, "utf8"), 8, 5, true);
  const xWords = encodeBigInt5BitWords(BigInt(expirySeconds));
  const nWords = convertBits(Buffer.from(payeePubkey, "hex"), 8, 5, true);
  const cWords = encodeBigInt5BitWords(40n);

  const taggedWords = [
    ...encodeTaggedField(TAG_PAYMENT_HASH, pWords),
    ...encodeTaggedField(TAG_DESCRIPTION, dWords),
    ...encodeTaggedField(TAG_EXPIRY, xWords),
    ...encodeTaggedField(TAG_PAYEE_PUBKEY, nWords),
    ...encodeTaggedField(TAG_MIN_FINAL_CLTV, cWords),
  ];

  const payloadWords = [...tsWords, ...taggedWords];
  const paddedBytes = Buffer.from(convertBits(payloadWords, 5, 8, true));
  const signingPreimage = Buffer.concat([
    Buffer.from(hrp, "ascii"),
    paddedBytes,
  ]);

  const signingKey = crypto.createPrivateKey(
    params.signingPrivateKeyPem ?? fallbackNode.privateKeyPem
  );
  const derSig = crypto.sign("sha256", signingPreimage, signingKey);
  const sig65 = derEcdsaToCompact65(derSig);
  const sigWords = convertBits(sig65, 8, 5, true);

  return bech32Encode(hrp, [...payloadWords, ...sigWords]);
}

export function decodeLightningInvoice(bolt11: string): DecodedBolt11Invoice {
  const { hrp, words } = bech32Decode(bolt11.trim());
  const { prefix, network, amountPart } = parsePrefixAndNetwork(hrp);
  const amountMsat = decodeAmountHrpPart(amountPart);

  // Minimum: 7 words timestamp + 104 words (65-byte signature) = 111 words
  if (words.length < 111) {
    throw new Error("BOLT11 invoice data too short for timestamp + signature");
  }

  const dataWords = words.slice(0, words.length - 104);
  const sigWords = words.slice(words.length - 104);
  const sigBytes = Buffer.from(convertBits(sigWords, 5, 8, false));

  let tsBig = 0n;
  for (let i = 0; i < 7; i++) {
    tsBig = (tsBig << 5n) | BigInt(dataWords[i]);
  }
  const timestampUnix = Number(tsBig);

  let paymentHash = "";
  let description = "";
  let descriptionHash: string | undefined;
  let payeePubkey = "";
  let expirySeconds = BOLT11_DEFAULT_EXPIRY_SECONDS;
  let minFinalCltvExpiry: number | undefined;

  let cursor = 7;
  while (cursor < dataWords.length) {
    if (cursor + 3 > dataWords.length) {
      throw new Error("Truncated BOLT11 tagged field header");
    }
    const tag = dataWords[cursor];
    const dataLength = (dataWords[cursor + 1] << 5) | dataWords[cursor + 2];
    cursor += 3;
    if (cursor + dataLength > dataWords.length) {
      throw new Error(`Truncated BOLT11 tagged field ${tag}`);
    }
    const fieldWords = dataWords.slice(cursor, cursor + dataLength);
    cursor += dataLength;

    switch (tag) {
      case TAG_PAYMENT_HASH: {
        if (dataLength === 52) {
          paymentHash = Buffer.from(
            convertBits(fieldWords, 5, 8, false)
          ).toString("hex");
        }
        break;
      }
      case TAG_DESCRIPTION: {
        description = Buffer.from(
          convertBits(fieldWords, 5, 8, false)
        ).toString("utf8");
        break;
      }
      case TAG_DESCRIPTION_HASH: {
        if (dataLength === 52) {
          descriptionHash = Buffer.from(
            convertBits(fieldWords, 5, 8, false)
          ).toString("hex");
        }
        break;
      }
      case TAG_EXPIRY: {
        expirySeconds = Number(decodeBigInt5BitWords(fieldWords));
        break;
      }
      case TAG_PAYEE_PUBKEY: {
        if (dataLength === 53) {
          payeePubkey = Buffer.from(
            convertBits(fieldWords, 5, 8, false)
          ).toString("hex");
        }
        break;
      }
      case TAG_MIN_FINAL_CLTV: {
        minFinalCltvExpiry = Number(decodeBigInt5BitWords(fieldWords));
        break;
      }
      default:
        break;
    }
  }

  if (!paymentHash) {
    throw new Error("BOLT11 invoice missing paymentHash ('p') tag");
  }

  return {
    bolt11: bolt11.trim().toLowerCase(),
    network,
    prefix,
    amountMsat,
    paymentHash,
    description,
    ...(descriptionHash ? { descriptionHash } : {}),
    payeePubkey,
    timestampUnix,
    expirySeconds,
    expiresAtUnix: timestampUnix + expirySeconds,
    ...(minFinalCltvExpiry !== undefined ? { minFinalCltvExpiry } : {}),
    signatureHex: sigBytes.toString("hex"),
  };
}

/**
 * Issues a simulated Lightning Network invoice on the HTLC escrow layer.
 * Returns ONLY public invoice metadata (`bolt11`, `paymentHash`, etc.) —
 * NEVER returns `preimage` to the server invoice store or HTTP 402 response.
 */
export function issueHtlcInvoice(params: {
  amountMsat: bigint | string | number;
  network?: LightningNetworkId;
  description?: string;
  expirySeconds?: number;
  payeePubkey?: string;
}): IssuedLightningInvoice {
  const preimageBytes = crypto.randomBytes(32);
  const preimageHex = preimageBytes.toString("hex");
  const paymentHash = crypto
    .createHash("sha256")
    .update(preimageBytes)
    .digest("hex");

  const nodeKey = getFallbackNodeKey();
  const payeePubkey = normalizeCompressedPubkey(
    params.payeePubkey ?? nodeKey.compressedPubkeyHex
  );
  const { network } = resolvePrefixAndNetwork(params.network);
  const timestampUnix = Math.floor(Date.now() / 1000);
  const expirySeconds = params.expirySeconds ?? DEFAULT_EXPIRY_SECONDS;
  const amountMsat = BigInt(params.amountMsat);
  const description = params.description ?? "x402 Lightning-402 payment";

  const bolt11 = encodeLightningInvoice({
    network,
    amountMsat,
    paymentHash,
    payeePubkey,
    description,
    timestampUnix,
    expirySeconds,
  });

  // Store preimage ONLY in the HTLC network escrow — never in the returned invoice!
  htlcNetworkEscrow.set(paymentHash, preimageHex);

  return {
    bolt11,
    paymentHash,
    amountMsat,
    payeePubkey,
    timestampUnix,
    expiresAtUnix: timestampUnix + expirySeconds,
    expirySeconds,
    network,
    description,
  };
}

export function createTestLightningSimulator(options?: {
  payerId?: string;
  payeePubkey?: string;
  useNetworkHtlcEscrow?: boolean;
}): TestLightningSimulator {
  const nodeKey = getFallbackNodeKey();
  const payeePubkey = normalizeCompressedPubkey(
    options?.payeePubkey ?? nodeKey.compressedPubkeyHex
  );
  const payerId =
    options?.payerId ??
    `ln-payer:${crypto.randomBytes(6).toString("hex")}`;
  const useNetworkHtlcEscrow = options?.useNetworkHtlcEscrow ?? true;

  // Payer-side preimage map: preimages stay strictly on the simulated payer side.
  const payerPreimages = new Map<string, string>();
  let settled = 0;

  const mintInvoice: TestLightningSimulator["mintInvoice"] = (params) => {
    const preimageBytes = crypto.randomBytes(32);
    const preimageHex = preimageBytes.toString("hex");
    const paymentHash = crypto
      .createHash("sha256")
      .update(preimageBytes)
      .digest("hex");
    const { network } = resolvePrefixAndNetwork(params.network);
    const timestampUnix = Math.floor(Date.now() / 1000);
    const expirySeconds = params.expirySeconds ?? DEFAULT_EXPIRY_SECONDS;
    const amountMsat = BigInt(params.amountMsat);
    const description = params.description ?? "x402 Lightning-402 payment";

    const bolt11 = encodeLightningInvoice({
      network,
      amountMsat,
      paymentHash,
      payeePubkey,
      description,
      timestampUnix,
      expirySeconds,
    });

    payerPreimages.set(paymentHash, preimageHex);

    return {
      bolt11,
      paymentHash,
      amountMsat,
      payeePubkey,
      timestampUnix,
      expiresAtUnix: timestampUnix + expirySeconds,
      expirySeconds,
      network,
      description,
    };
  };

  const registerPreimage = (paymentHash: string, preimage: string): void => {
    const cleanHash = normalizeHex32(paymentHash, "paymentHash");
    const cleanPreimage = normalizeHex32(preimage, "preimage");
    if (!verifyLightningPreimage(cleanPreimage, cleanHash)) {
      throw new Error("Cannot register preimage: SHA256(preimage) !== paymentHash");
    }
    payerPreimages.set(cleanHash, cleanPreimage);
  };

  const pay: LightningPayerFn = async (req: LightningPaymentRequest) => {
    const decoded = decodeLightningInvoice(req.bolt11);
    const cleanHash = normalizeHex32(req.paymentHash, "paymentHash");
    if (decoded.paymentHash !== cleanHash) {
      throw new Error(
        `BOLT11 paymentHash ${decoded.paymentHash} does not match requirement ${cleanHash}`
      );
    }
    if (decoded.amountMsat > 0n && decoded.amountMsat !== req.amountMsat) {
      throw new Error(
        `BOLT11 amount ${decoded.amountMsat.toString()} msat does not match requirement ${req.amountMsat.toString()} msat`
      );
    }
    const nowUnix = Math.floor(Date.now() / 1000);
    if (decoded.expiresAtUnix <= nowUnix) {
      throw new Error(
        `BOLT11 invoice expired at ${decoded.expiresAtUnix} (now=${nowUnix})`
      );
    }

    let preimage = payerPreimages.get(cleanHash);
    if (!preimage && useNetworkHtlcEscrow) {
      const escrowPreimage = htlcNetworkEscrow.get(cleanHash);
      if (escrowPreimage) {
        // Transfer preimage to payer upon HTLC settlement.
        payerPreimages.set(cleanHash, escrowPreimage);
        preimage = escrowPreimage;
      }
    }

    if (!preimage) {
      throw new Error(
        `Unable to settle Lightning HTLC: unknown preimage for paymentHash ${cleanHash}`
      );
    }
    if (!verifyLightningPreimage(preimage, cleanHash)) {
      throw new Error("Corrupt preimage in payer simulator");
    }

    settled += 1;
    return {
      preimage,
      payer: payerId,
    };
  };

  return {
    payeePubkey,
    payerId,
    mintInvoice,
    registerPreimage,
    pay,
    payer: pay,
    hasPreimage: (paymentHash: string) => {
      try {
        return payerPreimages.has(normalizeHex32(paymentHash, "paymentHash"));
      } catch {
        return false;
      }
    },
    settledCount: () => settled,
  };
}
