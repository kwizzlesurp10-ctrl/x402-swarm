import {
  isRetiredPayTo,
} from "../../shared/constants.js";
import { evaluateRequirementMicroUsd } from "../../shared/policy.js";
import type {
  EndpointCheck,
  EndpointValidationResult,
  X402PaymentRequiredEnvelope,
  X402PaymentRequirement,
} from "../../shared/types.js";
import { decodePaymentRequiredHeader } from "../../shared/x402-adapter.js";

const CAIP2_NETWORK_REGEX = /^[a-z0-9-]{2,16}:[a-zA-Z0-9_.-]{1,64}$/;
const EVM_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;
const INTEGER_STRING_REGEX = /^\d+$/;

export interface ValidateEndpointOptions {
  paidPath?: string;
  mcpPath?: string;
  paidMethod?: "GET" | "POST";
  paidBody?: unknown;
  paidToolName?: string;
  paidToolArgs?: Record<string, unknown>;
  timeoutMs?: number;
  allowOptionalWellKnown?: boolean;
  fetchImpl?: typeof globalThis.fetch;
}

interface JsonFetchOutcome {
  ok: boolean;
  status: number;
  headers: Headers;
  text: string;
  json: unknown;
  isJson: boolean;
  error?: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseSseOrJson(text: string, contentType: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("Empty response body");
  }
  if (contentType.includes("text/event-stream") || trimmed.startsWith("event:") || trimmed.startsWith("data:")) {
    const dataLines = trimmed
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .filter((line) => line.length > 0 && line !== "[DONE]");
    for (let i = dataLines.length - 1; i >= 0; i--) {
      try {
        return JSON.parse(dataLines[i]);
      } catch {
        // Keep scanning earlier SSE data lines.
      }
    }
  }
  return JSON.parse(trimmed);
}

async function fetchManual(
  fetchImpl: typeof globalThis.fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<JsonFetchOutcome> {
  try {
    const res = await fetchImpl(url, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    const contentType = String(res.headers.get("content-type") ?? "");
    let json: unknown = null;
    let isJson = false;
    if (text.trim().length > 0) {
      try {
        json = parseSseOrJson(text, contentType);
        isJson = true;
      } catch {
        isJson = false;
      }
    }
    return {
      ok: res.ok,
      status: res.status,
      headers: res.headers,
      text,
      json,
      isJson,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      headers: new Headers(),
      text: "",
      json: null,
      isJson: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function collectStringsRecursive(
  node: unknown,
  targetKey: string,
  out: Set<string>
): void {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) {
      collectStringsRecursive(item, targetKey, out);
    }
    return;
  }
  const obj = node as Record<string, unknown>;
  for (const [k, v] of Object.entries(obj)) {
    if (k === targetKey) {
      if (typeof v === "string" && v.trim()) {
        out.add(v.trim());
      } else if (Array.isArray(v)) {
        for (const item of v) {
          if (typeof item === "string" && item.trim()) {
            out.add(item.trim());
          }
        }
      }
    }
    if (v && typeof v === "object") {
      collectStringsRecursive(v, targetKey, out);
    }
  }
}

function extractDiscoveredPaidTarget(
  doc: Record<string, unknown>,
  origin: string
): { paidUrl?: string; paidToolName?: string } {
  const candidates: unknown[] = [
    doc.paidEndpoint,
    doc.paidUrl,
    doc.endpoint,
    doc.resource,
  ];

  for (const listKey of [
    "endpoints",
    "paidEndpoints",
    "httpEndpoints",
    "routes",
    "paidRoutes",
    "resources",
    "items",
  ]) {
    const list = doc[listKey];
    if (Array.isArray(list) && list.length > 0) {
      candidates.push(list[0]);
    } else if (isPlainObject(list)) {
      for (const val of Object.values(list)) {
        candidates.push(val);
      }
    }
  }

  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      try {
        return { paidUrl: new URL(candidate.trim(), origin).toString() };
      } catch {
        // Ignore invalid URL candidate
      }
    } else if (isPlainObject(candidate)) {
      const rawPath = candidate.resource ?? candidate.url ?? candidate.path ?? candidate.endpoint;
      if (typeof rawPath === "string" && rawPath.trim()) {
        try {
          return { paidUrl: new URL(rawPath.trim(), origin).toString() };
        } catch {
          // Ignore invalid URL candidate
        }
      }
    }
  }

  const paidTools = doc.paidTools;
  if (Array.isArray(paidTools) && paidTools.length > 0) {
    const first = paidTools[0];
    if (typeof first === "string" && first.trim()) {
      return { paidToolName: first.trim() };
    }
    if (isPlainObject(first) && typeof first.name === "string" && first.name.trim()) {
      return { paidToolName: first.name.trim() };
    }
  }

  return {};
}

function normalizeAndValidateEnvelope(
  rawEnvelope: unknown
): {
  valid: boolean;
  reason?: string;
  requirements: X402PaymentRequirement[];
} {
  if (!isPlainObject(rawEnvelope)) {
    return { valid: false, reason: "402 challenge payload is not a JSON object", requirements: [] };
  }

  const version = rawEnvelope.x402Version;
  if (version !== 2 && version !== 1) {
    return {
      valid: false,
      reason: `Unsupported or missing x402Version: ${String(version)}`,
      requirements: [],
    };
  }

  if (!Array.isArray(rawEnvelope.accepts) || rawEnvelope.accepts.length === 0) {
    return {
      valid: false,
      reason: "402 challenge accepts[] must be a non-empty array",
      requirements: [],
    };
  }

  const normalized: X402PaymentRequirement[] = [];
  for (let i = 0; i < rawEnvelope.accepts.length; i++) {
    const item = rawEnvelope.accepts[i];
    if (!isPlainObject(item)) {
      return { valid: false, reason: `accepts[${i}] is not an object`, requirements: [] };
    }

    const scheme = typeof item.scheme === "string" ? item.scheme.trim() : "";
    const network = typeof item.network === "string" ? item.network.trim() : "";
    const asset = typeof item.asset === "string" ? item.asset.trim() : "";
    const payTo = typeof item.payTo === "string" ? item.payTo.trim() : "";
    const rawAmount =
      item.amount !== undefined
        ? item.amount
        : version === 1
          ? item.maxAmountRequired
          : undefined;
    const amount = typeof rawAmount === "string" ? rawAmount.trim() : "";

    if (!scheme) {
      return { valid: false, reason: `accepts[${i}] missing valid scheme`, requirements: [] };
    }
    if (!network || !CAIP2_NETWORK_REGEX.test(network)) {
      return {
        valid: false,
        reason: `accepts[${i}] has invalid CAIP-2 network: ${String(item.network)}`,
        requirements: [],
      };
    }
    if (!asset) {
      return { valid: false, reason: `accepts[${i}] missing valid asset`, requirements: [] };
    }
    if (!amount || !INTEGER_STRING_REGEX.test(amount)) {
      return {
        valid: false,
        reason: `accepts[${i}] amount must be a non-negative integer string, got: ${String(rawAmount)}`,
        requirements: [],
      };
    }
    if (!payTo) {
      return { valid: false, reason: `accepts[${i}] missing valid payTo`, requirements: [] };
    }
    if (network.startsWith("eip155:") && !EVM_ADDRESS_REGEX.test(payTo)) {
      return {
        valid: false,
        reason: `accepts[${i}] EVM payTo is not a valid 20-byte hex address: ${payTo}`,
        requirements: [],
      };
    }

    normalized.push({
      scheme,
      network,
      asset,
      amount,
      payTo,
      maxTimeoutSeconds:
        typeof item.maxTimeoutSeconds === "number" ? item.maxTimeoutSeconds : 300,
      extra: isPlainObject(item.extra) ? item.extra : undefined,
    });
  }

  return { valid: true, requirements: normalized };
}

function derivePriceMicroUsd(requirements: X402PaymentRequirement[]): string | null {
  if (requirements.length === 0) return null;

  // Prefer native 6-decimal USD-pegged EVM requirements so integer micro-USD is exact without rate assumptions.
  const evmMicros: bigint[] = [];
  const allMicros: bigint[] = [];

  for (const req of requirements) {
    try {
      const micro = evaluateRequirementMicroUsd(req);
      allMicros.push(micro);
      const isLightning =
        req.scheme === "lightning" ||
        req.network.startsWith("lightning:") ||
        req.asset.toUpperCase() === "MSAT" ||
        req.asset.toUpperCase() === "SAT" ||
        req.asset.toUpperCase() === "BTC_SAT";
      if (!isLightning) {
        evmMicros.push(micro);
      }
    } catch {
      // Skip unparseable entry; validation check will already flag invalid amount.
    }
  }

  const pool = evmMicros.length > 0 ? evmMicros : allMicros;
  if (pool.length === 0) return null;

  let minMicro = pool[0];
  for (let i = 1; i < pool.length; i++) {
    if (pool[i] < minMicro) minMicro = pool[i];
  }
  return minMicro.toString();
}

export async function validateEndpoint(
  targetUrl: string,
  options: ValidateEndpointOptions = {}
): Promise<EndpointValidationResult> {
  const startedAt = performance.now();
  const parsed = new URL(targetUrl);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported URL protocol for validation: ${parsed.protocol}`);
  }

  const origin = parsed.origin;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 8000;
  const allowOptionalWellKnown = options.allowOptionalWellKnown ?? true;

  const checks: EndpointCheck[] = [];
  const discoveredPayTo = new Set<string>();
  const discoveredSchemes = new Set<string>();
  const discoveredNetworks = new Set<string>();

  // 1. Probe /.well-known/x402 first so mcpEndpoint & paidEndpoint can be auto-discovered.
  const wellKnownUrl = new URL("/.well-known/x402", origin).toString();
  const wellKnownRes = await fetchManual(
    fetchImpl,
    wellKnownUrl,
    {
      method: "GET",
      headers: { Accept: "application/json" },
    },
    timeoutMs
  );

  let wellKnownDoc: Record<string, unknown> | null = null;
  if (wellKnownRes.status === 200 && isPlainObject(wellKnownRes.json)) {
    wellKnownDoc = wellKnownRes.json;
    collectStringsRecursive(wellKnownDoc, "payTo", discoveredPayTo);
    if (Array.isArray(wellKnownDoc.schemes)) {
      for (const s of wellKnownDoc.schemes) {
        if (typeof s === "string" && s.trim()) discoveredSchemes.add(s.trim());
      }
    }
    if (Array.isArray(wellKnownDoc.networks)) {
      for (const n of wellKnownDoc.networks) {
        if (typeof n === "string" && n.trim()) discoveredNetworks.add(n.trim());
      }
    }
    if (Array.isArray(wellKnownDoc.accepts)) {
      for (const item of wellKnownDoc.accepts) {
        if (isPlainObject(item)) {
          if (typeof item.scheme === "string" && item.scheme.trim()) {
            discoveredSchemes.add(item.scheme.trim());
          }
          if (typeof item.network === "string" && item.network.trim()) {
            discoveredNetworks.add(item.network.trim());
          }
        }
      }
    }
    checks.push({
      name: "well_known_x402",
      passed: true,
      status: 200,
      detail: `GET /.well-known/x402 returned 200 OK JSON metadata`,
    });
  } else {
    const detail = wellKnownRes.error
      ? `GET /.well-known/x402 failed: ${wellKnownRes.error}`
      : wellKnownRes.status === 200
        ? "GET /.well-known/x402 returned 200 but body is not a JSON object"
        : `GET /.well-known/x402 returned HTTP ${wellKnownRes.status}${allowOptionalWellKnown ? " (optional)" : ""}`;
    checks.push({
      name: "well_known_x402",
      passed: false,
      status: wellKnownRes.status || undefined,
      detail,
    });
  }

  // Resolve MCP URL (base path without trailing slash, plus trailing-slash variant).
  let mcpBaseUrl: string;
  if (options.mcpPath) {
    mcpBaseUrl = new URL(options.mcpPath, origin).toString().replace(/\/+$/, "");
  } else if (parsed.pathname === "/mcp" || parsed.pathname === "/mcp/") {
    mcpBaseUrl = new URL("/mcp", origin).toString();
  } else if (wellKnownDoc && typeof wellKnownDoc.mcpEndpoint === "string" && wellKnownDoc.mcpEndpoint.trim()) {
    mcpBaseUrl = new URL(wellKnownDoc.mcpEndpoint.trim(), origin).toString().replace(/\/+$/, "");
  } else {
    mcpBaseUrl = new URL("/mcp", origin).toString();
  }
  const mcpSlashUrl = `${mcpBaseUrl}/`;

  // 2. Probe GET /mcp and GET /mcp/ without SSE Accept (must both return 200 OK JSON, never 307 -> 404).
  const [cardNoSlash, cardWithSlash] = await Promise.all([
    fetchManual(
      fetchImpl,
      mcpBaseUrl,
      { method: "GET", headers: { Accept: "application/json" } },
      timeoutMs
    ),
    fetchManual(
      fetchImpl,
      mcpSlashUrl,
      { method: "GET", headers: { Accept: "application/json" } },
      timeoutMs
    ),
  ]);

  let mcpCardPassed = false;
  let mcpCardStatus: number | undefined;
  let mcpCardDetail = "";

  if (cardNoSlash.status !== 200 || !isPlainObject(cardNoSlash.json)) {
    mcpCardStatus = cardNoSlash.status || undefined;
    const loc = cardNoSlash.headers.get("location");
    mcpCardDetail = cardNoSlash.error
      ? `GET ${new URL(mcpBaseUrl).pathname} failed: ${cardNoSlash.error}`
      : cardNoSlash.status !== 200
        ? `GET ${new URL(mcpBaseUrl).pathname} returned HTTP ${cardNoSlash.status}${loc ? ` -> ${loc}` : ""} (expected 200 OK JSON)`
        : `GET ${new URL(mcpBaseUrl).pathname} returned HTTP 200 but invalid JSON server card`;
  } else if (cardWithSlash.status !== 200 || !isPlainObject(cardWithSlash.json)) {
    mcpCardStatus = cardWithSlash.status || undefined;
    const loc = cardWithSlash.headers.get("location");
    mcpCardDetail = cardWithSlash.error
      ? `GET ${new URL(mcpSlashUrl).pathname} failed: ${cardWithSlash.error}`
      : cardWithSlash.status !== 200
        ? `GET ${new URL(mcpSlashUrl).pathname} returned HTTP ${cardWithSlash.status}${loc ? ` -> ${loc}` : ""} (expected 200 OK JSON)`
        : `GET ${new URL(mcpSlashUrl).pathname} returned HTTP 200 but invalid JSON server card`;
  } else {
    mcpCardPassed = true;
    mcpCardStatus = 200;
    mcpCardDetail = `GET /mcp and GET /mcp/ both returned 200 OK JSON server cards`;
    collectStringsRecursive(cardNoSlash.json, "payTo", discoveredPayTo);
    collectStringsRecursive(cardWithSlash.json, "payTo", discoveredPayTo);
  }

  checks.push({
    name: "mcp_get_card",
    passed: mcpCardPassed,
    status: mcpCardStatus,
    detail: mcpCardDetail,
  });

  // 3. Probe POST /mcp initialize + tools/list JSON-RPC 2.0.
  const initRes = await fetchManual(
    fetchImpl,
    mcpBaseUrl,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "x402-discovery-validator", version: "0.1.0" },
        },
      }),
    },
    timeoutMs
  );

  let mcpInitPassed = false;
  let mcpInitStatus: number | undefined = initRes.status || undefined;
  let mcpInitDetail = "";
  let sessionId = initRes.headers.get("mcp-session-id") ?? "";
  let listedToolsCount = 0;

  if (
    initRes.status === 200 &&
    isPlainObject(initRes.json) &&
    initRes.json.jsonrpc === "2.0" &&
    isPlainObject(initRes.json.result) &&
    !initRes.json.error
  ) {
    const listHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (sessionId) {
      listHeaders["Mcp-Session-Id"] = sessionId;
    }
    const listRes = await fetchManual(
      fetchImpl,
      mcpBaseUrl,
      {
        method: "POST",
        headers: listHeaders,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
          params: {},
        }),
      },
      timeoutMs
    );
    mcpInitStatus = listRes.status || undefined;

    if (
      listRes.status === 200 &&
      isPlainObject(listRes.json) &&
      listRes.json.jsonrpc === "2.0" &&
      isPlainObject(listRes.json.result) &&
      Array.isArray(listRes.json.result.tools) &&
      !listRes.json.error
    ) {
      const validTools = listRes.json.result.tools.every(
        (t) => isPlainObject(t) && typeof t.name === "string" && t.name.length > 0
      );
      if (validTools) {
        mcpInitPassed = true;
        listedToolsCount = listRes.json.result.tools.length;
        const serverInfo = isPlainObject(initRes.json.result.serverInfo)
          ? String(initRes.json.result.serverInfo.name ?? "mcp-server")
          : "mcp-server";
        mcpInitDetail = `MCP initialize + tools/list succeeded for ${serverInfo} (${listedToolsCount} tools)`;
      } else {
        mcpInitDetail = "MCP tools/list returned malformed tool definitions";
      }
    } else {
      mcpInitDetail = listRes.error
        ? `MCP tools/list failed: ${listRes.error}`
        : `MCP tools/list returned invalid JSON-RPC response (HTTP ${listRes.status})`;
    }
  } else {
    mcpInitDetail = initRes.error
      ? `MCP initialize failed: ${initRes.error}`
      : `MCP initialize returned invalid JSON-RPC response (HTTP ${initRes.status})`;
  }

  checks.push({
    name: "mcp_initialize_and_tools",
    passed: mcpInitPassed,
    status: mcpInitStatus,
    detail: mcpInitDetail,
  });

  // 4. Probe paid_402_challenge.
  const discoveredPaid = wellKnownDoc
    ? extractDiscoveredPaidTarget(wellKnownDoc, origin)
    : {};

  let paidTargetUrl: string | undefined;
  let paidToolName = options.paidToolName;

  if (options.paidPath) {
    if (options.paidPath.startsWith("mcp://tool/")) {
      paidToolName = options.paidPath.slice("mcp://tool/".length);
    } else {
      paidTargetUrl = new URL(options.paidPath, origin).toString();
    }
  } else if (
    parsed.pathname !== "/" &&
    parsed.pathname !== "" &&
    parsed.pathname !== "/mcp" &&
    parsed.pathname !== "/mcp/" &&
    parsed.pathname !== "/.well-known/x402"
  ) {
    paidTargetUrl = parsed.toString();
  } else if (discoveredPaid.paidUrl) {
    paidTargetUrl = discoveredPaid.paidUrl;
  } else if (discoveredPaid.paidToolName) {
    paidToolName = discoveredPaid.paidToolName;
  } else {
    paidTargetUrl = targetUrl;
  }

  let paidCheckPassed = false;
  let paidCheckStatus: number | undefined;
  let paidCheckDetail = "";
  let validatedRequirements: X402PaymentRequirement[] = [];

  if (paidToolName && !paidTargetUrl) {
    // Probe paid MCP tool via JSON-RPC tools/call without payment.
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (sessionId) headers["Mcp-Session-Id"] = sessionId;

    const toolRes = await fetchManual(
      fetchImpl,
      mcpBaseUrl,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: {
            name: paidToolName,
            arguments: options.paidToolArgs ?? {},
          },
        }),
      },
      timeoutMs
    );
    paidCheckStatus = toolRes.status || undefined;

    if (
      isPlainObject(toolRes.json) &&
      isPlainObject(toolRes.json.result) &&
      toolRes.json.result.isError === true
    ) {
      const meta = isPlainObject(toolRes.json.result._meta)
        ? toolRes.json.result._meta
        : undefined;
      let rawChallenge: unknown = meta?.["x402/payment-required"];

      if (!rawChallenge && Array.isArray(toolRes.json.result.content)) {
        const firstText = toolRes.json.result.content.find(
          (c) => isPlainObject(c) && typeof c.text === "string"
        ) as { text?: string } | undefined;
        if (firstText?.text) {
          try {
            rawChallenge = JSON.parse(firstText.text);
          } catch {
            // Keep undefined
          }
        }
      }

      if (rawChallenge) {
        collectStringsRecursive(rawChallenge, "payTo", discoveredPayTo);
        const validation = normalizeAndValidateEnvelope(rawChallenge);
        if (validation.valid) {
          paidCheckPassed = true;
          validatedRequirements = validation.requirements;
          paidCheckDetail = `MCP tool ${paidToolName} returned valid x402 PaymentRequired challenge (${validatedRequirements.length} accept option(s))`;
        } else {
          paidCheckDetail = `MCP tool ${paidToolName} challenge invalid: ${validation.reason}`;
        }
      } else {
        paidCheckDetail = `MCP tool ${paidToolName} returned isError:true without x402 PaymentRequired payload`;
      }
    } else {
      paidCheckDetail = toolRes.error
        ? `MCP paid tool probe failed: ${toolRes.error}`
        : `MCP tool ${paidToolName} did not return isError:true PaymentRequired challenge`;
    }
  } else if (paidTargetUrl) {
    const initialMethod = options.paidMethod ?? "GET";
    let paidRes = await fetchManual(
      fetchImpl,
      paidTargetUrl,
      {
        method: initialMethod,
        headers: {
          Accept: "application/json",
          ...(initialMethod === "POST" ? { "Content-Type": "application/json" } : {}),
        },
        ...(initialMethod === "POST"
          ? { body: JSON.stringify(options.paidBody ?? {}) }
          : {}),
      },
      timeoutMs
    );

    if (!options.paidMethod && initialMethod === "GET" && (paidRes.status === 405 || paidRes.status === 200)) {
      const postRes = await fetchManual(
        fetchImpl,
        paidTargetUrl,
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify(options.paidBody ?? {}),
        },
        timeoutMs
      );
      if (paidRes.status === 405 || postRes.status === 402) {
        paidRes = postRes;
      }
    }

    paidCheckStatus = paidRes.status || undefined;

    if (paidRes.status === 402) {
      const headerVal = paidRes.headers.get("payment-required");
      let rawChallenge: unknown = null;

      if (headerVal) {
        try {
          rawChallenge = decodePaymentRequiredHeader(headerVal);
        } catch (err) {
          paidCheckDetail = `Failed to decode PAYMENT-REQUIRED header: ${err instanceof Error ? err.message : String(err)}`;
        }
      }

      if (!rawChallenge && paidRes.isJson) {
        rawChallenge = paidRes.json;
      }

      if (rawChallenge) {
        collectStringsRecursive(rawChallenge, "payTo", discoveredPayTo);
        const validation = normalizeAndValidateEnvelope(rawChallenge);
        if (validation.valid) {
          paidCheckPassed = true;
          validatedRequirements = validation.requirements;
          paidCheckDetail = `HTTP 402 challenge validated (${validatedRequirements.length} accept option(s))`;
        } else {
          paidCheckDetail = `HTTP 402 challenge invalid: ${validation.reason}`;
        }
      } else if (!paidCheckDetail) {
        paidCheckDetail = "HTTP 402 returned without PAYMENT-REQUIRED header or valid JSON body";
      }
    } else {
      paidCheckDetail = paidRes.error
        ? `Paid endpoint probe failed: ${paidRes.error}`
        : `Expected HTTP 402 challenge from ${new URL(paidTargetUrl).pathname}, got HTTP ${paidRes.status}`;
    }
  }

  checks.push({
    name: "paid_402_challenge",
    passed: paidCheckPassed,
    status: paidCheckStatus,
    detail: paidCheckDetail,
  });

  // 5. Retired payee guard across ALL discovered payTo addresses and accepts[].
  for (const req of validatedRequirements) {
    discoveredPayTo.add(req.payTo);
    discoveredSchemes.add(req.scheme);
    discoveredNetworks.add(req.network);
  }

  // Deduplicate payTo case-insensitively while preserving first checksummed representation.
  const payToByLower = new Map<string, string>();
  for (const addr of discoveredPayTo) {
    const key = addr.trim().toLowerCase();
    if (key && !payToByLower.has(key)) {
      payToByLower.set(key, addr.trim());
    }
  }
  const uniquePayTo = [...payToByLower.values()];
  const retiredMatches = uniquePayTo.filter((addr) => isRetiredPayTo(addr));

  const retiredGuardPassed = retiredMatches.length === 0;
  checks.push({
    name: "retired_payee_guard",
    passed: retiredGuardPassed,
    detail: retiredGuardPassed
      ? uniquePayTo.length > 0
        ? `Verified ${uniquePayTo.length} payee address(es); all passed payee integrity policy`
        : "Payee integrity policy verified"
      : `CRITICAL: Payee address rejected by integrity policy`,
  });

  const valid =
    mcpCardPassed &&
    (allowOptionalWellKnown ? true : checks[0].passed) &&
    mcpInitPassed &&
    paidCheckPassed &&
    retiredGuardPassed;

  const passedCount = checks.filter((c) => c.passed).length;
  const score = retiredGuardPassed
    ? Math.round((passedCount / checks.length) * 100)
    : 0;

  const latencyMs = Math.max(0, Math.round(performance.now() - startedAt));

  return {
    url: targetUrl,
    valid,
    score,
    checks,
    schemes: [...discoveredSchemes],
    networks: [...discoveredNetworks],
    payTo: uniquePayTo,
    priceMicroUsd: derivePriceMicroUsd(validatedRequirements),
    latencyMs,
    checkedAt: new Date().toISOString(),
  };
}
