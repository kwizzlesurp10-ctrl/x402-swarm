import http, { type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { BRANDING } from "./constants.js";

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface McpToolContext {
  req: IncomingMessage;
  headers: http.IncomingHttpHeaders;
  meta: Record<string, unknown>;
  paymentSignatureHeader: string;
}

export interface McpToolResult {
  data: unknown;
  isError?: boolean;
  meta?: Record<string, unknown>;
  httpStatus?: number;
  httpHeaders?: Record<string, string>;
}

export type McpToolHandler = (
  args: Record<string, unknown>,
  ctx: McpToolContext
) => Promise<McpToolResult> | McpToolResult;

export type ExtraHttpRouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  url: URL
) => Promise<boolean> | boolean;

export interface McpServerOptions {
  port?: number;
  host?: string;
  name: string;
  title: string;
  version: string;
  description: string;
  tools: McpToolDefinition[];
  handlers: Record<string, McpToolHandler>;
  wellKnownX402?: () => Record<string, unknown>;
  serverCardExtras?: () => Record<string, unknown>;
  extraRoutes?: ExtraHttpRouteHandler;
}

export interface RunningMcpServer {
  server: http.Server;
  port: number;
  host: string;
  baseUrl: string;
  mcpUrl: string;
  close: () => Promise<void>;
}

export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Accept, Authorization, payment-signature, PAYMENT-SIGNATURE, x402-authorization, x-payment-signature, Mcp-Session-Id",
  "Access-Control-Expose-Headers":
    "WWW-Authenticate, PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Verified-Payer, X-Settlement-Tx, Mcp-Session-Id",
};

export function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): void {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...CORS_HEADERS,
    ...extraHeaders,
  });
  res.end(payload);
}

export async function readBodyText(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const raw = await readBodyText(req);
  if (!raw.trim()) return {};
  return JSON.parse(raw);
}

export function startMcpHttpServer(
  options: McpServerOptions
): Promise<RunningMcpServer> {
  const host = options.host ?? "127.0.0.1";
  const requestedPort = options.port ?? 0;

  const server = http.createServer(async (req, res) => {
    const method = (req.method ?? "GET").toUpperCase();
    const baseOrigin = `http://${req.headers.host || `${host}:${requestedPort}`}`;
    const url = new URL(req.url || "/", baseOrigin);
    const pathname = url.pathname;

    if (method === "OPTIONS") {
      res.writeHead(204, CORS_HEADERS);
      res.end();
      return;
    }

    if (options.extraRoutes) {
      try {
        const handled = await options.extraRoutes(req, res, url);
        if (handled) return;
      } catch (err) {
        sendJson(res, 500, {
          error: err instanceof Error ? err.message : String(err),
        });
        return;
      }
    }

    if (method === "GET" && pathname === "/health") {
      sendJson(res, 200, {
        status: "ok",
        name: options.name,
        title: options.title,
        version: options.version,
        toolsCount: options.tools.length,
        branding: BRANDING,
      });
      return;
    }

    if (method === "GET" && pathname === "/.well-known/x402") {
      const manifest = options.wellKnownX402
        ? options.wellKnownX402()
        : {
            x402Version: 2,
            name: options.name,
            title: options.title,
            description: options.description,
            mcpEndpoint: `${baseOrigin}/mcp`,
            branding: BRANDING,
          };
      sendJson(res, 200, manifest);
      return;
    }

    if (pathname === "/mcp" || pathname === "/mcp/") {
      if (method === "GET") {
        const accept = String(req.headers.accept ?? "");
        if (accept.includes("text/event-stream")) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream; charset=utf-8",
            "Cache-Control": "no-cache, no-transform",
            Connection: "keep-alive",
            ...CORS_HEADERS,
          });
          res.write(`event: endpoint\ndata: /mcp\n\n`);
          req.on("close", () => {
            if (!res.writableEnded) res.end();
          });
          return;
        }

        // Plain browser/crawler GET /mcp MUST return 200 application/json server card.
        const card = {
          name: options.name,
          title: options.title,
          version: options.version,
          description: options.description,
          transport: "streamable-http",
          protocolVersion: "2025-03-26",
          toolsCount: options.tools.length,
          tools: options.tools.map((t) => ({
            name: t.name,
            description: t.description,
          })),
          status: "ONLINE",
          branding: BRANDING,
          ...(options.serverCardExtras ? options.serverCardExtras() : {}),
        };
        sendJson(res, 200, card);
        return;
      }

      if (method === "POST") {
        let rpc: Record<string, unknown>;
        try {
          const parsed = await readJsonBody(req);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Expected JSON-RPC object");
          }
          rpc = parsed as Record<string, unknown>;
        } catch {
          sendJson(res, 400, {
            jsonrpc: "2.0",
            id: null,
            error: { code: -32700, message: "Parse error" },
          });
          return;
        }

        const id = (rpc.id as string | number | null | undefined) ?? null;
        const rpcMethod = String(rpc.method ?? "");
        const params =
          rpc.params && typeof rpc.params === "object"
            ? (rpc.params as Record<string, unknown>)
            : {};

        if (rpcMethod === "initialize") {
          sendJson(res, 200, {
            jsonrpc: "2.0",
            id,
            result: {
              protocolVersion: "2025-03-26",
              capabilities: {
                tools: { listChanged: false },
              },
              serverInfo: {
                name: options.name,
                title: options.title,
                version: options.version,
              },
            },
          });
          return;
        }

        if (rpcMethod === "notifications/initialized") {
          res.writeHead(202, CORS_HEADERS);
          res.end();
          return;
        }

        if (rpcMethod === "ping") {
          sendJson(res, 200, { jsonrpc: "2.0", id, result: {} });
          return;
        }

        if (rpcMethod === "tools/list") {
          sendJson(res, 200, {
            jsonrpc: "2.0",
            id,
            result: { tools: options.tools },
          });
          return;
        }

        if (rpcMethod === "tools/call") {
          const toolName = String(params.name ?? "");
          const handler = options.handlers[toolName];
          if (!handler) {
            sendJson(res, 200, {
              jsonrpc: "2.0",
              id,
              result: {
                isError: true,
                content: [
                  {
                    type: "text",
                    text: JSON.stringify({ error: `Unknown tool: ${toolName}` }),
                  },
                ],
              },
            });
            return;
          }

          const args =
            params.arguments && typeof params.arguments === "object"
              ? (params.arguments as Record<string, unknown>)
              : {};
          const meta =
            params._meta && typeof params._meta === "object"
              ? (params._meta as Record<string, unknown>)
              : {};

          const paymentSignatureHeader = String(
            req.headers["payment-signature"] ??
              req.headers["x-payment-signature"] ??
              req.headers["x402-authorization"] ??
              ""
          );

          try {
            const outcome = await handler(args, {
              req,
              headers: req.headers,
              meta,
              paymentSignatureHeader,
            });
            const text =
              typeof outcome.data === "string"
                ? outcome.data
                : JSON.stringify(outcome.data, null, 2);

            sendJson(
              res,
              outcome.httpStatus ?? 200,
              {
                jsonrpc: "2.0",
                id,
                result: {
                  ...(outcome.isError ? { isError: true } : {}),
                  content: [{ type: "text", text }],
                  ...(outcome.meta ? { _meta: outcome.meta } : {}),
                },
              },
              outcome.httpHeaders ?? {}
            );
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            sendJson(res, 200, {
              jsonrpc: "2.0",
              id,
              result: {
                isError: true,
                content: [
                  {
                    type: "text",
                    text: JSON.stringify({ error: message }),
                  },
                ],
              },
            });
          }
          return;
        }

        sendJson(res, 404, {
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Method not found: ${rpcMethod}` },
        });
        return;
      }
    }

    sendJson(res, 404, { error: "Not found", path: pathname });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, host, () => {
      const addr = server.address() as AddressInfo;
      const actualPort = addr.port;
      const baseUrl = `http://${host}:${actualPort}`;
      resolve({
        server,
        port: actualPort,
        host,
        baseUrl,
        mcpUrl: `${baseUrl}/mcp`,
        close: () =>
          new Promise<void>((resClose, rejClose) => {
            server.close((err) => (err ? rejClose(err) : resClose()));
          }),
      });
    });
  });
}
