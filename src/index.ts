import { jwtVerify, SignJWT } from "jose";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";

interface AgentAccessTokenPayload {
  sub: string;
  agentId: string;
  claimId: string;
  namespace: string;
}

const port = Number(process.env.PORT ?? "3000");
const issuer = "quickstack-auth-proxy";
const cookieName = "qs-auth-proxy-session";
const sessionSecret = crypto.getRandomValues(new Uint8Array(32));

interface ProxyWebSocketData {
  targetUrl: string;
  headers: Record<string, string>;
  protocol: string | null;
  upstream: WebSocket | null;
}

function unauthorized(): Response {
  return new Response("Unauthorized", { status: 401 });
}

function parseCookies(cookieHeader: string | null): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) {
    return cookies;
  }

  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (!rawName || rawValue.length === 0) {
      continue;
    }
    cookies[rawName] = decodeURIComponent(rawValue.join("="));
  }

  return cookies;
}

function getForwardedUri(req: Request): string {
  const requestUrl = new URL(req.url);
  return req.headers.get("x-forwarded-uri") ?? `${requestUrl.pathname}${requestUrl.search}`;
}

function getUrlFromForwardedUri(forwardedUri: string): URL {
  return new URL(forwardedUri, "http://quickstack.local");
}

function getExternalOrigin(req: Request): string {
  const proto = req.headers.get("x-forwarded-proto") ?? new URL(req.url).protocol.replace(":", "");
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? new URL(req.url).host;
  return `${proto}://${host}`;
}

function getExternalHost(req: Request): string {
  return req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? new URL(req.url).host;
}

function getSessionTtlSeconds(): number {
  return Number(process.env.AGENT_SESSION_JWT_TTL_SECONDS || process.env.AGENT_JWT_TTL_SECONDS || "3600");
}

async function verifyAccessToken(token: string): Promise<AgentAccessTokenPayload> {
  const secret = process.env.AGENT_JWT_SECRET;
  if (!secret) {
    throw new Error("AGENT_JWT_SECRET is required");
  }

  const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
    algorithms: ["HS256"],
    issuer,
  });

  if (
    typeof payload.sub !== "string" ||
    typeof payload.agentId !== "string" ||
    typeof payload.claimId !== "string" ||
    typeof payload.namespace !== "string"
  ) {
    throw new Error("Invalid token payload");
  }

  return {
    sub: payload.sub,
    agentId: payload.agentId,
    claimId: payload.claimId,
    namespace: payload.namespace,
  };
}

async function verifySessionToken(token: string): Promise<AgentAccessTokenPayload> {
  const { payload } = await jwtVerify(token, sessionSecret, {
    algorithms: ["HS256"],
    issuer,
  });

  if (
    typeof payload.sub !== "string" ||
    typeof payload.agentId !== "string" ||
    typeof payload.claimId !== "string" ||
    typeof payload.namespace !== "string"
  ) {
    throw new Error("Invalid token payload");
  }

  return {
    sub: payload.sub,
    agentId: payload.agentId,
    claimId: payload.claimId,
    namespace: payload.namespace,
  };
}

async function createSessionToken(payload: AgentAccessTokenPayload): Promise<string> {
  return await new SignJWT({
    agentId: payload.agentId,
    claimId: payload.claimId,
    namespace: payload.namespace,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(payload.sub)
    .setIssuer(issuer)
    .setIssuedAt()
    .setExpirationTime(`${getSessionTtlSeconds()}s`)
    .sign(sessionSecret);
}

function sessionCookie(token: string, req: Request): string {
  const parts = [
    `${cookieName}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (req.headers.get("x-forwarded-proto") === "https") {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function redirectWithSessionCookie(req: Request, forwardedUrl: URL, token: string): Response {
  forwardedUrl.searchParams.delete("token");
  const location = new URL(
    `${forwardedUrl.pathname}${forwardedUrl.search}${forwardedUrl.hash}`,
    getExternalOrigin(req),
  ).toString();

  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      "Set-Cookie": sessionCookie(token, req),
    },
  });
}

function sandboxPortFor(forwardedUrl: URL): string {
  return forwardedUrl.pathname.startsWith("/files") ? "80" : "4096";
}

function removeAuthProxyCookie(cookieHeader: string | null): string | null {
  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part && !part.startsWith(`${cookieName}=`));

  return cookies.length > 0 ? cookies.join("; ") : null;
}

function targetUrlFor(forwardedUrl: URL, payload: AgentAccessTokenPayload): string {
  forwardedUrl.searchParams.delete("token");
  forwardedUrl.protocol = "http:";
  forwardedUrl.hostname = `${payload.claimId}.${payload.namespace}.svc.cluster.local`;
  forwardedUrl.port = sandboxPortFor(forwardedUrl);
  return forwardedUrl.toString();
}

function requestHeadersForSandbox(req: Request): Headers {
  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.delete("authorization");
  headers.delete("accept-encoding");
  headers.delete("x-forwarded-uri");
  headers.delete("origin");
  headers.delete("referer");

  const appCookies = removeAuthProxyCookie(req.headers.get("cookie"));
  if (appCookies) {
    headers.set("cookie", appCookies);
  } else {
    headers.delete("cookie");
  }

  return headers;
}

function webSocketHeadersForSandbox(req: Request): { headers: Record<string, string>; protocol: string | null } {
  const headers = requestHeadersForSandbox(req);

  headers.delete("connection");
  headers.delete("upgrade");
  headers.delete("sec-websocket-key");
  headers.delete("sec-websocket-version");
  headers.delete("sec-websocket-extensions");

  const protocolHeader = req.headers.get("sec-websocket-protocol");
  const protocol = protocolHeader ? protocolHeader.split(",")[0]?.trim() ?? null : null;

  if (protocolHeader) {
    headers.delete("sec-websocket-protocol");
  }

  return {
    headers: headersToNode(headers),
    protocol,
  };
}

function isWebSocketUpgrade(req: Request): boolean {
  return req.headers.get("upgrade")?.toLowerCase() === "websocket";
}

function webSocketTargetUrlFor(forwardedUrl: URL, payload: AgentAccessTokenPayload): string {
  const target = new URL(targetUrlFor(forwardedUrl, payload));
  target.protocol = "ws:";
  return target.toString();
}

function proxyWebSocketToSandbox(
  req: Request,
  server: any,
  forwardedUrl: URL,
  payload: AgentAccessTokenPayload,
): Response | undefined {
  const targetUrl = webSocketTargetUrlFor(forwardedUrl, payload);
  const { headers, protocol } = webSocketHeadersForSandbox(req);

  const upgradeHeaders: Record<string, string> = {};
  if (protocol) {
    upgradeHeaders["Sec-WebSocket-Protocol"] = protocol;
  }

  const upgraded = server?.upgrade(req, {
    headers: upgradeHeaders,
    data: {
      targetUrl,
      headers,
      protocol,
      upstream: null,
    } satisfies ProxyWebSocketData,
  });

  if (!upgraded) {
    console.error("[ws-proxy] upgrade failed: server.upgrade() returned false");
    return new Response("Bad Gateway", { status: 502 });
  }

  // Bun has already sent 101 Switching Protocols; return undefined so the fetch
  // handler yields control to the websocket handlers.
  return undefined;
}

function headersToNode(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function rawResponseHeaders(rawHeaders: string[]): Headers {
  const headers = new Headers();
  const excludedHeaders = new Set([
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]);

  for (let i = 0; i < rawHeaders.length; i += 2) {
    const key = rawHeaders[i];
    const value = rawHeaders[i + 1];
    if (!key || value === undefined) {
      continue;
    }
    const lowerKey = key.toLowerCase();
    if (excludedHeaders.has(lowerKey)) {
      continue;
    }
    if (lowerKey === "set-cookie") {
      headers.append(key, value);
    } else if (!headers.has(key)) {
      headers.set(key, value);
    }
  }
  return headers;
}

async function proxyToSandbox(req: Request, forwardedUrl: URL, payload: AgentAccessTokenPayload): Promise<Response> {
  const targetUrl = new URL(targetUrlFor(forwardedUrl, payload));
  const headers = requestHeadersForSandbox(req);

  return await new Promise<Response>((resolve, reject) => {
    const upstreamReq = httpRequest({
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port: targetUrl.port,
      path: `${targetUrl.pathname}${targetUrl.search}`,
      method: req.method,
      headers: headersToNode(headers),
    }, (upstreamRes) => {
      resolve(new Response(Readable.toWeb(upstreamRes) as ReadableStream, {
        status: upstreamRes.statusCode ?? 502,
        statusText: upstreamRes.statusMessage,
        headers: rawResponseHeaders(upstreamRes.rawHeaders),
      }));
    });

    upstreamReq.on("error", reject);

    if (req.body && req.method !== "GET" && req.method !== "HEAD") {
      Readable.fromWeb(req.body as any).pipe(upstreamReq);
    } else {
      upstreamReq.end();
    }
  });
}

async function handleRequest(req: Request, server: any): Promise<Response | undefined> {
  if (process.env.AUTH_DISABLED === "true") {
    const forwardedUrl = getUrlFromForwardedUri(getForwardedUri(req));
    if (isWebSocketUpgrade(req)) {
      return proxyWebSocketToSandbox(req, server, forwardedUrl, {
        sub: "dev",
        agentId: "dev-agent",
        claimId: process.env.QS_DEV_CLAIM_ID ?? "dev-claim",
        namespace: process.env.QS_DEV_NAMESPACE ?? "default",
      });
    }

    return proxyToSandbox(req, forwardedUrl, {
      sub: "dev",
      agentId: "dev-agent",
      claimId: process.env.QS_DEV_CLAIM_ID ?? "dev-claim",
      namespace: process.env.QS_DEV_NAMESPACE ?? "default",
    });
  }

  try {
    const forwardedUrl = getUrlFromForwardedUri(getForwardedUri(req));
    const queryToken = forwardedUrl.searchParams.get("token");

    if (queryToken) {
      const payload = await verifyAccessToken(queryToken);
      const sessionToken = await createSessionToken(payload);
      return redirectWithSessionCookie(req, forwardedUrl, sessionToken);
    }

    const token = parseCookies(req.headers.get("cookie"))[cookieName];
    if (!token) {
      return unauthorized();
    }

    const payload = await verifySessionToken(token);

    if (isWebSocketUpgrade(req)) {
      return proxyWebSocketToSandbox(req, server, forwardedUrl, payload);
    }

    return proxyToSandbox(req, forwardedUrl, payload);
  } catch {
    return unauthorized();
  }
}

const bunServer = (globalThis as any).Bun.serve({
  port,
  fetch: (req: Request, server: any) => handleRequest(req, server),
  websocket: {
    open(ws: any) {
      const data = ws.data as ProxyWebSocketData;

      let protocols: string[] | undefined;
      if (data.protocol) {
        protocols = [data.protocol];
      }

      const upstream = new (WebSocket as any)(data.targetUrl, protocols, {
        headers: data.headers,
      }) as WebSocket;

      data.upstream = upstream;

      let closed = false;

      const closeBoth = () => {
        if (closed) return;
        closed = true;
        try { ws.close(); } catch { /* ignore */ }
      };

      upstream.onopen = () => {
        // Connection established – ready to relay
      };

      upstream.onmessage = (event: MessageEvent) => {
        if (closed) return;
        ws.send(event.data);
      };

      upstream.onclose = (event: CloseEvent) => {
        if (closed) return;
        closed = true;
        ws.close(event.code || 1000, event.reason || "Upstream closed");
      };

      upstream.onerror = () => {
        console.error(
          `[ws-proxy] upstream error for ${data.targetUrl}`,
        );
        closeBoth();
      };
    },
    message(ws: any, message: string | Uint8Array) {
      const upstream = (ws.data as ProxyWebSocketData).upstream;
      if (!upstream || upstream.readyState !== WebSocket.OPEN) return;

      if (typeof message === "string") {
        upstream.send(message);
      } else if (message instanceof Uint8Array) {
        upstream.send(message);
      } else {
        // Fallback: coerce ArrayBufferView to Uint8Array
        upstream.send(new Uint8Array((message as any).buffer ?? message));
      }
    },
    close(ws: any) {
      const upstream = (ws.data as ProxyWebSocketData).upstream;
      if (!upstream) return;

      if (upstream.readyState === WebSocket.OPEN) {
        upstream.close();
      }
    },
  },
});

console.log(`Agent auth proxy listening on port ${port}`);
