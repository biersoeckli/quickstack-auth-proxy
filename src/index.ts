import { jwtVerify, SignJWT } from "jose";

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

function responseHeadersFrom(upstream: Response): Headers {
  const headers = new Headers();
  upstream.headers.forEach((value, key) => {
    if (key.toLowerCase() !== "set-cookie") {
      headers.set(key, value);
    }
  });

  const setCookies = (upstream.headers as any).getSetCookie?.() as string[] | undefined;
  if (setCookies) {
    for (const cookie of setCookies) {
      headers.append("Set-Cookie", cookie);
    }
  } else {
    const cookie = upstream.headers.get("set-cookie");
    if (cookie) {
      headers.append("Set-Cookie", cookie);
    }
  }

  return headers;
}

async function proxyToSandbox(req: Request, forwardedUrl: URL, payload: AgentAccessTokenPayload): Promise<Response> {
  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.delete("authorization");
  headers.delete("x-forwarded-uri");

  const appCookies = removeAuthProxyCookie(req.headers.get("cookie"));
  if (appCookies) {
    headers.set("cookie", appCookies);
  } else {
    headers.delete("cookie");
  }

  const init: RequestInit = {
    method: req.method,
    headers,
    redirect: "manual",
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = req.body;
  }

  const upstream = await fetch(targetUrlFor(forwardedUrl, payload), init);
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeadersFrom(upstream),
  });
}

async function handleRequest(req: Request): Promise<Response> {
  if (process.env.AUTH_DISABLED === "true") {
    const forwardedUrl = getUrlFromForwardedUri(getForwardedUri(req));
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
    return proxyToSandbox(req, forwardedUrl, payload);
  } catch {
    return unauthorized();
  }
}

(globalThis as any).Bun.serve({
  port,
  fetch: handleRequest,
});

console.log(`Agent auth proxy listening on port ${port}`);
