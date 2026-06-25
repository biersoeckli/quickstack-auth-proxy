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

function sandboxHeaders(claimId: string, namespace: string, sandboxPort: string): Headers {
  return new Headers({
    "X-Sandbox-ID": claimId,
    "X-Sandbox-Port": sandboxPort,
    "X-Sandbox-Namespace": namespace,
  });
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
  return req.headers.get("x-forwarded-uri") ?? new URL(req.url).pathname;
}

function getUrlFromForwardedUri(forwardedUri: string): URL {
  return new URL(forwardedUri, "http://quickstack.local");
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

function redirectWithoutToken(req: Request, forwardedUrl: URL, token: string): Response {
  forwardedUrl.searchParams.delete("token");
  const location = `${forwardedUrl.pathname}${forwardedUrl.search}${forwardedUrl.hash}`;
  return new Response(null, {
    status: 302,
    headers: {
      Location: location || "/",
      "Set-Cookie": sessionCookie(token, req),
    },
  });
}

async function handleRequest(req: Request): Promise<Response> {
  if (process.env.AUTH_DISABLED === "true") {
    return new Response("OK", {
      status: 200,
      headers: sandboxHeaders(
        process.env.QS_DEV_CLAIM_ID ?? "dev-claim",
        process.env.QS_DEV_NAMESPACE ?? "default",
        process.env.QS_DEV_PORT ?? "4096",
      ),
    });
  }

  try {
    const forwardedUrl = getUrlFromForwardedUri(getForwardedUri(req));
    const queryToken = forwardedUrl.searchParams.get("token");

    if (queryToken) {
      const payload = await verifyAccessToken(queryToken);
      const sessionToken = await createSessionToken(payload);
      return redirectWithoutToken(req, forwardedUrl, sessionToken);
    }

    const token = parseCookies(req.headers.get("cookie"))[cookieName];
    if (!token) {
      return unauthorized();
    }

    const payload = await verifySessionToken(token);
    const sandboxPort = forwardedUrl.pathname.startsWith("/files") ? "80" : "4096";

    return new Response("OK", {
      status: 200,
      headers: sandboxHeaders(payload.claimId, payload.namespace, sandboxPort),
    });
  } catch {
    return unauthorized();
  }
}

(globalThis as any).Bun.serve({
  port,
  fetch: handleRequest,
});

console.log(`Agent auth proxy listening on port ${port}`);
