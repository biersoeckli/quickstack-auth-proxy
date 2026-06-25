import { jwtVerify } from "jose";

interface AgentAccessTokenPayload {
  sub: string;
  agentId: string;
  claimId: string;
  namespace: string;
}

const port = Number(process.env.PORT ?? "3000");
const issuer = "quickstack-agent";

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

function getForwardedUri(req: Request): string {
  return req.headers.get("x-forwarded-uri") ?? new URL(req.url).pathname;
}

function getUrlFromForwardedUri(forwardedUri: string): URL {
  return new URL(forwardedUri, "http://quickstack.local");
}

async function verifyToken(token: string): Promise<AgentAccessTokenPayload> {
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
    const token = forwardedUrl.searchParams.get("token");
    if (!token) {
      return unauthorized();
    }

    const payload = await verifyToken(token);
    const sandboxPort = forwardedUrl.pathname.startsWith("/files") ? "80" : "4096";

    return new Response("OK", {
      status: 200,
      headers: sandboxHeaders(payload.claimId, payload.namespace, sandboxPort),
    });
  } catch {
    return unauthorized();
  }
}

Bun.serve({
  port,
  fetch: handleRequest,
});

console.log(`Agent auth proxy listening on port ${port}`);
