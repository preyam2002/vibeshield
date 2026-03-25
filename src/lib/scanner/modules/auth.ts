import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

const SENSITIVE_PATTERNS = [
  /email/i, /password/i, /phone/i, /address/i, /ssn/i,
  /credit.?card/i, /token/i, /secret/i, /key/i, /balance/i,
  /salary/i, /payment/i, /bank/i, /account/i,
];

const ADMIN_PATHS = [
  "/admin", "/admin/", "/dashboard/admin", "/api/admin",
  "/api/admin/users", "/admin/dashboard", "/admin/settings",
  "/manage", "/management", "/internal", "/backstage",
  "/debug", "/debug/", "/_debug", "/api/debug",
  "/phpinfo.php", "/server-status", "/server-info",
];

export const authModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  const publicPatterns = /webhook|callback|health|status|ping|csp-report|cron|sitemap|feed|rss|\.well-known|auth\/signin|auth\/signup|auth\/login|auth\/register|auth\/providers|auth\/csrf|stripe|chilipiper|calendly|hubspot|intercom|zendesk|crisp|drift|segment|analytics|tracking|pixel|beacon/i;

  // Run all 5 test categories in parallel
  const [unauthResults, adminResults, tokenResults, methodResults, pathBypassResults] = await Promise.all([
    // 1. Unauthenticated API access
    Promise.allSettled(
      target.apiEndpoints.map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        if (publicPatterns.test(pathname)) return null;

        const res = await scanFetch(endpoint, { timeoutMs: 5000 });
        if (!res.ok) return null;

        const contentType = res.headers.get("content-type") || "";
        if (!contentType.includes("json")) return null;

        const text = await res.text();
        if (text.length < 5) return null;

        let data: unknown;
        try { data = JSON.parse(text); } catch { return null; }

        const hasSensitive = SENSITIVE_PATTERNS.some((p) => {
          const keyPattern = new RegExp(`"[^"]*${p.source}[^"]*"\\s*:\\s*"([^"]*)"`, "i");
          const match = text.match(keyPattern);
          if (!match) return false;
          const value = match[1];
          if (!value || value === "null" || value === "undefined" || value.length < 3) return false;
          return true;
        });
        const isArray = Array.isArray(data);
        const itemCount = isArray ? (data as unknown[]).length : 0;

        if ((hasSensitive && text.length > 50) || itemCount > 5) {
          return { pathname, endpoint, hasSensitive, isArray, itemCount, text };
        }
        return null;
      }),
    ),

    // 2. Admin paths
    Promise.allSettled(
      ADMIN_PATHS.map(async (path) => {
        const url = target.baseUrl + path;
        const res = await scanFetch(url, { timeoutMs: 5000 });
        if (res.status !== 200) return null;

        const text = await res.text();
        if (isSoft404(text, target)) return null;
        if (looksLikeHtml(text) && target.isSpa) return null;

        if (looksLikeHtml(text)) {
          const hasAdminUI = (/(<table|<form|<input|data-admin|admin-panel)/i.test(text)) &&
            (/<title[^>]*>.*(?:admin|dashboard|manage|panel)/i.test(text)) &&
            !/login|sign.?in|unauthorized|403|forbidden/i.test(text);
          if (!hasAdminUI) return null;
        }

        if (!looksLikeHtml(text)) {
          if (text.length < 20) return null;
          if (!/users|config|settings|permissions|roles/i.test(text)) return null;
        }

        return { path, url, text };
      }),
    ),

    // 3. Weak token validation + alg:none bypass
    Promise.allSettled(
      target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        if (publicPatterns.test(pathname)) return null;

        const noAuthRes = await scanFetch(endpoint, { timeoutMs: 5000 });
        if (noAuthRes.status !== 401 && noAuthRes.status !== 403) return null;

        // Test 1: random invalid token
        const invalidRes = await scanFetch(endpoint, {
          headers: { Authorization: "Bearer invalid-token-vibeshield-test" },
          timeoutMs: 5000,
        });
        if (invalidRes.ok) {
          const text = await invalidRes.text();
          if (looksLikeHtml(text) && isSoft404(text, target)) return null;
          if (text.length < 10) return null;
          return { pathname, noAuthStatus: noAuthRes.status, invalidStatus: invalidRes.status, text, type: "invalid-token" as const };
        }

        // Test 2: JWT with alg:none (signature bypass)
        const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" })).replace(/=/g, "");
        const payload = btoa(JSON.stringify({ sub: "test", admin: true, exp: Math.floor(Date.now() / 1000) + 3600 })).replace(/=/g, "");
        const algNoneToken = `${header}.${payload}.`;
        const algNoneRes = await scanFetch(endpoint, {
          headers: { Authorization: `Bearer ${algNoneToken}` },
          timeoutMs: 5000,
        });
        if (algNoneRes.ok) {
          const text = await algNoneRes.text();
          if (looksLikeHtml(text) && isSoft404(text, target)) return null;
          if (text.length < 10) return null;
          return { pathname, noAuthStatus: noAuthRes.status, invalidStatus: algNoneRes.status, text, type: "alg-none" as const };
        }
        return null;
      }),
    ),

    // 4. HTTP method testing — parallelize all endpoint+method combos
    (async () => {
      const combos: { endpoint: string; method: string }[] = [];
      for (const endpoint of target.apiEndpoints.slice(0, 10)) {
        for (const method of ["PUT", "PATCH", "DELETE"]) {
          combos.push({ endpoint, method });
        }
      }

      // Get baselines in parallel first
      const baselineResults = await Promise.allSettled(
        target.apiEndpoints.slice(0, 10).map(async (endpoint) => {
          const res = await scanFetch(endpoint, { timeoutMs: 5000 });
          return { endpoint, status: res.status, body: await res.text() };
        }),
      );
      const baselines = new Map<string, { status: number; body: string }>();
      for (const r of baselineResults) {
        if (r.status === "fulfilled") baselines.set(r.value.endpoint, { status: r.value.status, body: r.value.body });
      }

      return Promise.allSettled(
        combos.map(async ({ endpoint, method }) => {
          const res = await scanFetch(endpoint, { method, timeoutMs: 5000 });
          if (res.status !== 200 && res.status !== 204) return null;

          const text = await res.text();
          if (looksLikeHtml(text) && isSoft404(text, target)) return null;
          if (looksLikeHtml(text) && target.isSpa) return null;
          if (text.length < 5) return null;

          const baseline = baselines.get(endpoint);
          if (baseline && text === baseline.body && res.status === baseline.status) return null;

          return { endpoint, method, status: res.status, text };
        }),
      );
    })(),

    // 5. Path traversal, case sensitivity, and trailing slash bypass on protected paths
    (async () => {
      // Find endpoints that return 401/403 (protected)
      const protectedEndpoints: string[] = [];
      const probeResults = await Promise.allSettled(
        [...ADMIN_PATHS.slice(0, 6), ...target.apiEndpoints.slice(0, 6)].map(async (path) => {
          const url = path.startsWith("http") ? path : target.baseUrl + path;
          const res = await scanFetch(url, { timeoutMs: 5000 });
          if (res.status === 401 || res.status === 403) {
            protectedEndpoints.push(url);
          }
        }),
      );

      if (protectedEndpoints.length === 0) return [];

      const bypasses: { endpoint: string; variant: string; bypass: string; status: number; text: string }[] = [];
      const bypassTests = protectedEndpoints.slice(0, 4).flatMap((endpoint) => {
        const u = new URL(endpoint);
        const path = u.pathname;
        return [
          { endpoint, variant: path + "/", bypass: "trailing slash" },
          { endpoint, variant: path + "/.", bypass: "dot segment" },
          { endpoint, variant: path + "%20", bypass: "trailing space encoding" },
          { endpoint, variant: path + "%00", bypass: "null byte" },
          { endpoint, variant: path.replace(/\/([^/]+)$/, "/%2e%2e/$1"), bypass: "path traversal" },
          { endpoint, variant: "/" + path.slice(1).split("").map((c) => Math.random() > 0.5 ? c.toUpperCase() : c).join(""), bypass: "case variation" },
          { endpoint, variant: "//" + path.slice(1), bypass: "double slash prefix" },
        ];
      });

      const results = await Promise.allSettled(
        bypassTests.map(async ({ endpoint, variant, bypass }) => {
          const url = new URL(endpoint);
          url.pathname = variant;
          const res = await scanFetch(url.href, { timeoutMs: 5000 });
          if (res.ok) {
            const text = await res.text();
            if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
            if (text.length < 20) return null;
            return { endpoint, variant, bypass, status: res.status, text };
          }
          return null;
        }),
      );

      return results;
    })(),
  ]);

  // Collect unauthenticated access findings (max 3)
  for (const r of unauthResults) {
    if (findings.length >= 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { pathname, endpoint, hasSensitive, isArray, itemCount, text } = r.value;
    findings.push({
      id: `auth-no-auth-${findings.length}`,
      module: "Authentication",
      severity: hasSensitive ? "critical" : "high",
      title: `Unauthenticated access to ${pathname}`,
      description: isArray
        ? `This endpoint returns ${itemCount} records without any authentication.${hasSensitive ? " Response contains sensitive-looking fields (email, password, etc.)." : ""}`
        : `This endpoint returns data without authentication.${hasSensitive ? " Response contains sensitive-looking fields." : ""}`,
      evidence: `GET ${endpoint}\nStatus: 200\n${isArray ? `Records: ${itemCount}\n` : ""}Response preview: ${text.substring(0, 300)}...`,
      remediation: "Add authentication middleware to this endpoint. Verify the user's identity before returning data.",
      cwe: "CWE-306",
      owasp: "A07:2021",
      codeSnippet: `// middleware.ts — protect API routes\nimport { NextResponse } from "next/server";\nexport function middleware(req) {\n  if (req.nextUrl.pathname.startsWith("/api/")) {\n    const token = req.headers.get("authorization")?.split(" ")[1];\n    if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });\n  }\n  return NextResponse.next();\n}\nexport const config = { matcher: "/api/:path*" };`,
    });
  }

  // Collect admin path findings (max 2)
  let adminCount = 0;
  for (const r of adminResults) {
    if (adminCount >= 2) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, url, text } = r.value;
    adminCount++;
    findings.push({
      id: `auth-admin-exposed-${findings.length}`,
      module: "Authentication",
      severity: "critical",
      title: `Admin panel accessible without authentication: ${path}`,
      description: "An administrative interface is accessible without any authentication. Anyone who discovers this URL has full admin access.",
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 300)}`,
      remediation: "Protect admin routes with authentication and authorization checks. Consider IP allowlisting.",
      cwe: "CWE-306",
      owasp: "A07:2021",
      codeSnippet: `// middleware.ts — protect admin routes\nif (req.nextUrl.pathname.startsWith("/admin")) {\n  const session = await getToken({ req });\n  if (!session || session.role !== "admin") {\n    return NextResponse.redirect(new URL("/login", req.url));\n  }\n}`,
    });
  }

  // Collect weak token findings
  for (const r of tokenResults) {
    if (findings.length >= 6) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { pathname, noAuthStatus, invalidStatus, text, type } = r.value;
    if (type === "alg-none") {
      findings.push({
        id: `auth-alg-none-${findings.length}`,
        module: "Authentication",
        severity: "critical",
        title: `JWT alg:none bypass on ${pathname}`,
        description: "This endpoint accepts JWTs with algorithm set to 'none', meaning signatures are not verified. An attacker can forge tokens with arbitrary claims.",
        evidence: `Without token: ${noAuthStatus}\nWith alg:none JWT: ${invalidStatus}\nResponse: ${text.substring(0, 200)}`,
        remediation: "Configure your JWT library to reject alg:none tokens. Always specify the expected algorithm explicitly.",
        cwe: "CWE-327",
        owasp: "A02:2021",
        codeSnippet: `// Fix: Explicitly set algorithms\njwt.verify(token, secret, { algorithms: ["HS256"] });`,
      });
    } else {
      findings.push({
        id: `auth-weak-validation-${findings.length}`,
        module: "Authentication",
        severity: "critical",
        title: `Weak token validation on ${pathname}`,
        description: "This endpoint accepts invalid Bearer tokens. The server is not properly validating authentication tokens, allowing anyone with any string as a token to access protected data.",
        evidence: `Without token: ${noAuthStatus}\nWith invalid token: ${invalidStatus}\nResponse: ${text.substring(0, 200)}`,
        remediation: "Validate tokens cryptographically. Use a JWT library that verifies signatures, or validate tokens against your auth provider.",
        cwe: "CWE-287",
        owasp: "A07:2021",
        codeSnippet: `// Properly validate JWT tokens\nimport jwt from "jsonwebtoken";\ntry {\n  const decoded = jwt.verify(token, process.env.JWT_SECRET!, {\n    algorithms: ["HS256"],\n  });\n} catch (err) {\n  return Response.json({ error: "Invalid token" }, { status: 401 });\n}`,
      });
    }
  }

  // Collect HTTP method findings (max 3)
  let methodCount = 0;
  for (const r of methodResults) {
    if (methodCount >= 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { endpoint, method, status, text } = r.value;
    methodCount++;
    findings.push({
      id: `auth-method-${method.toLowerCase()}-${findings.length}`,
      module: "Authentication",
      severity: "high",
      title: `${method} allowed without auth on ${new URL(endpoint).pathname}`,
      description: `The ${method} method returns a success status (${status}) without authentication. This may allow unauthenticated data modification or deletion.`,
      evidence: `${method} ${endpoint}\nStatus: ${status}\nResponse: ${text.substring(0, 200)}`,
      remediation: `Add authentication checks for ${method} requests on this endpoint.`,
      cwe: "CWE-306",
      owasp: "A07:2021",
      codeSnippet: `// Protect write methods with auth middleware\nexport async function ${method}(req: Request) {\n  const session = await getServerSession(authOptions);\n  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  // ... handle ${method} request\n}`,
    });
  }

  // Collect path bypass findings (max 2)
  let pathBypassCount = 0;
  if (Array.isArray(pathBypassResults)) {
    for (const r of pathBypassResults) {
      if (pathBypassCount >= 2) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const { endpoint, variant, bypass, status, text } = r.value;
      pathBypassCount++;
      findings.push({
        id: `auth-path-bypass-${findings.length}`,
        module: "Authentication",
        severity: "critical",
        title: `Auth bypass via ${bypass} on ${new URL(endpoint).pathname}`,
        description: `This endpoint returns 401/403 normally, but a ${bypass} variant bypasses the auth check. The server's routing doesn't normalize paths before applying security middleware.`,
        evidence: `Original: ${endpoint} → 401/403\nBypass: ${variant} → ${status}\nResponse: ${text.substring(0, 200)}`,
        remediation: "Normalize request paths before applying auth middleware. Strip trailing slashes, decode percent-encoding, and canonicalize paths.",
        cwe: "CWE-863", owasp: "A01:2021",
        codeSnippet: `// middleware.ts — normalize paths before auth checks\nexport function middleware(req: NextRequest) {\n  const path = req.nextUrl.pathname\n    .replace(/\\/+/g, "/")\n    .replace(/\\/$/, "")\n    .toLowerCase();\n  // Apply auth checks on the normalized path\n  if (isProtectedPath(path)) {\n    const session = getSession(req);\n    if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });\n  }\n}`,
      });
    }
  }

  // 6. Rate limiting check on auth endpoints
  const authEndpoints = target.apiEndpoints.filter((ep) =>
    /auth|login|signin|signup|register|password|forgot|reset|verify|otp|2fa|mfa/i.test(new URL(ep).pathname),
  );
  if (authEndpoints.length > 0) {
    // Send 5 rapid requests and check for rate limit headers
    const rateLimitEndpoint = authEndpoints[0];
    try {
      const responses = await Promise.allSettled(
        Array.from({ length: 5 }, () =>
          scanFetch(rateLimitEndpoint, { method: "POST", body: JSON.stringify({ email: "test@vibeshield.dev", password: "wrong" }), headers: { "Content-Type": "application/json" }, timeoutMs: 5000 }),
        ),
      );
      const fulfilled = responses.filter((r) => r.status === "fulfilled").map((r) => (r as PromiseFulfilledResult<Response>).value);
      const hasRateLimitHeaders = fulfilled.some((r) =>
        r.headers.get("x-ratelimit-limit") || r.headers.get("x-ratelimit-remaining") || r.headers.get("retry-after") || r.status === 429,
      );
      if (!hasRateLimitHeaders && fulfilled.length >= 4) {
        const allSuccessOrSameStatus = fulfilled.every((r) => r.status === fulfilled[0].status);
        if (allSuccessOrSameStatus) {
          findings.push({
            id: "auth-no-rate-limit",
            module: "Authentication",
            severity: "high",
            title: `No rate limiting on ${new URL(rateLimitEndpoint).pathname}`,
            description: "5 rapid requests to this auth endpoint all returned the same status with no rate-limit headers (X-RateLimit-*, Retry-After) or 429 response. Attackers can brute-force passwords or enumerate accounts.",
            evidence: `POST ${rateLimitEndpoint}\n5 rapid requests → all returned ${fulfilled[0].status}\nNo rate-limit headers found`,
            remediation: "Add rate limiting to authentication endpoints. Limit to 5-10 attempts per minute per IP/account.",
            cwe: "CWE-307",
            owasp: "A07:2021",
            codeSnippet: `// Using next-rate-limit or upstash/ratelimit\nimport { Ratelimit } from "@upstash/ratelimit";\nimport { Redis } from "@upstash/redis";\n\nconst ratelimit = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(5, "60 s"),\n});\n\nexport async function POST(req: Request) {\n  const ip = req.headers.get("x-forwarded-for") || "unknown";\n  const { success } = await ratelimit.limit(ip);\n  if (!success) return Response.json({ error: "Too many attempts" }, { status: 429 });\n  // ... handle login\n}`,
          });
        }
      }
    } catch { /* skip */ }
  }

  return findings;
};
