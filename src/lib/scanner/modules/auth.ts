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
  "/wp-admin", "/wp-login.php", "/administrator",
  "/panel", "/console", "/portal", "/cpanel",
  "/phpmyadmin", "/adminer", "/grafana", "/kibana",
];

const DEFAULT_CREDENTIALS = [
  { username: "admin", password: "admin" },
  { username: "admin", password: "password" },
  { username: "admin", password: "123456" },
  { username: "admin", password: "admin123" },
  { username: "root", password: "root" },
  { username: "root", password: "toor" },
  { username: "test", password: "test" },
  { username: "user", password: "user" },
  { username: "demo", password: "demo" },
  { username: "guest", password: "guest" },
];

const LOGIN_PATHS = [
  "/api/auth/login", "/api/login", "/api/auth/signin",
  "/api/signin", "/api/authenticate", "/auth/login",
  "/login", "/api/session", "/api/auth/callback/credentials",
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

  // 7. Default credential testing
  const loginEndpoints = [
    ...target.apiEndpoints.filter((ep) => /login|signin|authenticate|session/i.test(new URL(ep).pathname)),
    ...LOGIN_PATHS.map((p) => target.baseUrl + p),
  ];
  const uniqueLoginEndpoints = [...new Set(loginEndpoints)].slice(0, 3);

  if (uniqueLoginEndpoints.length > 0) {
    const credResults = await Promise.allSettled(
      uniqueLoginEndpoints.flatMap((endpoint) =>
        DEFAULT_CREDENTIALS.slice(0, 5).map(async ({ username, password }) => {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password, email: username }),
            timeoutMs: 5000,
          });
          if (!res.ok) return null;
          const text = await res.text();
          if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
          if (text.length < 10) return null;
          // Check for successful login indicators
          if (/token|session|jwt|access_token|auth|logged.?in|success/i.test(text) && !/invalid|error|fail|wrong|incorrect|denied/i.test(text)) {
            return { endpoint, username, password, text };
          }
          return null;
        }),
      ),
    );

    let credCount = 0;
    for (const r of credResults) {
      if (credCount >= 2) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const { endpoint, username, password, text } = r.value;
      credCount++;
      findings.push({
        id: `auth-default-creds-${findings.length}`,
        module: "Authentication",
        severity: "critical",
        title: `Default credentials accepted: ${username}/${password}`,
        description: `The login endpoint accepted default credentials (${username}/${password}). This provides immediate unauthorized access to the application.`,
        evidence: `POST ${endpoint}\nCredentials: ${username}:${password}\nResponse: ${text.substring(0, 200)}`,
        remediation: "Remove or change all default credentials. Enforce strong password requirements on initial setup. Implement account provisioning that requires unique credentials.",
        cwe: "CWE-798",
        owasp: "A07:2021",
        codeSnippet: `// Block common/default passwords\nconst BLOCKED_PASSWORDS = new Set([\n  'admin', 'password', '123456', 'admin123', 'root', 'test', 'demo'\n]);\n\nif (BLOCKED_PASSWORDS.has(password.toLowerCase())) {\n  return Response.json({ error: 'Password too common' }, { status: 400 });\n}`,
      });
    }
  }

  // 8. Password policy analysis — test registration/signup endpoints
  const signupEndpoints = [
    ...target.apiEndpoints.filter((ep) => /signup|register|create.?account|onboard/i.test(new URL(ep).pathname)),
    ...["/api/auth/signup", "/api/register", "/api/auth/register", "/api/signup"].map((p) => target.baseUrl + p),
  ];
  const uniqueSignupEndpoints = [...new Set(signupEndpoints)].slice(0, 2);

  if (uniqueSignupEndpoints.length > 0) {
    const weakPasswords = [
      { pw: "1", desc: "single character" },
      { pw: "abc", desc: "3-char alphabetic" },
      { pw: "123456", desc: "numeric only" },
      { pw: "password", desc: "common dictionary word" },
    ];
    const policyResults = await Promise.allSettled(
      uniqueSignupEndpoints.flatMap((endpoint) =>
        weakPasswords.map(async ({ pw, desc }) => {
          const email = `vibeshield-test-${Math.random().toString(36).slice(2)}@example.com`;
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password: pw, username: email.split("@")[0], name: "Test" }),
            timeoutMs: 5000,
          });
          if (res.status === 404 || res.status === 405) return null;
          const text = await res.text();
          if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
          // Check if the weak password was accepted (no password policy error)
          if (res.ok && !/password.*(?:weak|short|simple|must|require|minimum|at least|too)/i.test(text)) {
            return { endpoint, pw, desc };
          }
          return null;
        }),
      ),
    );

    const acceptedWeak: string[] = [];
    for (const r of policyResults) {
      if (r.status === "fulfilled" && r.value) acceptedWeak.push(r.value.desc);
    }
    if (acceptedWeak.length >= 2) {
      findings.push({
        id: `auth-weak-password-policy-${findings.length}`,
        module: "Authentication",
        severity: "medium",
        title: "Weak password policy detected",
        description: `The signup endpoint accepts weak passwords: ${acceptedWeak.join(", ")}. No minimum length, complexity, or dictionary checks are enforced.`,
        evidence: `Accepted weak passwords: ${acceptedWeak.join(", ")}\nEndpoint: ${uniqueSignupEndpoints[0]}`,
        remediation: "Enforce a minimum password length of 8+ characters with complexity requirements. Check passwords against known breach databases (e.g., HaveIBeenPwned).",
        cwe: "CWE-521",
        owasp: "A07:2021",
        codeSnippet: `// Password validation\nfunction validatePassword(pw: string): string | null {\n  if (pw.length < 8) return 'Password must be at least 8 characters';\n  if (!/[A-Z]/.test(pw)) return 'Must contain uppercase letter';\n  if (!/[a-z]/.test(pw)) return 'Must contain lowercase letter';\n  if (!/[0-9]/.test(pw)) return 'Must contain a number';\n  return null; // valid\n}`,
      });
    }
  }

  // 9. Account lockout detection — send repeated failed logins
  if (uniqueLoginEndpoints.length > 0) {
    const lockoutEndpoint = uniqueLoginEndpoints[0];
    try {
      const lockoutResponses: { status: number; text: string; headers: Headers }[] = [];
      for (let i = 0; i < 10; i++) {
        const res = await scanFetch(lockoutEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: "lockout-test@vibeshield.dev", password: `wrong-password-${i}`, username: "lockout-test" }),
          timeoutMs: 5000,
        });
        const text = await res.text();
        lockoutResponses.push({ status: res.status, text, headers: res.headers });
        // Stop early if we get 429 or lockout
        if (res.status === 429 || /locked|blocked|too many|suspended|disabled/i.test(text)) break;
      }

      const gotLocked = lockoutResponses.some((r) =>
        r.status === 429 || /locked|blocked|too many|suspended|disabled/i.test(r.text) ||
        r.headers.get("retry-after") !== null,
      );

      if (!gotLocked && lockoutResponses.length >= 10) {
        const allSameStatus = lockoutResponses.every((r) => r.status === lockoutResponses[0].status);
        if (allSameStatus) {
          findings.push({
            id: `auth-no-lockout-${findings.length}`,
            module: "Authentication",
            severity: "medium",
            title: `No account lockout after 10 failed attempts on ${new URL(lockoutEndpoint).pathname}`,
            description: "10 consecutive failed login attempts did not trigger any account lockout, rate limiting, or CAPTCHA challenge. This enables unlimited brute-force attacks.",
            evidence: `POST ${lockoutEndpoint}\n10 failed login attempts → all returned ${lockoutResponses[0].status}\nNo lockout, 429, or retry-after headers detected`,
            remediation: "Implement progressive account lockout (e.g., lock for 15 minutes after 5 failed attempts). Add CAPTCHA after 3 failures. Send notification emails on suspicious login activity.",
            cwe: "CWE-307",
            owasp: "A07:2021",
            codeSnippet: `// Track failed attempts per account\nconst failures = await redis.incr(\`login:fail:\${email}\`);\nawait redis.expire(\`login:fail:\${email}\`, 900); // 15 min window\nif (failures > 5) {\n  await redis.set(\`login:locked:\${email}\`, '1', 'EX', 900);\n  return Response.json({ error: 'Account temporarily locked' }, { status: 423 });\n}`,
          });
        }
      }
    } catch { /* skip */ }
  }

  // 10. Password reset token analysis
  const resetEndpoints = [
    ...target.apiEndpoints.filter((ep) => /forgot|reset|recover/i.test(new URL(ep).pathname)),
    ...["/api/auth/forgot-password", "/api/forgot-password", "/api/auth/reset", "/api/password-reset"].map((p) => target.baseUrl + p),
  ];
  const uniqueResetEndpoints = [...new Set(resetEndpoints)].slice(0, 2);

  if (uniqueResetEndpoints.length > 0) {
    const resetResults = await Promise.allSettled(
      uniqueResetEndpoints.map(async (endpoint) => {
        // Send two reset requests to compare tokens for predictability
        const res1 = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: "reset-test-1@vibeshield.dev" }),
          timeoutMs: 5000,
        });
        if (res1.status === 404 || res1.status === 405) return null;
        const text1 = await res1.text();
        if (looksLikeHtml(text1) && (isSoft404(text1, target) || target.isSpa)) return null;

        const res2 = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: "reset-test-2@vibeshield.dev" }),
          timeoutMs: 5000,
        });
        const text2 = await res2.text();

        // Check if tokens are exposed in the response
        const tokenPattern = /["'](?:token|reset_token|resetToken|code)["']\s*:\s*["']([^"']+)["']/i;
        const match1 = text1.match(tokenPattern);
        const match2 = text2.match(tokenPattern);

        if (match1 && match2) {
          const token1 = match1[1];
          const token2 = match2[1];
          // Check for short/predictable tokens
          const isShort = token1.length < 20;
          const isSequential = Math.abs(parseInt(token1, 16) - parseInt(token2, 16)) < 1000;
          const isNumericOnly = /^\d+$/.test(token1);
          return { endpoint, token1, token2, isShort, isSequential, isNumericOnly, text: text1 };
        }

        // Check if the response reveals whether the email exists (enumeration)
        if (res1.ok !== res2.ok || text1.length !== text2.length) {
          const diff = Math.abs(text1.length - text2.length);
          if (diff > 10) {
            return { endpoint, enumeration: true, text1, text2 };
          }
        }

        return null;
      }),
    );

    for (const r of resetResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      if ("enumeration" in v && v.enumeration) {
        findings.push({
          id: `auth-reset-enumeration-${findings.length}`,
          module: "Authentication",
          severity: "medium",
          title: `User enumeration via password reset on ${new URL(v.endpoint).pathname}`,
          description: "The password reset endpoint returns different responses for existing vs non-existing emails, enabling user enumeration.",
          evidence: `POST ${v.endpoint}\nDifferent response lengths for different emails\nResponse 1: ${v.text1.substring(0, 100)}\nResponse 2: ${v.text2.substring(0, 100)}`,
          remediation: "Return a generic response regardless of whether the email exists. Always say 'If this email exists, a reset link has been sent.'",
          cwe: "CWE-204",
          owasp: "A07:2021",
        });
      } else if ("token1" in v) {
        const issues: string[] = [];
        if (v.isShort) issues.push("short token length");
        if (v.isSequential) issues.push("sequential/predictable values");
        if (v.isNumericOnly) issues.push("numeric-only token");
        issues.push("token exposed in response body");
        findings.push({
          id: `auth-reset-token-weak-${findings.length}`,
          module: "Authentication",
          severity: "high",
          title: `Weak password reset token on ${new URL(v.endpoint).pathname}`,
          description: `The password reset endpoint returns tokens directly in the response with issues: ${issues.join(", ")}. Reset tokens should be sent via email only and be cryptographically random.`,
          evidence: `POST ${v.endpoint}\nToken 1: ${v.token1}\nToken 2: ${v.token2}\nIssues: ${issues.join(", ")}`,
          remediation: "Generate reset tokens with crypto.randomBytes(32). Never expose tokens in API responses — send via email only. Set token expiry to 15-30 minutes.",
          cwe: "CWE-640",
          owasp: "A07:2021",
          codeSnippet: `import crypto from 'crypto';\n\nconst token = crypto.randomBytes(32).toString('hex');\nawait db.resetToken.create({\n  data: { token: await bcrypt.hash(token, 10), userId, expiresAt: new Date(Date.now() + 30 * 60000) },\n});\nawait sendEmail(email, \`Reset: \${url}/reset?token=\${token}\`);\n// NEVER return the token in the API response\nreturn Response.json({ message: 'If this email exists, a reset link was sent' });`,
        });
      }
    }
  }

  // 11. Multi-factor authentication detection
  if (uniqueLoginEndpoints.length > 0) {
    const mfaIndicators = {
      inJs: Array.from(target.jsContents.values()).some((js) => /2fa|mfa|totp|otp|authenticator|two.?factor|multi.?factor|verify.?code|sms.?code/i.test(js)),
      inEndpoints: target.apiEndpoints.some((ep) => /2fa|mfa|totp|otp|verify.?code/i.test(ep)),
    };

    if (!mfaIndicators.inJs && !mfaIndicators.inEndpoints) {
      findings.push({
        id: `auth-no-mfa-${findings.length}`,
        module: "Authentication",
        severity: "medium",
        title: "No multi-factor authentication detected",
        description: "No references to MFA, 2FA, TOTP, or OTP were found in the application's JavaScript bundles or API endpoints. Multi-factor authentication significantly reduces the risk of account compromise.",
        evidence: `Searched JS bundles (${target.jsContents.size} files) and ${target.apiEndpoints.length} API endpoints\nNo MFA/2FA/TOTP/OTP references found`,
        remediation: "Implement multi-factor authentication using TOTP (e.g., Google Authenticator) or WebAuthn. At minimum, offer SMS-based 2FA for high-value accounts.",
        cwe: "CWE-308",
        owasp: "A07:2021",
        codeSnippet: `// Using otplib for TOTP\nimport { authenticator } from 'otplib';\n\n// Generate secret for user\nconst secret = authenticator.generateSecret();\n// Verify TOTP code\nconst isValid = authenticator.verify({ token: userCode, secret: user.totpSecret });\nif (!isValid) return Response.json({ error: 'Invalid 2FA code' }, { status: 401 });`,
      });
    }
  }

  // 12. Remember-me token security — check for persistent auth cookies
  const authCookies = target.cookies.filter((c) =>
    /remember|persistent|stay.?logged|keep.?logged|auth|session|token/i.test(c.name),
  );
  for (const cookie of authCookies.slice(0, 2)) {
    const issues: string[] = [];
    if (!cookie.httpOnly) issues.push("missing HttpOnly flag (vulnerable to XSS theft)");
    if (!cookie.secure) issues.push("missing Secure flag (sent over HTTP)");
    if (!cookie.sameSite || cookie.sameSite.toLowerCase() === "none") issues.push("SameSite=None (vulnerable to CSRF)");
    // Check for predictable/short token values
    if (cookie.value && cookie.value.length < 20) issues.push("short token value (predictable)");

    if (issues.length >= 2) {
      findings.push({
        id: `auth-remember-me-insecure-${findings.length}`,
        module: "Authentication",
        severity: "high",
        title: `Insecure remember-me cookie: ${cookie.name}`,
        description: `The persistent authentication cookie "${cookie.name}" has security issues: ${issues.join("; ")}. This exposes the session to theft or hijacking.`,
        evidence: `Cookie: ${cookie.name}\nSecure: ${cookie.secure}\nHttpOnly: ${cookie.httpOnly}\nSameSite: ${cookie.sameSite}\nValue length: ${cookie.value?.length || 0}\nIssues: ${issues.join(", ")}`,
        remediation: "Set all auth cookies with Secure, HttpOnly, and SameSite=Lax/Strict flags. Use long, cryptographically random token values. Implement token rotation on each use.",
        cwe: "CWE-614",
        owasp: "A07:2021",
        codeSnippet: `// Secure cookie settings\nres.cookie('remember_token', crypto.randomBytes(32).toString('hex'), {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'lax',\n  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days\n  path: '/',\n});`,
      });
    }
  }

  // 13. Forced browsing to additional admin panels
  const additionalAdminPaths = [
    "/api/users", "/api/roles", "/api/permissions", "/api/config",
    "/api/settings", "/api/system", "/api/logs", "/api/audit",
    "/api/env", "/api/health/full", "/api/internal",
    "/.env", "/config.json", "/config.yml", "/settings.json",
  ];
  const forcedBrowsingResults = await Promise.allSettled(
    additionalAdminPaths.map(async (path) => {
      const url = target.baseUrl + path;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (res.status !== 200) return null;
      const text = await res.text();
      if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
      if (text.length < 20) return null;
      // Check for sensitive config/admin data
      if (/password|secret|api.?key|database|db_|redis|aws_|private|credential/i.test(text)) {
        return { path, url, text };
      }
      return null;
    }),
  );

  let forcedCount = 0;
  for (const r of forcedBrowsingResults) {
    if (forcedCount >= 2) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, url, text } = r.value;
    forcedCount++;
    findings.push({
      id: `auth-forced-browsing-${findings.length}`,
      module: "Authentication",
      severity: "critical",
      title: `Sensitive endpoint exposed without auth: ${path}`,
      description: "A sensitive administrative or configuration endpoint is accessible without authentication, exposing internal data such as credentials, API keys, or system configuration.",
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 300)}`,
      remediation: "Protect all sensitive endpoints with authentication. Move configuration files outside the web root. Use environment variables instead of config files.",
      cwe: "CWE-425",
      owasp: "A01:2021",
    });
  }

  return findings;
};
