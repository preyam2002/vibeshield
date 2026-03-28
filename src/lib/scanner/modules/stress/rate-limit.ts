import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

export const rateLimitModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Endpoints that MUST have rate limiting
  const criticalEndpoints: { url: string; category: string }[] = [];

  // Auth endpoints — only add if they exist in discovered API endpoints (which filters SPAs)
  const authPaths = [
    "/api/auth/signin", "/api/auth/login", "/api/login", "/auth/login",
    "/api/auth/signup", "/api/register", "/api/auth/register",
    "/api/auth/forgot-password", "/api/forgot-password",
  ];
  for (const path of authPaths) {
    const match = target.apiEndpoints.find((ep) => ep.includes(path));
    if (match) {
      criticalEndpoints.push({ url: match, category: "authentication" });
    }
  }

  // AI/expensive endpoints
  for (const ep of target.apiEndpoints) {
    if (/generate|ai|chat|completion|openai|anthropic|gpt/i.test(ep)) {
      criticalEndpoints.push({ url: ep, category: "AI/expensive" });
    }
  }

  // Payment endpoints
  for (const ep of target.apiEndpoints) {
    if (/payment|checkout|stripe|billing/i.test(ep)) {
      criticalEndpoints.push({ url: ep, category: "payment" });
    }
  }

  // Add main URL as fallback test
  if (criticalEndpoints.length === 0) {
    criticalEndpoints.push({ url: target.url, category: "main page" });
    for (const ep of target.apiEndpoints.slice(0, 3)) {
      criticalEndpoints.push({ url: ep, category: "API" });
    }
  }

  for (const { url, category } of criticalEndpoints.slice(0, 6)) {
    // Send 50 rapid-fire requests
    const N = 50;
    const results: { status: number; rateLimitHeaders: boolean }[] = [];

    for (let i = 0; i < N; i++) {
      try {
        const res = await scanFetch(url, {
          method: category === "authentication" ? "POST" : "GET",
          headers: { "Content-Type": "application/json" },
          body: category === "authentication"
            ? JSON.stringify({ email: "test@test.com", password: "password" })
            : undefined,
        });

        const hasRateLimit = !!(
          res.headers.get("x-ratelimit-limit") ||
          res.headers.get("x-ratelimit-remaining") ||
          res.headers.get("retry-after") ||
          res.headers.get("ratelimit-limit")
        );

        results.push({ status: res.status, rateLimitHeaders: hasRateLimit });

        // If rate limited, we found the limit
        if (res.status === 429) break;
      } catch {
        break;
      }
    }

    const rateLimited = results.some((r) => r.status === 429);
    const hasRateLimitHeaders = results.some((r) => r.rateLimitHeaders);
    const requestsSent = results.length;

    // If every response is an error (401, 403, 404, 405), the endpoint isn't really handling requests
    const allErrors = results.every((r) => [401, 403, 404, 405, 500, 502, 503].includes(r.status));
    if (allErrors) continue;

    if (!rateLimited && !hasRateLimitHeaders) {
      findings.push({
        id: `ratelimit-none-${findings.length}`,
        module: "Rate Limiting",
        severity: category === "authentication" ? "high" : category === "AI/expensive" ? "critical" : "medium",
        title: `No rate limiting on ${category} endpoint: ${new URL(url).pathname}`,
        description: `Sent ${requestsSent} rapid requests without being rate limited.${category === "authentication" ? " An attacker can brute-force credentials." : category === "AI/expensive" ? " An attacker can rack up massive API costs." : " An attacker can abuse this endpoint."}`,
        evidence: `Endpoint: ${url}\nRequests sent: ${requestsSent}\n429 responses: 0\nRate limit headers: none`,
        remediation: category === "authentication"
          ? "Add rate limiting: max 5 login attempts per minute per IP. Use a library like rate-limiter-flexible or Upstash ratelimit."
          : category === "AI/expensive"
            ? "CRITICAL: Add rate limiting immediately. Without it, attackers can drain your AI API budget. Max 10-20 requests per minute per user."
            : "Add rate limiting. 100 requests per minute per IP is a reasonable starting point.",
        codeSnippet: `import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(${category === "authentication" ? "5" : category === "AI/expensive" ? "10" : "100"}, "${category === "authentication" ? "1 m" : "1 m"}"),
  analytics: true,
});

// In your API route handler:
const { success } = await ratelimit.limit(ip);
if (!success) return new Response("Too Many Requests", { status: 429 });`,
        cwe: "CWE-307",
        owasp: "A07:2021",
      });
    } else if (rateLimited) {
      const limitAt = results.findIndex((r) => r.status === 429) + 1;
      findings.push({
        id: `ratelimit-found-${findings.length}`,
        module: "Rate Limiting",
        severity: "info",
        title: `Rate limiting active on ${new URL(url).pathname} (limit: ~${limitAt} requests)`,
        description: `Rate limiting kicked in after ${limitAt} requests.`,
        evidence: `429 received after ${limitAt} requests`,
        remediation: limitAt > 100
          ? "Rate limit is set very high. Consider lowering for auth endpoints (5-10/min)."
          : "Rate limiting is in place.",
        codeSnippet: `// Fine-tune limits per endpoint type:
const authLimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "1 m"),
});
const apiLimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(30, "1 m"),
});`,
      });
    }
  }

  // Phase 2: Rate limit bypass via IP header spoofing
  // Many rate limiters key on X-Forwarded-For — test if we can bypass by changing it
  const bypassEndpoint = criticalEndpoints.find((ep) =>
    ep.category === "authentication" || ep.category === "AI/expensive",
  ) || criticalEndpoints[0];

  if (bypassEndpoint) {
    const url = bypassEndpoint.url;
    const method = bypassEndpoint.category === "authentication" ? "POST" : "GET";
    const body = bypassEndpoint.category === "authentication"
      ? JSON.stringify({ email: "test@test.com", password: "password" })
      : undefined;

    // First, check if the endpoint is currently rate-limited (from Phase 1 testing)
    const checkRes = await scanFetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body,
      timeoutMs: 5000,
    }).catch(() => null);

    if (checkRes?.status === 429) {
      // Now try bypassing with spoofed IP headers
      const spoofHeaders: [string, string][] = [
        ["X-Forwarded-For", "1.2.3.4"],
        ["X-Real-IP", "5.6.7.8"],
        ["X-Originating-IP", "9.10.11.12"],
        ["True-Client-IP", "13.14.15.16"],
        ["CF-Connecting-IP", "17.18.19.20"],
      ];

      const bypassResults = await Promise.allSettled(
        spoofHeaders.map(async ([headerName, headerValue]) => {
          const res = await scanFetch(url, {
            method,
            headers: { "Content-Type": "application/json", [headerName]: headerValue },
            body,
            timeoutMs: 5000,
          });
          if (res.status !== 429) {
            return { header: headerName, status: res.status };
          }
          return null;
        }),
      );

      const bypassed = bypassResults
        .filter((r) => r.status === "fulfilled" && r.value)
        .map((r) => (r as PromiseFulfilledResult<{ header: string; status: number }>).value);

      if (bypassed.length > 0) {
        findings.push({
          id: "ratelimit-bypass-ip-spoofing",
          module: "Rate Limiting",
          severity: "high",
          title: `Rate limit bypass via ${bypassed[0].header} header spoofing`,
          description: `The rate limiter on ${new URL(url).pathname} can be bypassed by spoofing IP headers. After being rate-limited, setting ${bypassed.map((b) => b.header).join(", ")} allows unlimited requests. Attackers can cycle through fake IPs to avoid rate limits entirely.`,
          evidence: `Endpoint: ${url}\nRate limited: 429\nWith ${bypassed[0].header}: ${bypassed[0].status}\nBypass headers: ${bypassed.map((b) => `${b.header} → ${b.status}`).join(", ")}`,
          remediation: "Don't trust client-provided IP headers for rate limiting. Use the actual connection IP from your reverse proxy. In Vercel, use req.ip. Behind Cloudflare, use CF-Connecting-IP only if Cloudflare is in the trust chain.",
          cwe: "CWE-290",
          owasp: "A07:2021",
          codeSnippet: `// Use the actual client IP, not spoofable headers\n// Vercel/Next.js\nconst ip = req.ip; // Uses x-real-ip set by Vercel's proxy\n\n// Express behind trusted proxy\napp.set("trust proxy", 1); // Only trust first proxy\nconst ip = req.ip; // Correctly extracts from X-Forwarded-For\n\n// Or use Cloudflare's verified header\nconst ip = req.headers.get("CF-Connecting-IP"); // Only if Cloudflare is in chain`,
        });
      }
    }
  }

  // Phase 3: Test upload and webhook endpoints (often forgotten in rate limiting)
  const forgottenEndpoints = [
    ...target.apiEndpoints.filter((ep) => /upload|file|media|import|csv|bulk/i.test(ep)).map((ep) => ({ url: ep, category: "upload" })),
    ...target.apiEndpoints.filter((ep) => /webhook|hook|callback|notify/i.test(ep)).map((ep) => ({ url: ep, category: "webhook" })),
    ...target.apiEndpoints.filter((ep) => /send|email|sms|invite|otp|verify/i.test(ep)).map((ep) => ({ url: ep, category: "notification" })),
  ].slice(0, 3);

  for (const { url, category } of forgottenEndpoints) {
    const N = 30;
    let rateLimited = false;
    for (let i = 0; i < N; i++) {
      try {
        const res = await scanFetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}", timeoutMs: 3000 });
        if (res.status === 429) { rateLimited = true; break; }
        if ([401, 403, 404, 405, 500].includes(res.status)) break;
      } catch { break; }
    }

    if (!rateLimited) {
      findings.push({
        id: `ratelimit-forgotten-${findings.length}`,
        module: "Rate Limiting",
        severity: category === "notification" ? "high" : "medium",
        title: `No rate limiting on ${category} endpoint: ${new URL(url).pathname}`,
        description: `The ${category} endpoint accepts rapid requests without rate limiting.${category === "upload" ? " Attackers can exhaust storage or bandwidth." : category === "notification" ? " Attackers can spam emails/SMS, running up costs and harassing users." : " Webhook endpoints without rate limiting can be abused for request amplification."}`,
        evidence: `POST ${url}\n${N} rapid requests without 429 response`,
        remediation: `Add rate limiting to ${category} endpoints. ${category === "notification" ? "Limit to 3-5 per minute per user." : "Limit to 10-20 per minute per IP."}`,
        cwe: "CWE-770",
        owasp: "A04:2021",
      });
    }
  }

  // Phase 4: Rate limit bypass via random IP headers
  // Test if X-Forwarded-For, X-Real-IP, X-Originating-IP with random IPs can bypass rate limiting
  const headerBypassEndpoint = criticalEndpoints.find((ep) =>
    ep.category === "authentication" || ep.category === "AI/expensive",
  ) || criticalEndpoints[0];

  if (headerBypassEndpoint) {
    const url = headerBypassEndpoint.url;
    const method = headerBypassEndpoint.category === "authentication" ? "POST" : "GET";
    const body = headerBypassEndpoint.category === "authentication"
      ? JSON.stringify({ email: "test@test.com", password: "password" })
      : undefined;

    const randomIp = () => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

    const spoofableHeaders = ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP"];
    const headerBypassResults = await Promise.allSettled(
      spoofableHeaders.map(async (headerName) => {
        // Send 20 requests, each with a different random IP in the spoofed header
        let allSucceeded = true;
        const statuses: number[] = [];
        for (let i = 0; i < 20; i++) {
          try {
            const res = await scanFetch(url, {
              method,
              headers: { "Content-Type": "application/json", [headerName]: randomIp() },
              body,
              timeoutMs: 5000,
              noCache: true,
            });
            statuses.push(res.status);
            if (res.status === 429) { allSucceeded = false; break; }
            if ([401, 403, 404, 405, 500].includes(res.status)) { allSucceeded = false; break; }
          } catch { allSucceeded = false; break; }
        }
        return { header: headerName, allSucceeded, statuses };
      }),
    );

    // Compare with baseline: send 20 requests WITHOUT spoofed headers
    let baselineRateLimited = false;
    for (let i = 0; i < 20; i++) {
      try {
        const res = await scanFetch(url, {
          method,
          headers: { "Content-Type": "application/json" },
          body,
          timeoutMs: 5000,
          noCache: true,
        });
        if (res.status === 429) { baselineRateLimited = true; break; }
        if ([401, 403, 404, 405, 500].includes(res.status)) break;
      } catch { break; }
    }

    if (baselineRateLimited) {
      const bypassed = headerBypassResults
        .filter((r) => r.status === "fulfilled" && r.value.allSucceeded && r.value.statuses.length === 20)
        .map((r) => (r as PromiseFulfilledResult<{ header: string; allSucceeded: boolean; statuses: number[] }>).value);

      if (bypassed.length > 0) {
        findings.push({
          id: "ratelimit-bypass-random-ip-headers",
          module: "rate-limit",
          severity: "high",
          title: `Rate limit bypass via rotating ${bypassed.map((b) => b.header).join(", ")} headers`,
          description: `The rate limiter on ${new URL(url).pathname} keys on client-supplied IP headers. By rotating random IPs in ${bypassed.map((b) => b.header).join(", ")}, an attacker can send unlimited requests — each "new IP" gets a fresh rate limit bucket. Baseline requests were rate-limited after fewer than 20 requests, but spoofed-header requests all succeeded.`,
          evidence: `Endpoint: ${url}\nBaseline: rate-limited within 20 requests\n${bypassed.map((b) => `${b.header} with random IPs: ${b.statuses.length} requests, all status ${Array.from(new Set(b.statuses)).join("/")}`).join("\n")}`,
          remediation: "Never trust client-provided IP headers for rate limiting. Use the socket-level IP address or your reverse proxy's verified client IP (e.g., Vercel req.ip, Cloudflare CF-Connecting-IP only when Cloudflare is in the trust chain). Configure your framework's trust proxy setting to only trust known proxy hops.",
          cwe: "CWE-290",
          owasp: "A07:2021",
        });
      }
    }
  }

  // Phase 5: Rate limit bypass via HTTP method switching
  // Test if changing GET to POST or vice versa resets rate counters
  const methodBypassEndpoint = criticalEndpoints[0];
  if (methodBypassEndpoint) {
    const url = methodBypassEndpoint.url;
    const pathname = new URL(url).pathname;

    const methodPairs: [string, string][] = [["GET", "POST"], ["POST", "GET"]];
    const methodBypassResults = await Promise.allSettled(
      methodPairs.map(async ([primary, alternate]) => {
        // First, exhaust rate limit with the primary method
        let primaryLimited = false;
        for (let i = 0; i < 50; i++) {
          try {
            const res = await scanFetch(url, {
              method: primary,
              headers: { "Content-Type": "application/json" },
              body: primary === "POST" ? JSON.stringify({}) : undefined,
              timeoutMs: 5000,
              noCache: true,
            });
            if (res.status === 429) { primaryLimited = true; break; }
            if ([404, 405, 500].includes(res.status)) break;
          } catch { break; }
        }

        if (!primaryLimited) return null;

        // Now try the alternate method — if it succeeds, counters are separate
        try {
          const altRes = await scanFetch(url, {
            method: alternate,
            headers: { "Content-Type": "application/json" },
            body: alternate === "POST" ? JSON.stringify({}) : undefined,
            timeoutMs: 5000,
            noCache: true,
          });
          if (altRes.status !== 429 && ![404, 405, 500].includes(altRes.status)) {
            return { primary, alternate, altStatus: altRes.status };
          }
        } catch { /* skip */ }
        return null;
      }),
    );

    const methodBypassed = methodBypassResults
      .filter((r) => r.status === "fulfilled" && r.value !== null)
      .map((r) => (r as PromiseFulfilledResult<{ primary: string; alternate: string; altStatus: number }>).value);

    if (methodBypassed.length > 0) {
      const b = methodBypassed[0];
      findings.push({
        id: "ratelimit-bypass-method-switch",
        module: "rate-limit",
        severity: "medium",
        title: `Rate limit bypass via HTTP method switching on ${pathname}`,
        description: `After exhausting the rate limit with ${b.primary} requests on ${pathname}, switching to ${b.alternate} returned status ${b.altStatus} instead of 429. This indicates rate limit counters are keyed per HTTP method, allowing attackers to double their effective request budget by alternating methods.`,
        evidence: `Endpoint: ${url}\n${b.primary}: rate-limited (429)\n${b.alternate}: ${b.altStatus} (not limited)`,
        remediation: "Rate limit counters should be keyed on the endpoint path and client identity, not the HTTP method. Ensure your rate limiter counts all methods against the same bucket for a given path.",
        cwe: "CWE-799",
        owasp: "A07:2021",
      });
    }
  }

  // Phase 6: Rate limit bypass via path casing
  // Test if /api/login vs /Api/Login vs /API/LOGIN have separate rate limit counters
  const casingTestEndpoints = criticalEndpoints
    .filter((ep) => /\/(api|auth|login|register|signup)/i.test(new URL(ep.url).pathname))
    .slice(0, 3);

  for (const { url } of casingTestEndpoints) {
    const parsed = new URL(url);
    const originalPath = parsed.pathname;

    // Generate case variations
    const variations = [
      originalPath.toUpperCase(),
      originalPath.toLowerCase(),
      originalPath.split("/").map((seg) => seg.charAt(0).toUpperCase() + seg.slice(1).toLowerCase()).join("/"),
      originalPath.split("/").map((seg, i) => i % 2 === 0 ? seg.toUpperCase() : seg.toLowerCase()).join("/"),
    ].filter((v) => v !== originalPath);
    const uniqueVariations = Array.from(new Set(variations)).slice(0, 3);

    if (uniqueVariations.length === 0) continue;

    const casingResults = await Promise.allSettled(
      uniqueVariations.map(async (varPath) => {
        const varUrl = `${parsed.origin}${varPath}${parsed.search}`;
        try {
          const res = await scanFetch(varUrl, {
            method: "GET",
            headers: { "Content-Type": "application/json" },
            timeoutMs: 5000,
            noCache: true,
          });
          // If the variant resolves to the same resource (2xx or 3xx), it means the server
          // treats paths case-insensitively — separate counters would be a bypass vector
          return { path: varPath, status: res.status, rateLimited: res.status === 429, reachable: res.status < 400 };
        } catch { return null; }
      }),
    );

    // Check the original path too
    let originalReachable = false;
    try {
      const origRes = await scanFetch(url, { method: "GET", headers: { "Content-Type": "application/json" }, timeoutMs: 5000, noCache: true });
      originalReachable = origRes.status < 400;
    } catch { /* skip */ }

    const reachableVariants = casingResults
      .filter((r) => r.status === "fulfilled" && r.value !== null && r.value.reachable)
      .map((r) => (r as PromiseFulfilledResult<{ path: string; status: number; rateLimited: boolean; reachable: boolean }>).value);

    if (originalReachable && reachableVariants.length > 0) {
      findings.push({
        id: `ratelimit-bypass-path-casing-${findings.length}`,
        module: "rate-limit",
        severity: "medium",
        title: `Path casing variants resolve to same endpoint: ${originalPath}`,
        description: `The server responds to multiple case variations of ${originalPath} (e.g., ${reachableVariants.map((v) => v.path).join(", ")}). If the rate limiter keys on the exact path string, attackers can bypass limits by rotating case variants — each variant gets its own rate limit bucket while hitting the same backend handler.`,
        evidence: `Original: ${originalPath} (reachable)\nVariants:\n${reachableVariants.map((v) => `  ${v.path} → ${v.status}`).join("\n")}`,
        remediation: "Normalize request paths to lowercase before applying rate limiting. Most rate-limiting middleware should be applied after URL normalization. Example: app.use((req, res, next) => { req.url = req.url.toLowerCase(); next(); });",
        cwe: "CWE-178",
        owasp: "A07:2021",
      });
    }
  }

  // Phase 7: Missing rate limit headers on sensitive endpoints
  // Check login, registration, password reset, and API endpoints for rate limit response headers
  const sensitivePaths = [
    { path: "/api/auth/login", label: "login" },
    { path: "/api/auth/signin", label: "login" },
    { path: "/api/login", label: "login" },
    { path: "/auth/login", label: "login" },
    { path: "/api/auth/register", label: "registration" },
    { path: "/api/register", label: "registration" },
    { path: "/api/auth/signup", label: "registration" },
    { path: "/api/auth/forgot-password", label: "password reset" },
    { path: "/api/forgot-password", label: "password reset" },
    { path: "/api/auth/reset-password", label: "password reset" },
  ];

  const sensitiveEndpoints: { url: string; label: string }[] = [];
  for (const { path, label } of sensitivePaths) {
    const match = target.apiEndpoints.find((ep) => ep.includes(path));
    if (match && !sensitiveEndpoints.some((e) => e.url === match)) {
      sensitiveEndpoints.push({ url: match, label });
    }
  }
  // Also include first few generic API endpoints
  for (const ep of target.apiEndpoints.slice(0, 5)) {
    if (!sensitiveEndpoints.some((e) => e.url === ep)) {
      sensitiveEndpoints.push({ url: ep, label: "API" });
    }
  }

  const rateLimitHeaderChecks = await Promise.allSettled(
    sensitiveEndpoints.slice(0, 8).map(async ({ url, label }) => {
      try {
        const res = await scanFetch(url, {
          method: "GET",
          headers: { "Content-Type": "application/json" },
          timeoutMs: 5000,
        });

        // Check for standard rate limit headers
        const rateLimitHeaders = [
          "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
          "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
          "ratelimit-policy", "retry-after",
          "x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset",
        ];

        const foundHeaders: string[] = [];
        for (const header of rateLimitHeaders) {
          const value = res.headers.get(header);
          if (value) foundHeaders.push(`${header}: ${value}`);
        }

        return { url, label, status: res.status, foundHeaders, hasRateLimit: foundHeaders.length > 0 };
      } catch { return null; }
    }),
  );

  const missingRateLimitEndpoints = rateLimitHeaderChecks
    .filter((r) => r.status === "fulfilled" && r.value !== null && !r.value.hasRateLimit && r.value.status < 500)
    .map((r) => (r as PromiseFulfilledResult<{ url: string; label: string; status: number; foundHeaders: string[]; hasRateLimit: boolean }>).value);

  // Only report sensitive endpoints (login, registration, password reset) — generic API missing headers is too noisy
  const missingSensitive = missingRateLimitEndpoints.filter((e) => e.label !== "API");
  if (missingSensitive.length > 0) {
    findings.push({
      id: "ratelimit-missing-headers-sensitive",
      module: "rate-limit",
      severity: "medium",
      title: `No rate limit headers on ${missingSensitive.length} sensitive endpoint(s)`,
      description: `The following sensitive endpoints return no rate limit response headers (X-RateLimit-*, RateLimit-*, Retry-After): ${missingSensitive.map((e) => `${e.label} (${new URL(e.url).pathname})`).join(", ")}. While the absence of headers alone doesn't confirm missing rate limiting, well-configured rate limiters expose these headers so clients can self-throttle and so monitoring tools can detect abuse.`,
      evidence: missingSensitive.map((e) => `${e.label}: ${new URL(e.url).pathname} → ${e.status} (no rate limit headers)`).join("\n"),
      remediation: "Configure your rate limiter to return standard rate limit headers: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset (draft IETF standard), or X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset. This helps legitimate clients respect limits and enables monitoring.",
      cwe: "CWE-770",
      owasp: "A07:2021",
    });
  }

  // Phase 8: GraphQL rate limiting — check if GraphQL endpoints have query depth/complexity limiting
  const graphqlPaths = ["/graphql", "/api/graphql", "/graphql/v1", "/gql", "/api/query", "/v1/graphql"];
  const graphqlEndpoints: string[] = [];

  // Discover GraphQL endpoints
  const graphqlDiscovery = await Promise.allSettled(
    graphqlPaths.map(async (path) => {
      const url = `${target.baseUrl}${path}`;
      try {
        const res = await scanFetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: "{ __typename }" }),
          timeoutMs: 5000,
          noCache: true,
        });
        const text = await res.text();
        // A GraphQL endpoint typically returns JSON with a "data" key
        if (res.status < 500 && (text.includes('"data"') || text.includes('"errors"'))) {
          return url;
        }
      } catch { /* skip */ }
      return null;
    }),
  );

  for (const r of graphqlDiscovery) {
    if (r.status === "fulfilled" && r.value) graphqlEndpoints.push(r.value);
  }

  // Also check discovered API endpoints that look like GraphQL
  for (const ep of target.apiEndpoints) {
    if (/graphql|gql/i.test(ep) && !graphqlEndpoints.includes(ep)) {
      graphqlEndpoints.push(ep);
    }
  }

  for (const endpoint of graphqlEndpoints.slice(0, 3)) {
    const pathname = new URL(endpoint).pathname;

    // Test 1: Deep nested query (query depth limiting)
    const deepQuery = `{ ${"a: __typename ".repeat(1)}${Array.from({ length: 15 }, (_, i) => `d${i} { `).join("")}__typename${"} ".repeat(15)} }`;
    // Simplified: build a deeply nested __typename query
    let depthParts = "{ __typename";
    for (let i = 0; i < 15; i++) depthParts += ` d${i}: __type(name: "Query") { name`;
    for (let i = 0; i < 15; i++) depthParts += " }";
    depthParts += " }";

    const [depthResult, complexityResult, batchResult] = await Promise.allSettled([
      // Test depth limiting
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: depthParts }),
        timeoutMs: 8000,
        noCache: true,
      }).then(async (res) => {
        const text = await res.text();
        return { status: res.status, text, rateLimited: res.status === 429 };
      }),

      // Test complexity limiting — many aliased fields
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: `{ ${Array.from({ length: 50 }, (_, i) => `a${i}: __typename`).join(" ")} }`,
        }),
        timeoutMs: 8000,
        noCache: true,
      }).then(async (res) => {
        const text = await res.text();
        return { status: res.status, text, rateLimited: res.status === 429 };
      }),

      // Test batch query limiting
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          Array.from({ length: 20 }, () => ({ query: "{ __typename }" })),
        ),
        timeoutMs: 8000,
        noCache: true,
      }).then(async (res) => {
        const text = await res.text();
        return { status: res.status, text, rateLimited: res.status === 429 };
      }),
    ]);

    const issues: string[] = [];
    const evidenceLines: string[] = [`GraphQL endpoint: ${endpoint}`];

    // Check depth result
    if (depthResult.status === "fulfilled") {
      const r = depthResult.value;
      const hasDepthError = r.text.includes("depth") || r.text.includes("too complex") || r.text.includes("max depth");
      if (!hasDepthError && !r.rateLimited && r.status < 500 && r.text.includes('"data"')) {
        issues.push("no query depth limiting");
        evidenceLines.push(`Depth test: 15-level nested query accepted (status ${r.status})`);
      }
    }

    // Check complexity result
    if (complexityResult.status === "fulfilled") {
      const r = complexityResult.value;
      const hasComplexityError = r.text.includes("complexity") || r.text.includes("cost") || r.text.includes("too complex");
      if (!hasComplexityError && !r.rateLimited && r.status < 500 && r.text.includes('"data"')) {
        issues.push("no query complexity limiting");
        evidenceLines.push(`Complexity test: 50-alias query accepted (status ${r.status})`);
      }
    }

    // Check batch result
    if (batchResult.status === "fulfilled") {
      const r = batchResult.value;
      if (!r.rateLimited && r.status < 500 && (r.text.includes('"data"') || r.text.startsWith("["))) {
        issues.push("no batch query limiting");
        evidenceLines.push(`Batch test: 20-query batch accepted (status ${r.status})`);
      }
    }

    if (issues.length > 0) {
      findings.push({
        id: `ratelimit-graphql-no-limiting-${findings.length}`,
        module: "rate-limit",
        severity: "high",
        title: `GraphQL endpoint ${pathname} lacks ${issues.join(", ")}`,
        description: `The GraphQL endpoint at ${pathname} does not enforce ${issues.join(" or ")}. Without these controls, attackers can craft expensive queries that consume excessive server resources — a single deeply nested or highly aliased query can be equivalent to thousands of REST requests. This is a common denial-of-service vector for GraphQL APIs.`,
        evidence: evidenceLines.join("\n"),
        remediation: "Implement GraphQL-specific rate limiting:\n1. Query depth limiting (max 7-10 levels) using graphql-depth-limit\n2. Query complexity/cost analysis using graphql-query-complexity or graphql-validation-complexity\n3. Batch query limits (max 5-10 queries per batch)\n4. Request timeout for individual query execution",
        cwe: "CWE-770",
        owasp: "A04:2021",
      });
    }
  }

  return findings;
};
