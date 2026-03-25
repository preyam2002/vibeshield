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

  return findings;
};
