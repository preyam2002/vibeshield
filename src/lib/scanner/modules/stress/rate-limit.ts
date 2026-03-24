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
      });
    }
  }

  return findings;
};
