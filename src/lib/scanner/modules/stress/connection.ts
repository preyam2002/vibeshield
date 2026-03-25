import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

export const connectionExhaustionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Open many concurrent connections rapidly
  const N = 100;
  const startTime = Date.now();

  const results = await Promise.allSettled(
    Array.from({ length: N }, async (_, i) => {
      try {
        // Stagger slightly to simulate realistic attack
        await new Promise((r) => setTimeout(r, i * 10));
        const start = Date.now();
        const res = await scanFetch(target.url, { timeoutMs: 15000 });
        return { ok: res.ok, status: res.status, ms: Date.now() - start };
      } catch (err) {
        return { ok: false, status: 0, ms: Date.now() - startTime, error: String(err) };
      }
    }),
  );

  const successes = results.filter(
    (r) => r.status === "fulfilled" && r.value.ok,
  ).length;
  const failures = N - successes;
  const times = results
    .filter((r) => r.status === "fulfilled" && r.value.ok)
    .map((r) => (r as PromiseFulfilledResult<{ ok: boolean; ms: number }>).value.ms);

  const avgTime = times.length > 0 ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : 0;
  const maxTime = times.length > 0 ? Math.max(...times) : 0;

  // Check for connection refusals
  const connectionErrors = results.filter(
    (r) => r.status === "fulfilled" && !r.value.ok && r.value.status === 0,
  ).length;

  // If nearly all requests failed from the start, it's likely WAF/bot protection
  const wafBlocked = results.filter(
    (r) => r.status === "fulfilled" && (r.value.status === 403 || r.value.status === 503),
  ).length;
  if (wafBlocked > N * 0.5) return findings; // WAF blocking — not a real capacity issue

  if (connectionErrors > N * 0.3) {
    findings.push({
      id: "stress-connection-refused",
      module: "Connection Exhaustion",
      severity: "high",
      title: `Server refuses connections under sustained load (${connectionErrors}/${N} failed)`,
      description: `${connectionErrors} out of ${N} sustained connections were refused. This suggests the server has limited connection capacity and can be overwhelmed by relatively low traffic.`,
      evidence: `Total connections attempted: ${N}\nConnection failures: ${connectionErrors}\nSuccessful: ${successes}\nAvg response time (successful): ${avgTime}ms`,
      remediation: "Increase server connection limits. For serverless: increase concurrency limits. For traditional servers: tune connection pool sizes and worker processes. Add Cloudflare or similar for connection management.",
      codeSnippet: `// Tune connection handling and keep-alive
import { createServer } from "node:http";

const server = createServer(app);
server.keepAliveTimeout = 65000;  // > ALB's 60s idle timeout
server.headersTimeout = 66000;
server.maxConnections = 1024;

// For serverless (vercel.json):
// { "functions": { "api/**": { "maxDuration": 10, "memory": 1024 } } }

// Connection pool for DB
const pool = new Pool({
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});`,
      cwe: "CWE-400",
    });
  }

  // Check for severe degradation
  if (maxTime > 10000 && successes > 0) {
    findings.push({
      id: "stress-connection-degradation",
      module: "Connection Exhaustion",
      severity: "medium",
      title: "Severe response time degradation under sustained connections",
      description: `Under ${N} sustained connections, max response time reached ${(maxTime / 1000).toFixed(1)}s (avg: ${(avgTime / 1000).toFixed(1)}s). The server is struggling to process requests under load.`,
      evidence: `Avg response: ${avgTime}ms\nMax response: ${maxTime}ms\nSuccessful: ${successes}/${N}`,
      remediation: "Profile server performance under load. Check for: blocking I/O, unoptimized database queries, missing caching, or insufficient compute resources.",
      codeSnippet: `// Add request timeout + keep-alive tuning
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Limit concurrent connections per IP
const connLimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(50, "10 s"),
});

// Abort slow requests to free connections
const controller = new AbortController();
setTimeout(() => controller.abort(), 10_000);
const data = await fetch(upstreamUrl, { signal: controller.signal });`,
      cwe: "CWE-400",
    });
  }

  // Phase 2: Slow HTTP attack detection (Slowloris-style)
  // Send requests with very slow bodies to see if the server keeps connections open
  const slowEndpoints = target.apiEndpoints.filter((ep) =>
    !/health|ping|status/i.test(ep),
  ).slice(0, 3);

  if (slowEndpoints.length > 0) {
    const slowResults = await Promise.allSettled(
      slowEndpoints.map(async (endpoint) => {
        // Send a POST with a content-length promise but deliver body very slowly
        const start = Date.now();
        try {
          const controller = new AbortController();
          // Set a 12s timeout — if the server holds the connection for >10s, it's vulnerable
          const timeout = setTimeout(() => controller.abort(), 12000);
          const res = await fetch(endpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Content-Length": "1000000", // promise 1MB but never send it
            },
            body: new ReadableStream({
              start(ctrl) {
                // Send a tiny chunk then stall
                ctrl.enqueue(new TextEncoder().encode("{"));
                // Never close — simulates slowloris
              },
            }),
            signal: controller.signal,
            // @ts-expect-error -- Node.js specific
            duplex: "half",
          });
          clearTimeout(timeout);
          return { endpoint, elapsed: Date.now() - start, status: res.status, held: false };
        } catch (err) {
          const elapsed = Date.now() - start;
          // If it took >8s to abort, the server was holding the connection
          if (elapsed > 8000) {
            return { endpoint, elapsed, status: 0, held: true };
          }
          return null;
        }
      }),
    );

    const heldConnections = slowResults.filter(
      (r) => r.status === "fulfilled" && r.value?.held,
    );

    if (heldConnections.length > 0) {
      const ep = (heldConnections[0] as PromiseFulfilledResult<{ endpoint: string; elapsed: number }>).value;
      findings.push({
        id: "stress-slowloris-vulnerable",
        module: "Connection Exhaustion",
        severity: "high",
        title: "Server vulnerable to slow HTTP attacks (Slowloris-style)",
        description: `The server held a connection open for ${(ep.elapsed / 1000).toFixed(1)}s while receiving an incomplete request body. An attacker can exhaust server connections by opening many slow connections, denying service to legitimate users.`,
        evidence: `POST ${ep.endpoint}\nSent: 1 byte of promised 1MB body\nConnection held for: ${(ep.elapsed / 1000).toFixed(1)}s before timeout`,
        remediation: "Set aggressive request body timeouts (5-10s). Use a reverse proxy (nginx, Cloudflare) that buffers requests before forwarding. Limit concurrent connections per IP.",
        cwe: "CWE-400",
        owasp: "A06:2021",
        codeSnippet: `// nginx.conf — protect against slow HTTP attacks\nserver {\n  client_body_timeout 5s;\n  client_header_timeout 5s;\n  send_timeout 10s;\n  keepalive_timeout 65s;\n  limit_conn_zone $binary_remote_addr zone=conn_limit:10m;\n  limit_conn conn_limit 20;\n}\n\n// Or use Cloudflare's "Under Attack" mode for automatic protection`,
      });
    }
  }

  // Phase 3: HTTP/2 rapid reset detection (CVE-2023-44487)
  // Try sending many requests in rapid succession — if server accepts all without limiting, it may be vulnerable
  const rapidN = 200;
  const rapidStart = Date.now();
  const rapidResults = await Promise.allSettled(
    Array.from({ length: rapidN }, () =>
      scanFetch(target.url, { timeoutMs: 5000 }).then((res) => ({
        ok: res.ok,
        status: res.status,
      })).catch(() => ({ ok: false, status: 0 })),
    ),
  );
  const rapidElapsed = Date.now() - rapidStart;
  const rapidSuccess = rapidResults.filter(
    (r) => r.status === "fulfilled" && r.value.ok,
  ).length;
  const rapidRateLimited = rapidResults.filter(
    (r) => r.status === "fulfilled" && (r as PromiseFulfilledResult<{ status: number }>).value.status === 429,
  ).length;

  // If server processed all 200 requests with no rate limiting and it took < 5s, it's accepting rapid requests
  if (rapidSuccess > rapidN * 0.8 && rapidRateLimited === 0 && rapidElapsed < 5000) {
    findings.push({
      id: "stress-rapid-requests",
      module: "Connection Exhaustion",
      severity: "medium",
      title: `Server accepts ${rapidSuccess}/${rapidN} rapid requests with no rate limiting`,
      description: `Sent ${rapidN} concurrent requests in ${(rapidElapsed / 1000).toFixed(1)}s — ${rapidSuccess} succeeded with zero rate limiting. This makes the server susceptible to HTTP flood attacks and rapid request-based DoS.`,
      evidence: `${rapidN} concurrent requests in ${rapidElapsed}ms\nSuccessful: ${rapidSuccess}\nRate limited: ${rapidRateLimited}`,
      remediation: "Add connection-level rate limiting. Use a CDN/WAF that limits requests per IP. Consider Cloudflare's free plan for basic DDoS protection.",
      cwe: "CWE-770",
      owasp: "A06:2021",
      codeSnippet: `// Vercel middleware rate limiting\nimport { Ratelimit } from "@upstash/ratelimit";\nimport { Redis } from "@upstash/redis";\n\nconst ratelimit = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(100, "10 s"),\n});\n\nexport async function middleware(req: NextRequest) {\n  const ip = req.ip ?? req.headers.get("x-forwarded-for") ?? "unknown";\n  const { success } = await ratelimit.limit(ip);\n  if (!success) return new Response("Rate limited", { status: 429 });\n}`,
    });
  }

  return findings;
};
