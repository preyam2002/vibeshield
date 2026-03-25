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

  return findings;
};
