import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

interface LoadResult {
  concurrency: number;
  totalRequests: number;
  successCount: number;
  failCount: number;
  avgResponseMs: number;
  p50ResponseMs: number;
  p95ResponseMs: number;
  p99ResponseMs: number;
  maxResponseMs: number;
  errorRate: number;
  avgBodySize: number;
  bodySizeVariance: number;
  connectionIds: Set<string>;
}

interface BatchResult {
  ok: boolean;
  ms: number;
  status: number;
  bodySize: number;
  connectionId: string;
}

const sendBatch = async (
  url: string,
  count: number,
  timeoutMs = 10000,
): Promise<BatchResult[]> => {
  const results = await Promise.allSettled(
    Array.from({ length: count }, async () => {
      const start = Date.now();
      try {
        const res = await scanFetch(url, { timeoutMs, noCache: true });
        const body = await res.text().catch(() => "");
        const connectionId =
          res.headers.get("x-connection-id") ||
          res.headers.get("x-request-id") ||
          res.headers.get("cf-ray") ||
          "";
        return {
          ok: res.ok,
          ms: Date.now() - start,
          status: res.status,
          bodySize: body.length,
          connectionId,
        };
      } catch {
        return { ok: false, ms: Date.now() - start, status: 0, bodySize: 0, connectionId: "" };
      }
    }),
  );
  return results.map((r) =>
    r.status === "fulfilled"
      ? r.value
      : { ok: false, ms: 10000, status: 0, bodySize: 0, connectionId: "" },
  );
};

const percentile = (arr: number[], p: number): number => {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
};

const variance = (arr: number[]): number => {
  if (arr.length === 0) return 0;
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  return arr.reduce((sum, v) => sum + (v - mean) ** 2, 0) / arr.length;
};

export const loadModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const testUrl = target.url;

  // Progressive ramp: 10 → 25 → 50 → 75 → 100 concurrent requests
  const stages = [10, 25, 50, 75, 100];
  const results: LoadResult[] = [];

  for (const concurrency of stages) {
    const batch = await sendBatch(testUrl, concurrency);
    const times = batch.map((r) => r.ms);
    const successes = batch.filter((r) => r.ok).length;
    const rateLimited = batch.filter((r) => r.status === 429).length;
    const wafBlocked = batch.filter((r) => r.status === 403 || r.status === 503).length;
    const serverErrors = batch.filter((r) => r.status >= 500 && r.status !== 503).length;
    const fails = batch.filter((r) => !r.ok).length;
    const bodySizes = batch.filter((r) => r.ok).map((r) => r.bodySize);
    const connectionIds = new Set(batch.map((r) => r.connectionId).filter(Boolean));

    results.push({
      concurrency,
      totalRequests: concurrency,
      successCount: successes,
      failCount: fails,
      avgResponseMs: Math.round(times.reduce((a, b) => a + b, 0) / times.length),
      p50ResponseMs: Math.round(percentile(times, 50)),
      p95ResponseMs: Math.round(percentile(times, 95)),
      p99ResponseMs: Math.round(percentile(times, 99)),
      maxResponseMs: Math.round(Math.max(...times)),
      errorRate: fails / concurrency,
      avgBodySize: bodySizes.length > 0 ? Math.round(bodySizes.reduce((a, b) => a + b, 0) / bodySizes.length) : 0,
      bodySizeVariance: variance(bodySizes),
      connectionIds,
    });

    if (rateLimited > concurrency * 0.3) {
      findings.push({
        id: "stress-load-rate-limited",
        module: "Load Testing",
        severity: "info",
        title: `Rate limiting active at ${concurrency} concurrent requests`,
        description: `${rateLimited}/${concurrency} requests received 429 (Too Many Requests). Rate limiting is properly protecting your app.`,
        evidence: `At ${concurrency} concurrent: ${rateLimited} rate-limited, ${successes} succeeded, ${serverErrors} server errors`,
        remediation: "Rate limiting is working as intended. Review limits if they seem too aggressive for legitimate traffic.",
        codeSnippet: `// Connection pooling + caching for high-concurrency resilience
import { Pool } from "pg";

const pool = new Pool({
  max: 20,                    // max connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Add an LRU cache for hot reads
import { LRUCache } from "lru-cache";
const cache = new LRUCache<string, unknown>({ max: 1000, ttl: 60_000 });`,
      });
      break;
    }

    if ((rateLimited + wafBlocked) > concurrency * 0.5 && concurrency <= 20) {
      findings.push({
        id: "stress-load-waf-protected",
        module: "Load Testing",
        severity: "info",
        title: "WAF/bot protection detected",
        description: `${wafBlocked} requests received 403/503 at just ${concurrency} concurrent requests. Your app appears to have WAF or bot protection (e.g., Cloudflare) which blocks automated scanning.`,
        evidence: `At ${concurrency} concurrent: ${wafBlocked} blocked (403/503), ${rateLimited} rate-limited, ${successes} succeeded`,
        remediation: "WAF protection is working as intended. Load test results may not reflect actual capacity.",
        codeSnippet: `// WAF is active — ensure your origin is also protected
// vercel.json or next.config.ts
export default {
  headers: [
    { source: "/api/:path*", headers: [
      { key: "X-Frame-Options", value: "DENY" },
      { key: "X-Content-Type-Options", value: "nosniff" },
    ]},
  ],
};`,
      });
      return findings;
    }

    if (serverErrors / concurrency > 0.5) break;
  }

  // Build summary with full percentile data
  const summary = results
    .map(
      (r) =>
        `${r.concurrency} concurrent: p50 ${r.p50ResponseMs}ms, p95 ${r.p95ResponseMs}ms, p99 ${r.p99ResponseMs}ms, max ${r.maxResponseMs}ms, errors ${Math.round(r.errorRate * 100)}%`,
    )
    .join("\n");

  // --- Percentile degradation analysis ---
  if (results.length >= 2) {
    const first = results[0];
    const last = results[results.length - 1];
    const p99Ratio = last.p99ResponseMs / Math.max(first.p99ResponseMs, 1);
    const p95Ratio = last.p95ResponseMs / Math.max(first.p95ResponseMs, 1);

    // p99 growing much faster than p95 = tail latency problem
    if (p99Ratio > 5 && last.p99ResponseMs > 3000) {
      findings.push({
        id: "stress-load-tail-latency",
        module: "Load Testing",
        severity: "medium",
        title: "Severe tail latency under load",
        description: `P99 response time grew ${p99Ratio.toFixed(1)}x from ${first.p99ResponseMs}ms (at ${first.concurrency} concurrent) to ${last.p99ResponseMs}ms (at ${last.concurrency} concurrent). Tail latency problems often indicate lock contention, GC pauses, or connection pool exhaustion.`,
        evidence: `${summary}\n\nP99 growth: ${p99Ratio.toFixed(1)}x\nP95 growth: ${p95Ratio.toFixed(1)}x`,
        remediation:
          "Investigate tail latency causes: database connection pool exhaustion, mutex contention, garbage collection pauses, or cold starts. Use connection pooling with appropriate max sizes and add request timeouts.",
        codeSnippet: `// Diagnose tail latency with server timing headers
export async function middleware(req: NextRequest) {
  const start = performance.now();
  const res = NextResponse.next();
  const duration = performance.now() - start;
  res.headers.set("Server-Timing", \`total;dur=\${duration.toFixed(1)}\`);
  if (duration > 2000) {
    console.warn(\`Slow request: \${req.url} took \${duration}ms\`);
  }
  return res;
}`,
        cwe: "CWE-400",
        confidence: 70,
      });
    }

    // p50-to-p95 spread widening = inconsistent performance
    const firstSpread = first.p95ResponseMs - first.p50ResponseMs;
    const lastSpread = last.p95ResponseMs - last.p50ResponseMs;
    if (lastSpread > firstSpread * 4 && lastSpread > 2000) {
      findings.push({
        id: "stress-load-latency-spread",
        module: "Load Testing",
        severity: "low",
        title: "Increasing response time variance under load",
        description: `The gap between p50 and p95 grew from ${firstSpread}ms to ${lastSpread}ms as concurrency increased. This means user experience becomes highly unpredictable under load — some requests are fast while others are very slow.`,
        evidence: `At ${first.concurrency} concurrent: p50=${first.p50ResponseMs}ms, p95=${first.p95ResponseMs}ms (spread: ${firstSpread}ms)\nAt ${last.concurrency} concurrent: p50=${last.p50ResponseMs}ms, p95=${last.p95ResponseMs}ms (spread: ${lastSpread}ms)`,
        remediation:
          "Add request queuing with fair scheduling, ensure database queries have proper indexes, and use connection pool sizing appropriate for your concurrency level.",
        cwe: "CWE-400",
        confidence: 65,
      });
    }
  }

  // --- Progressive load analysis: find the concurrency inflection point ---
  if (results.length >= 3) {
    for (let i = 1; i < results.length; i++) {
      const prev = results[i - 1];
      const curr = results[i];
      const avgRatio = curr.avgResponseMs / Math.max(prev.avgResponseMs, 1);
      // If avg response time more than triples between stages, that's the inflection
      if (avgRatio > 3 && curr.avgResponseMs > 1000 && curr.errorRate <= 0.2) {
        findings.push({
          id: "stress-load-inflection",
          module: "Load Testing",
          severity: "medium",
          title: `Performance cliff between ${prev.concurrency} and ${curr.concurrency} concurrent users`,
          description: `Average response time jumped ${avgRatio.toFixed(1)}x (from ${prev.avgResponseMs}ms to ${curr.avgResponseMs}ms) when concurrency increased from ${prev.concurrency} to ${curr.concurrency}. This suggests a resource bottleneck (e.g., connection pool, worker threads, or database connections) saturates around ${prev.concurrency} concurrent users.`,
          evidence: summary,
          remediation: `Your app's practical concurrency limit is around ${prev.concurrency} users. Scale horizontally, increase connection pool sizes, or add caching to push this higher.`,
          codeSnippet: `// Increase connection pool and add queuing
import { Pool } from "pg";

const pool = new Pool({
  max: ${Math.min(prev.concurrency * 2, 100)},  // scale pool to match expected concurrency
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 3000,
  // Enable statement-level load balancing for read replicas
});

// Add a concurrency limiter for expensive operations
import pLimit from "p-limit";
const limit = pLimit(${prev.concurrency});
const result = await limit(() => expensiveOperation());`,
          cwe: "CWE-400",
          confidence: 75,
        });
        break;
      }
    }
  }

  // --- Response body size variance detection ---
  const successfulResults = results.filter((r) => r.successCount >= 3);
  if (successfulResults.length >= 2) {
    const firstBody = successfulResults[0];
    const lastBody = successfulResults[successfulResults.length - 1];

    // Large body size difference between low and high concurrency = error pages under load
    if (firstBody.avgBodySize > 0 && lastBody.avgBodySize > 0) {
      const sizeRatio = lastBody.avgBodySize / firstBody.avgBodySize;
      const sizeDiff = Math.abs(lastBody.avgBodySize - firstBody.avgBodySize);

      if ((sizeRatio < 0.3 || sizeRatio > 3) && sizeDiff > 500) {
        findings.push({
          id: "stress-load-body-size-change",
          module: "Load Testing",
          severity: "medium",
          title: "Response body size changes significantly under load",
          description: `Average response body size ${sizeRatio < 1 ? "shrank" : "grew"} from ${firstBody.avgBodySize} bytes (at ${firstBody.concurrency} concurrent) to ${lastBody.avgBodySize} bytes (at ${lastBody.concurrency} concurrent). ${sizeRatio < 0.5 ? "Smaller responses under load often indicate error pages or truncated responses replacing normal content." : "Larger responses may indicate verbose error messages or stack traces leaking under stress."}`,
          evidence: `At ${firstBody.concurrency} concurrent: avg body ${firstBody.avgBodySize} bytes\nAt ${lastBody.concurrency} concurrent: avg body ${lastBody.avgBodySize} bytes\nSize ratio: ${sizeRatio.toFixed(2)}x`,
          remediation:
            "Ensure error responses don't leak different content under load. Use consistent error formatting and verify your app returns the same response structure regardless of backend pressure.",
          codeSnippet: `// Consistent error handling that doesn't leak stack traces
export function errorHandler(err: Error, req: Request) {
  console.error("Internal error:", err);
  // Always return the same structure — never expose internals
  return Response.json(
    { error: "Internal server error", requestId: crypto.randomUUID() },
    { status: 500 }
  );
}`,
          cwe: "CWE-209",
          confidence: 60,
        });
      }
    }

    // High body size variance within a single stage = intermittent errors
    for (const stage of successfulResults) {
      if (stage.bodySizeVariance > 0 && stage.avgBodySize > 0) {
        const cv = Math.sqrt(stage.bodySizeVariance) / stage.avgBodySize; // coefficient of variation
        if (cv > 0.5 && stage.successCount >= 5) {
          findings.push({
            id: `stress-load-inconsistent-body-${stage.concurrency}`,
            module: "Load Testing",
            severity: "low",
            title: `Inconsistent response sizes at ${stage.concurrency} concurrent requests`,
            description: `Response body sizes vary widely (coefficient of variation: ${(cv * 100).toFixed(0)}%) at ${stage.concurrency} concurrent requests. This suggests some requests are receiving different content — possibly error pages, partial responses, or cached vs uncached variants.`,
            evidence: `At ${stage.concurrency} concurrent: avg body ${stage.avgBodySize} bytes, std dev ${Math.round(Math.sqrt(stage.bodySizeVariance))} bytes`,
            remediation:
              "Investigate why response sizes differ under the same concurrency level. Check for intermittent backend failures, partial responses from timeouts, or cache inconsistencies.",
            confidence: 55,
          });
          break; // only report once
        }
      }
    }
  }

  // --- Connection pooling analysis ---
  const stagesWithConnectionIds = results.filter((r) => r.connectionIds.size > 0);
  if (stagesWithConnectionIds.length >= 2) {
    const lastStage = stagesWithConnectionIds[stagesWithConnectionIds.length - 1];
    // If all requests share 1 connection ID at high concurrency, it's likely a single-connection bottleneck
    if (lastStage.connectionIds.size === 1 && lastStage.concurrency >= 25) {
      findings.push({
        id: "stress-load-single-connection",
        module: "Load Testing",
        severity: "medium",
        title: "Possible single-connection bottleneck",
        description: `All ${lastStage.concurrency} concurrent requests appear to use the same connection (identical request/connection IDs). This may indicate connection pooling is not configured or all requests are serialized through a single connection.`,
        evidence: `At ${lastStage.concurrency} concurrent: only ${lastStage.connectionIds.size} unique connection ID observed`,
        remediation:
          "Enable connection pooling with a pool size appropriate for your concurrency. For PostgreSQL, use PgBouncer or built-in pool. For HTTP clients, ensure keep-alive connections are pooled.",
        codeSnippet: `// Enable connection pooling for database
import { Pool } from "pg";
const pool = new Pool({
  max: 20,                       // match your expected concurrency
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// For Prisma, configure connection pool in schema
// datasource db {
//   provider = "postgresql"
//   url      = env("DATABASE_URL")
//   // Add ?connection_limit=20&pool_timeout=10 to URL
// }`,
        cwe: "CWE-400",
        confidence: 55,
      });
    }

    // Connection ID reuse analysis across stages
    if (stagesWithConnectionIds.length >= 2) {
      const firstStage = stagesWithConnectionIds[0];
      const connectionGrowthRatio =
        lastStage.connectionIds.size / Math.max(firstStage.connectionIds.size, 1);
      const concurrencyGrowthRatio = lastStage.concurrency / Math.max(firstStage.concurrency, 1);

      // If connections grow linearly with concurrency (no pooling), warn
      if (
        connectionGrowthRatio > concurrencyGrowthRatio * 0.8 &&
        lastStage.connectionIds.size > 10
      ) {
        findings.push({
          id: "stress-load-no-pooling",
          module: "Load Testing",
          severity: "low",
          title: "Connections scaling linearly with concurrency (no pooling detected)",
          description: `Connection IDs grew from ${firstStage.connectionIds.size} (at ${firstStage.concurrency} concurrent) to ${lastStage.connectionIds.size} (at ${lastStage.concurrency} concurrent), suggesting each request creates a new connection instead of reusing pooled connections. This can exhaust server-side connection limits.`,
          evidence: `At ${firstStage.concurrency} concurrent: ${firstStage.connectionIds.size} connections\nAt ${lastStage.concurrency} concurrent: ${lastStage.connectionIds.size} connections\nGrowth ratio: ${connectionGrowthRatio.toFixed(1)}x`,
          remediation:
            "Configure HTTP keep-alive and connection pooling. For reverse proxies (nginx), increase keepalive_requests. For databases, use a connection pooler.",
          cwe: "CWE-400",
          confidence: 50,
        });
      }
    }
  }

  // --- Standard breaking point / slow point analysis ---
  const breakPoint = results.find((r) => r.errorRate > 0.2);
  const lastGood = results.filter((r) => r.errorRate <= 0.2).pop();
  const slowPoint = results.find((r) => r.p95ResponseMs > 5000);

  if (breakPoint && breakPoint === results[0] && breakPoint.errorRate >= 0.99) {
    return findings;
  }

  if (breakPoint) {
    findings.push({
      id: "stress-load-breaking-point",
      module: "Load Testing",
      severity: breakPoint.concurrency <= 20 ? "high" : "medium",
      title: `App fails under ${breakPoint.concurrency} concurrent users`,
      description: `Your app starts failing at ${breakPoint.concurrency} concurrent requests (${Math.round(breakPoint.errorRate * 100)}% error rate). ${breakPoint.concurrency <= 20 ? "This is very low — a single viral post could take your app down." : "Consider scaling for production traffic."}`,
      evidence: summary,
      remediation:
        breakPoint.concurrency <= 20
          ? "Your app can't handle basic traffic. Check for: single-threaded processing, missing connection pooling, unoptimized database queries, or insufficient serverless concurrency limits."
          : "Optimize hot paths, add caching, increase serverless concurrency limits, and consider a CDN.",
      codeSnippet: `// Connection pool + serverless concurrency limits
import { Pool, neonConfig } from "@neondatabase/serverless";
neonConfig.poolQueryViaFetch = true;

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });

// Cache expensive queries
import { unstable_cache } from "next/cache";
const getProducts = unstable_cache(
  async () => pool.query("SELECT * FROM products WHERE active = true"),
  ["products"],
  { revalidate: 60 }
);`,
      cwe: "CWE-400",
    });
  }

  if (slowPoint && !breakPoint) {
    findings.push({
      id: "stress-load-slow",
      module: "Load Testing",
      severity: "medium",
      title: `Response times degrade severely at ${slowPoint.concurrency} concurrent users`,
      description: `P95 response time exceeds 5 seconds at ${slowPoint.concurrency} concurrent requests. Users will abandon your app.`,
      evidence: summary,
      remediation: "Profile slow endpoints. Add caching, optimize queries, and consider rate limiting.",
      codeSnippet: `// Add response caching for slow endpoints
import { NextResponse } from "next/server";

export async function GET() {
  const data = await getExpensiveData();
  return NextResponse.json(data, {
    headers: {
      "Cache-Control": "public, s-maxage=60, stale-while-revalidate=300",
    },
  });
}`,
      cwe: "CWE-400",
    });
  }

  if (!breakPoint && !slowPoint && lastGood) {
    findings.push({
      id: "stress-load-ok",
      module: "Load Testing",
      severity: "info",
      title: `App handles ${lastGood.concurrency} concurrent users`,
      description: `Your app remained stable up to ${lastGood.concurrency} concurrent users with p50 ${lastGood.p50ResponseMs}ms, p95 ${lastGood.p95ResponseMs}ms, p99 ${lastGood.p99ResponseMs}ms response times.`,
      evidence: summary,
      remediation: "Good baseline! Consider running extended load tests for sustained traffic patterns.",
      codeSnippet: `// k6 load test for sustained traffic patterns
// save as load-test.js, run: k6 run load-test.js
import http from "k6/http";
import { check } from "k6";

export const options = {
  stages: [
    { duration: "2m", target: 100 },
    { duration: "5m", target: 100 },
    { duration: "2m", target: 0 },
  ],
  thresholds: {
    http_req_duration: ["p(50)<500", "p(95)<2000", "p(99)<5000"],
  },
};

export default function () {
  const res = http.get("https://your-app.vercel.app");
  check(res, { "status 200": (r) => r.status === 200 });
}`,
    });
  }

  return findings;
};
