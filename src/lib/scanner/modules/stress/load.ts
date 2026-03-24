import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

interface LoadResult {
  concurrency: number;
  totalRequests: number;
  successCount: number;
  failCount: number;
  avgResponseMs: number;
  p95ResponseMs: number;
  maxResponseMs: number;
  errorRate: number;
}

const sendBatch = async (
  url: string,
  count: number,
  timeoutMs = 10000,
): Promise<{ ok: boolean; ms: number; status: number }[]> => {
  const results = await Promise.allSettled(
    Array.from({ length: count }, async () => {
      const start = Date.now();
      try {
        const res = await scanFetch(url, { timeoutMs });
        return { ok: res.ok, ms: Date.now() - start, status: res.status };
      } catch {
        return { ok: false, ms: Date.now() - start, status: 0 };
      }
    }),
  );
  return results.map((r) => (r.status === "fulfilled" ? r.value : { ok: false, ms: 10000, status: 0 }));
};

const percentile = (arr: number[], p: number): number => {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
};

export const loadModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const testUrl = target.url;

  // Ramp: 5 → 20 → 50 → 100 concurrent requests
  const stages = [5, 20, 50, 100];
  const results: LoadResult[] = [];

  for (const concurrency of stages) {
    const batch = await sendBatch(testUrl, concurrency);
    const times = batch.map((r) => r.ms);
    const successes = batch.filter((r) => r.ok).length;
    const rateLimited = batch.filter((r) => r.status === 429).length;
    const wafBlocked = batch.filter((r) => r.status === 403 || r.status === 503).length;
    const serverErrors = batch.filter((r) => r.status >= 500 && r.status !== 503).length;
    const fails = batch.filter((r) => !r.ok).length;

    results.push({
      concurrency,
      totalRequests: concurrency,
      successCount: successes,
      failCount: fails,
      avgResponseMs: Math.round(times.reduce((a, b) => a + b, 0) / times.length),
      p95ResponseMs: Math.round(percentile(times, 95)),
      maxResponseMs: Math.round(Math.max(...times)),
      errorRate: fails / concurrency,
    });

    // 429s mean rate limiting is working — that's good, not a failure
    if (rateLimited > concurrency * 0.3) {
      findings.push({
        id: "stress-load-rate-limited",
        module: "Load Testing",
        severity: "info",
        title: `Rate limiting active at ${concurrency} concurrent requests`,
        description: `${rateLimited}/${concurrency} requests received 429 (Too Many Requests). Rate limiting is properly protecting your app.`,
        evidence: `At ${concurrency} concurrent: ${rateLimited} rate-limited, ${successes} succeeded, ${serverErrors} server errors`,
        remediation: "Rate limiting is working as intended. Review limits if they seem too aggressive for legitimate traffic.",
      });
      break;
    }

    // 403/503 at low concurrency = WAF/bot protection, not a real failure
    if ((rateLimited + wafBlocked) > concurrency * 0.5 && concurrency <= 20) {
      findings.push({
        id: "stress-load-waf-protected",
        module: "Load Testing",
        severity: "info",
        title: "WAF/bot protection detected",
        description: `${wafBlocked} requests received 403/503 at just ${concurrency} concurrent requests. Your app appears to have WAF or bot protection (e.g., Cloudflare) which blocks automated scanning.`,
        evidence: `At ${concurrency} concurrent: ${wafBlocked} blocked (403/503), ${rateLimited} rate-limited, ${successes} succeeded`,
        remediation: "WAF protection is working as intended. Load test results may not reflect actual capacity.",
      });
      return findings; // WAF blocks everything — load test results are meaningless
    }

    // Stop if more than 50% server errors (not counting 429s and WAF blocks)
    if (serverErrors / concurrency > 0.5) break;
  }

  // Analyze results
  const summary = results
    .map((r) => `${r.concurrency} concurrent: avg ${r.avgResponseMs}ms, p95 ${r.p95ResponseMs}ms, errors ${Math.round(r.errorRate * 100)}%`)
    .join("\n");

  // Find breaking point
  const breakPoint = results.find((r) => r.errorRate > 0.2);
  const lastGood = results.filter((r) => r.errorRate <= 0.2).pop();
  const slowPoint = results.find((r) => r.p95ResponseMs > 5000);

  // If first batch already had 100% errors, it's likely WAF/CDN blocking — skip the finding
  if (breakPoint && breakPoint === results[0] && breakPoint.errorRate >= 0.99) {
    // All requests failed from the start — likely not a real capacity issue
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
      remediation: breakPoint.concurrency <= 20
        ? "Your app can't handle basic traffic. Check for: single-threaded processing, missing connection pooling, unoptimized database queries, or insufficient serverless concurrency limits."
        : "Optimize hot paths, add caching, increase serverless concurrency limits, and consider a CDN.",
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
      cwe: "CWE-400",
    });
  }

  if (!breakPoint && !slowPoint && lastGood) {
    findings.push({
      id: "stress-load-ok",
      module: "Load Testing",
      severity: "info",
      title: `App handles ${lastGood.concurrency} concurrent users`,
      description: `Your app remained stable up to ${lastGood.concurrency} concurrent users with ${lastGood.avgResponseMs}ms average response time.`,
      evidence: summary,
      remediation: "Good baseline! Consider running extended load tests for sustained traffic patterns.",
    });
  }

  return findings;
};
