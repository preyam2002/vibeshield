import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

interface CostEstimate {
  service: string;
  endpoint: string;
  costPerRequest: number;
  costPerHour: number;
  costPerDay: number;
  requestRate: number;
}

const AI_PRICING: Record<string, { input: number; output: number }> = {
  "openai": { input: 0.003, output: 0.015 },     // GPT-4o per 1K tokens
  "anthropic": { input: 0.003, output: 0.015 },   // Claude 3.5 Sonnet per 1K tokens
  "google": { input: 0.00025, output: 0.0005 },   // Gemini Flash per 1K tokens
};

// Cloud compute pricing per GB-second (approximate)
const CLOUD_PRICING: Record<string, number> = {
  "aws-lambda": 0.0000166667,
  "vercel": 0.000018,
  "cloudflare": 0.0000003,
  "gcp-functions": 0.0000025,
  "azure-functions": 0.000016,
};

// Patterns for third-party API calls that amplify cost
const THIRD_PARTY_PATTERNS = [
  { pattern: /stripe|paypal|braintree/i, name: "Payment processor", costPerCall: 0.01 },
  { pattern: /twilio|vonage|messagebird|plivo/i, name: "SMS/voice API", costPerCall: 0.0079 },
  { pattern: /sendgrid|resend|mailgun|postmark|ses/i, name: "Email API", costPerCall: 0.001 },
  { pattern: /maps\.google|mapbox|here\.com/i, name: "Geocoding/Maps API", costPerCall: 0.005 },
  { pattern: /aws\.amazon|s3\.amazonaws/i, name: "AWS services", costPerCall: 0.004 },
  { pattern: /firebase|firestore/i, name: "Firebase", costPerCall: 0.001 },
  { pattern: /pinecone|weaviate|qdrant|chroma/i, name: "Vector database", costPerCall: 0.001 },
];

export const costAttackModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  const estimates: CostEstimate[] = [];

  // Detect AI API usage — one finding per provider
  for (const [provider, pricing] of Object.entries(AI_PRICING)) {
    if (target.technologies.some((t) => t.toLowerCase().includes(provider)) ||
        new RegExp(provider, "i").test(allJs)) {
      const aiEndpoints = target.apiEndpoints.filter((ep) =>
        /generate|chat|completion|ai|ask|query|prompt/i.test(ep),
      );
      if (aiEndpoints.length === 0) continue;
      const costPerReq = (pricing.input * 0.5) + (pricing.output * 0.5);
      const rps = 100;
      estimates.push({
        service: `${provider} (${aiEndpoints.length} AI endpoints)`,
        endpoint: aiEndpoints[0],
        costPerRequest: costPerReq,
        costPerHour: costPerReq * rps * 3600,
        costPerDay: costPerReq * rps * 86400,
        requestRate: rps,
      });
    }
  }

  // Detect Vercel serverless — single consolidated finding
  if (target.technologies.includes("Vercel") && target.apiEndpoints.length > 0) {
    const functionCost = 0.0000004;
    const execTimeCost = 0.000018;
    const avgExecSeconds = 0.5;
    const costPerReq = functionCost + (execTimeCost * avgExecSeconds);
    const rps = 1000;
    const ep = target.apiEndpoints[0];
    estimates.push({
      service: `Vercel Functions (${target.apiEndpoints.length} endpoints)`,
      endpoint: ep,
      costPerRequest: costPerReq,
      costPerHour: costPerReq * rps * 3600,
      costPerDay: costPerReq * rps * 86400,
      requestRate: rps,
    });
  }

  // Detect Supabase — edge functions + database egress
  if (target.technologies.includes("Supabase")) {
    const edgeFnEndpoints = target.apiEndpoints.filter((ep) =>
      /supabase\.co\/functions\/v1\//i.test(ep),
    );
    if (edgeFnEndpoints.length > 0) {
      const costPerReq = 0.000002 + 0.00009;
      const rps = 500;
      estimates.push({
        service: `Supabase Edge Functions (${edgeFnEndpoints.length} functions)`,
        endpoint: edgeFnEndpoints[0],
        costPerRequest: costPerReq,
        costPerHour: costPerReq * rps * 3600,
        costPerDay: costPerReq * rps * 86400,
        requestRate: rps,
      });
    } else {
      const rps = 100;
      const costPerReq = 0.0001;
      estimates.push({
        service: "Supabase",
        endpoint: "Database egress",
        costPerRequest: costPerReq,
        costPerHour: costPerReq * rps * 3600,
        costPerDay: costPerReq * rps * 86400,
        requestRate: rps,
      });
    }
  }

  // Detect Cloudflare Workers / Pages Functions
  if (/cloudflare|workers\.dev/i.test(allJs) || target.headers["cf-ray"]) {
    const workerEndpoints = target.apiEndpoints.filter((ep) =>
      /workers\.dev|\/api\//i.test(ep),
    );
    if (workerEndpoints.length > 0) {
      const costPerReq = 0.0000003;
      const rps = 2000;
      estimates.push({
        service: `Cloudflare Workers (${workerEndpoints.length} endpoints)`,
        endpoint: workerEndpoints[0],
        costPerRequest: costPerReq,
        costPerHour: costPerReq * rps * 3600,
        costPerDay: costPerReq * rps * 86400,
        requestRate: rps,
      });
    }
  }

  // Detect image/media processing endpoints (Cloudinary, Imgix, etc.)
  const mediaPatterns = [
    { name: "Cloudinary", pattern: /res\.cloudinary\.com/i },
    { name: "Imgix", pattern: /\.imgix\.net/i },
    { name: "Uploadcare", pattern: /ucarecdn\.com/i },
  ];
  for (const { name, pattern } of mediaPatterns) {
    if (pattern.test(allJs)) {
      const transformEndpoints = target.apiEndpoints.filter((ep) =>
        /upload|image|media|transform|resize|optimize/i.test(ep),
      );
      const costPerReq = 0.02;
      const rps = 50;
      estimates.push({
        service: `${name} (image transforms)`,
        endpoint: transformEndpoints[0] || target.url,
        costPerRequest: costPerReq,
        costPerHour: costPerReq * rps * 3600,
        costPerDay: costPerReq * rps * 86400,
        requestRate: rps,
      });
      break;
    }
  }

  // Detect email/SMS sending endpoints (Resend, SendGrid, Twilio)
  const commsEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(send-email|send-sms|notify|invite|message|verification|otp)\b/i.test(ep),
  );
  if (commsEndpoints.length > 0) {
    const hasEmail = /resend|sendgrid|mailgun|postmark|ses/i.test(allJs);
    const hasSms = /twilio|vonage|messagebird|plivo/i.test(allJs);
    if (hasEmail || hasSms) {
      const costPerReq = hasSms ? 0.0079 : 0.001;
      const rps = hasSms ? 10 : 100;
      estimates.push({
        service: `${hasSms ? "SMS" : "Email"} sending (${commsEndpoints.length} endpoints)`,
        endpoint: commsEndpoints[0],
        costPerRequest: costPerReq,
        costPerHour: costPerReq * rps * 3600,
        costPerDay: costPerReq * rps * 86400,
        requestRate: rps,
      });
    }
  }

  // Report findings for expensive attack vectors
  for (const est of estimates) {
    if (est.costPerHour > 1) {
      findings.push({
        id: `cost-attack-${findings.length}`,
        module: "Cost Attack",
        severity: est.costPerHour > 100 ? "critical" : est.costPerHour > 10 ? "high" : "medium",
        title: `Cost attack vector: $${est.costPerHour.toFixed(0)}/hour via ${est.service}`,
        description: `Without rate limiting, an attacker hitting ${new URL(est.endpoint).pathname} at ${est.requestRate} req/sec could cost you:\n• ~$${est.costPerHour.toFixed(0)}/hour\n• ~$${est.costPerDay.toFixed(0)}/day\nThis is a "wallet drain" attack — the attacker doesn't need to take your app down, just run up your bill.`,
        evidence: `Service: ${est.service}\nEndpoint: ${est.endpoint}\nEst. cost per request: $${est.costPerRequest.toFixed(6)}\nAt ${est.requestRate} req/sec: $${est.costPerHour.toFixed(2)}/hour`,
        remediation: `1. Add rate limiting to ${new URL(est.endpoint).pathname}\n2. Set billing alerts and hard spending caps on ${est.service}\n3. Add API key rotation capability for emergency shutoff\n4. Consider Cloudflare or similar DDoS protection`,
        codeSnippet: `// Set a monthly usage cap and alert threshold
let monthlyUsage = await redis.get("api:usage:monthly");
const MONTHLY_CAP = 500; // $500 max spend

if (monthlyUsage >= MONTHLY_CAP) {
  await sendAlert("API budget exhausted — blocking requests");
  return new Response("Service temporarily unavailable", { status: 503 });
}
if (monthlyUsage >= MONTHLY_CAP * 0.8) {
  await sendAlert(\`API spend at \${monthlyUsage}/\${MONTHLY_CAP}\`);
}`,
        cwe: "CWE-400",
      });
    }
  }

  // --- Detect computationally expensive endpoints (response time > 2s) ---
  const expensiveChecks = target.apiEndpoints.slice(0, 10).map(async (endpoint) => {
    try {
      const start = Date.now();
      const res = await scanFetch(endpoint, { timeoutMs: 15000, noCache: true });
      const elapsed = Date.now() - start;
      const body = await res.text().catch(() => "");
      return { endpoint, elapsed, status: res.status, bodySize: body.length };
    } catch {
      return null;
    }
  });

  const expensiveResults = await Promise.allSettled(expensiveChecks);
  const slowEndpoints: { endpoint: string; elapsed: number; bodySize: number }[] = [];

  for (const r of expensiveResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { endpoint, elapsed, status, bodySize } = r.value;
    if (elapsed > 2000 && status >= 200 && status < 500) {
      slowEndpoints.push({ endpoint, elapsed, bodySize });
    }
  }

  if (slowEndpoints.length > 0) {
    const sorted = slowEndpoints.sort((a, b) => b.elapsed - a.elapsed);
    const worst = sorted[0];
    const detectedPlatform = target.technologies.includes("Vercel") ? "vercel"
      : target.headers["cf-ray"] ? "cloudflare"
      : /aws|lambda/i.test(allJs) ? "aws-lambda" : "vercel";
    const pricePerGbS = CLOUD_PRICING[detectedPlatform] || 0.000018;
    const gbSeconds = (worst.elapsed / 1000) * 0.256;
    const costPerReq = gbSeconds * pricePerGbS;
    const costPerHour = costPerReq * 100 * 3600;

    findings.push({
      id: "cost-expensive-endpoints",
      module: "Cost Attack",
      severity: costPerHour > 50 ? "high" : "medium",
      title: `Computationally expensive endpoint: ${new URL(worst.endpoint).pathname} (${(worst.elapsed / 1000).toFixed(1)}s)`,
      description: `${slowEndpoints.length} endpoint(s) respond in >2s, indicating heavy server-side computation. Slow endpoints consume more serverless GB-seconds, amplifying cost attacks. At 100 req/s this could cost ~$${costPerHour.toFixed(0)}/hour.`,
      evidence: sorted.slice(0, 5).map((e) => `${new URL(e.endpoint).pathname}: ${e.elapsed}ms`).join("\n"),
      remediation: "1. Add aggressive rate limiting to slow endpoints\n2. Implement caching for expensive computations\n3. Offload heavy work to background jobs/queues\n4. Set function timeout limits (5-10s max)",
      cwe: "CWE-400",
      confidence: 75,
    });
  }

  // --- Test file upload size limits ---
  const uploadEndpoints = target.apiEndpoints.filter((ep) =>
    /upload|file|attach|import|media/i.test(ep),
  );

  if (uploadEndpoints.length > 0) {
    const uploadChecks = uploadEndpoints.slice(0, 3).map(async (endpoint) => {
      const sizes = [1_000_000, 10_000_000, 50_000_000]; // 1MB, 10MB, 50MB
      let maxAccepted = 0;

      for (const size of sizes) {
        try {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/octet-stream",
              "Content-Length": String(size),
            },
            body: "x".repeat(Math.min(size, 1000)),
            timeoutMs: 10000,
          });
          if (res.status !== 413 && res.status < 500) {
            maxAccepted = size;
          } else {
            break;
          }
        } catch {
          break;
        }
      }
      return { endpoint, maxAccepted };
    });

    const uploadResults = await Promise.allSettled(uploadChecks);
    for (const r of uploadResults) {
      if (r.status !== "fulfilled") continue;
      const { endpoint, maxAccepted } = r.value;
      if (maxAccepted >= 10_000_000) {
        const storageCostPerGB = 0.023;
        const costPerUpload = (maxAccepted / 1_000_000_000) * storageCostPerGB;
        const costAt100rps = costPerUpload * 100 * 3600;

        findings.push({
          id: `cost-upload-limit-${findings.length}`,
          module: "Cost Attack",
          severity: maxAccepted >= 50_000_000 ? "high" : "medium",
          title: `Upload endpoint accepts large files (>${(maxAccepted / 1_000_000).toFixed(0)}MB): ${new URL(endpoint).pathname}`,
          description: `The upload endpoint did not reject a ${(maxAccepted / 1_000_000).toFixed(0)}MB Content-Length header. Without size limits, attackers can fill storage and rack up egress/storage costs.`,
          evidence: `Endpoint: ${endpoint}\nAccepted Content-Length: ${(maxAccepted / 1_000_000).toFixed(0)}MB\nNo 413 Payload Too Large response\nEstimated storage cost at scale: ~$${costAt100rps.toFixed(0)}/hour`,
          remediation: "1. Set Content-Length limits at the reverse proxy level (e.g., 5MB max)\n2. Validate file size server-side before persisting\n3. Add per-user upload quotas\n4. Use signed upload URLs with size constraints",
          cwe: "CWE-400",
          confidence: 70,
        });
      }
    }
  }

  // --- Test unbounded list/search endpoints (no max limit on results) ---
  const listEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(list|all|search|feed|posts|items|products|users|comments|transactions|orders|logs|events)\b/i.test(ep),
  ).slice(0, 6);

  if (listEndpoints.length > 0) {
    const unboundedChecks = listEndpoints.map(async (ep) => {
      const largeUrl = new URL(ep);
      largeUrl.searchParams.set("limit", "999999");
      largeUrl.searchParams.set("per_page", "999999");
      largeUrl.searchParams.set("page_size", "999999");

      const [largeRes, normalRes] = await Promise.allSettled([
        (async () => {
          const start = Date.now();
          const res = await scanFetch(largeUrl.toString(), { timeoutMs: 15000, noCache: true });
          const body = await res.text().catch(() => "");
          return { status: res.status, bodySize: body.length, elapsed: Date.now() - start };
        })(),
        (async () => {
          const start = Date.now();
          const res = await scanFetch(ep, { timeoutMs: 10000, noCache: true });
          const body = await res.text().catch(() => "");
          return { status: res.status, bodySize: body.length, elapsed: Date.now() - start };
        })(),
      ]);

      if (largeRes.status !== "fulfilled" || normalRes.status !== "fulfilled") return null;
      return { endpoint: ep, large: largeRes.value, normal: normalRes.value };
    });

    const unboundedResults = await Promise.allSettled(unboundedChecks);
    for (const r of unboundedResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const { endpoint, large, normal } = r.value;

      if (large.status >= 200 && large.status < 400 && normal.status >= 200) {
        const sizeRatio = large.bodySize / Math.max(normal.bodySize, 1);
        const timeRatio = large.elapsed / Math.max(normal.elapsed, 1);

        if ((sizeRatio > 3 && large.bodySize > 50000) || (timeRatio > 3 && large.elapsed > 3000)) {
          findings.push({
            id: `cost-unbounded-list-${findings.length}`,
            module: "Cost Attack",
            severity: large.bodySize > 500000 ? "high" : "medium",
            title: `Unbounded list endpoint: ${new URL(endpoint).pathname}`,
            description: `Setting limit=999999 caused the response to ${sizeRatio > 3 ? `grow ${sizeRatio.toFixed(0)}x (from ${normal.bodySize} to ${large.bodySize} bytes)` : `take ${timeRatio.toFixed(1)}x longer (from ${normal.elapsed}ms to ${large.elapsed}ms)`}. The endpoint does not enforce a maximum page size.`,
            evidence: `Endpoint: ${endpoint}\nNormal: ${normal.bodySize} bytes in ${normal.elapsed}ms\nWith limit=999999: ${large.bodySize} bytes in ${large.elapsed}ms`,
            remediation: "Enforce a server-side maximum page size (e.g., 100 items) regardless of client request. Implement cursor-based pagination.",
            codeSnippet: `// Enforce maximum page size server-side
const MAX_PAGE_SIZE = 100;
const limit = Math.min(Number(req.query.limit) || 20, MAX_PAGE_SIZE);
const cursor = req.query.cursor;

const items = await db.item.findMany({
  take: limit + 1,
  ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
});
const hasMore = items.length > limit;
return Response.json({
  items: items.slice(0, limit),
  nextCursor: hasMore ? items[limit - 1].id : null,
});`,
            cwe: "CWE-770",
            confidence: 75,
          });
        }
      }
    }
  }

  // --- Detect third-party API amplification ---
  for (const { name, pattern, costPerCall } of THIRD_PARTY_PATTERNS) {
    if (!pattern.test(allJs)) continue;

    const proxyEndpoints = target.apiEndpoints.filter((ep) => {
      const path = new URL(ep).pathname.toLowerCase();
      return (
        pattern.test(ep) ||
        /\/(webhook|callback|proxy|gateway)\b/i.test(path) ||
        (name === "Payment processor" && /\/(pay|charge|checkout|subscribe)\b/i.test(path)) ||
        (name === "SMS/voice API" && /\/(sms|call|verify|otp|send-code)\b/i.test(path)) ||
        (name === "Email API" && /\/(send|email|notify|invite|newsletter)\b/i.test(path)) ||
        (name === "Geocoding/Maps API" && /\/(geocode|location|address|directions)\b/i.test(path))
      );
    });

    if (proxyEndpoints.length === 0) continue;

    const amplification = name.includes("SMS") || name.includes("Email") ? 1 : 2;
    const rps = 100;
    const totalCostPerHour = costPerCall * amplification * rps * 3600;

    if (totalCostPerHour > 5) {
      findings.push({
        id: `cost-third-party-${findings.length}`,
        module: "Cost Attack",
        severity: totalCostPerHour > 100 ? "critical" : totalCostPerHour > 20 ? "high" : "medium",
        title: `Third-party cost amplification: $${totalCostPerHour.toFixed(0)}/hr via ${name}`,
        description: `Your app uses ${name} (detected in JS bundles). ${proxyEndpoints.length} endpoint(s) may trigger ${name} calls. Without rate limiting, an attacker at ${rps} req/sec could generate ~$${totalCostPerHour.toFixed(0)}/hour in third-party API costs.`,
        evidence: `Third-party: ${name}\nProxy endpoints: ${proxyEndpoints.map((e) => new URL(e).pathname).join(", ")}\nEst. cost per call: $${costPerCall}\nAmplification factor: ${amplification}x`,
        remediation: `1. Rate limit endpoints that trigger ${name} calls\n2. Set spending alerts on your ${name} account\n3. Add per-user daily limits for costly operations\n4. Use webhook signature verification to prevent abuse`,
        cwe: "CWE-400",
        confidence: 65,
      });
    }
  }

  // --- Test GraphQL query complexity limits ---
  const graphqlEndpoints = target.apiEndpoints.filter((ep) =>
    /graphql|gql/i.test(ep),
  );
  if (graphqlEndpoints.length === 0 && /graphql|__schema|__typename/i.test(allJs)) {
    graphqlEndpoints.push(`${target.baseUrl}/graphql`);
  }

  for (const endpoint of graphqlEndpoints.slice(0, 2)) {
    const deepQuery = `{ __schema { types { fields { type { fields { type { name } } } } } } }`;
    const wideQuery = `{ __schema { types { name kind description fields { name type { name kind ofType { name kind ofType { name } } } } } } }`;

    const gqlChecks = [
      { query: deepQuery, label: "deeply nested" },
      { query: wideQuery, label: "wide introspection" },
    ].map(async ({ query, label }) => {
      try {
        const start = Date.now();
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query }),
          timeoutMs: 10000,
          noCache: true,
        });
        const elapsed = Date.now() - start;
        const body = await res.text();
        return { label, status: res.status, elapsed, bodyLength: body.length, hasData: body.includes('"data"') };
      } catch {
        return null;
      }
    });

    const gqlResults = await Promise.allSettled(gqlChecks);
    for (const r of gqlResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const { label, status, elapsed, bodyLength, hasData } = r.value;
      if (status === 200 && hasData && bodyLength > 10000) {
        findings.push({
          id: `cost-graphql-complexity-${findings.length}`,
          module: "Cost Attack",
          severity: bodyLength > 100000 ? "high" : "medium",
          title: `GraphQL accepts ${label} queries without complexity limits`,
          description: `A ${label} GraphQL query returned ${(bodyLength / 1000).toFixed(0)}KB in ${elapsed}ms without being rejected. Without query complexity limits, attackers can craft queries that consume excessive server resources.`,
          evidence: `Endpoint: ${endpoint}\nQuery type: ${label}\nResponse size: ${(bodyLength / 1000).toFixed(0)}KB\nResponse time: ${elapsed}ms`,
          remediation: "1. Implement query complexity analysis (e.g., graphql-query-complexity)\n2. Set a max query depth limit (depth <= 5)\n3. Disable introspection in production\n4. Use persisted queries / allowlists",
          codeSnippet: `// graphql-query-complexity setup
import { createComplexityRule, simpleEstimator } from "graphql-query-complexity";

const server = new ApolloServer({
  validationRules: [
    createComplexityRule({
      maximumComplexity: 1000,
      estimators: [simpleEstimator({ defaultComplexity: 1 })],
      onComplete: (complexity) => {
        if (complexity > 500) console.warn("High complexity query:", complexity);
      },
    }),
  ],
});`,
          cwe: "CWE-400",
          confidence: 80,
        });
        break;
      }
    }
  }

  // --- Estimate total API abuse cost based on cloud pricing models ---
  if (estimates.length > 0 || slowEndpoints.length > 0) {
    const detectedPlatform = target.technologies.includes("Vercel") ? "Vercel"
      : target.technologies.includes("Netlify") ? "Netlify"
      : target.headers["cf-ray"] ? "Cloudflare"
      : /aws|lambda/i.test(allJs) ? "AWS Lambda"
      : target.technologies.includes("Supabase") ? "Supabase"
      : null;

    if (detectedPlatform) {
      let totalCostPerDay = estimates.reduce((sum, e) => sum + e.costPerDay, 0);
      for (const slow of slowEndpoints) {
        const gbS = (slow.elapsed / 1000) * 0.256;
        totalCostPerDay += gbS * (CLOUD_PRICING["vercel"] || 0.000018) * 50 * 86400;
      }

      if (totalCostPerDay > 100) {
        findings.push({
          id: "cost-abuse-estimate",
          module: "Cost Attack",
          severity: totalCostPerDay > 10000 ? "critical" : totalCostPerDay > 1000 ? "high" : "medium",
          title: `Estimated max abuse cost on ${detectedPlatform}: $${totalCostPerDay.toFixed(0)}/day`,
          description: `Based on detected services, endpoints, and ${detectedPlatform} pricing, an attacker could generate up to ~$${totalCostPerDay.toFixed(0)}/day in costs by abusing unprotected endpoints. This combines compute, API calls, egress, and third-party service costs.`,
          evidence: `Platform: ${detectedPlatform}\nDetected cost vectors: ${estimates.length}\nSlow endpoints (>2s): ${slowEndpoints.length}\nTotal estimated daily abuse cost: $${totalCostPerDay.toFixed(2)}\nTotal estimated monthly abuse cost: $${(totalCostPerDay * 30).toFixed(0)}`,
          remediation: `1. Set a hard spending cap on ${detectedPlatform}\n2. Configure billing alerts at 50%, 80%, and 100% of budget\n3. Implement per-IP and per-user rate limiting on all API endpoints\n4. Use Cloudflare or equivalent WAF to absorb volumetric attacks\n5. Create a runbook for emergency API key rotation and service shutoff`,
          cwe: "CWE-400",
          confidence: 55,
        });
      }
    }
  }

  // General serverless cost warning if no rate limiting was found
  if (target.technologies.includes("Vercel") || target.technologies.includes("Netlify")) {
    const hasAnyRateLimit = target.headers["x-ratelimit-limit"] ||
      target.headers["x-ratelimit-remaining"];

    if (!hasAnyRateLimit) {
      findings.push({
        id: "cost-serverless-no-limits",
        module: "Cost Attack",
        severity: "medium",
        title: "Serverless deployment with no apparent rate limiting",
        description: "Your app runs on serverless infrastructure with usage-based billing and shows no rate limiting headers. An attacker could intentionally run up your hosting bill by generating high traffic.",
        remediation: "1. Add rate limiting (Upstash, Vercel KV, or middleware-based)\n2. Set spending limits in your hosting dashboard\n3. Configure DDoS protection (Cloudflare free tier works)",
        codeSnippet: `// vercel.json — set spending and concurrency limits
{
  "functions": {
    "api/**": { "maxDuration": 10 }
  },
  "crons": [{
    "path": "/api/check-billing",
    "schedule": "0 * * * *"
  }]
}

// Also set a Spend Limit in Vercel Dashboard → Settings → Billing`,
        cwe: "CWE-400",
      });
    }
  }

  return findings;
};
