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

// Patterns for computationally expensive operations
const EXPENSIVE_ENDPOINT_PATTERNS = [
  { pattern: /\/(generate-pdf|pdf|export|report)\b/i, name: "PDF generation", costMultiplier: 5 },
  { pattern: /\/(resize|crop|thumbnail|optimize|watermark|convert)\b/i, name: "Image processing", costMultiplier: 3 },
  { pattern: /\/(transcode|encode|render|video)\b/i, name: "Video/media processing", costMultiplier: 10 },
  { pattern: /\/(ai|ml|predict|inference|embedding|classify|summarize|translate)\b/i, name: "AI/ML inference", costMultiplier: 8 },
  { pattern: /\/(search|fulltext|elasticsearch|algolia)\b/i, name: "Full-text search", costMultiplier: 2 },
  { pattern: /\/(aggregate|analytics|dashboard|metrics|stats)\b/i, name: "Data aggregation", costMultiplier: 3 },
  { pattern: /\/(compile|build|deploy|execute|run-code|sandbox)\b/i, name: "Code execution", costMultiplier: 10 },
  { pattern: /\/(ocr|parse-document|extract)\b/i, name: "Document parsing/OCR", costMultiplier: 4 },
];

interface ExpensiveEndpointResult {
  endpoint: string;
  elapsed: number;
  status: number;
  bodySize: number;
  pattern: RegExp;
  name: string;
  costMultiplier: number;
}

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

  // --- Detect computationally expensive endpoints ---
  const expensiveEndpointChecks = await Promise.allSettled(
    target.apiEndpoints.slice(0, 20).map(async (ep) => {
      const matched = EXPENSIVE_ENDPOINT_PATTERNS.find((p) => p.pattern.test(ep));
      if (!matched) return null;

      // Time the endpoint to estimate compute cost
      const start = Date.now();
      try {
        const res = await scanFetch(ep, { timeoutMs: 15000 });
        const elapsed = Date.now() - start;
        const bodySize = (await res.text().catch(() => "")).length;
        return { endpoint: ep, elapsed, status: res.status, bodySize, ...matched };
      } catch {
        return { endpoint: ep, elapsed: Date.now() - start, status: 0, bodySize: 0, ...matched };
      }
    }),
  );

  const expensiveResults: ExpensiveEndpointResult[] = expensiveEndpointChecks
    .filter((r) => r.status === "fulfilled" && r.value && r.value.status >= 200 && r.value.status < 500)
    .map((r) => (r as PromiseFulfilledResult<ExpensiveEndpointResult>).value)
    .filter(Boolean);

  // Group by operation type to avoid duplicate findings
  const expensiveByType: Record<string, ExpensiveEndpointResult[]> = {};
  for (const r of expensiveResults) {
    const existing = expensiveByType[r.name] || [];
    existing.push(r);
    expensiveByType[r.name] = existing;
  }

  for (const [opType, endpoints] of Object.entries(expensiveByType)) {
    const slowest = endpoints.reduce((a, b) => (a.elapsed > b.elapsed ? a : b));
    if (slowest.elapsed > 1000) {
      const costPerReq = slowest.costMultiplier * 0.000018 * (slowest.elapsed / 1000); // serverless cost model
      const rps = 50;
      findings.push({
        id: `cost-expensive-endpoint-${findings.length}`,
        module: "Cost Attack",
        severity: slowest.elapsed > 5000 ? "high" : "medium",
        title: `Expensive ${opType} endpoint: ${slowest.elapsed}ms per request`,
        description: `${endpoints.length} ${opType} endpoint(s) detected. The slowest (${new URL(slowest.endpoint).pathname}) takes ${slowest.elapsed}ms per request. At ${rps} req/sec, this would cost ~$${(costPerReq * rps * 3600).toFixed(0)}/hour in compute alone, and tie up server resources for legitimate users.`,
        evidence: `Endpoint: ${slowest.endpoint}\nResponse time: ${slowest.elapsed}ms\nOperation: ${opType}\nEndpoints found: ${endpoints.map((e) => new URL(e.endpoint).pathname).join(", ")}`,
        remediation: `1. Add aggressive rate limiting to ${opType} endpoints\n2. Use a job queue (Bull, Inngest) for async processing\n3. Set request timeouts and maximum input sizes\n4. Cache results where possible`,
        codeSnippet: `// Queue expensive work instead of processing inline
import { inngest } from "@/lib/inngest";

export async function POST(req: Request) {
  const { input } = await req.json();
  // Validate input size before queuing
  if (input.length > 10000) {
    return Response.json({ error: "Input too large" }, { status: 413 });
  }
  // Queue for async processing
  const { ids } = await inngest.send({
    name: "app/${opType.toLowerCase().replace(/\s+/g, ".")}.requested",
    data: { input, userId },
  });
  return Response.json({ jobId: ids[0], status: "processing" });
}`,
        cwe: "CWE-400",
        confidence: 70,
      });
    }
  }

  // --- API endpoint cost estimation based on response time * request rate ---
  const endpointTimings = await Promise.allSettled(
    target.apiEndpoints.slice(0, 15).map(async (ep) => {
      const times: number[] = [];
      for (let i = 0; i < 3; i++) {
        const start = Date.now();
        try {
          await scanFetch(ep, { timeoutMs: 8000, noCache: true });
          times.push(Date.now() - start);
        } catch {
          times.push(Date.now() - start);
        }
      }
      const avgMs = times.reduce((a, b) => a + b, 0) / times.length;
      return { endpoint: ep, avgMs };
    }),
  );

  const validTimings = endpointTimings
    .filter((r) => r.status === "fulfilled")
    .map((r) => (r as PromiseFulfilledResult<{ endpoint: string; avgMs: number }>).value)
    .sort((a, b) => b.avgMs - a.avgMs);

  if (validTimings.length >= 3) {
    const slowEndpoints = validTimings.filter((t) => t.avgMs > 2000);
    if (slowEndpoints.length > 0) {
      const costTable = slowEndpoints
        .slice(0, 5)
        .map((t) => {
          const costPerReq = 0.000018 * (t.avgMs / 1000); // serverless compute cost
          return `${new URL(t.endpoint).pathname}: ${Math.round(t.avgMs)}ms (~$${(costPerReq * 100 * 3600).toFixed(0)}/hr at 100 rps)`;
        })
        .join("\n");

      findings.push({
        id: "cost-slow-endpoint-ranking",
        module: "Cost Attack",
        severity: "medium",
        title: `${slowEndpoints.length} slow API endpoints identified as cost targets`,
        description: `These endpoints take >2 seconds to respond and are prime targets for cost-based attacks. An attacker would target the slowest endpoints to maximize compute costs per request.`,
        evidence: `Slow endpoints by response time:\n${costTable}`,
        remediation:
          "Add per-endpoint rate limiting weighted by response time. Slower endpoints should have stricter limits. Consider caching, pagination, and async processing for slow endpoints.",
        codeSnippet: `// Weighted rate limiting — slower endpoints get stricter limits
const RATE_LIMITS: Record<string, { requests: number; window: string }> = {
  "/api/generate-report": { requests: 5, window: "60 s" },   // slow endpoint
  "/api/search":          { requests: 30, window: "60 s" },  // medium endpoint
  "/api/user":            { requests: 100, window: "60 s" },  // fast endpoint
};

export async function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname;
  const limit = RATE_LIMITS[path] || { requests: 60, window: "60 s" };
  const { success } = await ratelimit.limit(\`\${getUserIp(req)}:\${path}\`);
  if (!success) return new Response("Rate limited", { status: 429 });
}`,
        cwe: "CWE-400",
        confidence: 75,
      });
    }
  }

  // --- Detect unbounded list endpoints (no pagination limit) ---
  const listEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(list|all|search|feed|posts|items|products|users|comments|transactions|orders|logs|events|notifications|messages)\b/i.test(ep),
  ).slice(0, 8);

  const unboundedChecks = await Promise.allSettled(
    listEndpoints.map(async (ep) => {
      // Try requesting with a very large limit parameter
      const largeUrl = new URL(ep);
      largeUrl.searchParams.set("limit", "999999");
      largeUrl.searchParams.set("per_page", "999999");
      largeUrl.searchParams.set("page_size", "999999");
      largeUrl.searchParams.set("count", "999999");

      const start = Date.now();
      try {
        const res = await scanFetch(largeUrl.toString(), { timeoutMs: 15000, noCache: true });
        const body = await res.text().catch(() => "");
        return {
          endpoint: ep,
          status: res.status,
          bodySize: body.length,
          elapsed: Date.now() - start,
          hasNextPage: /next_page|nextPage|has_more|hasMore|next_cursor|cursor/i.test(body),
        };
      } catch {
        return { endpoint: ep, status: 0, bodySize: 0, elapsed: Date.now() - start, hasNextPage: false };
      }
    }),
  );

  // Also fetch the same endpoints with no limit to compare
  const normalChecks = await Promise.allSettled(
    listEndpoints.map(async (ep) => {
      const start = Date.now();
      try {
        const res = await scanFetch(ep, { timeoutMs: 10000, noCache: true });
        const body = await res.text().catch(() => "");
        return { endpoint: ep, status: res.status, bodySize: body.length, elapsed: Date.now() - start };
      } catch {
        return { endpoint: ep, status: 0, bodySize: 0, elapsed: Date.now() - start };
      }
    }),
  );

  for (let i = 0; i < listEndpoints.length; i++) {
    const large = unboundedChecks[i];
    const normal = normalChecks[i];
    if (large.status !== "fulfilled" || normal.status !== "fulfilled") continue;

    const largeResult = large.value;
    const normalResult = normal.value;

    if (largeResult.status >= 200 && largeResult.status < 400 && normalResult.status >= 200) {
      // If the large limit response is significantly bigger, the endpoint accepts arbitrary limits
      const sizeRatio = largeResult.bodySize / Math.max(normalResult.bodySize, 1);
      const timeRatio = largeResult.elapsed / Math.max(normalResult.elapsed, 1);

      if ((sizeRatio > 3 && largeResult.bodySize > 50000) || (timeRatio > 3 && largeResult.elapsed > 3000)) {
        findings.push({
          id: `cost-unbounded-list-${findings.length}`,
          module: "Cost Attack",
          severity: largeResult.bodySize > 500000 ? "high" : "medium",
          title: `Unbounded list endpoint: ${new URL(largeResult.endpoint).pathname}`,
          description: `Setting limit=999999 caused the response to ${sizeRatio > 3 ? `grow ${sizeRatio.toFixed(0)}x (from ${normalResult.bodySize} to ${largeResult.bodySize} bytes)` : `take ${timeRatio.toFixed(1)}x longer (from ${normalResult.elapsed}ms to ${largeResult.elapsed}ms)`}. The endpoint does not enforce a maximum page size, allowing attackers to dump large datasets in a single request, causing high egress costs and memory pressure.`,
          evidence: `Endpoint: ${largeResult.endpoint}\nNormal: ${normalResult.bodySize} bytes in ${normalResult.elapsed}ms\nWith limit=999999: ${largeResult.bodySize} bytes in ${largeResult.elapsed}ms`,
          remediation:
            "Enforce a server-side maximum page size (e.g., 100 items) regardless of what the client requests. Implement cursor-based pagination instead of offset-based.",
          codeSnippet: `// Enforce maximum page size server-side
const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 20;

export async function GET(req: Request) {
  const url = new URL(req.url);
  const rawLimit = parseInt(url.searchParams.get("limit") || "");
  const limit = Math.min(
    Math.max(rawLimit || DEFAULT_PAGE_SIZE, 1),
    MAX_PAGE_SIZE // never exceed this
  );
  const cursor = url.searchParams.get("cursor");

  const items = await db.item.findMany({
    take: limit + 1, // fetch one extra to detect next page
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
  });

  const hasMore = items.length > limit;
  return Response.json({
    items: items.slice(0, limit),
    nextCursor: hasMore ? items[limit - 1].id : null,
  });
}`,
          cwe: "CWE-770",
          confidence: 75,
        });
      }
    }
  }

  // --- Third-party API cost amplification detection ---
  for (const { name, pattern, costPerCall } of THIRD_PARTY_PATTERNS) {
    if (!pattern.test(allJs)) continue;

    // Find endpoints that might proxy to this third-party service
    const proxyEndpoints = target.apiEndpoints.filter((ep) => {
      const path = new URL(ep).pathname.toLowerCase();
      return (
        // Direct matches
        pattern.test(ep) ||
        // Common proxy patterns
        /\/(webhook|callback|proxy|gateway)\b/i.test(path) ||
        // Service-specific patterns
        (name === "Payment processor" && /\/(pay|charge|checkout|subscribe|invoice)\b/i.test(path)) ||
        (name === "SMS/voice API" && /\/(sms|call|verify|otp|send-code)\b/i.test(path)) ||
        (name === "Email API" && /\/(send|email|notify|invite|newsletter)\b/i.test(path)) ||
        (name === "Geocoding/Maps API" && /\/(geocode|location|address|directions)\b/i.test(path))
      );
    });

    if (proxyEndpoints.length === 0) continue;

    // Estimate amplification: 1 user request might trigger N third-party calls
    const amplification = name.includes("SMS") || name.includes("Email") ? 1 : 2;
    const rps = 100;
    const totalCostPerHour = costPerCall * amplification * rps * 3600;

    if (totalCostPerHour > 5) {
      findings.push({
        id: `cost-third-party-${findings.length}`,
        module: "Cost Attack",
        severity: totalCostPerHour > 100 ? "critical" : totalCostPerHour > 20 ? "high" : "medium",
        title: `Third-party cost amplification: $${totalCostPerHour.toFixed(0)}/hr via ${name}`,
        description: `Your app uses ${name} (detected in JS bundles). ${proxyEndpoints.length} endpoint(s) may trigger ${name} calls. Without rate limiting, an attacker at ${rps} req/sec could generate ~$${totalCostPerHour.toFixed(0)}/hour in third-party API costs${amplification > 1 ? ` (estimated ${amplification}x amplification per request)` : ""}.`,
        evidence: `Third-party: ${name}\nProxy endpoints: ${proxyEndpoints.map((e) => new URL(e).pathname).join(", ")}\nEst. cost per call: $${costPerCall}\nAmplification factor: ${amplification}x`,
        remediation: `1. Rate limit endpoints that trigger ${name} calls\n2. Set spending alerts on your ${name} account\n3. Add per-user daily limits for operations that cost money\n4. Use webhook signature verification to prevent abuse`,
        codeSnippet: `// Per-user daily spending limit for third-party API calls
const DAILY_LIMIT = 50; // max calls per user per day
const key = \`third-party:\${userId}:\${new Date().toISOString().slice(0, 10)}\`;
const count = await redis.incr(key);
if (count === 1) await redis.expire(key, 86400);
if (count > DAILY_LIMIT) {
  return Response.json(
    { error: "Daily limit reached for this operation" },
    { status: 429 }
  );
}
// Proceed with ${name} API call...`,
        cwe: "CWE-400",
        confidence: 65,
      });
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
