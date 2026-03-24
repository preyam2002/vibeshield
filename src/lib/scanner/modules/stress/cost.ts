import type { ScanModule, Finding } from "../../types";

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

  // Detect Supabase
  if (target.technologies.includes("Supabase")) {
    // Supabase Pro: $25/mo + $0.09/GB egress beyond 50GB
    // A sustained read attack can exhaust egress quickly
    estimates.push({
      service: "Supabase",
      endpoint: "Database egress",
      costPerRequest: 0.0001, // ~100 bytes per response
      costPerHour: 100 * 3600 * 0.000000009, // rough egress
      costPerDay: 0,
      requestRate: 100,
    });
  }

  // Report findings for expensive attack vectors
  for (const est of estimates) {
    if (est.costPerHour > 1) { // More than $1/hour of damage
      findings.push({
        id: `cost-attack-${findings.length}`,
        module: "Cost Attack",
        severity: est.costPerHour > 100 ? "critical" : est.costPerHour > 10 ? "high" : "medium",
        title: `Cost attack vector: $${est.costPerHour.toFixed(0)}/hour via ${est.service}`,
        description: `Without rate limiting, an attacker hitting ${new URL(est.endpoint).pathname} at ${est.requestRate} req/sec could cost you:\n• ~$${est.costPerHour.toFixed(0)}/hour\n• ~$${est.costPerDay.toFixed(0)}/day\nThis is a "wallet drain" attack — the attacker doesn't need to take your app down, just run up your bill.`,
        evidence: `Service: ${est.service}\nEndpoint: ${est.endpoint}\nEst. cost per request: $${est.costPerRequest.toFixed(6)}\nAt ${est.requestRate} req/sec: $${est.costPerHour.toFixed(2)}/hour`,
        remediation: `1. Add rate limiting to ${new URL(est.endpoint).pathname}\n2. Set billing alerts and hard spending caps on ${est.service}\n3. Add API key rotation capability for emergency shutoff\n4. Consider Cloudflare or similar DDoS protection`,
        cwe: "CWE-400",
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
        cwe: "CWE-400",
      });
    }
  }

  return findings;
};
