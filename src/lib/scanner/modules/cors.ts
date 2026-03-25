import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const makeEvilOrigins = (targetHost: string) => [
  "https://evil.com",
  "https://attacker.com",
  "null",
  `https://${targetHost}.evil.com`,
  `https://evil${targetHost}`,
  `https://${targetHost.replace(".", "")}.com`,
];

export const corsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const endpoints = [target.url, ...target.apiEndpoints.filter((ep) => !ep.includes("/.well-known/")).slice(0, 10)];
  const targetHost = new URL(target.url).hostname;
  const evilOrigins = makeEvilOrigins(targetHost);
  let wildcardFound = false;
  let reflectFound = false;

  // Phase 1: Test all endpoints for wildcard/reflect in parallel
  const phase1 = await Promise.allSettled(
    endpoints.map(async (endpoint) => {
      const res = await scanFetch(endpoint, { headers: { Origin: "https://evil.com" } });
      return {
        endpoint,
        acao: res.headers.get("access-control-allow-origin"),
        acac: res.headers.get("access-control-allow-credentials"),
      };
    }),
  );

  for (const r of phase1) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, acao, acac } = r.value;

    if (acao === "*" && !wildcardFound) {
      wildcardFound = true;
      findings.push({
        id: `cors-wildcard-${findings.length}`,
        module: "CORS",
        severity: acac === "true" ? "critical" : "medium",
        title: `Wildcard CORS on ${new URL(endpoint).pathname}`,
        description: acac === "true"
          ? "This endpoint allows ANY origin with credentials. Any website can make authenticated requests to this endpoint and read the response — this is a full CORS bypass."
          : "This endpoint allows requests from any origin. While credentials aren't shared, data from this endpoint is readable by any website.",
        evidence: `Access-Control-Allow-Origin: *${acac ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        remediation: "Set Access-Control-Allow-Origin to your specific domain instead of *.",
        cwe: "CWE-942",
        owasp: "A05:2021",
        codeSnippet: `// middleware.ts or API route\nres.headers.set("Access-Control-Allow-Origin", "https://yourdomain.com");\nres.headers.set("Vary", "Origin");`,
      });
    }
  }

  // Phase 2: Test origin reflection with evil origins (only if no wildcard found)
  if (!wildcardFound) {
    // Test first 5 endpoints in parallel, each with all evil origins
    const reflectTests = endpoints.slice(0, 5).map(async (endpoint) => {
      if (reflectFound) return;
      for (const origin of evilOrigins) {
        if (reflectFound) break;
        try {
          const res = await scanFetch(endpoint, { headers: { Origin: origin } });
          const acao = res.headers.get("access-control-allow-origin");
          if (acao === origin) {
            reflectFound = true;
            const acac = res.headers.get("access-control-allow-credentials");
            const withCreds = acac === "true";
            const isSubdomainBypass = origin.includes(targetHost) && origin !== `https://${targetHost}`;
            findings.push({
              id: `cors-reflect-${findings.length}`,
              module: "CORS",
              severity: withCreds ? "critical" : "high",
              title: `CORS reflects ${isSubdomainBypass ? "subdomain-spoofed " : ""}Origin${withCreds ? " with credentials" : ""} on ${new URL(endpoint).pathname}`,
              description: withCreds
                ? `This endpoint echoes back any Origin AND allows credentials. Any website can make fully authenticated requests and steal user data.`
                : isSubdomainBypass
                  ? `This endpoint trusts origins containing "${targetHost}" (like ${origin}). An attacker can register a domain matching this pattern.`
                  : `This endpoint echoes back whatever Origin is sent, including "${origin}". Any website can read responses.`,
              evidence: `Origin: ${origin}\nAccess-Control-Allow-Origin: ${acao}${withCreds ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
              remediation: "Validate the Origin header against an exact whitelist of allowed domains.",
              cwe: "CWE-942",
              owasp: "A05:2021",
              codeSnippet: `// middleware.ts\nconst ALLOWED_ORIGINS = ["https://yourdomain.com"];\nconst origin = req.headers.get("origin") || "";\nif (ALLOWED_ORIGINS.includes(origin)) {\n  res.headers.set("Access-Control-Allow-Origin", origin);\n  res.headers.set("Vary", "Origin");\n}`,
            });
            break;
          }
        } catch { /* skip */ }
      }
    });
    await Promise.allSettled(reflectTests);
  }

  // Phase 3: Vary: Origin check + preflight (parallel)
  const [varyResults, preflightResults] = await Promise.all([
    Promise.allSettled(
      endpoints.slice(0, 5).map(async (endpoint) => {
        const res = await scanFetch(endpoint, { headers: { Origin: `https://${targetHost}` } });
        return {
          endpoint,
          acao: res.headers.get("access-control-allow-origin"),
          vary: res.headers.get("vary") || "",
        };
      }),
    ),
    Promise.allSettled(
      target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
        const res = await scanFetch(endpoint, {
          method: "OPTIONS",
          headers: {
            Origin: "https://evil.com",
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "Authorization",
          },
        });
        return {
          endpoint,
          methods: res.headers.get("access-control-allow-methods") || "",
          allowHeaders: res.headers.get("access-control-allow-headers") || "",
        };
      }),
    ),
  ]);

  let varyFlagged = false;
  for (const r of varyResults) {
    if (r.status !== "fulfilled" || varyFlagged) continue;
    const { endpoint, acao, vary } = r.value;
    if (acao && acao !== "*" && !/\borigin\b/i.test(vary)) {
      varyFlagged = true;
      findings.push({
        id: `cors-no-vary-${findings.length}`,
        module: "CORS",
        severity: "low",
        title: `CORS response missing Vary: Origin on ${new URL(endpoint).pathname}`,
        description: "The server returns a dynamic Access-Control-Allow-Origin but doesn't include Vary: Origin. This allows CDN/proxy cache poisoning.",
        evidence: `Access-Control-Allow-Origin: ${acao}\nVary: ${vary || "(not set)"}`,
        remediation: "Add Vary: Origin to responses with dynamic ACAO headers.",
        cwe: "CWE-942",
      });
    }
  }

  for (const r of preflightResults) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, methods, allowHeaders } = r.value;
    if (/DELETE|PUT|PATCH/i.test(methods)) {
      findings.push({
        id: `cors-dangerous-methods-${findings.length}`,
        module: "CORS",
        severity: "medium",
        title: `CORS allows dangerous methods on ${new URL(endpoint).pathname}`,
        description: `Preflight response allows ${methods}. Cross-origin sites may be able to modify or delete data.`,
        evidence: `Access-Control-Allow-Methods: ${methods}`,
        remediation: "Only allow the HTTP methods that are actually needed.",
        cwe: "CWE-942",
      });
    }
    if (allowHeaders === "*") {
      findings.push({
        id: `cors-wildcard-headers-${findings.length}`,
        module: "CORS",
        severity: "medium",
        title: `CORS allows any request header on ${new URL(endpoint).pathname}`,
        description: "Preflight response allows all request headers via wildcard, permitting cross-origin requests with arbitrary headers.",
        evidence: `Access-Control-Allow-Headers: *`,
        remediation: "Restrict to specific required headers.",
        cwe: "CWE-942",
      });
    }
  }

  return findings;
};
