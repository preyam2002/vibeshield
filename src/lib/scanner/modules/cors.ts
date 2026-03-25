import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const makeEvilOrigins = (targetHost: string) => {
  const parts = targetHost.split(".");
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join(".") : targetHost;
  return [
    "https://evil.com",
    "https://attacker.com",
    "null",
    `https://${targetHost}.evil.com`,       // subdomain of attacker (endsWith bypass)
    `https://evil${targetHost}`,            // prefix bypass (includes bypass)
    `https://${targetHost.replace(".", "")}.com`, // dot-stripping bypass
    `https://not${baseDomain}`,             // domain suffix bypass
    `http://${targetHost}`,                 // protocol downgrade
  ];
};

export const corsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const endpoints = [target.url, ...target.apiEndpoints.filter((ep) => !ep.includes("/.well-known/")).slice(0, 5)];
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
    // Test all endpoint+origin combos in parallel, take first match
    const reflectTests = await Promise.allSettled(
      endpoints.slice(0, 3).flatMap((endpoint) =>
        evilOrigins.map(async (origin) => {
          const res = await scanFetch(endpoint, { headers: { Origin: origin }, timeoutMs: 5000 });
          const acao = res.headers.get("access-control-allow-origin");
          if (acao !== origin) return null;
          return {
            endpoint,
            origin,
            acac: res.headers.get("access-control-allow-credentials"),
          };
        }),
      ),
    );
    for (const r of reflectTests) {
      if (r.status !== "fulfilled" || !r.value || reflectFound) continue;
      reflectFound = true;
      const { endpoint, origin, acac } = r.value;
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
        evidence: `Origin: ${origin}\nAccess-Control-Allow-Origin: ${origin}${withCreds ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        remediation: "Validate the Origin header against an exact whitelist of allowed domains.",
        cwe: "CWE-942",
        owasp: "A05:2021",
        codeSnippet: `// middleware.ts\nconst ALLOWED_ORIGINS = ["https://yourdomain.com"];\nconst origin = req.headers.get("origin") || "";\nif (ALLOWED_ORIGINS.includes(origin)) {\n  res.headers.set("Access-Control-Allow-Origin", origin);\n  res.headers.set("Vary", "Origin");\n}`,
      });
    }
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
        codeSnippet: `// Always include Vary: Origin when ACAO is dynamic\nres.headers.set("Vary", "Origin");`,
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
        codeSnippet: `// Only allow needed methods\nres.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");`,
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
        codeSnippet: `// Only allow specific headers\nres.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");`,
      });
    }
  }

  // Phase 4: Null origin and max-age checks
  const nullAndMaxAgeTests = await Promise.allSettled(
    endpoints.slice(0, 3).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { headers: { Origin: "null" }, timeoutMs: 5000 });
      return {
        endpoint,
        acao: res.headers.get("access-control-allow-origin"),
        acac: res.headers.get("access-control-allow-credentials"),
        maxAge: res.headers.get("access-control-max-age"),
      };
    }),
  );
  let nullFlagged = false;
  let maxAgeFlagged = false;
  for (const r of nullAndMaxAgeTests) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, acao, acac, maxAge } = r.value;
    if (acao === "null" && !nullFlagged && !reflectFound) {
      nullFlagged = true;
      findings.push({
        id: `cors-null-origin-${findings.length}`,
        module: "CORS",
        severity: acac === "true" ? "critical" : "high",
        title: `CORS accepts null Origin${acac === "true" ? " with credentials" : ""} on ${new URL(endpoint).pathname}`,
        description: `The server trusts the "null" Origin. Sandboxed iframes, data: URIs, and file:// pages send Origin: null — an attacker can use these to bypass CORS and ${acac === "true" ? "make authenticated requests stealing user data" : "read API responses"}.`,
        evidence: `Origin: null\nAccess-Control-Allow-Origin: null${acac === "true" ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        remediation: 'Never allow "null" as an origin. Use a strict allowlist of specific https:// origins.',
        cwe: "CWE-942", owasp: "A05:2021",
        codeSnippet: `// Reject null origin explicitly\nconst origin = req.headers.get("origin") || "";\nif (origin === "null" || !ALLOWED_ORIGINS.includes(origin)) {\n  // Do not set ACAO header — deny the cross-origin request\n  return res;\n}`,
      });
    }
    if (maxAge && parseInt(maxAge) > 86400 && !maxAgeFlagged) {
      maxAgeFlagged = true;
      findings.push({
        id: `cors-max-age-${findings.length}`,
        module: "CORS",
        severity: "low",
        title: `CORS preflight cached for ${Math.round(parseInt(maxAge) / 3600)}h on ${new URL(endpoint).pathname}`,
        description: `Access-Control-Max-Age is set to ${maxAge} seconds (${Math.round(parseInt(maxAge) / 3600)} hours). Overly long preflight caching means CORS policy changes won't take effect for browsers that cached the old preflight.`,
        evidence: `Access-Control-Max-Age: ${maxAge}`,
        remediation: "Set Access-Control-Max-Age to 3600 (1 hour) or less for reasonable cache freshness.",
        cwe: "CWE-942",
        codeSnippet: `// Reasonable preflight cache duration\nres.headers.set("Access-Control-Max-Age", "3600"); // 1 hour`,
      });
    }
  }

  // Phase 5: Check for overly permissive Access-Control-Expose-Headers
  const exposeTests = await Promise.allSettled(
    endpoints.slice(0, 3).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { headers: { Origin: `https://${targetHost}` } });
      return {
        endpoint,
        expose: res.headers.get("access-control-expose-headers") || "",
      };
    }),
  );
  let exposeFlagged = false;
  for (const r of exposeTests) {
    if (r.status !== "fulfilled" || exposeFlagged) continue;
    const { endpoint, expose } = r.value;
    if (expose === "*") {
      exposeFlagged = true;
      findings.push({
        id: `cors-expose-wildcard-${findings.length}`,
        module: "CORS",
        severity: "low",
        title: `CORS exposes all response headers on ${new URL(endpoint).pathname}`,
        description: "Access-Control-Expose-Headers: * allows cross-origin JavaScript to read any response header, potentially leaking internal headers like X-Request-Id, X-RateLimit-Remaining, or custom auth headers.",
        evidence: `Access-Control-Expose-Headers: *`,
        remediation: "Only expose the specific response headers that cross-origin clients need.",
        cwe: "CWE-942",
        codeSnippet: `// Only expose specific headers\nres.headers.set("Access-Control-Expose-Headers", "Content-Length, X-Request-Id");`,
      });
    }
  }

  return findings;
};
