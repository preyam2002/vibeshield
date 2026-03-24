import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const makeEvilOrigins = (targetHost: string) => [
  "https://evil.com",
  "https://attacker.com",
  "null",
  `https://${targetHost}.evil.com`,         // subdomain of attacker containing target
  `https://evil${targetHost}`,              // prefix attack
  `https://${targetHost.replace(".", "")}.com`, // domain without dot
];

export const corsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const endpoints = [target.url, ...target.apiEndpoints.filter((ep) => !ep.includes("/.well-known/")).slice(0, 10)];
  const targetHost = new URL(target.url).hostname;
  const evilOrigins = makeEvilOrigins(targetHost);
  let wildcardFound = false;
  let reflectFound = false;

  for (const endpoint of endpoints) {
    try {
      const res = await scanFetch(endpoint, {
        headers: { Origin: "https://evil.com" },
      });
      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");

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
        });
        continue;
      }

      // Test if it reflects the origin (including subdomain/prefix bypasses)
      if (reflectFound) continue;
      for (const origin of evilOrigins) {
        const res2 = await scanFetch(endpoint, {
          headers: { Origin: origin },
        });
        const acao2 = res2.headers.get("access-control-allow-origin");
        if (acao2 === origin) {
          reflectFound = true;
          const acac2 = res2.headers.get("access-control-allow-credentials");
          const withCreds = acac2 === "true";
          const isSubdomainBypass = origin.includes(targetHost) && origin !== `https://${targetHost}`;
          findings.push({
            id: `cors-reflect-${findings.length}`,
            module: "CORS",
            severity: withCreds ? "critical" : "high",
            title: `CORS reflects ${isSubdomainBypass ? "subdomain-spoofed " : ""}Origin${withCreds ? " with credentials" : ""} on ${new URL(endpoint).pathname}`,
            description: withCreds
              ? `This endpoint echoes back any Origin AND allows credentials. Any website can make fully authenticated requests and steal user data — this is a full CORS bypass.`
              : isSubdomainBypass
                ? `This endpoint trusts origins containing "${targetHost}" (like ${origin}). An attacker can register a domain matching this pattern to bypass CORS.`
                : `This endpoint echoes back whatever Origin is sent, including "${origin}". Any website can make cross-origin requests and read responses.`,
            evidence: `Origin: ${origin}\nAccess-Control-Allow-Origin: ${acao2}${withCreds ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
            remediation: "Validate the Origin header against an exact whitelist of allowed domains. Do not use substring/contains matching.",
            cwe: "CWE-942",
            owasp: "A05:2021",
          });
          break;
        }
      }
    } catch {
      // skip unreachable endpoints
    }
  }

  // Check for missing Vary: Origin (cache poisoning risk)
  for (const endpoint of endpoints.slice(0, 5)) {
    try {
      const res = await scanFetch(endpoint, { headers: { Origin: `https://${targetHost}` } });
      const acao = res.headers.get("access-control-allow-origin");
      if (acao && acao !== "*") {
        const vary = res.headers.get("vary") || "";
        if (!/\borigin\b/i.test(vary)) {
          findings.push({
            id: `cors-no-vary-${findings.length}`,
            module: "CORS",
            severity: "low",
            title: `CORS response missing Vary: Origin on ${new URL(endpoint).pathname}`,
            description: "The server returns a dynamic Access-Control-Allow-Origin header but doesn't include Vary: Origin. This allows CDN/proxy cache poisoning — a cached response for one origin could be served to another.",
            evidence: `Access-Control-Allow-Origin: ${acao}\nVary: ${vary || "(not set)"}`,
            remediation: "Add Vary: Origin to responses that set dynamic Access-Control-Allow-Origin headers.",
            cwe: "CWE-942",
          });
          break;
        }
      }
    } catch { /* skip */ }
  }

  // Test preflight for dangerous methods
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    try {
      const res = await scanFetch(endpoint, {
        method: "OPTIONS",
        headers: {
          Origin: "https://evil.com",
          "Access-Control-Request-Method": "DELETE",
          "Access-Control-Request-Headers": "Authorization",
        },
      });
      const methods = res.headers.get("access-control-allow-methods") || "";
      const allowHeaders = res.headers.get("access-control-allow-headers") || "";
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
          description: "Preflight response allows all request headers via wildcard. This permits cross-origin requests with arbitrary headers including Authorization.",
          evidence: `Access-Control-Allow-Headers: *`,
          remediation: "Restrict Access-Control-Allow-Headers to specific required headers.",
          cwe: "CWE-942",
        });
      }
    } catch {
      // skip
    }
  }

  return findings;
};
