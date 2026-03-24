import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const EVIL_ORIGINS = [
  "https://evil.com",
  "https://attacker.com",
  "null",
];

export const corsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const endpoints = [target.url, ...target.apiEndpoints.slice(0, 10)];

  for (const endpoint of endpoints) {
    // Test wildcard CORS
    try {
      const res = await scanFetch(endpoint, {
        headers: { Origin: "https://evil.com" },
      });
      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");

      if (acao === "*") {
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

      // Test if it reflects the origin
      for (const origin of EVIL_ORIGINS) {
        const res2 = await scanFetch(endpoint, {
          headers: { Origin: origin },
        });
        const acao2 = res2.headers.get("access-control-allow-origin");
        if (acao2 === origin) {
          findings.push({
            id: `cors-reflect-${findings.length}`,
            module: "CORS",
            severity: "high",
            title: `CORS reflects arbitrary Origin on ${new URL(endpoint).pathname}`,
            description: `This endpoint echoes back whatever Origin is sent, including "${origin}". Any website can make cross-origin requests and read responses.`,
            evidence: `Origin: ${origin}\nAccess-Control-Allow-Origin: ${acao2}`,
            remediation: "Validate the Origin header against a whitelist of allowed domains.",
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
    } catch {
      // skip
    }
  }

  return findings;
};
