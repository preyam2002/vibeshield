import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const DANGEROUS_METHODS = ["TRACE", "TRACK", "DEBUG", "CONNECT"];

export const httpMethodsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const endpoints = [target.url, ...target.apiEndpoints.slice(0, 5)];

  for (const endpoint of endpoints) {
    // Test OPTIONS to see allowed methods
    try {
      const res = await scanFetch(endpoint, { method: "OPTIONS", timeoutMs: 5000 });
      const allow = res.headers.get("allow") || res.headers.get("access-control-allow-methods") || "";

      for (const method of DANGEROUS_METHODS) {
        if (allow.toUpperCase().includes(method)) {
          findings.push({
            id: `http-methods-${method.toLowerCase()}-${findings.length}`,
            module: "HTTP Methods",
            severity: method === "TRACE" ? "medium" : "low",
            title: `Dangerous HTTP method ${method} allowed on ${new URL(endpoint).pathname}`,
            description: method === "TRACE"
              ? "TRACE method is enabled. Attackers can use Cross-Site Tracing (XST) to steal credentials from HTTP headers."
              : `The ${method} method is enabled. This can reveal debug information or be used for attacks.`,
            evidence: `OPTIONS ${endpoint}\nAllow: ${allow}`,
            remediation: `Disable the ${method} method in your web server configuration.`,
            cwe: "CWE-749",
          });
        }
      }
    } catch {
      // skip
    }

    // Actually test TRACE
    try {
      const res = await scanFetch(endpoint, { method: "TRACE", timeoutMs: 5000 });
      if (res.ok) {
        findings.push({
          id: `http-methods-trace-active-${findings.length}`,
          module: "HTTP Methods",
          severity: "medium",
          title: `TRACE method active on ${new URL(endpoint).pathname}`,
          description: "TRACE method returns 200 OK. Can be used for Cross-Site Tracing attacks.",
          evidence: `TRACE ${endpoint} → ${res.status}`,
          remediation: "Disable TRACE in your web server.",
          cwe: "CWE-749",
        });
      }
    } catch {
      // skip
    }
  }

  return findings;
};
