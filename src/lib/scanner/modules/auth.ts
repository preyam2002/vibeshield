import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

const SENSITIVE_PATTERNS = [
  /email/i, /password/i, /phone/i, /address/i, /ssn/i,
  /credit.?card/i, /token/i, /secret/i, /key/i, /balance/i,
  /salary/i, /payment/i, /bank/i, /account/i,
];

const ADMIN_PATHS = [
  "/admin", "/admin/", "/dashboard/admin", "/api/admin",
  "/api/admin/users", "/admin/dashboard", "/admin/settings",
  "/manage", "/management", "/internal", "/backstage",
  "/debug", "/debug/", "/_debug", "/api/debug",
  "/phpinfo.php", "/server-status", "/server-info",
];

export const authModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Test API endpoints without authentication
  for (const endpoint of target.apiEndpoints) {
    try {
      const res = await scanFetch(endpoint);
      if (!res.ok) continue;

      const contentType = res.headers.get("content-type") || "";
      if (!contentType.includes("json")) continue;

      const text = await res.text();
      if (text.length < 5) continue;

      let data: unknown;
      try { data = JSON.parse(text); } catch { continue; }

      // Check if response contains sensitive-looking data
      const hasSensitive = SENSITIVE_PATTERNS.some((p) => p.test(text));
      const isArray = Array.isArray(data);
      const itemCount = isArray ? (data as unknown[]).length : 0;

      if (hasSensitive || itemCount > 1) {
        findings.push({
          id: `auth-no-auth-${findings.length}`,
          module: "Authentication",
          severity: hasSensitive ? "critical" : "high",
          title: `Unauthenticated access to ${new URL(endpoint).pathname}`,
          description: isArray
            ? `This endpoint returns ${itemCount} records without any authentication.${hasSensitive ? " Response contains sensitive-looking fields (email, password, etc.)." : ""}`
            : `This endpoint returns data without authentication.${hasSensitive ? " Response contains sensitive-looking fields." : ""}`,
          evidence: `GET ${endpoint}\nStatus: 200\n${isArray ? `Records: ${itemCount}\n` : ""}Response preview: ${text.substring(0, 300)}...`,
          remediation: "Add authentication middleware to this endpoint. Verify the user's identity before returning data.",
          cwe: "CWE-306",
          owasp: "A07:2021",
        });
      }
    } catch {
      // skip
    }
  }

  // Test admin paths
  for (const path of ADMIN_PATHS) {
    try {
      const url = target.baseUrl + path;
      const res = await scanFetch(url);
      if (res.status === 200) {
        const text = await res.text();
        // Skip if this is a SPA returning its shell for any route
        if (isSoft404(text, target)) continue;
        // Check if it looks like an actual admin page, not just a redirect or 404 page
        const looksAdmin = /admin|dashboard|manage|settings|configuration/i.test(text) &&
          !/login|sign.?in|unauthorized/i.test(text.substring(0, 2000));
        if (looksAdmin) {
          findings.push({
            id: `auth-admin-exposed-${findings.length}`,
            module: "Authentication",
            severity: "critical",
            title: `Admin panel accessible without authentication: ${path}`,
            description: "An administrative interface is accessible without any authentication. Anyone who discovers this URL has full admin access.",
            evidence: `GET ${url}\nStatus: 200\nPage appears to be an admin interface`,
            remediation: "Protect admin routes with authentication and authorization checks. Consider IP allowlisting.",
            cwe: "CWE-306",
            owasp: "A07:2021",
          });
        }
      }
    } catch {
      // skip
    }
  }

  // Test API endpoints with different HTTP methods
  for (const endpoint of target.apiEndpoints.slice(0, 10)) {
    // Get baseline GET response for comparison
    let baselineBody = "";
    let baselineStatus = 0;
    try {
      const baseRes = await scanFetch(endpoint);
      baselineStatus = baseRes.status;
      baselineBody = await baseRes.text();
    } catch { /* skip */ }

    for (const method of ["PUT", "PATCH", "DELETE"]) {
      try {
        const res = await scanFetch(endpoint, { method });
        // A 200/204 on DELETE/PUT without auth is very bad
        if (res.status === 200 || res.status === 204) {
          const text = await res.text();
          // Skip if response is SPA shell HTML (soft 404)
          if (looksLikeHtml(text) && isSoft404(text, target)) continue;
          // Skip if response is just the SPA returning HTML for a non-HTML endpoint
          if (looksLikeHtml(text) && target.isSpa) continue;
          // Skip empty or near-empty responses — likely just a permissive server/CDN, not real processing
          if (text.length < 5) continue;
          // Skip if response is identical to GET baseline — method is being ignored, not processed
          if (text === baselineBody && res.status === baselineStatus) continue;
          findings.push({
            id: `auth-method-${method.toLowerCase()}-${findings.length}`,
            module: "Authentication",
            severity: "high",
            title: `${method} allowed without auth on ${new URL(endpoint).pathname}`,
            description: `The ${method} method returns a success status (${res.status}) without authentication. This may allow unauthenticated data modification or deletion.`,
            evidence: `${method} ${endpoint}\nStatus: ${res.status}\nResponse: ${text.substring(0, 200)}`,
            remediation: `Add authentication checks for ${method} requests on this endpoint.`,
            cwe: "CWE-306",
            owasp: "A07:2021",
          });
        }
      } catch {
        // skip
      }
    }
  }

  return findings;
};
