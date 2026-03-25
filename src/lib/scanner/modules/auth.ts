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

  const publicPatterns = /webhook|callback|health|status|ping|csp-report|cron|sitemap|feed|rss|\.well-known|auth\/signin|auth\/signup|auth\/login|auth\/register|auth\/providers|auth\/csrf|stripe|chilipiper|calendly|hubspot|intercom|zendesk|crisp|drift|segment|analytics|tracking|pixel|beacon/i;

  // Run all 4 test categories in parallel
  const [unauthResults, adminResults, tokenResults, methodResults] = await Promise.all([
    // 1. Unauthenticated API access
    Promise.allSettled(
      target.apiEndpoints.map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        if (publicPatterns.test(pathname)) return null;

        const res = await scanFetch(endpoint, { timeoutMs: 5000 });
        if (!res.ok) return null;

        const contentType = res.headers.get("content-type") || "";
        if (!contentType.includes("json")) return null;

        const text = await res.text();
        if (text.length < 5) return null;

        let data: unknown;
        try { data = JSON.parse(text); } catch { return null; }

        const hasSensitive = SENSITIVE_PATTERNS.some((p) => {
          const keyPattern = new RegExp(`"[^"]*${p.source}[^"]*"\\s*:\\s*"([^"]*)"`, "i");
          const match = text.match(keyPattern);
          if (!match) return false;
          const value = match[1];
          if (!value || value === "null" || value === "undefined" || value.length < 3) return false;
          return true;
        });
        const isArray = Array.isArray(data);
        const itemCount = isArray ? (data as unknown[]).length : 0;

        if ((hasSensitive && text.length > 50) || itemCount > 5) {
          return { pathname, endpoint, hasSensitive, isArray, itemCount, text };
        }
        return null;
      }),
    ),

    // 2. Admin paths
    Promise.allSettled(
      ADMIN_PATHS.map(async (path) => {
        const url = target.baseUrl + path;
        const res = await scanFetch(url, { timeoutMs: 5000 });
        if (res.status !== 200) return null;

        const text = await res.text();
        if (isSoft404(text, target)) return null;
        if (looksLikeHtml(text) && target.isSpa) return null;

        if (looksLikeHtml(text)) {
          const hasAdminUI = (/(<table|<form|<input|data-admin|admin-panel)/i.test(text)) &&
            (/<title[^>]*>.*(?:admin|dashboard|manage|panel)/i.test(text)) &&
            !/login|sign.?in|unauthorized|403|forbidden/i.test(text);
          if (!hasAdminUI) return null;
        }

        if (!looksLikeHtml(text)) {
          if (text.length < 20) return null;
          if (!/users|config|settings|permissions|roles/i.test(text)) return null;
        }

        return { path, url, text };
      }),
    ),

    // 3. Weak token validation
    Promise.allSettled(
      target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        if (publicPatterns.test(pathname)) return null;

        const noAuthRes = await scanFetch(endpoint, { timeoutMs: 5000 });
        if (noAuthRes.status !== 401 && noAuthRes.status !== 403) return null;

        const invalidRes = await scanFetch(endpoint, {
          headers: { Authorization: "Bearer invalid-token-vibeshield-test" },
          timeoutMs: 5000,
        });
        if (invalidRes.ok) {
          const text = await invalidRes.text();
          if (looksLikeHtml(text) && isSoft404(text, target)) return null;
          if (text.length < 10) return null;
          return { pathname, noAuthStatus: noAuthRes.status, invalidStatus: invalidRes.status, text };
        }
        return null;
      }),
    ),

    // 4. HTTP method testing — parallelize all endpoint+method combos
    (async () => {
      const combos: { endpoint: string; method: string }[] = [];
      for (const endpoint of target.apiEndpoints.slice(0, 10)) {
        for (const method of ["PUT", "PATCH", "DELETE"]) {
          combos.push({ endpoint, method });
        }
      }

      // Get baselines in parallel first
      const baselineResults = await Promise.allSettled(
        target.apiEndpoints.slice(0, 10).map(async (endpoint) => {
          const res = await scanFetch(endpoint, { timeoutMs: 5000 });
          return { endpoint, status: res.status, body: await res.text() };
        }),
      );
      const baselines = new Map<string, { status: number; body: string }>();
      for (const r of baselineResults) {
        if (r.status === "fulfilled") baselines.set(r.value.endpoint, { status: r.value.status, body: r.value.body });
      }

      return Promise.allSettled(
        combos.map(async ({ endpoint, method }) => {
          const res = await scanFetch(endpoint, { method, timeoutMs: 5000 });
          if (res.status !== 200 && res.status !== 204) return null;

          const text = await res.text();
          if (looksLikeHtml(text) && isSoft404(text, target)) return null;
          if (looksLikeHtml(text) && target.isSpa) return null;
          if (text.length < 5) return null;

          const baseline = baselines.get(endpoint);
          if (baseline && text === baseline.body && res.status === baseline.status) return null;

          return { endpoint, method, status: res.status, text };
        }),
      );
    })(),
  ]);

  // Collect unauthenticated access findings (max 3)
  for (const r of unauthResults) {
    if (findings.length >= 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { pathname, endpoint, hasSensitive, isArray, itemCount, text } = r.value;
    findings.push({
      id: `auth-no-auth-${findings.length}`,
      module: "Authentication",
      severity: hasSensitive ? "critical" : "high",
      title: `Unauthenticated access to ${pathname}`,
      description: isArray
        ? `This endpoint returns ${itemCount} records without any authentication.${hasSensitive ? " Response contains sensitive-looking fields (email, password, etc.)." : ""}`
        : `This endpoint returns data without authentication.${hasSensitive ? " Response contains sensitive-looking fields." : ""}`,
      evidence: `GET ${endpoint}\nStatus: 200\n${isArray ? `Records: ${itemCount}\n` : ""}Response preview: ${text.substring(0, 300)}...`,
      remediation: "Add authentication middleware to this endpoint. Verify the user's identity before returning data.",
      cwe: "CWE-306",
      owasp: "A07:2021",
    });
  }

  // Collect admin path findings (max 2)
  let adminCount = 0;
  for (const r of adminResults) {
    if (adminCount >= 2) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, url, text } = r.value;
    adminCount++;
    findings.push({
      id: `auth-admin-exposed-${findings.length}`,
      module: "Authentication",
      severity: "critical",
      title: `Admin panel accessible without authentication: ${path}`,
      description: "An administrative interface is accessible without any authentication. Anyone who discovers this URL has full admin access.",
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 300)}`,
      remediation: "Protect admin routes with authentication and authorization checks. Consider IP allowlisting.",
      cwe: "CWE-306",
      owasp: "A07:2021",
    });
  }

  // Collect weak token findings
  for (const r of tokenResults) {
    if (findings.length >= 6) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { pathname, noAuthStatus, invalidStatus, text } = r.value;
    findings.push({
      id: `auth-weak-validation-${findings.length}`,
      module: "Authentication",
      severity: "critical",
      title: `Weak token validation on ${pathname}`,
      description: "This endpoint accepts invalid Bearer tokens. The server is not properly validating authentication tokens, allowing anyone with any string as a token to access protected data.",
      evidence: `Without token: ${noAuthStatus}\nWith invalid token: ${invalidStatus}\nResponse: ${text.substring(0, 200)}`,
      remediation: "Validate tokens cryptographically. Use a JWT library that verifies signatures, or validate tokens against your auth provider.",
      cwe: "CWE-287",
      owasp: "A07:2021",
    });
  }

  // Collect HTTP method findings
  for (const r of methodResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { endpoint, method, status, text } = r.value;
    findings.push({
      id: `auth-method-${method.toLowerCase()}-${findings.length}`,
      module: "Authentication",
      severity: "high",
      title: `${method} allowed without auth on ${new URL(endpoint).pathname}`,
      description: `The ${method} method returns a success status (${status}) without authentication. This may allow unauthenticated data modification or deletion.`,
      evidence: `${method} ${endpoint}\nStatus: ${status}\nResponse: ${text.substring(0, 200)}`,
      remediation: `Add authentication checks for ${method} requests on this endpoint.`,
      cwe: "CWE-306",
      owasp: "A07:2021",
    });
  }

  return findings;
};
