import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const csrfModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Check if SameSite cookies provide CSRF protection
  // Missing SameSite defaults to Lax in modern browsers (provides CSRF protection)
  const hasSameSiteCookie = target.cookies.some(
    (c) => !c.sameSite || c.sameSite.toLowerCase() !== "none",
  );

  // Check forms for CSRF tokens
  for (const form of target.forms.slice(0, 10)) {
    if (form.method === "GET") continue;
    const hasCsrfToken = form.inputs.some((i) =>
      /csrf|xsrf|token|_token|authenticity/i.test(i.name),
    );

    if (!hasCsrfToken && !hasSameSiteCookie) {
      findings.push({
        id: `csrf-no-token-${findings.length}`,
        module: "CSRF",
        severity: "medium",
        title: `Form missing CSRF token: ${form.action}`,
        description: "This form submits data without a CSRF token and no SameSite cookies are set. A malicious site could trick logged-in users into submitting this form unknowingly.",
        evidence: `Form action: ${form.action}\nMethod: ${form.method}\nInputs: ${form.inputs.map((i) => i.name).join(", ")}`,
        remediation: "Add CSRF protection. For Next.js API routes, check the Origin header. For traditional forms, include a CSRF token.",
        cwe: "CWE-352",
        owasp: "A01:2021",
      });
    }
  }

  // Test state-changing API endpoints without CSRF protection — all in parallel
  const csrfResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 10).map(async (endpoint) => {
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: "https://evil.com" },
        body: JSON.stringify({ test: true }),
      });
      if (!res.ok) return null;
      const acao = res.headers.get("access-control-allow-origin");
      if (acao !== "*" && acao !== "https://evil.com") return null;
      const simpleRes = await scanFetch(endpoint, {
        method: "POST",
        headers: { Origin: "https://evil.com", "Content-Type": "application/x-www-form-urlencoded" },
        body: "test=true",
      });
      if (simpleRes.ok && !hasSameSiteCookie) {
        return { endpoint, pathname: new URL(endpoint).pathname, status: simpleRes.status, acao };
      }
      return null;
    }),
  );

  for (const r of csrfResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `csrf-api-${findings.length}`, module: "CSRF", severity: "high",
      title: `API endpoint vulnerable to CSRF: ${v.pathname}`,
      description: "This endpoint accepts simple cross-origin POST requests without CSRF protection.",
      evidence: `POST ${v.endpoint} with Origin: https://evil.com\nStatus: ${v.status}\nACAO: ${v.acao}`,
      remediation: "Validate the Origin header on state-changing endpoints. Require a custom Content-Type or header that triggers CORS preflight. Set SameSite cookies.",
      cwe: "CWE-352", owasp: "A01:2021",
    });
  }

  return findings;
};
