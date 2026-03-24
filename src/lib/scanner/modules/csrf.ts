import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const csrfModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Check if SameSite cookies provide CSRF protection already
  const hasSameSiteCookie = target.cookies.some(
    (c) => c.sameSite && c.sameSite.toLowerCase() !== "none",
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

  // Test state-changing API endpoints without CSRF protection
  for (const endpoint of target.apiEndpoints.slice(0, 10)) {
    try {
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: "https://evil.com",
        },
        body: JSON.stringify({ test: true }),
      });

      // If cross-origin POST succeeds, CSRF might be possible
      if (res.ok) {
        const acao = res.headers.get("access-control-allow-origin");
        if (acao === "*" || acao === "https://evil.com") {
          // Check if the endpoint requires a custom header (valid CSRF defense)
          // Try without Content-Type (simple request) — if it still works, no custom header required
          const simpleRes = await scanFetch(endpoint, {
            method: "POST",
            headers: { Origin: "https://evil.com" },
            body: "test=true",
          });
          if (simpleRes.ok && !hasSameSiteCookie) {
            findings.push({
              id: `csrf-api-${findings.length}`,
              module: "CSRF",
              severity: "high",
              title: `API endpoint vulnerable to CSRF: ${new URL(endpoint).pathname}`,
              description: "This endpoint accepts simple cross-origin POST requests without CSRF protection. A malicious website can make authenticated requests on behalf of users.",
              evidence: `POST ${endpoint} with Origin: https://evil.com\nStatus: ${simpleRes.status}\nACAO: ${acao}`,
              remediation: "Validate the Origin header on state-changing endpoints. Require a custom Content-Type or header that triggers CORS preflight. Set SameSite cookies.",
              cwe: "CWE-352",
              owasp: "A01:2021",
            });
          }
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};
