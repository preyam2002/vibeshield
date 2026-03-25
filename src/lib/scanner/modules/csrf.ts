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
        codeSnippet: `// middleware.ts — Origin-based CSRF protection\nexport function middleware(req: NextRequest) {\n  if (req.method !== "GET" && req.method !== "HEAD") {\n    const origin = req.headers.get("origin");\n    const host = req.headers.get("host");\n    if (origin && !origin.includes(host || "")) {\n      return NextResponse.json({ error: "CSRF rejected" }, { status: 403 });\n    }\n  }\n  return NextResponse.next();\n}`,
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
      codeSnippet: `// API route — require custom header to trigger CORS preflight\nexport async function POST(req: Request) {\n  // Custom headers like X-Requested-With trigger CORS preflight,\n  // which blocks cross-origin simple requests\n  if (!req.headers.get("x-requested-with")) {\n    return Response.json({ error: "Missing required header" }, { status: 403 });\n  }\n  // ... handle request\n}`,
    });
  }

  return findings;
};
