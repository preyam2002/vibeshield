import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const csrfModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Check if SameSite cookies provide CSRF protection
  // Missing SameSite defaults to Lax in modern browsers (provides CSRF protection)
  const hasSameSiteCookie = target.cookies.some(
    (c) => !c.sameSite || c.sameSite.toLowerCase() !== "none",
  );

  // Flag SameSite=None cookies without Secure (exploitable for CSRF)
  const insecureSameSiteNone = target.cookies.filter(
    (c) => c.sameSite?.toLowerCase() === "none" && !c.secure,
  );
  if (insecureSameSiteNone.length > 0) {
    findings.push({
      id: "csrf-samesite-none-insecure",
      module: "CSRF",
      severity: "medium",
      title: `SameSite=None cookie without Secure flag: ${insecureSameSiteNone.map((c) => c.name).join(", ")}`,
      description: "Cookies with SameSite=None are sent on cross-site requests. Without the Secure flag, they're sent over HTTP too, enabling both CSRF and session hijacking on non-HTTPS connections.",
      evidence: `Cookies: ${insecureSameSiteNone.map((c) => `${c.name} (SameSite=None, Secure=${c.secure})`).join("; ")}`,
      remediation: "Set Secure flag on all SameSite=None cookies. Better yet, use SameSite=Lax unless cross-site sending is specifically needed.",
      cwe: "CWE-352", owasp: "A01:2021",
      codeSnippet: `// Set SameSite=Lax (or Strict) by default\nres.headers.set("Set-Cookie", "session=abc; HttpOnly; Secure; SameSite=Lax; Path=/");`,
    });
  }

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
      // Test both simple request types that bypass CORS preflight
      const [formRes, textRes] = await Promise.all([
        scanFetch(endpoint, {
          method: "POST",
          headers: { Origin: "https://evil.com", "Content-Type": "application/x-www-form-urlencoded" },
          body: "test=true",
        }),
        scanFetch(endpoint, {
          method: "POST",
          headers: { Origin: "https://evil.com", "Content-Type": "text/plain" },
          body: JSON.stringify({ test: true }),
        }),
      ]);
      const simpleRes = formRes.ok ? formRes : textRes.ok ? textRes : null;
      if (simpleRes?.ok && !hasSameSiteCookie) {
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

  // Test if JSON endpoints accept form-encoded content (enables simple CSRF via <form>)
  const contentTypeResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 8).map(async (endpoint) => {
      // First, check if endpoint expects JSON
      const jsonRes = await scanFetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test: "csrf-check" }), timeoutMs: 5000,
      });
      if (!jsonRes.ok) return null;

      // Now try text/plain (bypasses CORS preflight) with JSON body
      const plainRes = await scanFetch(endpoint, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({ test: "csrf-check" }), timeoutMs: 5000,
      });
      if (plainRes.ok) {
        const plainText = await plainRes.text();
        if (plainText.length > 10 && !/error|invalid|unsupported.*content/i.test(plainText.substring(0, 200))) {
          return { endpoint, pathname: new URL(endpoint).pathname, type: "text/plain" as const };
        }
      }

      // Try form-encoded (also a "simple" CSRF request)
      const formRes = await scanFetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "test=csrf-check", timeoutMs: 5000,
      });
      if (formRes.ok) {
        const formText = await formRes.text();
        if (formText.length > 10 && !/error|invalid|unsupported/i.test(formText.substring(0, 200))) {
          return { endpoint, pathname: new URL(endpoint).pathname, type: "form-encoded" as const };
        }
      }

      return null;
    }),
  );

  let ctBypassCount = 0;
  for (const r of contentTypeResults) {
    if (ctBypassCount >= 2) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (!hasSameSiteCookie) {
      ctBypassCount++;
      findings.push({
        id: `csrf-content-type-${findings.length}`, module: "CSRF", severity: "medium",
        title: `JSON endpoint accepts ${v.type} on ${v.pathname}`,
        description: `This JSON API endpoint also processes ${v.type} requests. Since ${v.type} is a "simple" content type that doesn't trigger CORS preflight, a malicious site can submit cross-origin requests using a <form> element.`,
        evidence: `POST ${v.endpoint} with Content-Type: ${v.type} succeeded`,
        remediation: "Reject requests with unexpected Content-Type. Require application/json and validate the Content-Type header server-side.",
        cwe: "CWE-352", owasp: "A01:2021",
        codeSnippet: `// Enforce Content-Type on API routes\nexport async function POST(req: Request) {\n  const ct = req.headers.get("content-type") || "";\n  if (!ct.includes("application/json")) {\n    return Response.json({ error: "Content-Type must be application/json" }, { status: 415 });\n  }\n  const body = await req.json();\n}`,
      });
    }
  }

  return findings;
};
