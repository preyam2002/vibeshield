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

  // Phase 5: Login CSRF — check if login forms can be submitted cross-origin
  // (allows attacker to log victim into attacker's account)
  const loginEndpoints = target.apiEndpoints.filter((ep) =>
    /login|signin|sign-in|authenticate/i.test(ep),
  );
  const loginForms = target.forms.filter((f) =>
    f.method === "POST" && /login|signin|sign-in|authenticate/i.test(f.action),
  );
  const loginTargets = [
    ...loginEndpoints.slice(0, 3).map((ep) => ({ url: ep, type: "api" as const })),
    ...loginForms.slice(0, 2).map((f) => ({
      url: f.action.startsWith("http") ? f.action : target.baseUrl + f.action,
      type: "form" as const,
    })),
  ];

  const loginResults = await Promise.allSettled(
    loginTargets.map(async ({ url, type }) => {
      // Test cross-origin POST with simple content type (bypasses CORS preflight)
      const res = await scanFetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Origin: "https://evil.com",
        },
        body: "email=attacker@evil.com&password=password123",
        timeoutMs: 5000,
      });
      // If the endpoint doesn't reject the cross-origin request, it's vulnerable
      if (res.status !== 403 && res.status !== 401 && res.status !== 400) {
        const text = await res.text();
        if (!/csrf|forbidden|invalid.*origin|cross.*origin/i.test(text.substring(0, 500))) {
          return { url: new URL(url).pathname, status: res.status, type };
        }
      }
      return null;
    }),
  );

  for (const r of loginResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (!hasSameSiteCookie) {
      findings.push({
        id: `csrf-login-${findings.length}`,
        module: "CSRF",
        severity: "medium",
        title: `Login CSRF: ${v.url} accepts cross-origin login`,
        description: `The login endpoint accepts cross-origin POST requests without CSRF protection. An attacker can force a victim to log into the attacker's account, then observe the victim's activity or harvest data entered under that session.`,
        evidence: `POST ${v.url} with Origin: https://evil.com\nStatus: ${v.status}\nContent-Type: application/x-www-form-urlencoded (simple request, no CORS preflight)`,
        remediation: "Add CSRF protection to login forms. Validate the Origin header, or require a CSRF token even on login endpoints.",
        cwe: "CWE-352",
        owasp: "A01:2021",
        codeSnippet: `// Protect login endpoint with Origin validation\nexport async function POST(req: Request) {\n  const origin = req.headers.get("origin");\n  const host = req.headers.get("host");\n  if (!origin || !origin.includes(host || "")) {\n    return Response.json({ error: "Invalid origin" }, { status: 403 });\n  }\n  // ... handle login\n}`,
      });
      break;
    }
  }

  // Phase 6: Double-submit cookie pattern weakness detection
  const csrfCookies = target.cookies.filter((c) =>
    /csrf|xsrf|_token/i.test(c.name),
  );
  for (const cookie of csrfCookies) {
    // If the CSRF cookie doesn't have SameSite or is SameSite=None, the double-submit pattern is weak
    if (!cookie.sameSite || cookie.sameSite.toLowerCase() === "none") {
      findings.push({
        id: `csrf-double-submit-weak-${findings.length}`,
        module: "CSRF",
        severity: "low",
        title: `Weak double-submit cookie: ${cookie.name}`,
        description: `The CSRF token cookie "${cookie.name}" is not protected with SameSite attribute. In the double-submit cookie pattern, attackers can set this cookie via a subdomain or cookie injection, then submit a matching token in the request body.`,
        evidence: `Cookie: ${cookie.name}\nSameSite: ${cookie.sameSite || "(not set)"}\nSecure: ${cookie.secure}\nHttpOnly: ${cookie.httpOnly}`,
        remediation: "Add SameSite=Strict to CSRF token cookies. Better yet, use HMAC-signed tokens tied to the user session instead of simple double-submit cookies.",
        cwe: "CWE-352",
        owasp: "A01:2021",
        confidence: 70,
        codeSnippet: `// Use HMAC-signed CSRF tokens instead of plain double-submit\nimport { createHmac } from "crypto";\nconst secret = process.env.CSRF_SECRET!;\n\nfunction generateCsrfToken(sessionId: string) {\n  const hmac = createHmac("sha256", secret);\n  hmac.update(sessionId + ":" + Date.now());\n  return hmac.digest("hex");\n}`,
      });
    }
  }

  // Phase 7: SameSite=None without CSRF tokens — critical combination
  const hasSameSiteNone = target.cookies.some((c) => c.sameSite?.toLowerCase() === "none");
  if (hasSameSiteNone) {
    const formsWithoutCsrf = target.forms.filter((f) =>
      f.method === "POST" && !f.inputs.some((i) => /csrf|xsrf|token|_token|authenticity/i.test(i.name)),
    );
    if (formsWithoutCsrf.length > 0) {
      findings.push({
        id: "csrf-samesite-none-no-token",
        module: "CSRF",
        severity: "high",
        title: `${formsWithoutCsrf.length} form(s) without CSRF tokens while SameSite=None cookies are set`,
        description: "Session cookies are set with SameSite=None (sent on cross-origin requests) but forms lack CSRF tokens. This is the worst combination — browsers will send cookies on cross-site form submissions with zero protection.",
        evidence: `SameSite=None cookies: ${target.cookies.filter((c) => c.sameSite?.toLowerCase() === "none").map((c) => c.name).join(", ")}\nForms without CSRF token: ${formsWithoutCsrf.slice(0, 3).map((f) => f.action).join(", ")}`,
        remediation: "Either change SameSite to Lax (recommended) or add CSRF tokens to all forms. SameSite=None should only be used when cross-site cookie sending is genuinely needed (e.g., embedded iframes).",
        cwe: "CWE-352",
        owasp: "A01:2021",
        confidence: 95,
      });
    }
  }

  // Phase 7b: CSRF token predictability check
  const csrfTokenInputs = target.forms.flatMap((f) =>
    f.inputs.filter((i) => /csrf|xsrf|token|_token|authenticity/i.test(i.name)),
  );
  // If we can see token values in form HTML, check quality
  const allHtml = Array.from(target.jsContents.values()).join("\n");
  for (const input of csrfTokenInputs.slice(0, 3)) {
    const valMatch = allHtml.match(new RegExp(`name=["']${input.name}["'][^>]*value=["']([^"']+)["']`, "i"));
    if (valMatch) {
      const token = valMatch[1];
      const isWeak = token.length < 16 || /^\d+$/.test(token) || /^[a-f0-9]{1,8}$/i.test(token);
      if (isWeak) {
        findings.push({
          id: `csrf-weak-token-${findings.length}`,
          module: "CSRF",
          severity: "medium",
          title: `Weak CSRF token in "${input.name}" (${token.length} chars${/^\d+$/.test(token) ? ", numeric-only" : ""})`,
          description: `The CSRF token appears weak: ${token.length < 16 ? "too short" : "low entropy"}. Weak tokens can be brute-forced or predicted, defeating CSRF protection.`,
          evidence: `Input: ${input.name}\nToken: ${token.substring(0, 20)}${token.length > 20 ? "..." : ""}\nLength: ${token.length}`,
          remediation: "Use cryptographically random tokens of at least 32 bytes. In Node.js: crypto.randomBytes(32).toString('hex').",
          cwe: "CWE-330",
          confidence: 75,
        });
        break;
      }
    }
  }

  // Phase 8: Referer header validation bypass
  // Some apps check Referer but can be bypassed with Referer suppression
  const refererResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
      // First try with no Referer (suppressed via Referrer-Policy: no-referrer)
      const noRefRes = await scanFetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Referer: "",
        },
        body: JSON.stringify({ test: true }),
        timeoutMs: 5000,
      });
      if (!noRefRes.ok) return null;

      // Then try with evil Referer that contains the target domain as substring
      const hostname = new URL(target.url).hostname;
      const bypassReferers = [
        `https://evil.com/${hostname}`,
        `https://${hostname}.evil.com/`,
        `https://evil.com?ref=${hostname}`,
      ];
      for (const ref of bypassReferers) {
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Referer: ref,
            Origin: ref.split("/").slice(0, 3).join("/"),
          },
          body: JSON.stringify({ test: true }),
          timeoutMs: 5000,
        });
        if (res.ok) {
          return { endpoint: new URL(endpoint).pathname, bypass: ref };
        }
      }
      return null;
    }),
  );

  for (const r of refererResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `csrf-referer-bypass-${findings.length}`,
      module: "CSRF",
      severity: "medium",
      title: `Referer validation bypass on ${v.endpoint}`,
      description: `The endpoint accepts requests with a manipulated Referer header ("${v.bypass}"). If the application relies on Referer-based CSRF protection, this bypass allows cross-site request forgery.`,
      evidence: `POST ${v.endpoint} with Referer: ${v.bypass}\nRequest accepted (200 OK)`,
      remediation: "Don't rely solely on Referer header for CSRF protection. Use proper CSRF tokens or validate the Origin header strictly (exact match, not substring).",
      cwe: "CWE-352",
      owasp: "A01:2021",
      confidence: 65,
      codeSnippet: `// Strict Origin validation — exact match, not substring\nfunction isValidOrigin(req: Request): boolean {\n  const origin = req.headers.get("origin");\n  const allowed = new Set([process.env.APP_URL]);\n  return origin !== null && allowed.has(origin);\n}`,
    });
    break;
  }

  return findings;
};
