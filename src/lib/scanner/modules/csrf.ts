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

  // Phase 7: SameSite cookie bypass via top-level navigation
  // SameSite=Lax allows cookies on top-level GET navigations, enabling CSRF on GET side-effects
  const sameSiteLaxCookies = target.cookies.filter(
    (c) => !c.sameSite || c.sameSite.toLowerCase() === "lax",
  );
  if (sameSiteLaxCookies.length > 0) {
    // Check for state-changing GET endpoints (common CSRF vector with Lax cookies)
    const stateChangingGetPaths = target.apiEndpoints.filter((ep) =>
      /logout|delete|remove|unsubscribe|confirm|approve|verify|activate|deactivate|toggle|enable|disable/i.test(ep),
    );
    const getResults = await Promise.allSettled(
      stateChangingGetPaths.slice(0, 5).map(async (endpoint) => {
        const res = await scanFetch(endpoint, {
          method: "GET",
          headers: { Origin: "https://evil.com" },
          timeoutMs: 5000,
        });
        if (res.ok && res.status === 200) {
          const text = await res.text();
          // Check if the response suggests the action was performed
          if (!/error|unauthorized|forbidden|login|redirect/i.test(text.substring(0, 300))) {
            return { endpoint, pathname: new URL(endpoint).pathname, status: res.status };
          }
        }
        return null;
      }),
    );
    for (const r of getResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `csrf-get-side-effect-${findings.length}`,
        module: "CSRF",
        severity: "medium",
        title: `State-changing GET endpoint: ${v.pathname}`,
        description: `The endpoint ${v.pathname} appears to perform state-changing actions via GET request. SameSite=Lax cookies (the default) are sent on top-level GET navigations, so an attacker can trigger this action via <a href>, <img src>, or window.open(). This bypasses SameSite=Lax protection because the browser treats top-level navigations as "safe".`,
        evidence: `GET ${v.endpoint} → ${v.status} OK\nSameSite=Lax cookies: ${sameSiteLaxCookies.map((c) => c.name).join(", ")}`,
        remediation: "Never perform state-changing operations via GET requests. Use POST/PUT/DELETE for mutations. Add CSRF tokens to all state-changing endpoints regardless of SameSite cookie settings.",
        cwe: "CWE-352",
        owasp: "A01:2021",
        confidence: 60,
        codeSnippet: `// Reject state-changing GET requests\nexport async function GET(req: Request) {\n  // GET should be safe/idempotent — no side effects\n  return Response.json({ error: "Use POST for this action" }, { status: 405 });\n}\n\nexport async function POST(req: Request) {\n  // Validate CSRF token or Origin header\n  // ... perform action\n}`,
      });
      break;
    }
  }

  // Phase 7a: SameSite=None without CSRF tokens — critical combination
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

  // Phase 7b: CSRF token entropy analysis
  const csrfTokenInputs = target.forms.flatMap((f) =>
    f.inputs.filter((i) => /csrf|xsrf|token|_token|authenticity/i.test(i.name)),
  );
  const allHtml = Array.from(target.jsContents.values()).join("\n");
  for (const input of csrfTokenInputs.slice(0, 3)) {
    const valMatch = allHtml.match(new RegExp(`name=["']${input.name}["'][^>]*value=["']([^"']+)["']`, "i"));
    if (valMatch) {
      const token = valMatch[1];
      // Entropy analysis: check length, character set diversity, and patterns
      const isShort = token.length < 16;
      const isNumericOnly = /^\d+$/.test(token);
      const isLowHex = /^[a-f0-9]{1,8}$/i.test(token);
      const isTimestamp = /^1[6-7]\d{8,11}$/.test(token); // Unix timestamp-like
      const isSequential = /^0*[1-9]\d{0,5}$/.test(token); // Small sequential number
      const uniqueChars = new Set(token).size;
      const charRatio = uniqueChars / token.length;
      const isLowEntropy = charRatio < 0.3 && token.length > 8; // Repetitive characters

      const weaknesses: string[] = [];
      if (isShort) weaknesses.push(`too short (${token.length} chars, need 32+)`);
      if (isNumericOnly) weaknesses.push("numeric-only (limited keyspace)");
      if (isLowHex) weaknesses.push("short hex value (brute-forceable)");
      if (isTimestamp) weaknesses.push("appears to be a Unix timestamp (predictable)");
      if (isSequential) weaknesses.push("appears sequential (predictable)");
      if (isLowEntropy) weaknesses.push(`low entropy (only ${uniqueChars} unique chars in ${token.length} char token)`);

      if (weaknesses.length > 0) {
        findings.push({
          id: `csrf-weak-token-${findings.length}`,
          module: "CSRF",
          severity: "medium",
          title: `Weak CSRF token in "${input.name}": ${weaknesses[0]}`,
          description: `The CSRF token has weak entropy characteristics: ${weaknesses.join("; ")}. An attacker may be able to predict or brute-force the token, completely defeating CSRF protection.`,
          evidence: `Input: ${input.name}\nToken: ${token.substring(0, 20)}${token.length > 20 ? "..." : ""}\nLength: ${token.length}\nUnique characters: ${uniqueChars}\nWeaknesses: ${weaknesses.join(", ")}`,
          remediation: "Use cryptographically random tokens of at least 32 bytes. In Node.js: crypto.randomBytes(32).toString('hex'). Avoid timestamps, sequential IDs, or low-entropy values as CSRF tokens.",
          cwe: "CWE-330",
          confidence: 75,
        });
        break;
      }
    }
  }

  // Phase 7c: CSRF token fixation — check if token can be reused across sessions
  // Fetch the page twice and compare CSRF tokens
  if (csrfTokenInputs.length > 0) {
    const tokenName = csrfTokenInputs[0].name;
    const tokenFetchResults = await Promise.allSettled([
      scanFetch(target.url, { timeoutMs: 5000 }),
      scanFetch(target.url, { timeoutMs: 5000, headers: { Cookie: "" } }),
    ]);
    const tokens: string[] = [];
    for (const r of tokenFetchResults) {
      if (r.status !== "fulfilled") continue;
      const html = await r.value.text();
      const match = html.match(new RegExp(`name=["']${tokenName}["'][^>]*value=["']([^"']+)["']`, "i"));
      if (match) tokens.push(match[1]);
    }
    if (tokens.length === 2 && tokens[0] === tokens[1] && tokens[0].length > 0) {
      findings.push({
        id: `csrf-token-fixation-${findings.length}`,
        module: "CSRF",
        severity: "medium",
        title: `CSRF token "${tokenName}" appears static across requests`,
        description: "The CSRF token is identical across two separate requests with different session contexts. This suggests the token is either globally static or not tied to the user session. An attacker could obtain a valid token from their own session and use it in a CSRF attack against another user.",
        evidence: `Token name: ${tokenName}\nToken value (both requests): ${tokens[0].substring(0, 20)}...`,
        remediation: "Generate unique CSRF tokens per session and tie them cryptographically to the session ID. Tokens should be unpredictable and non-reusable across different sessions.",
        cwe: "CWE-352",
        confidence: 70,
      });
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
