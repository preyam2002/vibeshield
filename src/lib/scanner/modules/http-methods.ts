import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const DANGEROUS_METHODS = ["TRACE", "TRACK", "DEBUG", "CONNECT"];

const METHOD_OVERRIDE_HEADERS = [
  "X-HTTP-Method-Override",
  "X-Method-Override",
  "X-HTTP-Method",
];

export const httpMethodsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const endpoints = [target.url, ...target.apiEndpoints.slice(0, 3)];

  const tests: Promise<void>[] = [];

  for (const endpoint of endpoints) {
    // Test OPTIONS to see allowed methods
    tests.push(
      (async () => {
        try {
          const res = await scanFetch(endpoint, { method: "OPTIONS", timeoutMs: 3000 });
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
                codeSnippet: `// vercel.json — block dangerous methods\n{\n  "headers": [{ "source": "/(.*)", "headers": [{ "key": "Allow", "value": "GET, POST, HEAD" }] }]\n}\n// Or in middleware.ts:\nif (["TRACE", "TRACK", "DEBUG"].includes(req.method)) return new Response(null, { status: 405 });`,
              });
            }
          }
        } catch {
          // skip
        }
      })(),
    );

    // Actually test TRACE and check for XST (Cross-Site Tracing) — cookie/auth header echo
    tests.push(
      (async () => {
        try {
          const xstProbe = `XST-Probe-${Date.now()}`;
          const res = await scanFetch(endpoint, {
            method: "TRACE",
            headers: {
              "Cookie": `xst_test=${xstProbe}`,
              "Authorization": `Bearer ${xstProbe}`,
            },
            timeoutMs: 3000,
          });
          if (res.ok) {
            const body = await res.text();
            const echoesCookies = body.includes(xstProbe) || body.includes("Cookie:");
            const echoesAuth = body.includes("Authorization:") || body.includes("Bearer");

            if (echoesCookies || echoesAuth) {
              findings.push({
                id: `http-methods-trace-xst-${findings.length}`,
                module: "HTTP Methods",
                severity: "high",
                title: `Cross-Site Tracing (XST) — TRACE echoes sensitive headers on ${new URL(endpoint).pathname}`,
                description: "TRACE method echoes back cookies and/or authorization headers in the response body. An attacker can exploit this via XSS to steal HttpOnly cookies or auth tokens that are otherwise inaccessible to JavaScript.",
                evidence: `TRACE ${endpoint} → ${res.status}\nEchoes cookies: ${echoesCookies}\nEchoes auth headers: ${echoesAuth}\nResponse (truncated): ${body.substring(0, 300)}`,
                remediation: "Disable TRACE method entirely in your web server configuration. This is the only effective mitigation.",
                cwe: "CWE-693",
                owasp: "A05:2021",
                codeSnippet: `// middleware.ts — block TRACE requests\nif (req.method === "TRACE") return new Response(null, { status: 405 });`,
              });
            } else {
              findings.push({
                id: `http-methods-trace-active-${findings.length}`,
                module: "HTTP Methods",
                severity: "medium",
                title: `TRACE method active on ${new URL(endpoint).pathname}`,
                description: "TRACE method returns 200 OK. Can be used for Cross-Site Tracing attacks.",
                evidence: `TRACE ${endpoint} → ${res.status}`,
                remediation: "Disable TRACE in your web server.",
                cwe: "CWE-749",
                codeSnippet: `// middleware.ts — block TRACE requests\nif (req.method === "TRACE") return new Response(null, { status: 405 });`,
              });
            }
          }
        } catch {
          // skip
        }
      })(),
    );

    // Test HTTP method override headers — can a POST with override header act as DELETE/PUT?
    tests.push(
      (async () => {
        const pathname = new URL(endpoint).pathname;
        try {
          // Baseline: normal GET
          const baseRes = await scanFetch(endpoint, { timeoutMs: 3000 });
          const baseStatus = baseRes.status;
          const baseText = await baseRes.text();

          for (const header of METHOD_OVERRIDE_HEADERS) {
            // Try overriding GET → DELETE via the header
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { [header]: "DELETE", "Content-Length": "0" },
              timeoutMs: 3000,
            });

            // If server accepts the override and returns different behavior than baseline
            // (e.g., 200/204 for DELETE instead of a normal page), it's vulnerable
            if (res.ok && res.status !== baseStatus) {
              const text = await res.text();
              // Confirm it's actually different behavior, not just the same page
              if (text.length < baseText.length * 0.5 || res.status === 204) {
                findings.push({
                  id: `http-methods-override-${header}-${findings.length}`,
                  module: "HTTP Methods",
                  severity: "medium",
                  title: `HTTP method override via ${header} on ${pathname}`,
                  description: `The server accepts the ${header} header to override the HTTP method. An attacker can use this to bypass method-based access controls — e.g., sending a POST with ${header}: DELETE to delete resources.`,
                  evidence: `POST ${endpoint}\n${header}: DELETE\nBaseline status: ${baseStatus}\nOverride status: ${res.status}`,
                  remediation: `Disable HTTP method override headers in production. If needed, restrict to authenticated admin requests only.`,
                  cwe: "CWE-749",
                  owasp: "A01:2021",
                  codeSnippet: `// middleware.ts — strip method override headers\nconst BLOCKED_HEADERS = ["x-http-method-override", "x-method-override", "x-http-method"];\nexport function middleware(req) {\n  const headers = new Headers(req.headers);\n  BLOCKED_HEADERS.forEach(h => headers.delete(h));\n  return NextResponse.next({ request: { headers } });\n}`,
                });
                break;
              }
            }

            // Also try overriding to TRACE
            const traceRes = await scanFetch(endpoint, {
              method: "POST",
              headers: { [header]: "TRACE", "Content-Length": "0" },
              timeoutMs: 3000,
            });
            if (traceRes.ok) {
              const traceText = await traceRes.text();
              if (traceText.includes("TRACE") || traceText.includes(header)) {
                findings.push({
                  id: `http-methods-override-trace-${findings.length}`,
                  module: "HTTP Methods",
                  severity: "medium",
                  title: `TRACE via method override (${header}) on ${pathname}`,
                  description: `The server allows TRACE method via the ${header} override header, enabling Cross-Site Tracing even when TRACE is blocked directly.`,
                  evidence: `POST ${endpoint}\n${header}: TRACE\nStatus: ${traceRes.status}\nResponse: ${traceText.substring(0, 200)}`,
                  remediation: `Disable HTTP method override headers. Block TRACE at the server level.`,
                  cwe: "CWE-749",
                  owasp: "A05:2021",
                });
                break;
              }
            }
          }
        } catch {
          // skip
        }
      })(),
    );

    // Test _method query parameter override (Rails, Laravel, etc.)
    tests.push(
      (async () => {
        const pathname = new URL(endpoint).pathname;
        try {
          const baseRes = await scanFetch(endpoint, { timeoutMs: 3000 });
          const baseStatus = baseRes.status;
          const baseText = await baseRes.text();

          for (const overrideMethod of ["DELETE", "PUT", "PATCH"]) {
            const separator = endpoint.includes("?") ? "&" : "?";
            const overrideUrl = `${endpoint}${separator}_method=${overrideMethod}`;
            const res = await scanFetch(overrideUrl, {
              method: "POST",
              headers: { "Content-Length": "0" },
              timeoutMs: 3000,
            });

            if (res.ok && res.status !== baseStatus) {
              const text = await res.text();
              if (text.length < baseText.length * 0.5 || res.status === 204) {
                findings.push({
                  id: `http-methods-query-override-${overrideMethod.toLowerCase()}-${findings.length}`,
                  module: "HTTP Methods",
                  severity: "medium",
                  title: `HTTP method override via _method query param on ${pathname}`,
                  description: `The server accepts _method=${overrideMethod} query parameter to override the HTTP method. Attackers can craft URLs that trigger destructive operations (DELETE/PUT) via simple links or form submissions, bypassing method-based access controls.`,
                  evidence: `POST ${overrideUrl}\nBaseline status: ${baseStatus}\nOverride status: ${res.status}`,
                  remediation: "Disable _method query parameter override in production. If needed for legacy form support, restrict to authenticated requests and validate CSRF tokens.",
                  cwe: "CWE-749",
                  owasp: "A01:2021",
                  codeSnippet: `// middleware.ts — strip _method query parameter\nexport function middleware(req: NextRequest) {\n  const url = new URL(req.url);\n  if (url.searchParams.has("_method")) {\n    url.searchParams.delete("_method");\n    return NextResponse.redirect(url, { status: 400 });\n  }\n  return NextResponse.next();\n}`,
                });
                break;
              }
            }
          }
        } catch {
          // skip
        }
      })(),
    );
  }

  await Promise.allSettled(tests);

  // Test for unintended PUT/PATCH/DELETE on API endpoints (should require auth)
  const writeMethods = ["PUT", "PATCH", "DELETE"] as const;
  const writeResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 5).flatMap((endpoint) =>
      writeMethods.map(async (method) => {
        const res = await scanFetch(endpoint, {
          method,
          headers: { "Content-Type": "application/json" },
          body: method !== "DELETE" ? JSON.stringify({ test: true }) : undefined,
          timeoutMs: 5000,
        });
        // If write method succeeds without auth headers, it's concerning
        if (res.ok && res.status !== 404) {
          const text = await res.text();
          if (text.length > 5 && !/unauthorized|unauthenticated|forbidden|login|sign.?in/i.test(text.substring(0, 300))) {
            return { endpoint, pathname: new URL(endpoint).pathname, method, status: res.status, text: text.substring(0, 200) };
          }
        }
        return null;
      }),
    ),
  );

  const writeSeen = new Set<string>();
  for (const r of writeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.method}`;
    if (writeSeen.has(key)) continue;
    writeSeen.add(key);
    const isDestructive = v.method === "DELETE" || v.method === "PATCH";
    findings.push({
      id: `http-methods-write-no-auth-${findings.length}`,
      module: "HTTP Methods",
      severity: isDestructive ? "high" : "medium",
      title: `${v.method} accepted without authentication on ${v.pathname}`,
      description: isDestructive
        ? `The destructive ${v.method} method succeeds without authentication on this API endpoint. An unauthenticated attacker can ${v.method === "DELETE" ? "delete resources" : "modify data"} without any credentials.`
        : `The ${v.method} method is accepted without authentication on this endpoint. Write methods (PUT, PATCH, DELETE) should require authentication to prevent unauthorized data modification.`,
      evidence: `${v.method} ${v.endpoint}\nStatus: ${v.status}\nResponse: ${v.text}`,
      remediation: `Require authentication for ${v.method} requests. Return 401 for unauthenticated write attempts.`,
      cwe: "CWE-306", owasp: "A07:2021",
      codeSnippet: `// Protect write methods in API routes\nexport async function ${v.method}(req: Request) {\n  const session = await auth();\n  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  // ... handle authenticated ${v.method}\n}`,
    });
  }

  // Test destructive methods (PATCH/DELETE) with fabricated auth to detect missing authorization
  const destructiveMethods = ["PATCH", "DELETE"] as const;
  const authBypassResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 5).flatMap((endpoint) =>
      destructiveMethods.map(async (method) => {
        const pathname = new URL(endpoint).pathname;
        // Send request with a clearly invalid/fabricated auth token
        const res = await scanFetch(endpoint, {
          method,
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer invalid_token_test_00000",
          },
          body: method === "PATCH" ? JSON.stringify({ test: true }) : undefined,
          timeoutMs: 5000,
        });
        // If destructive method succeeds with invalid auth, authorization is not enforced
        if (res.ok && res.status !== 404) {
          const text = await res.text();
          if (text.length > 5 && !/unauthorized|unauthenticated|forbidden|invalid.?token|expired/i.test(text.substring(0, 300))) {
            return { endpoint, pathname, method, status: res.status, text: text.substring(0, 200) };
          }
        }
        return null;
      }),
    ),
  );

  for (const r of authBypassResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.method}:authbypass`;
    if (writeSeen.has(key)) continue;
    writeSeen.add(key);
    findings.push({
      id: `http-methods-destructive-auth-bypass-${findings.length}`,
      module: "HTTP Methods",
      severity: "high",
      title: `${v.method} succeeds with invalid auth token on ${v.pathname}`,
      description: `The ${v.method} endpoint accepts requests with a fabricated authentication token. This indicates that authorization is not properly validated — the server may check for the presence of an Authorization header but not verify the token.`,
      evidence: `${v.method} ${v.endpoint}\nAuthorization: Bearer invalid_token_test_00000\nStatus: ${v.status}\nResponse: ${v.text}`,
      remediation: `Validate authentication tokens on every request. Verify token signature, expiration, and issuer before processing destructive operations.`,
      cwe: "CWE-287",
      owasp: "A07:2021",
      codeSnippet: `// Properly validate auth tokens\nexport async function ${v.method}(req: Request) {\n  const token = req.headers.get("Authorization")?.replace("Bearer ", "");\n  if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  try {\n    const payload = await verifyToken(token); // Verify signature + expiration\n    // ... handle authenticated ${v.method}\n  } catch {\n    return Response.json({ error: "Invalid token" }, { status: 401 });\n  }\n}`,
    });
  }

  return findings;
};
