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

  // ── Phase: HTTP Method Override via POST body (_method in form data) ──
  const bodyOverrideResults = await Promise.allSettled(
    endpoints.map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      try {
        const baseRes = await scanFetch(endpoint, { timeoutMs: 3000 });
        const baseStatus = baseRes.status;
        const baseText = await baseRes.text();

        for (const overrideMethod of ["DELETE", "PUT"]) {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `_method=${overrideMethod}`,
            timeoutMs: 3000,
          });

          if (res.ok && res.status !== baseStatus) {
            const text = await res.text();
            if (text.length < baseText.length * 0.5 || res.status === 204) {
              return {
                endpoint,
                pathname,
                overrideMethod,
                baseStatus,
                overrideStatus: res.status,
              };
            }
          }
        }
      } catch {
        // skip
      }
      return null;
    }),
  );

  for (const r of bodyOverrideResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `http-methods-body-override-${v.overrideMethod.toLowerCase()}-${findings.length}`,
      module: "HTTP Methods",
      severity: "medium",
      title: `HTTP method override via _method POST body on ${v.pathname}`,
      description: `The server accepts _method=${v.overrideMethod} in the POST body (form-encoded) to override the HTTP method. Frameworks like Rails and Laravel support this by default, allowing attackers to perform destructive operations through form submissions that bypass method-based access controls.`,
      evidence: `POST ${v.endpoint}\nContent-Type: application/x-www-form-urlencoded\nBody: _method=${v.overrideMethod}\nBaseline status: ${v.baseStatus}\nOverride status: ${v.overrideStatus}`,
      remediation: "Disable _method body parameter override in production or restrict it to authenticated sessions with CSRF protection.",
      cwe: "CWE-749",
      owasp: "A01:2021",
      codeSnippet: `// middleware.ts — reject _method in POST body\nexport async function middleware(req: NextRequest) {\n  if (req.method === "POST") {\n    const body = await req.text();\n    if (body.includes("_method=")) {\n      return new Response("Method override not allowed", { status: 400 });\n    }\n  }\n  return NextResponse.next();\n}`,
    });
  }

  // ── Phase: TRACK method enabled (XST variant) ──
  const trackResults = await Promise.allSettled(
    endpoints.map(async (endpoint) => {
      try {
        const probe = `TRACK-Probe-${Date.now()}`;
        const res = await scanFetch(endpoint, {
          method: "TRACK",
          headers: {
            "Cookie": `track_test=${probe}`,
            "Authorization": `Bearer ${probe}`,
          },
          timeoutMs: 3000,
        });
        if (res.ok) {
          const body = await res.text();
          const echoes = body.includes(probe) || body.includes("Cookie:") || body.includes("Authorization:");
          return { endpoint, pathname: new URL(endpoint).pathname, status: res.status, echoes, body: body.substring(0, 300) };
        }
      } catch {
        // skip
      }
      return null;
    }),
  );

  for (const r of trackResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `http-methods-track-${v.echoes ? "xst" : "active"}-${findings.length}`,
      module: "HTTP Methods",
      severity: v.echoes ? "high" : "medium",
      title: v.echoes
        ? `Cross-Site Tracing via TRACK method on ${v.pathname}`
        : `TRACK method active on ${v.pathname}`,
      description: v.echoes
        ? "The TRACK method echoes back request headers including cookies and authorization tokens. This is a variant of Cross-Site Tracing (XST) that can be exploited via XSS to steal HttpOnly cookies."
        : "The TRACK method (Microsoft IIS variant of TRACE) is enabled. This can be used for Cross-Site Tracing attacks to steal credentials.",
      evidence: `TRACK ${v.endpoint} → ${v.status}\nEchoes sensitive headers: ${v.echoes}\nResponse (truncated): ${v.body}`,
      remediation: "Disable the TRACK method in your web server configuration. On IIS, disable TRACK via request filtering.",
      cwe: v.echoes ? "CWE-693" : "CWE-749",
      owasp: "A05:2021",
      codeSnippet: `// middleware.ts — block TRACK requests\nif (req.method === "TRACK") return new Response(null, { status: 405 });`,
    });
  }

  // ── Phase: Arbitrary/WebDAV method handling ──
  const ARBITRARY_METHODS = ["PROPFIND", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK", "SEARCH"] as const;
  const arbitraryResults = await Promise.allSettled(
    endpoints.slice(0, 2).flatMap((endpoint) =>
      ARBITRARY_METHODS.map(async (method) => {
        try {
          const res = await scanFetch(endpoint, {
            method,
            headers: method === "PROPFIND" ? { Depth: "1", "Content-Type": "application/xml" } : {},
            timeoutMs: 3000,
          });
          // WebDAV methods returning 2xx or 207 Multi-Status indicate an enabled WebDAV surface
          if ((res.ok || res.status === 207) && res.status !== 404) {
            const text = await res.text();
            // Filter out generic error pages / frameworks that return 200 for everything
            if (text.length > 5 && !/not.?found|cannot|error|<!DOCTYPE/i.test(text.substring(0, 200))) {
              return { endpoint, pathname: new URL(endpoint).pathname, method, status: res.status, text: text.substring(0, 300) };
            }
          }
        } catch {
          // skip
        }
        return null;
      }),
    ),
  );

  const arbitrarySeen = new Set<string>();
  for (const r of arbitraryResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.method}`;
    if (arbitrarySeen.has(key)) continue;
    arbitrarySeen.add(key);
    const isWebDav = ["PROPFIND", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK"].includes(v.method);
    findings.push({
      id: `http-methods-arbitrary-${v.method.toLowerCase()}-${findings.length}`,
      module: "HTTP Methods",
      severity: isWebDav ? "medium" : "low",
      title: `${v.method} method returns data on ${v.pathname}`,
      description: isWebDav
        ? `The WebDAV method ${v.method} is accepted and returns a valid response. WebDAV exposes file management operations (create, move, copy, lock) that can be abused to enumerate directories, upload files, or modify server content.`
        : `The non-standard method ${v.method} returns a valid response. This may indicate misconfigured routing or an unintended attack surface that reveals server internals.`,
      evidence: `${v.method} ${v.endpoint} → ${v.status}\nResponse (truncated): ${v.text}`,
      remediation: isWebDav
        ? "Disable WebDAV if not needed. If required, restrict WebDAV methods to authenticated users and specific paths."
        : `Reject unknown HTTP methods with a 405 response. Only allow methods your application explicitly handles.`,
      cwe: isWebDav ? "CWE-749" : "CWE-200",
      owasp: "A05:2021",
      codeSnippet: `// middleware.ts — allowlist HTTP methods\nconst ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];\nexport function middleware(req: NextRequest) {\n  if (!ALLOWED_METHODS.includes(req.method)) {\n    return new Response(null, { status: 405, headers: { Allow: ALLOWED_METHODS.join(", ") } });\n  }\n  return NextResponse.next();\n}`,
    });
  }

  // ── Phase: HEAD vs GET information disclosure ──
  const headDisclosureResults = await Promise.allSettled(
    endpoints.map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      try {
        const [getRes, headRes] = await Promise.all([
          scanFetch(endpoint, { timeoutMs: 3000 }),
          scanFetch(endpoint, { method: "HEAD", timeoutMs: 3000 }),
        ]);

        const discrepancies: string[] = [];

        // Check for headers present in HEAD but absent in GET (or vice versa)
        const headHeaders = new Map<string, string>();
        const getHeaders = new Map<string, string>();
        headRes.headers.forEach((v, k) => headHeaders.set(k.toLowerCase(), v));
        getRes.headers.forEach((v, k) => getHeaders.set(k.toLowerCase(), v));

        // Sensitive headers that differ between HEAD and GET
        const sensitiveHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-debug", "x-runtime", "x-request-id", "x-backend", "x-served-by", "x-cache"];
        for (const h of sensitiveHeaders) {
          const headVal = headHeaders.get(h);
          const getVal = getHeaders.get(h);
          if (headVal && !getVal) {
            discrepancies.push(`HEAD exposes "${h}: ${headVal}" not present in GET`);
          }
        }

        // Status code mismatch can reveal different handling logic
        if (getRes.status !== headRes.status && headRes.status !== 405) {
          discrepancies.push(`Status mismatch: GET=${getRes.status}, HEAD=${headRes.status}`);
        }

        // Content-Length mismatch can reveal a different resource being served
        const getCL = getHeaders.get("content-length");
        const headCL = headHeaders.get("content-length");
        const getBody = await getRes.text();
        if (headCL && getCL && headCL !== getCL && Math.abs(parseInt(headCL) - parseInt(getCL)) > 100) {
          discrepancies.push(`Content-Length mismatch: GET=${getCL}, HEAD=${headCL} (actual body: ${getBody.length})`);
        }

        if (discrepancies.length > 0) {
          return { endpoint, pathname, discrepancies };
        }
      } catch {
        // skip
      }
      return null;
    }),
  );

  for (const r of headDisclosureResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `http-methods-head-disclosure-${findings.length}`,
      module: "HTTP Methods",
      severity: "low",
      title: `HEAD vs GET response inconsistency on ${v.pathname}`,
      description: "The server returns different headers or status codes for HEAD and GET requests to the same endpoint. This inconsistency may reveal server internals, backend architecture, or caching behavior that is stripped from normal GET responses.",
      evidence: `Endpoint: ${v.endpoint}\nDiscrepancies:\n${v.discrepancies.map((d) => `  - ${d}`).join("\n")}`,
      remediation: "Ensure HEAD responses mirror GET responses (same status code and headers, without the body). Review middleware and reverse proxy configuration for inconsistent header stripping.",
      cwe: "CWE-200",
      owasp: "A05:2021",
    });
  }

  // ── Phase: Method-based access control bypass ──
  const acBypassResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      try {
        // Step 1: Identify a protected endpoint (GET returns 401/403)
        const getRes = await scanFetch(endpoint, { timeoutMs: 3000 });
        const isProtected = getRes.status === 401 || getRes.status === 403;
        if (!isProtected) return null;

        const bypassMethods = ["POST", "PUT", "PATCH", "HEAD", "OPTIONS"] as const;
        const bypasses: { method: string; status: number; text: string }[] = [];

        const methodResults = await Promise.allSettled(
          bypassMethods.map(async (method) => {
            const res = await scanFetch(endpoint, {
              method,
              headers: method !== "HEAD" && method !== "OPTIONS" ? { "Content-Type": "application/json" } : {},
              body: ["POST", "PUT", "PATCH"].includes(method) ? JSON.stringify({}) : undefined,
              timeoutMs: 3000,
            });
            return { method, status: res.status, text: (await res.text()).substring(0, 200) };
          }),
        );

        for (const mr of methodResults) {
          if (mr.status !== "fulfilled") continue;
          const m = mr.value;
          // If a different method bypasses the auth check (returns 2xx instead of 401/403)
          if (m.status >= 200 && m.status < 300 && m.text.length > 5) {
            // Filter out generic OPTIONS responses and empty HEAD responses
            if (m.method === "OPTIONS" || (m.method === "HEAD" && m.text.length === 0)) continue;
            if (!/unauthorized|unauthenticated|forbidden|login|sign.?in/i.test(m.text)) {
              bypasses.push(m);
            }
          }
        }

        if (bypasses.length > 0) {
          return { endpoint, pathname, getStatus: getRes.status, bypasses };
        }
      } catch {
        // skip
      }
      return null;
    }),
  );

  for (const r of acBypassResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    for (const bypass of v.bypasses) {
      findings.push({
        id: `http-methods-ac-bypass-${bypass.method.toLowerCase()}-${findings.length}`,
        module: "HTTP Methods",
        severity: "high",
        title: `Access control bypass via ${bypass.method} on ${v.pathname}`,
        description: `The endpoint returns ${v.getStatus} (protected) for GET requests but ${bypass.status} (success) for ${bypass.method}. This indicates that authentication or authorization is only enforced for certain HTTP methods, allowing attackers to bypass access controls by switching the request method.`,
        evidence: `GET ${v.endpoint} → ${v.getStatus} (blocked)\n${bypass.method} ${v.endpoint} → ${bypass.status} (allowed)\nResponse: ${bypass.text}`,
        remediation: `Enforce authentication and authorization checks consistently across all HTTP methods. Apply auth middleware before routing to method-specific handlers.`,
        cwe: "CWE-287",
        owasp: "A01:2021",
        codeSnippet: `// Apply auth BEFORE method routing\nexport async function middleware(req: NextRequest) {\n  // Auth check runs for ALL methods\n  const session = await getSession(req);\n  if (!session && isProtectedRoute(req.nextUrl.pathname)) {\n    return Response.json({ error: "Unauthorized" }, { status: 401 });\n  }\n  return NextResponse.next();\n}`,
      });
    }
  }

  return findings;
};
