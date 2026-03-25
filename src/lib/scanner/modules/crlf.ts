import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const CRLF_PAYLOADS = [
  "%0d%0aX-Injected: true",
  "%0d%0aSet-Cookie: crlf=injected",
  "\r\nX-Injected: true",
  "%0d%0a%0d%0a<script>alert(1)</script>",
  "%E5%98%8D%E5%98%8AX-Injected: true", // Unicode CRLF variant
  "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a", // Response splitting
  "%0a%20X-Injected: true", // LF + space continuation
  "%0d%0aLocation: https://evil.com", // Redirect injection
];

const CRLF_PARAMS = ["url", "redirect", "return", "next", "dest", "path", "page", "view", "callback", "q", "search", "ref", "lang", "locale", "utm_source"];

interface CrlfTest {
  endpoint: string;
  pathname: string;
  param: string;
  payload: string;
}

export const crlfModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const tested = new Set<string>();

  const endpoints = [target.url, ...target.pages.slice(0, 5), ...target.apiEndpoints.slice(0, 5)];

  // Build all test cases upfront
  const tests: CrlfTest[] = [];
  for (const endpoint of endpoints) {
    try {
      const url = new URL(endpoint);
      const pathname = url.pathname;
      if (tested.has(pathname)) continue;
      tested.add(pathname);

      const params = [...url.searchParams.keys()];
      const testParams = params.length > 0 ? params.slice(0, 3) : CRLF_PARAMS.slice(0, 3);

      for (const param of testParams) {
        for (const payload of CRLF_PAYLOADS.slice(0, 3)) {
          tests.push({ endpoint, pathname, param, payload });
        }
      }
    } catch { /* skip */ }
  }

  const results = await Promise.allSettled(
    tests.map(async ({ endpoint, pathname, param, payload }) => {
      const testUrl = new URL(endpoint);
      testUrl.searchParams.set(param, payload);
      const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });

      const injectedHeader = res.headers.get("x-injected");
      const injectedCookie = (res.headers.get("set-cookie") || "").includes("crlf=injected");

      if (injectedHeader || injectedCookie) {
        return {
          type: "header" as const,
          pathname, param, payload, injectedHeader,
        };
      }

      const text = await res.text();
      if (text.includes("\nX-Injected: true") && payload.includes("X-Injected")) {
        return { type: "split" as const, pathname, param, payload };
      }

      return null;
    }),
  );

  const seenPaths = new Set<string>();
  for (const r of results) {
    if (findings.length >= 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.param}`;
    if (seenPaths.has(key)) continue;
    seenPaths.add(key);

    if (v.type === "header") {
      findings.push({
        id: `crlf-${findings.length}`,
        module: "CRLF Injection",
        severity: "high",
        title: `CRLF injection on ${v.pathname} (param: ${v.param})`,
        description: "HTTP response headers can be injected via CRLF characters in user input. Attackers can set arbitrary cookies, redirect users, or perform response splitting attacks.",
        evidence: `Payload: ${v.param}=${v.payload}\n${v.injectedHeader ? `Injected header: X-Injected: ${v.injectedHeader}` : `Injected cookie: crlf=injected`}`,
        remediation: "Strip or encode \\r\\n characters from all user input before using it in HTTP headers or redirects. Use framework-provided redirect functions that handle encoding.",
        codeSnippet: `// Sanitize header values before setting them
function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\\r\\n]+/g, "");
}
res.setHeader("Location", sanitizeHeaderValue(userInput));`,
        cwe: "CWE-93",
        owasp: "A03:2021",
      });
    } else {
      findings.push({
        id: `crlf-split-${findings.length}`,
        module: "CRLF Injection",
        severity: "medium",
        title: `HTTP response splitting on ${v.pathname} (param: ${v.param})`,
        description: "CRLF characters in input cause content injection in the HTTP response body. This indicates the server doesn't strip newline characters from user input.",
        evidence: `Payload: ${v.param}=${v.payload}\nInjected content appears on its own line in response body`,
        remediation: "Strip or encode \\r\\n characters from all user input. Use framework-provided response methods.",
        codeSnippet: `// Strip CRLF sequences from user-controlled values
const safe = input.replace(/\\r?\\n|\\r/g, "");
// Or use encodeURIComponent for redirect targets
res.redirect(encodeURIComponent(userPath));`,
        cwe: "CWE-113",
        owasp: "A03:2021",
      });
    }
  }

  // Phase 2: Test POST body parameters for CRLF
  const postEndpoints = target.apiEndpoints.slice(0, 5);
  const postResults = await Promise.allSettled(
    postEndpoints.map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      if (seenPaths.has(`${pathname}:body`)) return null;

      for (const payload of CRLF_PAYLOADS.slice(0, 4)) {
        try {
          // Test JSON body with CRLF in values
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: `test${payload}`, url: payload }),
            timeoutMs: 5000,
          });

          const injectedHeader = res.headers.get("x-injected");
          const injectedCookie = (res.headers.get("set-cookie") || "").includes("crlf=injected");
          const locationHeader = res.headers.get("location") || "";
          const locationInjected = locationHeader.includes("evil.com");

          if (injectedHeader || injectedCookie || locationInjected) {
            return { pathname, payload, injectedHeader, injectedCookie, locationInjected };
          }
        } catch { /* skip */ }
      }
      return null;
    }),
  );

  for (const r of postResults) {
    if (findings.length >= 5) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    seenPaths.add(`${v.pathname}:body`);
    findings.push({
      id: `crlf-post-${findings.length}`,
      module: "CRLF Injection",
      severity: "high",
      title: `CRLF injection via POST body on ${v.pathname}`,
      description: "HTTP response headers can be injected via CRLF characters in POST body values. The server reflects user input into response headers without sanitizing newline characters.",
      evidence: `POST ${v.pathname} with CRLF in body\n${v.injectedHeader ? "Injected X-Injected header" : v.locationInjected ? "Injected Location redirect" : "Injected Set-Cookie header"}`,
      remediation: "Sanitize all user input before reflecting it in response headers. Strip \\r and \\n characters from any value used in HTTP headers.",
      cwe: "CWE-93", owasp: "A03:2021",
      confidence: 95,
      codeSnippet: `// Middleware to sanitize response headers\nexport function middleware(req: NextRequest) {\n  const res = NextResponse.next();\n  // Ensure no user input in headers contains CRLF\n  const sanitize = (v: string) => v.replace(/[\\r\\n]/g, "");\n  // Apply to any header set from user input\n  return res;\n}`,
    });
  }

  // Phase 3: Path-based CRLF injection — inject in URL path instead of query params
  const pathPayloads = [
    "%0d%0aX-Injected:%20true",
    "%0d%0aSet-Cookie:%20crlfpath=injected",
    "%E5%98%8D%E5%98%8AX-Injected:%20true",
  ];

  const pathEndpoints = [target.url, ...target.pages.slice(0, 3)];
  const pathResults = await Promise.allSettled(
    pathEndpoints.flatMap((endpoint) =>
      pathPayloads.map(async (payload) => {
        try {
          const base = new URL(endpoint);
          const testUrl = `${base.origin}${base.pathname}/${payload}`;
          const res = await scanFetch(testUrl, { timeoutMs: 5000 });
          const injected = res.headers.get("x-injected");
          const cookieInjected = (res.headers.get("set-cookie") || "").includes("crlfpath=injected");
          if (injected || cookieInjected) {
            return { pathname: base.pathname, payload, injected: injected ? "header" : "cookie" };
          }
        } catch { /* skip */ }
        return null;
      }),
    ),
  );

  const pathSeen = new Set<string>();
  for (const r of pathResults) {
    if (findings.length >= 7) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (pathSeen.has(v.pathname)) continue;
    pathSeen.add(v.pathname);
    findings.push({
      id: `crlf-path-${findings.length}`,
      module: "CRLF Injection",
      severity: "high",
      title: `Path-based CRLF injection on ${v.pathname}`,
      description: "CRLF characters in the URL path inject HTTP response headers. This is harder to detect than query parameter injection since WAFs often only inspect query strings. Attackers can use this for cache poisoning or session fixation.",
      evidence: `GET ${v.pathname}/${v.payload}\nInjected: ${v.injected}`,
      remediation: "URL-decode and sanitize the full request path, not just query parameters. Ensure your reverse proxy or framework rejects paths containing %0d or %0a sequences.",
      cwe: "CWE-93",
      owasp: "A03:2021",
      confidence: 95,
      codeSnippet: `// Middleware to reject CRLF in paths\nexport function middleware(req: NextRequest) {\n  const decoded = decodeURIComponent(req.nextUrl.pathname);\n  if (/[\\r\\n]/.test(decoded)) {\n    return new NextResponse("Bad Request", { status: 400 });\n  }\n}`,
    });
  }

  // Phase 4: CRLF via Cookie header — test if cookie values are reflected in response headers
  const cookiePayloads = [
    "test%0d%0aX-Injected: true",
    "test\r\nX-Injected: true",
  ];

  const cookieResults = await Promise.allSettled(
    [target.url, ...target.apiEndpoints.slice(0, 3)].map(async (endpoint) => {
      for (const payload of cookiePayloads) {
        try {
          const res = await scanFetch(endpoint, {
            headers: { Cookie: `session=${payload}; test=${payload}` },
            timeoutMs: 5000,
          });
          if (res.headers.get("x-injected")) {
            return { endpoint: new URL(endpoint).pathname };
          }
        } catch { /* skip */ }
      }
      return null;
    }),
  );

  for (const r of cookieResults) {
    if (findings.length >= 8) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `crlf-cookie-${findings.length}`,
      module: "CRLF Injection",
      severity: "high",
      title: `CRLF injection via Cookie header on ${r.value.endpoint}`,
      description: "CRLF characters in cookie values inject HTTP response headers. Attackers who control a subdomain cookie or exploit an XSS vulnerability can use this to set arbitrary response headers, enabling cache poisoning or session fixation.",
      evidence: `Cookie: session=test%0d%0aX-Injected: true → X-Injected header present`,
      remediation: "Sanitize cookie values before reflecting them in response headers. Most frameworks handle this automatically — ensure you're not manually concatenating cookie values into headers.",
      cwe: "CWE-113",
      owasp: "A03:2021",
      confidence: 95,
    });
  }

  return findings;
};
