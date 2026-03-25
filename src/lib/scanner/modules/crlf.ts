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

  // Phase 5: Unicode CRLF variants — bypass WAFs using Unicode line separators
  const unicodePayloads = [
    { payload: "%E5%98%8A%E5%98%8DX-Injected:%20true", name: "Unicode LS/PS bypass (U+560A/U+560D)" },
    { payload: "%0D%20%0AX-Injected:%20true", name: "Space insertion bypass (CR SP LF)" },
    { payload: "%0D%09%0AX-Injected:%20true", name: "Tab insertion bypass (CR TAB LF)" },
  ];

  const unicodeEndpoints = [target.url, ...target.pages.slice(0, 3), ...target.apiEndpoints.slice(0, 3)];
  const unicodeResults = await Promise.allSettled(
    unicodeEndpoints.flatMap((endpoint) => {
      try {
        const url = new URL(endpoint);
        const pathname = url.pathname;
        const params = [...url.searchParams.keys()];
        const testParams = params.length > 0 ? params.slice(0, 2) : CRLF_PARAMS.slice(0, 2);

        return testParams.flatMap((param) =>
          unicodePayloads.map(async ({ payload, name }) => {
            try {
              const testUrl = new URL(endpoint);
              testUrl.searchParams.set(param, payload);
              const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });
              const injected = res.headers.get("x-injected");
              if (injected) {
                return { pathname, param, payload, name };
              }

              // Also test in path segment
              const pathUrl = `${url.origin}${pathname}/${payload}`;
              const pathRes = await scanFetch(pathUrl, { timeoutMs: 5000 });
              if (pathRes.headers.get("x-injected")) {
                return { pathname, param: "(path)", payload, name };
              }
            } catch { /* skip */ }
            return null;
          }),
        );
      } catch { return []; }
    }),
  );

  const unicodeSeen = new Set<string>();
  for (const r of unicodeResults) {
    if (findings.length >= 10) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.name}`;
    if (unicodeSeen.has(key)) continue;
    unicodeSeen.add(key);
    findings.push({
      id: `crlf-unicode-${findings.length}`,
      module: "CRLF Injection",
      severity: "high",
      title: `Unicode CRLF bypass on ${v.pathname} (${v.name})`,
      description: `CRLF injection succeeds using Unicode line separator variants (${v.name}). This bypasses WAFs and input filters that only check for standard %0d%0a sequences. The server decodes Unicode characters into line breaks before processing headers.`,
      evidence: `${v.param === "(path)" ? `GET ${v.pathname}/${v.payload}` : `GET ${v.pathname}?${v.param}=${v.payload}`}\nBypass: ${v.name}\nInjected: X-Injected header present`,
      remediation: "Sanitize input after full Unicode normalization and URL decoding. Check for all Unicode line separator characters (U+2028, U+2029, U+560A, U+560D) in addition to CR/LF. Apply multiple rounds of decoding before validation.",
      cwe: "CWE-93",
      owasp: "A03:2021",
      confidence: 95,
      codeSnippet: `// Sanitize all line-break variants including Unicode\nfunction sanitizeCrlf(value: string): string {\n  return value.replace(\n    /[\\r\\n\\u2028\\u2029\\u560a\\u560d]/g, ""\n  );\n}`,
    });
  }

  // Phase 6: Double URL-encoded CRLF — bypass single-decode sanitization
  const doubleEncodedPayloads = [
    { payload: "%250d%250aX-Injected:%20true", name: "double-encoded %0d%0a" },
    { payload: "%250d%250aSet-Cookie:%20crlfdouble=injected", name: "double-encoded Set-Cookie" },
  ];

  const doubleEncEndpoints = [target.url, ...target.pages.slice(0, 3), ...target.apiEndpoints.slice(0, 3)];
  const doubleEncResults = await Promise.allSettled(
    doubleEncEndpoints.flatMap((endpoint) => {
      try {
        const url = new URL(endpoint);
        const pathname = url.pathname;
        const params = [...url.searchParams.keys()];
        const testParams = params.length > 0 ? params.slice(0, 2) : CRLF_PARAMS.slice(0, 2);

        return [
          // Test in query parameters
          ...testParams.flatMap((param) =>
            doubleEncodedPayloads.map(async ({ payload, name }) => {
              try {
                const testUrl = new URL(endpoint);
                testUrl.searchParams.set(param, payload);
                const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });
                const injected = res.headers.get("x-injected");
                const cookieInjected = (res.headers.get("set-cookie") || "").includes("crlfdouble=injected");
                if (injected || cookieInjected) {
                  return { pathname, param, name, injected: injected ? "header" : "cookie", location: "param" as const };
                }
              } catch { /* skip */ }
              return null;
            }),
          ),
          // Test in path
          ...doubleEncodedPayloads.map(async ({ payload, name }) => {
            try {
              const pathUrl = `${url.origin}${pathname}/${payload}`;
              const res = await scanFetch(pathUrl, { timeoutMs: 5000 });
              const injected = res.headers.get("x-injected");
              const cookieInjected = (res.headers.get("set-cookie") || "").includes("crlfdouble=injected");
              if (injected || cookieInjected) {
                return { pathname, param: "(path)", name, injected: injected ? "header" : "cookie", location: "path" as const };
              }
            } catch { /* skip */ }
            return null;
          }),
        ];
      } catch { return []; }
    }),
  );

  const doubleEncSeen = new Set<string>();
  for (const r of doubleEncResults) {
    if (findings.length >= 12) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.name}`;
    if (doubleEncSeen.has(key)) continue;
    doubleEncSeen.add(key);
    findings.push({
      id: `crlf-double-enc-${findings.length}`,
      module: "CRLF Injection",
      severity: "high",
      title: `Double-encoded CRLF injection on ${v.pathname} (${v.name})`,
      description: `CRLF injection succeeds using double URL-encoded sequences (%250d%250a). This indicates the server decodes URL encoding twice — once during routing and again when processing the value. Single-decode sanitization is bypassed because %250d is decoded to %0d after the first pass, then to \\r on the second.`,
      evidence: `${v.location === "path" ? `GET ${v.pathname}/${v.name}` : `GET ${v.pathname}?${v.param}=${v.name}`}\nInjected: ${v.injected}`,
      remediation: "Sanitize input after all decoding is complete, not between decode steps. Avoid double-decoding URL parameters. Validate at the last point before use in headers.",
      cwe: "CWE-93",
      owasp: "A03:2021",
      confidence: 95,
      codeSnippet: `// Decode fully then sanitize — don't sanitize between decode steps\nfunction safeDecode(value: string): string {\n  let decoded = value;\n  let prev = "";\n  while (decoded !== prev) {\n    prev = decoded;\n    decoded = decodeURIComponent(decoded);\n  }\n  return decoded.replace(/[\\r\\n]/g, "");\n}`,
    });
  }

  // Phase 7: HTTP response splitting via Referer/User-Agent headers
  const headerInjectionPayloads = [
    "%0d%0aX-Injected: true",
    "%0d%0aSet-Cookie: crlfheader=injected",
  ];

  const headerInjectionEndpoints = [target.url, ...target.pages.slice(0, 3), ...target.apiEndpoints.slice(0, 3)];
  const headerInjectionResults = await Promise.allSettled(
    headerInjectionEndpoints.flatMap((endpoint) => {
      const pathname = new URL(endpoint).pathname;
      return [
        // Test Referer header
        ...headerInjectionPayloads.map(async (payload) => {
          try {
            const res = await scanFetch(endpoint, {
              headers: { Referer: `https://example.com/${payload}` },
              timeoutMs: 5000,
            });
            const injected = res.headers.get("x-injected");
            const cookieInjected = (res.headers.get("set-cookie") || "").includes("crlfheader=injected");
            if (injected || cookieInjected) {
              return { pathname, header: "Referer", injected: injected ? "header" : "cookie" };
            }
          } catch { /* skip */ }
          return null;
        }),
        // Test User-Agent header
        ...headerInjectionPayloads.map(async (payload) => {
          try {
            const res = await scanFetch(endpoint, {
              headers: { "User-Agent": `Mozilla/5.0 ${payload}` },
              timeoutMs: 5000,
            });
            const injected = res.headers.get("x-injected");
            const cookieInjected = (res.headers.get("set-cookie") || "").includes("crlfheader=injected");
            if (injected || cookieInjected) {
              return { pathname, header: "User-Agent", injected: injected ? "header" : "cookie" };
            }
          } catch { /* skip */ }
          return null;
        }),
      ];
    }),
  );

  const headerInjSeen = new Set<string>();
  for (const r of headerInjectionResults) {
    if (findings.length >= 14) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.header}`;
    if (headerInjSeen.has(key)) continue;
    headerInjSeen.add(key);
    findings.push({
      id: `crlf-header-inj-${findings.length}`,
      module: "CRLF Injection",
      severity: "high",
      title: `CRLF injection via ${v.header} header on ${v.pathname}`,
      description: `The server reflects the ${v.header} request header into response headers without sanitizing CRLF characters. Attackers can inject arbitrary headers by crafting a malicious ${v.header} value. Since ${v.header} is automatically sent by browsers, this can be exploited via a redirect from an attacker-controlled page.`,
      evidence: `GET ${v.pathname}\n${v.header}: ...%0d%0aX-Injected: true\nInjected: ${v.injected}`,
      remediation: `Never reflect the ${v.header} header into response headers. If logging or analytics require these values, sanitize all CRLF characters before use. Apply output encoding at the HTTP header layer.`,
      cwe: "CWE-113",
      owasp: "A03:2021",
      confidence: 95,
      codeSnippet: `// Sanitize request headers before reflecting\nconst referer = req.headers.get("referer") || "";\nconst safeReferer = referer.replace(/[\\r\\n]/g, "");\n// Never: res.setHeader("X-Original-Referer", req.headers.referer)`,
    });
  }

  return findings;
};
