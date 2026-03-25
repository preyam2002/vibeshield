import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const REDIRECT_PARAMS = [
  "redirect", "redirect_uri", "redirect_url", "return", "returnUrl",
  "return_to", "returnTo", "next", "url", "target", "rurl",
  "dest", "destination", "redir", "redirect_to", "callback",
  "callbackUrl", "go", "goto", "link", "navigate",
  "next_url", "back_url", "back", "continue", "continueTo",
  "forward", "to", "out", "view", "login_redirect",
  "fallback", "exit_url", "service_url", "ref",
];

const EVIL_URLS = [
  "https://evil.com",
  "//evil.com",
  "/\\evil.com",
  "https://evil.com%00.legitimate.com",
  "https://legitimate.com@evil.com",
  "https://evil.com#.legitimate.com",
  "https://evil.com?.legitimate.com",
  "//evil.com/%2f..",
  // Additional bypass variants
  "javascript:alert(1)",                    // JS protocol
  "data:text/html,<h1>phished</h1>",       // data: URI
  "%2f%2fevil.com",                         // double-encoded //
  "https://evil.com%09.legitimate.com",     // tab injection
  "///evil.com",                            // triple slash
  "https:evil.com",                         // missing slashes
  "//%0d%0aevil.com",                       // CRLF in URL
];

// Phase-specific payloads for targeted testing
const PROTOCOL_RELATIVE_PAYLOADS = [
  "//evil.com",
  "///evil.com",
  "/\\evil.com",
  "\\/evil.com",
  "//evil.com/%2f..",
  "%2f%2fevil.com",
  "/%2fevil.com",
  "\\\\evil.com",
  "//evil.com/..;/",
];

const DATA_URI_PAYLOADS = [
  "data:text/html,<script>alert(1)</script>",
  "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
  "data:text/html,<h1>phished</h1>",
  "javascript:alert(1)",
  "javascript:alert(document.domain)",
  "javascript://evil.com/%0aalert(1)",
  "jAvAsCrIpT:alert(1)",                   // mixed case bypass
  "java%0ascript:alert(1)",                 // newline in protocol
];

const PARAM_POLLUTION_PAYLOADS: { payload: string; label: string }[] = [
  { payload: "@evil.com", label: "credential-section injection" },
  { payload: "%00evil.com", label: "null byte injection" },
  { payload: "%0d%0aLocation: https://evil.com", label: "CRLF header injection" },
  { payload: "?@evil.com", label: "query-based credential injection" },
  { payload: "#@evil.com", label: "fragment-based credential injection" },
  { payload: "%23@evil.com", label: "encoded fragment injection" },
];

export const openRedirectModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Test redirect parameters on pages and endpoints — all URLs in parallel
  const testUrls = [target.url, ...target.pages.slice(0, 5), ...target.apiEndpoints.slice(0, 5)];
  const foundPaths = new Set<string>();
  const MAX_FINDINGS = 3;
  const firstEvil = EVIL_URLS[0];

  // Deduplicate by pathname
  const urlsByPath = new Map<string, string>();
  for (const u of testUrls) {
    const p = new URL(u).pathname;
    if (!urlsByPath.has(p)) urlsByPath.set(p, u);
  }

  const isEvilRedirect = (location: string, origin: string): boolean => {
    try { return new URL(location, origin).hostname === "evil.com"; }
    catch { return /^(https?:)?\/\/evil\.com(\/|$)/i.test(location); }
  };
  const isJsOrDataRedirect = (location: string): boolean =>
    /^javascript:/i.test(location) || /^data:/i.test(location);

  const allParamTests = await Promise.allSettled(
    [...urlsByPath.entries()].flatMap(([pathname, baseUrl]) =>
      REDIRECT_PARAMS.slice(0, 8).map(async (param) => {
        // Try each bypass variant until one works
        for (const evilUrl of EVIL_URLS) {
          const url = new URL(baseUrl);
          url.searchParams.set(param, evilUrl);
          const res = await scanFetch(url.href, { redirect: "manual", timeoutMs: 4000 });
          if (res.status < 300 || res.status >= 400) continue;
          const location = res.headers.get("location") || "";
          if (isEvilRedirect(location, new URL(baseUrl).origin) || isJsOrDataRedirect(location)) {
            const bypass = evilUrl === "https://evil.com" ? "direct" : evilUrl.startsWith("javascript:") ? "javascript: protocol" : evilUrl.startsWith("data:") ? "data: URI" : evilUrl.includes("@") ? "credential injection" : evilUrl.includes("%") ? "URL encoding" : evilUrl.includes("\\") ? "backslash" : "bypass variant";
            return { param, pathname, location, testUrl: url.href, bypass, evilUrl };
          }
        }
        return null;
      }),
    ),
  );

  for (const r of allParamTests) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { param, pathname, location, testUrl, bypass, evilUrl } = r.value;
    if (foundPaths.has(pathname)) continue;
    foundPaths.add(pathname);
    const isJsProtocol = evilUrl.startsWith("javascript:");
    findings.push({
      id: `openredirect-${findings.length}`,
      module: "Open Redirect",
      severity: isJsProtocol ? "high" : "medium",
      title: `Open redirect${bypass !== "direct" ? ` (${bypass})` : ""} via "${param}" parameter on ${pathname}`,
      description: isJsProtocol
        ? "This endpoint redirects to javascript: URIs. Attackers can execute arbitrary JavaScript in the context of your domain, enabling session theft."
        : `This endpoint redirects to arbitrary external URLs${bypass !== "direct" ? ` using a ${bypass} technique that bypasses URL validation` : ""}. Attackers can craft phishing links using your domain.`,
      evidence: `GET ${testUrl}\nLocation: ${location}`,
      remediation: "Validate redirect URLs against a whitelist of allowed domains. Never redirect to user-controlled URLs.",
      cwe: "CWE-601",
      owasp: "A01:2021",
      codeSnippet: `// Validate redirect URL\nconst ALLOWED_HOSTS = [new URL(process.env.APP_URL!).hostname];\nconst redirectUrl = new URL(userInput, process.env.APP_URL);\nif (!ALLOWED_HOSTS.includes(redirectUrl.hostname)) {\n  return Response.redirect(process.env.APP_URL!);\n}\nreturn Response.redirect(redirectUrl.href);`,
    });
  }

  // Also check existing redirect-looking URLs in parallel
  const redirectTests: { link: string; param: string; val: string }[] = [];
  for (const link of target.linkUrls.slice(0, 20)) {
    try {
      const url = new URL(link);
      for (const param of REDIRECT_PARAMS) {
        if (url.searchParams.has(param)) {
          const val = url.searchParams.get(param) || "";
          if (val.startsWith("http") || val.startsWith("//")) {
            redirectTests.push({ link, param, val });
          }
        }
      }
    } catch { /* skip */ }
  }

  const redirectResults = await Promise.allSettled(
    redirectTests.map(async ({ link, param, val }) => {
      const url = new URL(link);
      url.searchParams.set(param, "https://evil.com");
      const res = await scanFetch(url.href, { redirect: "manual", timeoutMs: 5000 });
      if (res.status < 300 || res.status >= 400) return null;
      const location = res.headers.get("location") || "";
      const isExternal = (() => {
        try { return new URL(location, url.origin).hostname === "evil.com"; }
        catch { return /^(https?:)?\/\/evil\.com(\/|$)/i.test(location); }
      })();
      return isExternal ? { param, val } : null;
    }),
  );

  for (const r of redirectResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `openredirect-existing-${findings.length}`,
      module: "Open Redirect",
      severity: "medium",
      title: `Open redirect in existing URL parameter "${r.value.param}"`,
      description: "A URL with a redirect parameter accepts arbitrary external URLs.",
      evidence: `Original URL had ${r.value.param}=${r.value.val}\nModified to evil.com → redirected`,
      remediation: "Validate redirect targets against a whitelist.",
      cwe: "CWE-601",
      codeSnippet: `// Validate redirect URLs\nconst ALLOWED_HOSTS = new Set(["yourdomain.com"]);\nconst target = new URL(redirectUrl, req.url);\nif (!ALLOWED_HOSTS.has(target.hostname)) {\n  return Response.redirect("/", 302);\n}`,
    });
  }

  // Phase 3: Protocol-relative redirect bypass
  // Test payloads like //evil.com, ///evil.com, /\evil.com — common WAF bypasses
  if (findings.length < MAX_FINDINGS) {
    const protocolRelativeResults = await Promise.allSettled(
      [...urlsByPath.entries()].slice(0, 4).flatMap(([pathname, baseUrl]) =>
        REDIRECT_PARAMS.slice(0, 6).map(async (param) => {
          for (const payload of PROTOCOL_RELATIVE_PAYLOADS) {
            const url = new URL(baseUrl);
            url.searchParams.set(param, payload);
            try {
              const res = await scanFetch(url.href, { redirect: "manual", timeoutMs: 4000 });
              if (res.status < 300 || res.status >= 400) continue;
              const location = res.headers.get("location") || "";
              if (isEvilRedirect(location, new URL(baseUrl).origin)) {
                return { param, pathname, location, payload, testUrl: url.href };
              }
            } catch { continue; }
          }
          return null;
        }),
      ),
    );

    for (const r of protocolRelativeResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const { param, pathname, location, payload, testUrl } = r.value;
      if (foundPaths.has(`proto-${pathname}`)) continue;
      foundPaths.add(`proto-${pathname}`);
      const technique = payload.startsWith("///") ? "triple-slash" : payload.includes("\\") ? "backslash" : payload.includes("%") ? "URL-encoded" : "protocol-relative";
      findings.push({
        id: `openredirect-proto-${findings.length}`,
        module: "Open Redirect",
        severity: "medium",
        title: `Protocol-relative open redirect (${technique}) via "${param}" on ${pathname}`,
        description: `This endpoint follows ${technique} redirect payloads to external domains. Protocol-relative URLs (//evil.com) and backslash variants (/\\evil.com) are commonly used to bypass WAF rules and URL validation that only checks for "http://" or "https://" prefixes.`,
        evidence: `GET ${testUrl}\nPayload: ${payload}\nLocation: ${location}`,
        remediation: "Normalize URLs before validation. Strip leading slashes and backslashes, then verify the resolved hostname against an allowlist. Reject any URL that does not start with a known safe path or origin.",
        cwe: "CWE-601",
        owasp: "A01:2021",
        confidence: 90,
        codeSnippet: `// Normalize and validate redirect URLs\nfunction isSafeRedirect(input: string, origin: string): boolean {\n  // Strip protocol-relative and backslash tricks\n  const normalized = input.replace(/^[\\\\/]+/, "/");\n  try {\n    const url = new URL(normalized, origin);\n    return url.origin === origin;\n  } catch { return false; }\n}`,
      });
    }
  }

  // Phase 4: Data URI and javascript: protocol redirect
  // Test data:text/html and javascript: payloads — can lead to XSS via redirect
  if (findings.length < MAX_FINDINGS) {
    const dataUriResults = await Promise.allSettled(
      [...urlsByPath.entries()].slice(0, 4).flatMap(([pathname, baseUrl]) =>
        REDIRECT_PARAMS.slice(0, 6).map(async (param) => {
          for (const payload of DATA_URI_PAYLOADS) {
            const url = new URL(baseUrl);
            url.searchParams.set(param, payload);
            try {
              const res = await scanFetch(url.href, { redirect: "manual", timeoutMs: 4000 });
              if (res.status < 300 || res.status >= 400) continue;
              const location = res.headers.get("location") || "";
              if (/^(javascript|data):/i.test(location)) {
                return { param, pathname, location, payload, testUrl: url.href };
              }
            } catch { continue; }
          }
          return null;
        }),
      ),
    );

    for (const r of dataUriResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const { param, pathname, location, payload, testUrl } = r.value;
      if (foundPaths.has(`datauri-${pathname}`)) continue;
      foundPaths.add(`datauri-${pathname}`);
      const isJs = /^javascript:/i.test(location);
      findings.push({
        id: `openredirect-datauri-${findings.length}`,
        module: "Open Redirect",
        severity: "high",
        title: `${isJs ? "javascript:" : "data:"} URI redirect via "${param}" on ${pathname}`,
        description: isJs
          ? `This endpoint redirects to javascript: URIs, allowing arbitrary JavaScript execution in the context of your domain. This is effectively a reflected XSS via open redirect — attackers can steal session tokens, cookies, and user data.`
          : `This endpoint redirects to data: URIs, which can render arbitrary HTML/JavaScript content. Attackers can craft data: URIs containing phishing pages or malicious scripts that execute in a privileged context.`,
        evidence: `GET ${testUrl}\nPayload: ${payload}\nLocation: ${location}`,
        remediation: isJs
          ? "Block all javascript: URIs in redirect targets. Validate that redirect URLs use only http: or https: protocols before issuing the redirect."
          : "Block data: URIs in redirect targets. Validate that redirect URLs use only http: or https: protocols. Consider using a Content-Security-Policy with strict navigate-to directives.",
        cwe: isJs ? "CWE-79" : "CWE-601",
        owasp: "A01:2021",
        confidence: 95,
        codeSnippet: `// Block dangerous URI schemes in redirects\nconst SAFE_PROTOCOLS = new Set(["http:", "https:"]);\nfunction validateRedirect(input: string, origin: string): string {\n  try {\n    const url = new URL(input, origin);\n    if (!SAFE_PROTOCOLS.has(url.protocol)) return "/";\n    if (url.origin !== origin) return "/";\n    return url.href;\n  } catch { return "/"; }\n}`,
      });
    }
  }

  // Phase 5: URL parameter pollution — @evil.com suffix, null byte injection, CRLF
  if (findings.length < MAX_FINDINGS) {
    const paramPollutionResults = await Promise.allSettled(
      [...urlsByPath.entries()].slice(0, 4).flatMap(([pathname, baseUrl]) =>
        REDIRECT_PARAMS.slice(0, 6).map(async (param) => {
          const origin = new URL(baseUrl).origin;
          for (const { payload, label } of PARAM_POLLUTION_PAYLOADS) {
            const url = new URL(baseUrl);
            // Build the polluted redirect value: prepend the target origin for @-based attacks
            const fullPayload = payload.startsWith("@") || payload.startsWith("?@") || payload.startsWith("#@") || payload.startsWith("%23@")
              ? `${origin}${payload}`
              : payload;
            url.searchParams.set(param, fullPayload);
            try {
              const res = await scanFetch(url.href, { redirect: "manual", timeoutMs: 4000 });
              if (res.status < 300 || res.status >= 400) continue;
              const location = res.headers.get("location") || "";
              // Check if the redirect landed on evil.com or if CRLF injected a new Location header
              if (isEvilRedirect(location, origin) || (/evil\.com/i.test(location) && label.includes("CRLF"))) {
                return { param, pathname, location, payload: fullPayload, label, testUrl: url.href };
              }
              // For null byte injection, check if the server truncated the URL
              if (label === "null byte injection" && location && !location.includes(new URL(baseUrl).hostname)) {
                return { param, pathname, location, payload: fullPayload, label, testUrl: url.href };
              }
            } catch { continue; }
          }
          return null;
        }),
      ),
    );

    for (const r of paramPollutionResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const { param, pathname, location, payload, label, testUrl } = r.value;
      if (foundPaths.has(`pollution-${pathname}`)) continue;
      foundPaths.add(`pollution-${pathname}`);
      const isCrlf = label.includes("CRLF");
      findings.push({
        id: `openredirect-pollution-${findings.length}`,
        module: "Open Redirect",
        severity: isCrlf ? "high" : "medium",
        title: `Open redirect via ${label} in "${param}" on ${pathname}`,
        description: isCrlf
          ? `This endpoint is vulnerable to CRLF injection in the redirect parameter. By injecting \\r\\n characters, an attacker can set arbitrary HTTP headers including a new Location header, enabling response splitting attacks.`
          : label.includes("null byte")
            ? `This endpoint is vulnerable to null byte injection in the redirect URL. The server truncates the URL at the null byte (%00), allowing an attacker to control the redirect destination by appending a malicious domain after the null byte.`
            : `This endpoint is vulnerable to URL credential-section injection. By appending @evil.com to the redirect URL (e.g., https://target.com@evil.com), the browser interprets "target.com" as a username and navigates to evil.com instead.`,
        evidence: `GET ${testUrl}\nPayload: ${payload}\nLocation: ${location}`,
        remediation: isCrlf
          ? "Sanitize all user input in HTTP headers. Strip or reject \\r and \\n characters. Use framework-provided redirect methods that handle encoding automatically."
          : label.includes("null byte")
            ? "Strip null bytes (%00) from all user input before processing. Parse the URL after sanitization and validate the hostname against an allowlist."
            : "Parse the redirect URL fully and validate the resolved hostname — do not rely on string prefix matching. The URL spec treats the segment before @ as credentials, not as the hostname.",
        cwe: isCrlf ? "CWE-113" : "CWE-601",
        owasp: "A01:2021",
        confidence: isCrlf ? 90 : 85,
        codeSnippet: isCrlf
          ? `// Strip CRLF from redirect values\nconst sanitized = userInput.replace(/[\\r\\n]/g, "");\nconst url = new URL(sanitized, origin);\nif (url.origin !== origin) return Response.redirect("/");`
          : `// Always parse and validate the full URL\nconst url = new URL(redirectInput);\n// Check resolved hostname, not string prefix\nif (!ALLOWED_HOSTS.has(url.hostname)) {\n  return Response.redirect("/", 302);\n}\n// Also reject URLs with credentials section\nif (url.username || url.password) {\n  return Response.redirect("/", 302);\n}`,
      });
    }
  }

  // Phase 6: Meta refresh / JS-based redirect detection
  // Some apps use client-side redirects instead of 3xx — test for meta refresh and window.location
  if (findings.length < MAX_FINDINGS) {
    const clientRedirectResults = await Promise.allSettled(
      [...urlsByPath.entries()].slice(0, 5).flatMap(([pathname, baseUrl]) =>
        REDIRECT_PARAMS.slice(0, 5).map(async (param) => {
          const url = new URL(baseUrl);
          url.searchParams.set(param, "https://evil.com");
          const res = await scanFetch(url.href, { redirect: "follow", timeoutMs: 5000 });
          if (res.status >= 300 && res.status < 400) return null; // Already caught by earlier phases
          const text = await res.text();
          // Check for meta refresh redirect
          const metaMatch = text.match(/<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+;\s*url\s*=\s*([^"'>\s]+)/i);
          if (metaMatch && /evil\.com/i.test(metaMatch[1])) {
            return { param, pathname, type: "meta-refresh" as const, location: metaMatch[1], testUrl: url.href };
          }
          // Check for JS redirect to evil.com via various patterns
          const jsRedirectPatterns = [
            /(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=(]\s*["']https?:\/\/evil\.com/i,
            /(?:window\.location|location\.href)\s*=\s*(?:decodeURIComponent|atob|unescape)\s*\(/i,
            /document\.write\s*\(\s*["']<meta[^>]*refresh[^>]*evil\.com/i,
            /\.navigate\s*\(\s*["']https?:\/\/evil\.com/i,
          ];
          for (const pattern of jsRedirectPatterns) {
            if (pattern.test(text)) {
              return { param, pathname, type: "js-redirect" as const, location: "evil.com", testUrl: url.href };
            }
          }
          // Also test with data: and javascript: payloads for client-side rendering
          for (const payload of ["javascript:alert(1)", "data:text/html,<h1>phished</h1>"]) {
            const url2 = new URL(baseUrl);
            url2.searchParams.set(param, payload);
            try {
              const res2 = await scanFetch(url2.href, { redirect: "follow", timeoutMs: 4000 });
              if (res2.status >= 300 && res2.status < 400) continue;
              const text2 = await res2.text();
              const metaMatch2 = text2.match(/<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+;\s*url\s*=\s*([^"'>\s]+)/i);
              if (metaMatch2 && /^(javascript:|data:)/i.test(metaMatch2[1])) {
                return { param, pathname, type: "meta-refresh" as const, location: metaMatch2[1], testUrl: url2.href };
              }
              if (/(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=(]\s*["'](javascript:|data:)/i.test(text2)) {
                return { param, pathname, type: "js-redirect" as const, location: payload, testUrl: url2.href };
              }
            } catch { continue; }
          }
          return null;
        }),
      ),
    );

    for (const r of clientRedirectResults) {
      if (findings.length >= MAX_FINDINGS + 2) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const { param, pathname, type, location, testUrl } = r.value;
      if (foundPaths.has(`client-${pathname}`)) continue;
      foundPaths.add(`client-${pathname}`);
      const isDangerous = /^(javascript:|data:)/i.test(location);
      findings.push({
        id: `openredirect-client-${findings.length}`,
        module: "Open Redirect",
        severity: isDangerous ? "high" : "medium",
        title: `Client-side redirect (${type}) via "${param}" on ${pathname}`,
        description: type === "meta-refresh"
          ? `The page uses a <meta http-equiv="refresh"> tag that redirects to user-controlled URLs${isDangerous ? " including dangerous URI schemes (javascript:/data:)" : ""}. This bypasses server-side redirect validation and is harder to detect in security scans.`
          : `The page sets window.location to a user-controlled URL${isDangerous ? " including dangerous URI schemes" : ""}. Client-side redirects bypass server-side URL validation and CSP navigate-to directives.`,
        evidence: `GET ${testUrl}\nRedirect type: ${type}\nTarget: ${location}`,
        remediation: "Validate redirect targets on the server before rendering. Never insert user input directly into meta refresh tags or window.location assignments. Block javascript: and data: URI schemes explicitly.",
        cwe: isDangerous ? "CWE-79" : "CWE-601",
        owasp: "A01:2021",
        confidence: 85,
        codeSnippet: type === "meta-refresh"
          ? `// Don't use meta refresh with user input\n// BAD: <meta http-equiv="refresh" content="0;url=\${userInput}" />\n// GOOD: Validate on server, then redirect\nconst SAFE_PROTOCOLS = new Set(["http:", "https:"]);\nconst url = new URL(target, origin);\nif (!SAFE_PROTOCOLS.has(url.protocol) || !ALLOWED_HOSTS.has(url.hostname)) {\n  return Response.redirect("/");\n}`
          : `// Don't use user input in window.location\n// BAD: window.location.href = params.get("redirect")\n// GOOD: Validate against allowlist and block dangerous schemes\nconst url = new URL(redirectUrl, window.location.origin);\nconst SAFE = new Set(["http:", "https:"]);\nif (!SAFE.has(url.protocol) || url.origin !== window.location.origin) {\n  window.location.href = "/";\n}`,
      });
    }
  }

  // Phase 4: Fragment-based redirect — #redirect=url patterns in JS
  const allJs = Array.from(target.jsContents.values()).join("\n");
  if (/location\.hash.*(?:redirect|url|next|return|goto)/i.test(allJs) || /(?:redirect|url|next|return|goto).*location\.hash/i.test(allJs)) {
    findings.push({
      id: "openredirect-fragment",
      module: "Open Redirect",
      severity: "low",
      title: "Potential hash-based open redirect in client-side JavaScript",
      description: "Client-side JavaScript reads redirect parameters from the URL fragment (location.hash). Fragment values are never sent to the server, so server-side validation cannot protect against this. Attackers can craft links like yourapp.com/#redirect=evil.com.",
      evidence: "JavaScript contains patterns reading redirect-like values from location.hash",
      remediation: "Validate any URLs extracted from the fragment against an allowlist before navigating.",
      cwe: "CWE-601",
      owasp: "A01:2021",
      confidence: 50,
      codeSnippet: `// Validate hash-based redirect targets\nconst hash = new URLSearchParams(location.hash.slice(1));\nconst redirect = hash.get("redirect");\nif (redirect) {\n  const target = new URL(redirect, location.origin);\n  if (target.origin === location.origin) {\n    location.href = target.href;\n  }\n}`,
    });
  }

  return findings;
};
