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

  // Phase 3: Meta refresh / JS-based redirect detection
  // Some apps use client-side redirects instead of 3xx — test for meta refresh and window.location
  if (findings.length < MAX_FINDINGS) {
    const clientRedirectResults = await Promise.allSettled(
      [...urlsByPath.entries()].slice(0, 5).flatMap(([pathname, baseUrl]) =>
        REDIRECT_PARAMS.slice(0, 5).map(async (param) => {
          const url = new URL(baseUrl);
          url.searchParams.set(param, "https://evil.com");
          const res = await scanFetch(url.href, { redirect: "follow", timeoutMs: 5000 });
          if (res.status >= 300 && res.status < 400) return null; // Already caught by Phase 1
          const text = await res.text();
          // Check for meta refresh redirect
          const metaMatch = text.match(/<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+;\s*url\s*=\s*([^"'>\s]+)/i);
          if (metaMatch && /evil\.com/i.test(metaMatch[1])) {
            return { param, pathname, type: "meta-refresh", location: metaMatch[1] };
          }
          // Check for JS redirect to evil.com
          if (/(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=(]\s*["']https?:\/\/evil\.com/i.test(text)) {
            return { param, pathname, type: "js-redirect", location: "evil.com" };
          }
          return null;
        }),
      ),
    );

    for (const r of clientRedirectResults) {
      if (findings.length >= MAX_FINDINGS + 2) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const { param, pathname, type, location } = r.value;
      if (foundPaths.has(pathname)) continue;
      foundPaths.add(pathname);
      findings.push({
        id: `openredirect-client-${findings.length}`,
        module: "Open Redirect",
        severity: "medium",
        title: `Client-side redirect (${type}) via "${param}" on ${pathname}`,
        description: type === "meta-refresh"
          ? `The page uses a <meta http-equiv="refresh"> tag that redirects to user-controlled URLs. This bypasses server-side redirect validation and is harder to detect in security scans.`
          : `The page sets window.location to a user-controlled URL. Client-side redirects bypass server-side URL validation and CSP navigate-to directives.`,
        evidence: `GET ${pathname}?${param}=https://evil.com\nRedirect type: ${type}\nTarget: ${location}`,
        remediation: "Validate redirect targets on the server before rendering. Never insert user input directly into meta refresh tags or window.location assignments.",
        cwe: "CWE-601",
        owasp: "A01:2021",
        confidence: 85,
        codeSnippet: type === "meta-refresh"
          ? `// Don't use meta refresh with user input\n// BAD: <meta http-equiv="refresh" content="0;url=\${userInput}" />\n// GOOD: Validate on server, then redirect\nconst allowed = ALLOWED_HOSTS.has(new URL(target, origin).hostname);\nif (!allowed) return Response.redirect("/");`
          : `// Don't use user input in window.location\n// BAD: window.location.href = params.get("redirect")\n// GOOD: Validate against allowlist\nconst target = new URL(redirectUrl, window.location.origin);\nif (target.origin !== window.location.origin) {\n  window.location.href = "/";\n}`,
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
