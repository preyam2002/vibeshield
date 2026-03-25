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

  const allParamTests = await Promise.allSettled(
    [...urlsByPath.entries()].flatMap(([pathname, baseUrl]) =>
      REDIRECT_PARAMS.slice(0, 8).map(async (param) => {
        const url = new URL(baseUrl);
        url.searchParams.set(param, firstEvil);
        const res = await scanFetch(url.href, { redirect: "manual", timeoutMs: 4000 });
        if (res.status < 300 || res.status >= 400) return null;
        const location = res.headers.get("location") || "";
        const isExternal = (() => {
          try { return new URL(location, new URL(baseUrl).origin).hostname === "evil.com"; }
          catch { return /^(https?:)?\/\/evil\.com(\/|$)/i.test(location); }
        })();
        return isExternal ? { param, pathname, location, testUrl: url.href } : null;
      }),
    ),
  );

  for (const r of allParamTests) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const { param, pathname, location, testUrl } = r.value;
    if (foundPaths.has(pathname)) continue;
    foundPaths.add(pathname);
    findings.push({
      id: `openredirect-${findings.length}`,
      module: "Open Redirect",
      severity: "medium",
      title: `Open redirect via "${param}" parameter on ${pathname}`,
      description: "This endpoint redirects to arbitrary external URLs. Attackers can craft phishing links using your domain that redirect to malicious sites.",
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

  return findings;
};
