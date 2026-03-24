import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const REDIRECT_PARAMS = [
  "redirect", "redirect_uri", "redirect_url", "return", "returnUrl",
  "return_to", "returnTo", "next", "url", "target", "rurl",
  "dest", "destination", "redir", "redirect_to", "callback",
  "callbackUrl", "go", "goto", "link", "navigate",
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

  // Test redirect parameters on a subset of pages and endpoints
  const testUrls = [target.url, ...target.pages.slice(0, 3), ...target.apiEndpoints.slice(0, 3)];
  const foundPaths = new Set<string>();
  const MAX_FINDINGS = 3;

  for (const baseUrl of testUrls) {
    if (findings.length >= MAX_FINDINGS) break;
    const pathname = new URL(baseUrl).pathname;
    if (foundPaths.has(pathname)) continue;

    // Test all params with the first payload in parallel, then try more payloads on hits
    const firstEvil = EVIL_URLS[0];
    const paramTests = await Promise.allSettled(
      REDIRECT_PARAMS.slice(0, 10).map(async (param) => {
        const url = new URL(baseUrl);
        url.searchParams.set(param, firstEvil);
        const res = await scanFetch(url.href, { redirect: "manual", timeoutMs: 5000 });
        return { param, status: res.status, location: res.headers.get("location") || "", url: url.href };
      }),
    );

    for (const r of paramTests) {
      if (r.status !== "fulfilled" || foundPaths.has(pathname)) continue;
      const { param, status, location, url: testUrl } = r.value;
      if (status < 300 || status >= 400) continue;

      const isExternalRedirect = (() => {
        try {
          return new URL(location, new URL(baseUrl).origin).hostname === "evil.com";
        } catch {
          return /^(https?:)?\/\/evil\.com/i.test(location);
        }
      })();

      if (isExternalRedirect) {
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
        });
        break;
      }
    }
  }

  // Also check existing redirect-looking URLs
  for (const link of target.linkUrls) {
    try {
      const url = new URL(link);
      for (const param of REDIRECT_PARAMS) {
        if (url.searchParams.has(param)) {
          const val = url.searchParams.get(param) || "";
          if (val.startsWith("http") || val.startsWith("//")) {
            // Test with evil URL
            url.searchParams.set(param, "https://evil.com");
            const res = await scanFetch(url.href, { redirect: "manual" });
            if (res.status >= 300 && res.status < 400) {
              const location = res.headers.get("location") || "";
              const isExternal = (() => {
                try { return new URL(location, url.origin).hostname === "evil.com"; }
                catch { return /^(https?:)?\/\/evil\.com/i.test(location); }
              })();
              if (isExternal) {
                findings.push({
                  id: `openredirect-existing-${findings.length}`,
                  module: "Open Redirect",
                  severity: "medium",
                  title: `Open redirect in existing URL parameter "${param}"`,
                  description: "A URL with a redirect parameter accepts arbitrary external URLs.",
                  evidence: `Original URL had ${param}=${val}\nModified to evil.com → redirected`,
                  remediation: "Validate redirect targets against a whitelist.",
                  cwe: "CWE-601",
                });
              }
            }
          }
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};
