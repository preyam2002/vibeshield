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
];

export const openRedirectModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Test redirect parameters on all known pages and endpoints
  const testUrls = [target.url, ...target.pages.slice(0, 5), ...target.apiEndpoints.slice(0, 5)];
  const foundPaths = new Set<string>();
  const MAX_FINDINGS = 3;

  for (const baseUrl of testUrls) {
    if (findings.length >= MAX_FINDINGS) break;
    const pathname = new URL(baseUrl).pathname;
    if (foundPaths.has(pathname)) continue;

    for (const param of REDIRECT_PARAMS) {
      if (foundPaths.has(pathname)) break;
      for (const evil of EVIL_URLS.slice(0, 2)) {
        try {
          const url = new URL(baseUrl);
          url.searchParams.set(param, evil);
          const res = await scanFetch(url.href, { redirect: "manual" });

          if (res.status >= 300 && res.status < 400) {
            const location = res.headers.get("location") || "";
            if (location.includes("evil.com")) {
              foundPaths.add(pathname);
              findings.push({
                id: `openredirect-${findings.length}`,
                module: "Open Redirect",
                severity: "medium",
                title: `Open redirect via "${param}" parameter on ${pathname}`,
                description: "This endpoint redirects to arbitrary external URLs. Attackers can craft phishing links using your domain that redirect to malicious sites.",
                evidence: `GET ${url.href}\nLocation: ${location}`,
                remediation: "Validate redirect URLs against a whitelist of allowed domains. Never redirect to user-controlled URLs.",
                cwe: "CWE-601",
                owasp: "A01:2021",
              });
              break;
            }
          }
        } catch {
          // skip
        }
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
              if (location.includes("evil.com")) {
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
