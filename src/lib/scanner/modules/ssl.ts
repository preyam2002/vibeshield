import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const sslModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const url = new URL(target.url);

  // Check if HTTPS
  if (url.protocol === "http:") {
    findings.push({
      id: "ssl-no-https",
      module: "SSL/TLS",
      severity: "critical",
      title: "Site does not use HTTPS",
      description: "Your site is served over plain HTTP. All traffic including passwords, tokens, and user data is sent unencrypted and can be intercepted by anyone on the network.",
      remediation: "Enable HTTPS. Most hosting providers (Vercel, Netlify, Cloudflare) provide free SSL certificates.",
      cwe: "CWE-319",
      owasp: "A02:2021",
    });
  }

  // Check HTTP → HTTPS redirect
  if (url.protocol === "https:") {
    try {
      const httpUrl = target.url.replace("https://", "http://");
      const res = await scanFetch(httpUrl, { redirect: "manual" });
      const location = res.headers.get("location") || "";
      if (res.status < 300 || res.status >= 400 || !location.startsWith("https://")) {
        findings.push({
          id: "ssl-no-redirect",
          module: "SSL/TLS",
          severity: "medium",
          title: "HTTP does not redirect to HTTPS",
          description: "Visiting the HTTP version of your site does not redirect to HTTPS. Users who type your URL without https:// will get an insecure connection.",
          remediation: "Add a 301 redirect from HTTP to HTTPS.",
          cwe: "CWE-319",
        });
      }
    } catch {
      // HTTP might not be reachable which is fine
    }
  }

  // Check HSTS preload readiness
  const hsts = target.headers["strict-transport-security"];
  if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1]);
      if (maxAge < 31536000) {
        findings.push({
          id: "ssl-hsts-short",
          module: "SSL/TLS",
          severity: "low",
          title: "HSTS max-age is too short",
          description: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). For proper protection, it should be at least 1 year (31536000 seconds).`,
          evidence: `Strict-Transport-Security: ${hsts}`,
          remediation: "Set max-age=31536000 (1 year) and add includeSubDomains and preload directives.",
          cwe: "CWE-319",
        });
      }
    }
  }

  // Check for mixed content indicators
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const httpRefs = allJs.match(/http:\/\/[^"'\s]+\.(js|css|png|jpg|gif|svg|woff)/gi);
  if (httpRefs && httpRefs.length > 0) {
    findings.push({
      id: "ssl-mixed-content",
      module: "SSL/TLS",
      severity: "medium",
      title: "Potential mixed content detected",
      description: `Found ${httpRefs.length} HTTP resource references in JavaScript bundles. Mixed content can be blocked by browsers and indicates insecure resource loading.`,
      evidence: httpRefs.slice(0, 3).join("\n"),
      remediation: "Change all resource URLs to use HTTPS or protocol-relative URLs.",
      cwe: "CWE-319",
    });
  }

  return findings;
};
