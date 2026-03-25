import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import * as tls from "tls";

const checkCertificate = (hostname: string): Promise<{ valid: boolean; daysLeft: number; issuer: string; protocol: string; error?: string } | null> => {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), 8000);
    try {
      const socket = tls.connect(443, hostname, { rejectUnauthorized: false, servername: hostname }, () => {
        clearTimeout(timer);
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() || "unknown";
        socket.destroy();
        if (!cert || !cert.valid_to) { resolve(null); return; }
        const expiry = new Date(cert.valid_to);
        const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86400000);
        const issuer = String(cert.issuer?.O || cert.issuer?.CN || "unknown");
        resolve({ valid: !socket.authorizationError, daysLeft, issuer, protocol });
      });
      socket.on("error", () => { clearTimeout(timer); resolve(null); });
    } catch { clearTimeout(timer); resolve(null); }
  });
};

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
      codeSnippet: `// Vercel: automatic HTTPS — just deploy\n// Self-hosted: use Let's Encrypt in next.config.ts\nconst { createServer } = require("https");\nconst { parse } = require("url");\nconst next = require("next");\nconst fs = require("fs");\nconst app = next({ dev: false });\nconst handle = app.getRequestHandler();\napp.prepare().then(() => {\n  createServer({ key: fs.readFileSync("key.pem"), cert: fs.readFileSync("cert.pem") },\n    (req, res) => handle(req, res, parse(req.url!, true))\n  ).listen(443);\n});`,
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
          codeSnippet: `// next.config.ts\nmodule.exports = {\n  async redirects() {\n    return [{ source: "/:path*", has: [{ type: "header", key: "x-forwarded-proto", value: "http" }],\n      destination: "https://:host/:path*", permanent: true }];\n  },\n};\n// Or in middleware.ts\nimport { NextResponse } from "next/server";\nexport function middleware(req) {\n  if (req.headers.get("x-forwarded-proto") === "http")\n    return NextResponse.redirect(req.url.replace("http://", "https://"), 301);\n}`,
        });
      }
    } catch {
      // HTTP might not be reachable which is fine
    }
  }

  // Check HSTS configuration
  const hsts = target.headers["strict-transport-security"];
  if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
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
          codeSnippet: `// next.config.ts\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Strict-Transport-Security",\n        value: "max-age=31536000; includeSubDomains; preload" }\n    ]}];\n  },\n};`,
        });
      }
    }
    // Check for missing preload directive (only if max-age is sufficient)
    if (!hsts.includes("preload") && maxAgeMatch && parseInt(maxAgeMatch[1], 10) >= 31536000) {
      findings.push({
        id: "ssl-hsts-no-preload",
        module: "SSL/TLS",
        severity: "info",
        title: "HSTS missing preload directive",
        description: "HSTS is configured with a long max-age but lacks the preload directive. Adding preload and submitting to hstspreload.org ensures browsers always use HTTPS, even on first visit.",
        evidence: `Strict-Transport-Security: ${hsts}`,
        remediation: "Add preload and includeSubDomains to your HSTS header, then submit to hstspreload.org.",
        cwe: "CWE-319",
      });
    }
    // Check for missing includeSubDomains
    if (!hsts.includes("includeSubDomains")) {
      findings.push({
        id: "ssl-hsts-no-subdomains",
        module: "SSL/TLS",
        severity: "low",
        title: "HSTS missing includeSubDomains",
        description: "HSTS is configured but without includeSubDomains. Subdomains are not protected by HSTS and can still be accessed over HTTP.",
        evidence: `Strict-Transport-Security: ${hsts}`,
        remediation: "Add includeSubDomains to your HSTS header.",
        cwe: "CWE-319",
        codeSnippet: `// next.config.ts headers()\n{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }`,
      });
    }
  }

  // Certificate and TLS version checks
  if (url.protocol === "https:") {
    const certInfo = await checkCertificate(url.hostname);
    if (certInfo) {
      if (certInfo.daysLeft < 0) {
        findings.push({
          id: "ssl-cert-expired",
          module: "SSL/TLS",
          severity: "critical",
          title: "SSL certificate has expired",
          description: `The certificate expired ${Math.abs(certInfo.daysLeft)} days ago. Browsers will show security warnings and users will be unable to access the site safely.`,
          evidence: `Issuer: ${certInfo.issuer}\nExpired: ${Math.abs(certInfo.daysLeft)} days ago`,
          remediation: "Renew your SSL certificate immediately. If using a managed provider (Vercel, Cloudflare), check your domain configuration.",
          cwe: "CWE-295",
          owasp: "A02:2021",
        });
      } else if (certInfo.daysLeft < 14) {
        findings.push({
          id: "ssl-cert-expiring",
          module: "SSL/TLS",
          severity: "high",
          title: `SSL certificate expires in ${certInfo.daysLeft} days`,
          description: "Your certificate is about to expire. If not renewed, browsers will show security warnings.",
          evidence: `Issuer: ${certInfo.issuer}\nDays remaining: ${certInfo.daysLeft}`,
          remediation: "Renew your certificate now. Set up auto-renewal with Let's Encrypt or your hosting provider.",
          cwe: "CWE-295",
        });
      } else if (certInfo.daysLeft < 30) {
        findings.push({
          id: "ssl-cert-expiring-soon",
          module: "SSL/TLS",
          severity: "low",
          title: `SSL certificate expires in ${certInfo.daysLeft} days`,
          description: "Certificate will expire within 30 days. Ensure auto-renewal is configured.",
          evidence: `Issuer: ${certInfo.issuer}\nDays remaining: ${certInfo.daysLeft}`,
          remediation: "Verify auto-renewal is set up. Most providers renew certificates automatically.",
          cwe: "CWE-295",
        });
      }

      // TLS version check
      if (certInfo.protocol === "TLSv1" || certInfo.protocol === "TLSv1.1" || certInfo.protocol === "SSLv3") {
        findings.push({
          id: "ssl-weak-tls",
          module: "SSL/TLS",
          severity: "high",
          title: `Weak TLS version: ${certInfo.protocol}`,
          description: `Server is using ${certInfo.protocol} which has known vulnerabilities. TLS 1.2 or 1.3 should be the minimum supported version.`,
          evidence: `Negotiated protocol: ${certInfo.protocol}`,
          remediation: "Configure your server to only accept TLS 1.2 and TLS 1.3. Disable TLS 1.0, TLS 1.1, and SSLv3.",
          cwe: "CWE-326",
          owasp: "A02:2021",
        });
      }

      if (!certInfo.valid) {
        findings.push({
          id: "ssl-cert-invalid",
          module: "SSL/TLS",
          severity: "high",
          title: "SSL certificate validation failed",
          description: "The certificate could not be validated. It may be self-signed, have an incomplete chain, or the hostname may not match.",
          evidence: `Issuer: ${certInfo.issuer}\nProtocol: ${certInfo.protocol}`,
          remediation: "Use a certificate from a trusted CA. Ensure the certificate matches your domain and the full chain is served.",
          cwe: "CWE-295",
        });
      }
    }
  }

  // Check for mixed content indicators
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const httpRefs = allJs.match(/http:\/\/[a-zA-Z0-9._\-\/]+\.(js|css|png|jpg|gif|svg|woff2?|ico|json)(?=["'\s;,)])/gi);
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
      codeSnippet: `// next.config.ts — block mixed content via CSP\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Content-Security-Policy",\n        value: "upgrade-insecure-requests" }\n    ]}];\n  },\n};\n// Fix in code: replace http:// URLs\n// Before: <img src="http://cdn.example.com/img.png" />\n// After:  <img src="https://cdn.example.com/img.png" />`,
    });
  }

  // TLS 1.3 support check
  if (url.protocol === "https:") {
    const tls13 = await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), 5000);
      try {
        const socket = tls.connect(443, url.hostname, {
          rejectUnauthorized: false, servername: url.hostname,
          minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
        }, () => { clearTimeout(timer); socket.destroy(); resolve(true); });
        socket.on("error", () => { clearTimeout(timer); resolve(false); });
      } catch { clearTimeout(timer); resolve(false); }
    });
    if (!tls13) {
      findings.push({
        id: "ssl-no-tls13",
        module: "SSL/TLS",
        severity: "info",
        title: "TLS 1.3 not supported",
        description: "The server does not support TLS 1.3. While TLS 1.2 is still considered secure, TLS 1.3 offers improved performance (faster handshakes) and stronger security guarantees.",
        remediation: "Enable TLS 1.3 on your server or hosting provider. Most modern platforms (Cloudflare, Vercel, AWS) support it by default.",
        cwe: "CWE-326",
      });
    }
  }

  // Certificate Transparency check
  const expectCt = target.headers["expect-ct"];
  const ctHeader = target.headers["certificate-transparency"] || target.headers["signed-certificate-timestamp"];
  const majorProviders = ["cloudflare", "vercel", "amazonaws", "google", "fastly", "akamai"];
  const serverHeader = (target.headers["server"] || "").toLowerCase();
  const viaHeader = (target.headers["via"] || "").toLowerCase();
  const isMajorProvider = majorProviders.some((p) => serverHeader.includes(p) || viaHeader.includes(p) || url.hostname.includes(p));
  if (!expectCt && !ctHeader && !isMajorProvider) {
    findings.push({
      id: "ssl-no-ct",
      module: "SSL/TLS",
      severity: "info",
      title: "No Certificate Transparency evidence in headers",
      description: "No Expect-CT or Certificate Transparency headers were found. Certificate Transparency helps detect misissued certificates. Major providers handle this automatically, but self-managed certificates should ensure CT log inclusion.",
      remediation: "Ensure your certificate is logged in public CT logs. Use a CA that supports CT by default (Let's Encrypt does). The Expect-CT header is deprecated but can still be used for reporting.",
      cwe: "CWE-295",
    });
  }

  // HPKP detection (deprecated and dangerous)
  const hpkp = target.headers["public-key-pins"] || target.headers["public-key-pins-report-only"];
  if (hpkp) {
    findings.push({
      id: "ssl-hpkp-detected",
      module: "SSL/TLS",
      severity: "medium",
      title: "Deprecated HPKP header detected",
      description: "The site sends a Public-Key-Pins header. HPKP is deprecated by all major browsers and is dangerous — a misconfigured pin can make your site permanently inaccessible to users. This often appears when vibe-coded apps copy outdated security header configurations.",
      evidence: `Public-Key-Pins: ${hpkp.substring(0, 120)}${hpkp.length > 120 ? "..." : ""}`,
      remediation: "Remove the Public-Key-Pins header immediately. Use Certificate Transparency (Expect-CT) or CAA DNS records instead for certificate security.",
      cwe: "CWE-693",
      codeSnippet: `// Remove from your headers config — do NOT use HPKP\n// next.config.ts\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      // Use Expect-CT instead (or just rely on CT logs)\n      { key: "Expect-CT", value: "max-age=86400, enforce" }\n    ]}];\n  },\n};`,
    });
  }

  return findings;
};
