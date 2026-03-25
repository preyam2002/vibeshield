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

  // Certificate chain validation — check if intermediate certs are properly included
  if (url.protocol === "https:") {
    const chainResult = await new Promise<{ valid: boolean; depth: number; error?: string } | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), 8000);
      try {
        const socket = tls.connect(443, url.hostname, { rejectUnauthorized: true, servername: url.hostname }, () => {
          clearTimeout(timer);
          const cert = socket.getPeerCertificate(true);
          socket.destroy();
          if (!cert) { resolve(null); return; }
          // Walk the certificate chain
          let depth = 0;
          let current = cert as tls.DetailedPeerCertificate;
          while (current) {
            depth++;
            const issuerCert = (current as tls.DetailedPeerCertificate).issuerCertificate;
            // Self-signed root: issuerCertificate points to itself
            if (!issuerCert || issuerCert === current || issuerCert.fingerprint256 === current.fingerprint256) break;
            current = issuerCert;
            if (depth > 10) break; // safety limit
          }
          resolve({ valid: true, depth });
        });
        socket.on("error", (err) => {
          clearTimeout(timer);
          const msg = err.message || "";
          if (msg.includes("unable to get local issuer certificate") || msg.includes("UNABLE_TO_VERIFY_LEAF_SIGNATURE") || msg.includes("unable to verify the first certificate")) {
            resolve({ valid: false, depth: 0, error: msg });
          } else {
            resolve(null);
          }
        });
      } catch { clearTimeout(timer); resolve(null); }
    });

    if (chainResult && !chainResult.valid) {
      findings.push({
        id: "ssl-incomplete-chain",
        module: "SSL/TLS",
        severity: "high",
        title: "Incomplete SSL certificate chain",
        description: "The server does not include all required intermediate certificates in its TLS handshake. Some clients and browsers may fail to validate the certificate, causing connection errors or security warnings.",
        evidence: `Chain validation error: ${chainResult.error || "missing intermediate certificate(s)"}`,
        remediation: "Configure your server to send the full certificate chain including all intermediate certificates. Use tools like SSL Labs or `openssl s_client -showcerts` to verify the chain. Most CAs provide a bundle file with intermediates.",
        cwe: "CWE-295",
        owasp: "A02:2021",
        codeSnippet: `// Node.js HTTPS server with full chain\nconst https = require("https");\nhttps.createServer({\n  key: fs.readFileSync("server.key"),\n  cert: fs.readFileSync("server.crt"),\n  // Include intermediate certs — concatenate them in order\n  ca: [fs.readFileSync("intermediate.crt"), fs.readFileSync("root.crt")],\n}, app).listen(443);`,
      });
    } else if (chainResult && chainResult.valid && chainResult.depth < 2) {
      findings.push({
        id: "ssl-short-chain",
        module: "SSL/TLS",
        severity: "low",
        title: "SSL certificate chain has only one certificate",
        description: "The server presented only a single certificate (no intermediates). While it may validate in some environments, missing intermediates can cause failures on older clients or mobile devices.",
        evidence: `Chain depth: ${chainResult.depth}`,
        remediation: "Include the full certificate chain in your server configuration to ensure compatibility across all clients.",
        cwe: "CWE-295",
      });
    }
  }

  // Mixed content on subresources — check if page loads HTTP resources (scripts, styles, iframes)
  if (url.protocol === "https:") {
    try {
      const res = await scanFetch(target.url, { timeoutMs: 8000 });
      if (res.ok) {
        const html = await res.text();
        const httpSubresources: { type: string; url: string }[] = [];
        // Match src= and href= attributes pointing to http:// URLs
        const attrPatterns = [
          { regex: /<script[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "script" },
          { regex: /<link[^>]+href=["'](http:\/\/[^"']+)["']/gi, type: "stylesheet" },
          { regex: /<iframe[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "iframe" },
          { regex: /<img[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "image" },
          { regex: /<source[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "media" },
          { regex: /<object[^>]+data=["'](http:\/\/[^"']+)["']/gi, type: "object" },
        ];
        for (const { regex, type } of attrPatterns) {
          let m: RegExpExecArray | null;
          while ((m = regex.exec(html)) !== null) {
            httpSubresources.push({ type, url: m[1] });
          }
        }
        // Also check for @import with http URLs in inline styles
        const importRegex = /@import\s+(?:url\()?["']?(http:\/\/[^"');\s]+)/gi;
        let im: RegExpExecArray | null;
        while ((im = importRegex.exec(html)) !== null) {
          httpSubresources.push({ type: "css-import", url: im[1] });
        }

        if (httpSubresources.length > 0) {
          const hasActiveContent = httpSubresources.some((r) => r.type === "script" || r.type === "stylesheet" || r.type === "iframe");
          findings.push({
            id: "ssl-mixed-subresources",
            module: "SSL/TLS",
            severity: hasActiveContent ? "high" : "medium",
            title: `Mixed content: ${httpSubresources.length} HTTP subresource(s) on HTTPS page`,
            description: `The HTTPS page loads ${httpSubresources.length} resource(s) over plain HTTP.${hasActiveContent ? " This includes active content (scripts/stylesheets/iframes) which browsers will block and which can enable man-in-the-middle attacks." : " Passive mixed content (images/media) may be loaded but triggers browser warnings."}`,
            evidence: httpSubresources.slice(0, 5).map((r) => `[${r.type}] ${r.url}`).join("\n"),
            remediation: "Update all subresource URLs to use HTTPS. Add a Content-Security-Policy header with upgrade-insecure-requests to automatically upgrade HTTP resources.",
            cwe: "CWE-319",
            owasp: "A02:2021",
            codeSnippet: `// Add CSP header to auto-upgrade mixed content\n// next.config.ts\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Content-Security-Policy",\n        value: "upgrade-insecure-requests" }\n    ]}];\n  },\n};`,
          });
        }
      }
    } catch {
      // skip if page fetch fails
    }
  }

  // OCSP stapling check — look for Expect-CT header and test OCSP stapling via TLS
  if (url.protocol === "https:") {
    const [ocspStapled, expectCtHeader] = await Promise.allSettled([
      new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), 8000);
        try {
          const socket = tls.connect(443, url.hostname, {
            rejectUnauthorized: false, servername: url.hostname,
            ...({ requestOCSP: true } as Record<string, unknown>),
          }, () => {
            clearTimeout(timer);
            socket.destroy();
            resolve(false); // connected but no OCSP response in callback
          });
          socket.on("OCSPResponse", (response: Buffer) => {
            clearTimeout(timer);
            socket.destroy();
            // If response is non-empty, OCSP stapling is configured
            resolve(response && response.length > 0);
          });
          socket.on("error", () => { clearTimeout(timer); resolve(false); });
        } catch { clearTimeout(timer); resolve(false); }
      }),
      Promise.resolve(target.headers["expect-ct"] || null),
    ]);

    const hasOcspStapling = ocspStapled.status === "fulfilled" && ocspStapled.value;
    const hasExpectCt = expectCtHeader.status === "fulfilled" && expectCtHeader.value;

    if (!hasOcspStapling && !hasExpectCt) {
      findings.push({
        id: "ssl-no-ocsp-stapling",
        module: "SSL/TLS",
        severity: "info",
        title: "OCSP stapling not detected",
        description: "The server does not appear to have OCSP stapling configured. Without OCSP stapling, browsers must contact the CA's OCSP responder directly to check certificate revocation status, which adds latency and creates a privacy concern (the CA learns which sites users visit). If the OCSP responder is down, browsers may soft-fail and skip the check entirely.",
        remediation: "Enable OCSP stapling on your web server. In Nginx: `ssl_stapling on; ssl_stapling_verify on;`. In Apache: `SSLUseStapling On`. Most managed platforms (Cloudflare, Vercel) enable this by default.",
        cwe: "CWE-299",
        codeSnippet: `# Nginx — enable OCSP stapling\nssl_stapling on;\nssl_stapling_verify on;\nssl_trusted_certificate /path/to/chain.pem;\nresolver 8.8.8.8 8.8.4.4 valid=300s;\nresolver_timeout 5s;\n\n# Apache — enable OCSP stapling\nSSLUseStapling On\nSSLStaplingCache shmcb:/tmp/stapling_cache(128000)`,
      });
    }
  }

  // Mixed content detection — check HTML for http:// URLs in src, href, action attributes
  if (url.protocol === "https:") {
    try {
      const res = await scanFetch(target.url, { timeoutMs: 8000 });
      if (res.ok) {
        const html = await res.text();
        const mixedContentUrls: { type: string; url: string }[] = [];
        const mixedPatterns = [
          { regex: /<script[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "script" },
          { regex: /<link[^>]+href=["'](http:\/\/[^"']+)["']/gi, type: "stylesheet" },
          { regex: /<img[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "image" },
          { regex: /<form[^>]+action=["'](http:\/\/[^"']+)["']/gi, type: "form-action" },
          { regex: /<iframe[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "iframe" },
          { regex: /<video[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "video" },
          { regex: /<audio[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "audio" },
          { regex: /<source[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "media-source" },
          { regex: /<embed[^>]+src=["'](http:\/\/[^"']+)["']/gi, type: "embed" },
          { regex: /<object[^>]+data=["'](http:\/\/[^"']+)["']/gi, type: "object" },
        ];
        for (const { regex, type } of mixedPatterns) {
          let m: RegExpExecArray | null;
          while ((m = regex.exec(html)) !== null) {
            mixedContentUrls.push({ type, url: m[1] });
          }
        }
        if (mixedContentUrls.length > 0) {
          const hasFormAction = mixedContentUrls.some((r) => r.type === "form-action");
          const hasActiveContent = mixedContentUrls.some((r) => r.type === "script" || r.type === "stylesheet" || r.type === "iframe");
          findings.push({
            id: "ssl-html-mixed-content",
            module: "SSL/TLS",
            severity: hasActiveContent || hasFormAction ? "high" : "medium",
            title: `Mixed content: ${mixedContentUrls.length} HTTP URL(s) in HTML attributes`,
            description: `The HTTPS page contains ${mixedContentUrls.length} HTTP URL(s) in src, href, or action attributes.${hasFormAction ? " Form actions over HTTP will submit user data unencrypted." : ""}${hasActiveContent ? " Active content (scripts/stylesheets) loaded over HTTP can be tampered with by network attackers." : ""}`,
            evidence: mixedContentUrls.slice(0, 5).map((r) => `[${r.type}] ${r.url}`).join("\n"),
            remediation: "Update all URLs to use HTTPS. Add Content-Security-Policy: upgrade-insecure-requests to auto-upgrade remaining HTTP resources.",
            cwe: "CWE-319",
            owasp: "A02:2021",
            codeSnippet: `// Fix form actions and resource URLs\n// Before: <form action="http://example.com/submit">\n// After:  <form action="https://example.com/submit">\n\n// Auto-upgrade via CSP header in next.config.ts\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Content-Security-Policy",\n        value: "upgrade-insecure-requests" }\n    ]}];\n  },\n};`,
          });
        }
      }
    } catch {
      // skip if page fetch fails
    }
  }

  // Certificate Transparency header check
  if (url.protocol === "https:") {
    const expectCtHeader = target.headers["expect-ct"];
    const ctHeader = target.headers["certificate-transparency"] || target.headers["signed-certificate-timestamp"];
    if (!expectCtHeader && !ctHeader) {
      // Check if the Expect-CT header is enforced or just reporting
      findings.push({
        id: "ssl-no-ct-header",
        module: "SSL/TLS",
        severity: "info",
        title: "No Certificate Transparency headers present",
        description: "Neither Expect-CT nor Certificate-Transparency headers were found in the response. While Expect-CT is being deprecated as CT becomes universally required, having it in enforce mode provides an additional layer of protection against misissued certificates.",
        remediation: "Add Expect-CT header with enforce and report-uri directives. Note: Chrome requires CT for all public certificates since 2018, so this is primarily useful for reporting.",
        cwe: "CWE-295",
        codeSnippet: `// next.config.ts headers()\n{ key: "Expect-CT", value: "max-age=86400, enforce, report-uri=\\"https://your-domain.report-uri.com/r/d/ct/enforce\\"" }`,
      });
    } else if (expectCtHeader && !expectCtHeader.includes("enforce")) {
      findings.push({
        id: "ssl-ct-not-enforced",
        module: "SSL/TLS",
        severity: "info",
        title: "Expect-CT header present but not enforcing",
        description: "The Expect-CT header is set but does not include the enforce directive. Without enforce, the browser will only report CT failures but not block connections with non-CT-compliant certificates.",
        evidence: `Expect-CT: ${expectCtHeader}`,
        remediation: "Add the enforce directive to your Expect-CT header.",
        cwe: "CWE-295",
        codeSnippet: `// Add enforce to Expect-CT\n{ key: "Expect-CT", value: "max-age=86400, enforce" }`,
      });
    }
  }

  // HTTP-only on HTTPS site — check if http:// redirects to https://
  if (url.protocol === "https:") {
    try {
      const httpUrl = target.url.replace("https://", "http://");
      const res = await scanFetch(httpUrl, { redirect: "manual", timeoutMs: 8000 });
      const location = res.headers.get("location") || "";
      if (res.status >= 200 && res.status < 300) {
        findings.push({
          id: "ssl-http-serves-content",
          module: "SSL/TLS",
          severity: "high",
          title: "HTTP version serves content without redirecting to HTTPS",
          description: "The HTTP version of the site serves content with a 200 status instead of redirecting to HTTPS. Users who visit the HTTP URL will receive an unencrypted page, exposing their data to network attackers. This also allows cookie theft and session hijacking on the insecure connection.",
          evidence: `GET ${httpUrl} → HTTP ${res.status} (no redirect)`,
          remediation: "Configure a 301 redirect from HTTP to HTTPS for all routes. Ensure HSTS is also set to prevent future HTTP connections.",
          cwe: "CWE-319",
          owasp: "A02:2021",
          codeSnippet: `// middleware.ts — force HTTPS redirect\nimport { NextResponse } from "next/server";\nexport function middleware(req: Request) {\n  if (new URL(req.url).protocol === "http:") {\n    return NextResponse.redirect(\n      req.url.replace("http://", "https://"), 301\n    );\n  }\n}\n\n// Nginx\nserver {\n  listen 80;\n  return 301 https://$host$request_uri;\n}`,
        });
      } else if (res.status >= 300 && res.status < 400 && location && !location.startsWith("https://")) {
        findings.push({
          id: "ssl-http-redirect-not-https",
          module: "SSL/TLS",
          severity: "medium",
          title: "HTTP redirects but not to HTTPS",
          description: `The HTTP version redirects to "${location}" which is not an HTTPS URL. The redirect should point to the HTTPS version of the site.`,
          evidence: `GET ${httpUrl} → ${res.status} → ${location}`,
          remediation: "Update the HTTP redirect to point to the HTTPS version of the URL.",
          cwe: "CWE-319",
        });
      }
    } catch {
      // HTTP not reachable, which is acceptable
    }
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
