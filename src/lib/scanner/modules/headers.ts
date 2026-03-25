import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const REQUIRED_HEADERS: {
  header: string;
  severity: Finding["severity"];
  title: string;
  description: string;
  remediation: string;
  cwe: string;
  codeSnippet?: string;
}[] = [
  {
    header: "content-security-policy",
    severity: "medium",
    title: "Missing Content-Security-Policy header",
    description:
      "No CSP header found. This allows browsers to load scripts, styles, and other resources from any origin, making XSS attacks much easier to exploit.",
    remediation:
      "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
    cwe: "CWE-693",
    codeSnippet: `// next.config.ts\nconst securityHeaders = [\n  { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'" }\n];\nexport default { async headers() { return [{ source: "/(.*)", headers: securityHeaders }]; } };`,
  },
  {
    header: "strict-transport-security",
    severity: "medium",
    title: "Missing Strict-Transport-Security (HSTS) header",
    description:
      "Without HSTS, browsers can be tricked into connecting over HTTP instead of HTTPS, enabling man-in-the-middle attacks.",
    remediation:
      "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    cwe: "CWE-319",
    codeSnippet: `// next.config.ts headers()\n{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }`,
  },
  {
    header: "x-content-type-options",
    severity: "low",
    title: "Missing X-Content-Type-Options header",
    description:
      "Without this header, browsers may MIME-sniff responses, potentially executing uploaded files as scripts.",
    remediation: "Add header: X-Content-Type-Options: nosniff",
    cwe: "CWE-693",
    codeSnippet: `// next.config.ts headers()\n{ key: "X-Content-Type-Options", value: "nosniff" }`,
  },
  {
    header: "referrer-policy",
    severity: "low",
    title: "Missing Referrer-Policy header",
    description:
      "Without a referrer policy, your site may leak sensitive URL paths and query parameters to third-party sites.",
    remediation: "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    cwe: "CWE-200",
    codeSnippet: `// next.config.ts headers()\n{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }`,
  },
  {
    header: "permissions-policy",
    severity: "low",
    title: "Missing Permissions-Policy header",
    description:
      "Without this header, embedded content can access browser features like camera, microphone, and geolocation.",
    remediation:
      "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    cwe: "CWE-693",
    codeSnippet: `// next.config.ts headers()\n{ key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" }`,
  },
  {
    header: "cross-origin-resource-policy",
    severity: "low",
    title: "Missing Cross-Origin-Resource-Policy (CORP) header",
    description:
      "Without CORP, other origins can embed your resources (images, scripts, etc.) in their pages, potentially leaking sensitive data via side-channel attacks.",
    remediation:
      "Add header: Cross-Origin-Resource-Policy: same-origin (or same-site if you serve resources across subdomains)",
    cwe: "CWE-693",
    codeSnippet: `// next.config.ts headers()\n{ key: "Cross-Origin-Resource-Policy", value: "same-origin" }`,
  },
];

const checkSriMissing = (target: Parameters<ScanModule>[0]): Finding | null => {
  const externalScripts = target.scripts.filter((s) => {
    try { return new URL(s).origin !== target.baseUrl; } catch { return false; }
  });
  if (externalScripts.length === 0) return null;
  // If we have external scripts and the CSP doesn't require SRI, flag it
  const csp = target.headers["content-security-policy"] || "";
  if (csp.includes("require-sri-for")) return null;
  return {
    id: "headers-no-sri",
    module: "Security Headers",
    severity: "low",
    title: `${externalScripts.length} external scripts loaded without Subresource Integrity`,
    description: `Your app loads ${externalScripts.length} script(s) from external CDNs without SRI hashes. If a CDN is compromised, malicious code would execute in your users' browsers.`,
    evidence: `External scripts:\n${externalScripts.slice(0, 5).join("\n")}${externalScripts.length > 5 ? `\n...and ${externalScripts.length - 5} more` : ""}`,
    remediation: "Add integrity=\"sha384-...\" crossorigin=\"anonymous\" attributes to external <script> tags, or use CSP require-sri-for directive.",
    cwe: "CWE-353",
    owasp: "A08:2021",
    codeSnippet: `<!-- Add SRI hash to external scripts -->\n<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-..." crossorigin="anonymous"></script>\n\n# Generate hash: curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A`,
  };
};

export const headersModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  for (const check of REQUIRED_HEADERS) {
    if (!target.headers[check.header]) {
      findings.push({
        id: `headers-${check.header}`,
        module: "Security Headers",
        severity: check.severity,
        title: check.title,
        description: check.description,
        remediation: check.remediation,
        cwe: check.cwe,
        owasp: "A05:2021",
        ...(check.codeSnippet ? { codeSnippet: check.codeSnippet } : {}),
      });
    }
  }

  // Check for dangerous headers that leak info
  const serverHeader = target.headers["server"];
  if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
    findings.push({
      id: "headers-server-version",
      module: "Security Headers",
      severity: "low",
      title: "Server header leaks version information",
      description: `The Server header reveals: "${serverHeader}". Attackers can use this to find known vulnerabilities for this specific version.`,
      evidence: `Server: ${serverHeader}`,
      remediation: "Remove or genericize the Server header to hide version information.",
      cwe: "CWE-200",
      codeSnippet: `// nginx.conf\nserver_tokens off;\n\n// Express\napp.disable("x-powered-by");`,
    });
  }

  const poweredBy = target.headers["x-powered-by"];
  if (poweredBy) {
    findings.push({
      id: "headers-powered-by",
      module: "Security Headers",
      severity: "low",
      title: "X-Powered-By header leaks technology stack",
      description: `The X-Powered-By header reveals: "${poweredBy}". This helps attackers fingerprint your application.`,
      evidence: `X-Powered-By: ${poweredBy}`,
      remediation: "Remove the X-Powered-By header.",
      cwe: "CWE-200",
      codeSnippet: `// next.config.ts\nexport default { poweredByHeader: false };\n\n// Express\napp.disable("x-powered-by");`,
    });
  }

  // Note: Detailed CSP analysis (unsafe-inline, unsafe-eval, CDN bypasses, etc.)
  // is handled by the dedicated CSP Analysis module. Headers module only flags
  // the missing header itself (above).

  // Cross-Origin isolation headers
  if (!target.headers["cross-origin-opener-policy"]) {
    findings.push({
      id: "headers-no-coop",
      module: "Security Headers",
      severity: "low",
      title: "Missing Cross-Origin-Opener-Policy (COOP) header",
      description: "Without COOP, your site may be vulnerable to cross-origin attacks like Spectre that can read data from your page's process.",
      remediation: "Add header: Cross-Origin-Opener-Policy: same-origin",
      cwe: "CWE-693",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts headers()\n{ key: "Cross-Origin-Opener-Policy", value: "same-origin" }`,
    });
  }

  // SRI check for external scripts
  const sriFinding = checkSriMissing(target);
  if (sriFinding) findings.push(sriFinding);

  // Check Cache-Control on API endpoints
  if (target.apiEndpoints.length > 0) {
    const endpointsToCheck = target.apiEndpoints.slice(0, 5);
    for (const endpoint of endpointsToCheck) {
      try {
        const res = await scanFetch(endpoint, { timeoutMs: 5000 });
        const cacheControl = res.headers.get("cache-control") || "";
        if (!cacheControl || (cacheControl.includes("public") && !cacheControl.includes("no-store"))) {
          findings.push({
            id: "headers-api-cache-control",
            module: "Security Headers",
            severity: "low",
            title: "API endpoint may cache sensitive data",
            description: `The API endpoint "${endpoint}" ${!cacheControl ? "has no Cache-Control header" : `uses public caching ("${cacheControl}")`}. API responses often contain sensitive data that should not be stored in shared caches.`,
            evidence: `Endpoint: ${endpoint}\nCache-Control: ${cacheControl || "(missing)"}`,
            remediation: "Add Cache-Control: no-store, no-cache, private to API responses that may contain sensitive data.",
            cwe: "CWE-525",
            owasp: "A05:2021",
            codeSnippet: `// Next.js API route\nexport async function GET() {\n  return Response.json(data, {\n    headers: { "Cache-Control": "no-store, no-cache, private" },\n  });\n}`,
          });
          break; // One finding is enough
        }
      } catch {
        // Endpoint not reachable, skip
      }
    }
  }

  // Check for inconsistent security headers across pages/API routes
  const pagesToCheck = [...target.pages.slice(0, 5), ...target.apiEndpoints.slice(0, 3)];
  if (pagesToCheck.length > 1) {
    const headerChecks = ["content-security-policy", "strict-transport-security", "x-frame-options"];
    const pageHeaderResults = await Promise.allSettled(
      pagesToCheck.map(async (pageUrl) => {
        const res = await scanFetch(pageUrl, { timeoutMs: 5000 });
        const hdrs: Record<string, string> = {};
        for (const h of headerChecks) {
          const val = res.headers.get(h);
          if (val) hdrs[h] = val;
        }
        return { url: new URL(pageUrl).pathname, headers: hdrs };
      }),
    );

    const pageHeaders = pageHeaderResults
      .filter((r) => r.status === "fulfilled")
      .map((r) => (r as PromiseFulfilledResult<{ url: string; headers: Record<string, string> }>).value);

    // Find pages missing headers that the main page has
    const mainHeaders = new Set(Object.keys(pageHeaders[0]?.headers || {}));
    const inconsistentPages: { url: string; missing: string[] }[] = [];
    for (const page of pageHeaders.slice(1)) {
      const missing = [...mainHeaders].filter((h) => !page.headers[h]);
      if (missing.length > 0) {
        inconsistentPages.push({ url: page.url, missing });
      }
    }

    if (inconsistentPages.length > 0) {
      findings.push({
        id: "headers-inconsistent",
        module: "Security Headers",
        severity: "medium",
        title: `Inconsistent security headers across ${inconsistentPages.length} page${inconsistentPages.length > 1 ? "s" : ""}`,
        description: "Some pages/endpoints are missing security headers that the main page has. This often happens when API routes or dynamic pages don't inherit the global header configuration, creating security gaps.",
        evidence: inconsistentPages.slice(0, 5).map((p) => `${p.url}: missing ${p.missing.join(", ")}`).join("\n"),
        remediation: "Apply security headers globally via middleware or next.config.ts with a catch-all source pattern, not per-route.",
        cwe: "CWE-693",
        owasp: "A05:2021",
        confidence: 75,
        codeSnippet: `// Apply headers globally in middleware.ts (catches ALL routes)\nimport { NextResponse } from "next/server";\n\nexport function middleware() {\n  const res = NextResponse.next();\n  res.headers.set("X-Frame-Options", "DENY");\n  res.headers.set("Content-Security-Policy", "frame-ancestors 'none'");\n  res.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");\n  return res;\n}\n\nexport const config = { matcher: "/(.*)" }; // Match ALL routes`,
      });
    }
  }

  // Cross-Origin-Embedder-Policy (COEP) — needed for cross-origin isolation
  if (!target.headers["cross-origin-embedder-policy"] && target.headers["cross-origin-opener-policy"]) {
    findings.push({
      id: "headers-no-coep",
      module: "Security Headers",
      severity: "low",
      title: "Missing Cross-Origin-Embedder-Policy (COEP) with COOP present",
      description: "COOP is set but COEP is missing. Full cross-origin isolation requires both. Without COEP, SharedArrayBuffer and high-resolution timers remain restricted, and Spectre-class attacks are not fully mitigated.",
      remediation: "Add header: Cross-Origin-Embedder-Policy: require-corp (or credentialless for easier adoption)",
      cwe: "CWE-693",
      codeSnippet: `// next.config.ts headers()\n{ key: "Cross-Origin-Embedder-Policy", value: "credentialless" }\n// Note: "require-corp" is stricter but breaks cross-origin images/fonts\n// "credentialless" is more permissive and usually sufficient`,
    });
  }

  // Cache-Control on sensitive pages — check /account, /profile, /dashboard, /api paths
  const sensitivePaths = ["/account", "/profile", "/dashboard", "/api", "/settings", "/admin"];
  const sensitivePages = target.pages.filter((p) => {
    try {
      const pathname = new URL(p).pathname.toLowerCase();
      return sensitivePaths.some((sp) => pathname.startsWith(sp) || pathname.includes(sp));
    } catch { return false; }
  });
  if (sensitivePages.length > 0) {
    const cacheResults = await Promise.allSettled(
      sensitivePages.slice(0, 5).map(async (pageUrl) => {
        const res = await scanFetch(pageUrl, { timeoutMs: 5000 });
        const cacheControl = res.headers.get("cache-control") || "";
        return { url: new URL(pageUrl).pathname, cacheControl };
      }),
    );
    const pagesWithoutNoStore = cacheResults
      .filter((r) => r.status === "fulfilled")
      .map((r) => (r as PromiseFulfilledResult<{ url: string; cacheControl: string }>).value)
      .filter((r) => !r.cacheControl.includes("no-store"));
    if (pagesWithoutNoStore.length > 0) {
      findings.push({
        id: "headers-sensitive-page-cache",
        module: "Security Headers",
        severity: "medium",
        title: `${pagesWithoutNoStore.length} sensitive page${pagesWithoutNoStore.length > 1 ? "s" : ""} missing Cache-Control: no-store`,
        description: "Pages that likely contain user data (account, profile, dashboard, API routes) do not set Cache-Control: no-store. Without this, browsers and proxies may cache sensitive responses, potentially exposing user data to other users on shared devices or through cached proxy responses.",
        evidence: pagesWithoutNoStore.slice(0, 5).map((p) => `${p.url}: ${p.cacheControl || "(no Cache-Control header)"}`).join("\n"),
        remediation: "Add Cache-Control: no-store, no-cache, private to all responses containing user-specific data.",
        cwe: "CWE-525",
        owasp: "A05:2021",
        codeSnippet: `// middleware.ts — set Cache-Control for sensitive routes\nimport { NextResponse } from "next/server";\nexport function middleware(req: Request) {\n  const res = NextResponse.next();\n  const path = new URL(req.url).pathname;\n  if (/^\\/(account|profile|dashboard|api|settings|admin)/.test(path)) {\n    res.headers.set("Cache-Control", "no-store, no-cache, private");\n  }\n  return res;\n}`,
      });
    }
  }

  // Cross-Origin headers — check for COOP, COEP, CORP together
  const coop = target.headers["cross-origin-opener-policy"];
  const coep = target.headers["cross-origin-embedder-policy"];
  const corp = target.headers["cross-origin-resource-policy"];
  if (!coop && !coep && !corp) {
    findings.push({
      id: "headers-no-cross-origin-isolation",
      module: "Security Headers",
      severity: "low",
      title: "No cross-origin isolation headers configured",
      description: "None of the cross-origin isolation headers (COOP, COEP, CORP) are set. These headers protect against Spectre-class side-channel attacks by controlling how your site interacts with cross-origin resources and windows. Without them, cross-origin attackers may be able to read sensitive data from your page's process.",
      remediation: "Add Cross-Origin-Opener-Policy: same-origin, Cross-Origin-Embedder-Policy: require-corp (or credentialless), and Cross-Origin-Resource-Policy: same-origin.",
      cwe: "CWE-693",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts — full cross-origin isolation\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Cross-Origin-Opener-Policy", value: "same-origin" },\n      { key: "Cross-Origin-Embedder-Policy", value: "credentialless" },\n      { key: "Cross-Origin-Resource-Policy", value: "same-origin" },\n    ]}];\n  },\n};`,
    });
  }

  // NEL (Network Error Logging) — check for NEL header configuration
  const nel = target.headers["nel"];
  const reportTo = target.headers["report-to"];
  if (!nel) {
    findings.push({
      id: "headers-no-nel",
      module: "Security Headers",
      severity: "info",
      title: "No Network Error Logging (NEL) configured",
      description: "The NEL header is not set. Network Error Logging allows your site to receive reports when users experience DNS, TCP, or TLS errors connecting to your server. This helps detect network-level attacks (DNS hijacking, BGP hijacking) and connectivity issues before users report them.",
      remediation: "Add NEL and Report-To headers to enable network error reporting. NEL requires a Report-To group to be configured first.",
      cwe: "CWE-778",
      codeSnippet: `// next.config.ts — enable NEL\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Report-To",\n        value: JSON.stringify({\n          group: "network-errors",\n          max_age: 86400,\n          endpoints: [{ url: "https://your-domain.com/reports/nel" }]\n        }) },\n      { key: "NEL",\n        value: JSON.stringify({ report_to: "network-errors", max_age: 86400 }) },\n    ]}];\n  },\n};`,
    });
  } else if (!reportTo) {
    findings.push({
      id: "headers-nel-no-report-to",
      module: "Security Headers",
      severity: "low",
      title: "NEL header present but Report-To is missing",
      description: "The NEL header is configured but there is no Report-To header. NEL requires a Report-To group to define where error reports should be sent. Without it, NEL is non-functional.",
      evidence: `NEL: ${nel}`,
      remediation: "Add a Report-To header that defines the reporting endpoint referenced in your NEL configuration.",
      cwe: "CWE-778",
      codeSnippet: `// Add Report-To header alongside NEL\n{ key: "Report-To", value: JSON.stringify({\n  group: "network-errors",\n  max_age: 86400,\n  endpoints: [{ url: "https://your-domain.com/reports/nel" }]\n}) }`,
    });
  }

  // Check for deprecated X-XSS-Protection (can introduce vulnerabilities in some browsers)
  const xssProtection = target.headers["x-xss-protection"];
  if (xssProtection && xssProtection !== "0") {
    findings.push({
      id: "headers-xss-protection-deprecated",
      module: "Security Headers",
      severity: "info",
      title: "X-XSS-Protection header is set (deprecated)",
      description: `X-XSS-Protection is set to "${xssProtection}". This header is deprecated and can actually introduce XSS vulnerabilities in older browsers (via selective script blocking that can be exploited). Modern browsers ignore it. Use CSP instead.`,
      evidence: `X-XSS-Protection: ${xssProtection}`,
      remediation: "Set X-XSS-Protection: 0 to disable it, and rely on Content-Security-Policy for XSS protection.",
      cwe: "CWE-693",
      codeSnippet: `// Disable deprecated XSS filter — rely on CSP instead\n{ key: "X-XSS-Protection", value: "0" }`,
    });
  }

  return findings;
};
