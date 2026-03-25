import type { ScanModule, Finding } from "../types";

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
        const res = await fetch(endpoint, { method: "GET", redirect: "follow" });
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

  return findings;
};
