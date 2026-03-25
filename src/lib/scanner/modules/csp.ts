import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const UNSAFE_DIRECTIVES: {
  directive: string;
  value: string | RegExp;
  severity: Finding["severity"];
  title: string;
  description: string;
  remediation: string;
}[] = [
  {
    directive: "script-src",
    value: "'unsafe-inline'",
    severity: "high",
    title: "CSP allows unsafe-inline scripts",
    description: "The script-src directive includes 'unsafe-inline', allowing any inline script to execute. This negates most XSS protection from CSP.",
    remediation: "Remove 'unsafe-inline' from script-src. Use nonces or hashes for inline scripts.",
  },
  {
    directive: "script-src",
    value: "'unsafe-eval'",
    severity: "high",
    title: "CSP allows unsafe-eval",
    description: "The script-src directive includes 'unsafe-eval', allowing eval(), Function(), and setTimeout/setInterval with strings. Attackers can execute arbitrary code if they find an injection point.",
    remediation: "Remove 'unsafe-eval' from script-src. Refactor code that uses eval().",
  },
  {
    directive: "script-src",
    value: /\*(?:\s|;|$)/,
    severity: "critical",
    title: "CSP script-src is wildcard (*)",
    description: "The script-src directive allows scripts from any origin, completely defeating CSP's XSS protection.",
    remediation: "Restrict script-src to specific trusted domains.",
  },
  {
    directive: "default-src",
    value: /\*(?:\s|;|$)/,
    severity: "high",
    title: "CSP default-src is wildcard (*)",
    description: "The default-src directive allows loading resources from any origin. Without a restrictive script-src fallback, this allows arbitrary script execution.",
    remediation: "Set default-src to 'self' and explicitly allow necessary domains per directive.",
  },
  {
    directive: "script-src",
    value: /data:/,
    severity: "high",
    title: "CSP allows data: URIs in scripts",
    description: "The data: scheme in script-src allows executing scripts from data URIs, which is a common XSS bypass.",
    remediation: "Remove data: from script-src.",
  },
  {
    directive: "object-src",
    value: /(?:^|\s)\*|'none'/,
    severity: "medium",
    title: "CSP missing restrictive object-src",
    description: "Without a restrictive object-src, plugins like Flash can be loaded from any origin. Set object-src to 'none' to prevent plugin-based attacks.",
    remediation: "Add object-src 'none' to your CSP.",
  },
  {
    directive: "base-uri",
    value: /.*/,
    severity: "medium",
    title: "CSP missing base-uri directive",
    description: "Without base-uri, attackers can inject a <base> tag to hijack relative URLs, redirecting script loads to attacker-controlled servers.",
    remediation: "Add base-uri 'self' to your CSP.",
  },
];

// CDNs commonly exploited as CSP bypasses (serve user-uploadable JS)
const BYPASS_CDNS = [
  { pattern: /cdn\.jsdelivr\.net/, name: "jsDelivr" },
  { pattern: /unpkg\.com/, name: "unpkg" },
  { pattern: /cdnjs\.cloudflare\.com/, name: "cdnjs" },
  { pattern: /raw\.githubusercontent\.com/, name: "GitHub raw" },
  { pattern: /gist\.githubusercontent\.com/, name: "GitHub Gist" },
  { pattern: /ajax\.googleapis\.com/, name: "Google AJAX APIs" },
  { pattern: /accounts\.google\.com\/gsi/, name: "Google GSI" },
];

const parseCSP = (csp: string): Map<string, string> => {
  const directives = new Map<string, string>();
  for (const part of csp.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const spaceIdx = trimmed.indexOf(" ");
    if (spaceIdx === -1) {
      directives.set(trimmed, "");
    } else {
      directives.set(trimmed.substring(0, spaceIdx), trimmed.substring(spaceIdx + 1));
    }
  }
  return directives;
};

export const cspModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Fetch the main page and API endpoints to check CSP
  const endpoints = [target.url, ...target.apiEndpoints.slice(0, 3)];
  const results = await Promise.allSettled(
    endpoints.map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      return {
        endpoint,
        csp: res.headers.get("content-security-policy") || "",
        cspRO: res.headers.get("content-security-policy-report-only") || "",
      };
    }),
  );

  let mainCSP = "";
  let mainCSPRO = "";
  for (const r of results) {
    if (r.status !== "fulfilled") continue;
    if (r.value.csp) { mainCSP = r.value.csp; break; }
    if (r.value.cspRO && !mainCSPRO) mainCSPRO = r.value.cspRO;
  }

  // Fall back to CSP from recon (includes <meta> tag CSP)
  if (!mainCSP && target.headers["content-security-policy"]) {
    mainCSP = target.headers["content-security-policy"];
  }

  // No CSP at all
  if (!mainCSP && !mainCSPRO) {
    findings.push({
      id: "csp-missing-0",
      module: "CSP Analysis",
      severity: "high",
      title: "No Content Security Policy header",
      description: "The site has no Content-Security-Policy header. Without CSP, any injected script runs with full privileges. CSP is one of the strongest defenses against XSS.",
      remediation: "Add a Content-Security-Policy header starting with a restrictive policy.",
      cwe: "CWE-693",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts — add CSP header\nconst cspHeader = \`\n  default-src 'self';\n  script-src 'self' 'nonce-\${nonce}';\n  style-src 'self' 'unsafe-inline';\n  img-src 'self' blob: data:;\n  font-src 'self';\n  object-src 'none';\n  base-uri 'self';\n  form-action 'self';\n  frame-ancestors 'none';\n  upgrade-insecure-requests;\n\`;\nexport default {\n  async headers() {\n    return [{ source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: cspHeader.replace(/\\n/g, "") }] }];\n  },\n};`,
    });
    return findings;
  }

  // Report-only but no enforcing
  if (!mainCSP && mainCSPRO) {
    findings.push({
      id: "csp-report-only-0",
      module: "CSP Analysis",
      severity: "medium",
      title: "CSP is in report-only mode (not enforced)",
      description: "The site uses Content-Security-Policy-Report-Only, which logs violations but doesn't block them. XSS attacks will still execute.",
      evidence: `Content-Security-Policy-Report-Only: ${mainCSPRO.substring(0, 200)}`,
      remediation: "Switch from Content-Security-Policy-Report-Only to Content-Security-Policy to enforce the policy.",
      cwe: "CWE-693",
      owasp: "A05:2021",
    });
    mainCSP = mainCSPRO; // Analyze the report-only policy
  }

  const directives = parseCSP(mainCSP);

  // Check for specific unsafe directives
  const scriptSrc = directives.get("script-src") || directives.get("default-src") || "";
  const objectSrc = directives.get("object-src");

  for (const check of UNSAFE_DIRECTIVES) {
    if (check.directive === "base-uri") {
      if (!directives.has("base-uri")) {
        findings.push({
          id: `csp-base-uri-${findings.length}`,
          module: "CSP Analysis",
          severity: check.severity,
          title: check.title,
          description: check.description,
          evidence: `CSP: ${mainCSP.substring(0, 300)}`,
          remediation: check.remediation,
          cwe: "CWE-693",
          owasp: "A05:2021",
        });
      }
      continue;
    }

    if (check.directive === "object-src") {
      if (!objectSrc && !directives.get("default-src")?.includes("'none'")) {
        findings.push({
          id: `csp-object-src-${findings.length}`,
          module: "CSP Analysis",
          severity: check.severity,
          title: "CSP missing object-src 'none'",
          description: check.description,
          evidence: `CSP: ${mainCSP.substring(0, 300)}`,
          remediation: check.remediation,
          cwe: "CWE-693",
          codeSnippet: `// Add object-src 'none' to your CSP\nobject-src 'none';`,
        });
      }
      continue;
    }

    const value = directives.get(check.directive) || "";
    const matches = typeof check.value === "string"
      ? value.includes(check.value)
      : check.value.test(value);

    if (matches) {
      findings.push({
        id: `csp-${check.directive}-${findings.length}`,
        module: "CSP Analysis",
        severity: check.severity,
        title: check.title,
        description: check.description,
        evidence: `${check.directive}: ${value}`,
        remediation: check.remediation,
        cwe: "CWE-693",
        owasp: "A05:2021",
        codeSnippet: check.directive === "script-src" && typeof check.value === "string" && check.value === "'unsafe-inline'"
          ? `// Use nonces instead of 'unsafe-inline'\n// middleware.ts\nconst nonce = crypto.randomUUID();\nconst csp = \`script-src 'self' 'nonce-\${nonce}';\`;\nres.headers.set("Content-Security-Policy", csp);\n// In your component: <script nonce={nonce}>...</script>`
          : undefined,
      });
    }
  }

  // Check for CDN bypasses in script-src
  for (const cdn of BYPASS_CDNS) {
    if (cdn.pattern.test(scriptSrc)) {
      findings.push({
        id: `csp-cdn-bypass-${findings.length}`,
        module: "CSP Analysis",
        severity: "medium",
        title: `CSP allows ${cdn.name} (known bypass)`,
        description: `The script-src allows ${cdn.name}, which serves user-uploadable content. Attackers can host malicious scripts on ${cdn.name} and bypass your CSP.`,
        evidence: `script-src includes: ${cdn.name}\nFull: ${scriptSrc.substring(0, 200)}`,
        remediation: `If possible, use strict-dynamic with nonces instead of allowlisting CDN domains. If you must allowlist, use specific paths rather than the entire domain.`,
        cwe: "CWE-693",
      });
      break; // Only report first CDN bypass
    }
  }

  // Check for frame-ancestors (clickjacking via CSP)
  if (!directives.has("frame-ancestors")) {
    findings.push({
      id: `csp-frame-ancestors-${findings.length}`,
      module: "CSP Analysis",
      severity: "low",
      title: "CSP missing frame-ancestors directive",
      description: "Without frame-ancestors, the CSP doesn't protect against clickjacking. While X-Frame-Options may provide some protection, frame-ancestors is the modern replacement.",
      evidence: `CSP: ${mainCSP.substring(0, 200)}`,
      remediation: "Add frame-ancestors 'self' (or 'none') to your CSP.",
      cwe: "CWE-1021",
    });
  }

  // Check for form-action (prevents form submission to attacker domains)
  if (!directives.has("form-action")) {
    findings.push({
      id: `csp-form-action-${findings.length}`,
      module: "CSP Analysis",
      severity: "medium",
      title: "CSP missing form-action directive",
      description: "Without form-action, attackers who inject HTML can add forms that submit user data (passwords, tokens) to an external server. This bypasses script-src restrictions since no JavaScript is needed.",
      evidence: `CSP: ${mainCSP.substring(0, 200)}`,
      remediation: "Add form-action 'self' to your CSP to restrict where forms can submit data.",
      cwe: "CWE-693",
      owasp: "A05:2021",
      codeSnippet: `// Add form-action to your CSP\nform-action 'self';`,
    });
  }

  // Check for upgrade-insecure-requests
  if (!directives.has("upgrade-insecure-requests") && new URL(target.url).protocol === "https:") {
    // Only suggest this for HTTPS sites — it's meaningless for HTTP
    findings.push({
      id: `csp-no-upgrade-insecure-${findings.length}`,
      module: "CSP Analysis",
      severity: "low",
      title: "CSP missing upgrade-insecure-requests",
      description: "Without upgrade-insecure-requests, browsers won't automatically upgrade http:// resource URLs to https://. Mixed content may be blocked or loaded insecurely.",
      evidence: `CSP: ${mainCSP.substring(0, 200)}`,
      remediation: "Add upgrade-insecure-requests to your CSP to auto-upgrade HTTP resources to HTTPS.",
      cwe: "CWE-319",
      codeSnippet: `// Add to your CSP header\nupgrade-insecure-requests;`,
    });
  }

  // Check for JSONP endpoints on CSP-allowed domains (known bypass technique)
  const jsonpDomains: { domain: string; endpoints: string[] }[] = [
    { domain: "ajax.googleapis.com", endpoints: ["/ajax/libs/angularjs/1.6.0/angular.min.js"] },
    { domain: "accounts.google.com", endpoints: ["/o/oauth2/revoke?callback=alert"] },
    { domain: "www.google.com", endpoints: ["/complete/search?client=chrome&q=test&callback=alert"] },
    { domain: "api.twitter.com", endpoints: ["/1/urls/count.json?url=http://example.com&callback=alert"] },
    { domain: "graph.facebook.com", endpoints: ["/v2.0/me?callback=alert"] },
  ];
  for (const { domain, endpoints: jsonpEndpoints } of jsonpDomains) {
    if (scriptSrc.includes(domain)) {
      findings.push({
        id: `csp-jsonp-bypass-${findings.length}`,
        module: "CSP Analysis",
        severity: "high",
        title: `CSP bypass via JSONP on ${domain}`,
        description: `The script-src allows ${domain} which has known JSONP endpoints. Attackers can use these callback parameters to execute arbitrary JavaScript while staying within the CSP allowlist.`,
        evidence: `script-src includes: ${domain}\nKnown JSONP endpoints: ${jsonpEndpoints.join(", ")}`,
        remediation: `Remove ${domain} from script-src or switch to strict-dynamic with nonces. If you need this domain, use specific path restrictions in script-src.`,
        cwe: "CWE-693", owasp: "A05:2021",
        codeSnippet: `// JSONP bypass example:\n// <script src="https://${domain}${jsonpEndpoints[0]}"></script>\n// This executes attacker-controlled JS within your CSP!\n\n// Fix: Use strict-dynamic instead of domain allowlists\nscript-src 'strict-dynamic' 'nonce-{random}';`,
      });
      break;
    }
  }

  // Check for overly permissive script-src with many domains
  const scriptDomains = scriptSrc.split(/\s+/).filter((s) => s.includes(".") && !s.startsWith("'"));
  if (scriptDomains.length > 10) {
    findings.push({
      id: `csp-too-many-domains-${findings.length}`,
      module: "CSP Analysis",
      severity: "medium",
      title: `CSP script-src allowlists ${scriptDomains.length} domains`,
      description: `The script-src directive allows ${scriptDomains.length} external domains. Each allowlisted domain is a potential CSP bypass — if any serve user-controllable JavaScript, the entire CSP is defeated. Consider strict-dynamic with nonces instead.`,
      evidence: `script-src domains: ${scriptDomains.slice(0, 8).join(", ")}${scriptDomains.length > 8 ? ` ...and ${scriptDomains.length - 8} more` : ""}`,
      remediation: "Switch to strict-dynamic with nonces instead of domain allowlisting. This is more maintainable and harder to bypass.",
      cwe: "CWE-693",
      owasp: "A05:2021",
      codeSnippet: `// Use strict-dynamic with nonces instead of domain lists\n// middleware.ts\nconst nonce = crypto.randomUUID();\nconst csp = "script-src 'strict-dynamic' 'nonce-" + nonce + "';";\nres.headers.set("Content-Security-Policy", csp);\n// Then add nonce to script tags: <script nonce={nonce}>`,
    });
  }

  return findings;
};
