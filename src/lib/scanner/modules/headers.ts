import type { ScanModule, Finding } from "../types";

const REQUIRED_HEADERS: {
  header: string;
  severity: Finding["severity"];
  title: string;
  description: string;
  remediation: string;
  cwe: string;
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
  },
  {
    header: "x-content-type-options",
    severity: "low",
    title: "Missing X-Content-Type-Options header",
    description:
      "Without this header, browsers may MIME-sniff responses, potentially executing uploaded files as scripts.",
    remediation: "Add header: X-Content-Type-Options: nosniff",
    cwe: "CWE-693",
  },
  {
    header: "referrer-policy",
    severity: "low",
    title: "Missing Referrer-Policy header",
    description:
      "Without a referrer policy, your site may leak sensitive URL paths and query parameters to third-party sites.",
    remediation: "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    cwe: "CWE-200",
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
    });
  }

  // Check CSP quality if present
  const csp = target.headers["content-security-policy"];
  if (csp) {
    if (csp.includes("'unsafe-inline'") && csp.includes("script-src")) {
      findings.push({
        id: "headers-csp-unsafe-inline",
        module: "Security Headers",
        severity: "medium",
        title: "CSP allows unsafe-inline scripts",
        description:
          "Your Content-Security-Policy includes 'unsafe-inline' for scripts, which defeats most of the XSS protection CSP provides.",
        evidence: `CSP: ${csp.substring(0, 200)}`,
        remediation:
          "Remove 'unsafe-inline' from script-src and use nonces or hashes instead.",
        cwe: "CWE-693",
      });
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push({
        id: "headers-csp-unsafe-eval",
        module: "Security Headers",
        severity: "medium",
        title: "CSP allows unsafe-eval",
        description:
          "Your CSP includes 'unsafe-eval', allowing eval() and similar dangerous functions that attackers can exploit.",
        evidence: `CSP: ${csp.substring(0, 200)}`,
        remediation: "Remove 'unsafe-eval' from your CSP.",
        cwe: "CWE-693",
      });
    }
    // Wildcard script sources
    const scriptSrc = csp.match(/script-src\s+([^;]+)/)?.[1] || "";
    const defaultSrc = csp.match(/default-src\s+([^;]+)/)?.[1] || "";
    const effectiveScriptSrc = scriptSrc || defaultSrc;
    if (/\*(?!\.)/.test(effectiveScriptSrc) || effectiveScriptSrc.includes("https:")) {
      findings.push({
        id: "headers-csp-wildcard-script",
        module: "Security Headers",
        severity: "high",
        title: "CSP script-src allows wildcard or any HTTPS source",
        description: "Your CSP allows loading scripts from any origin (via * or https:), making it trivially bypassable for XSS.",
        evidence: `Effective script-src: ${effectiveScriptSrc.substring(0, 200)}`,
        remediation: "Restrict script-src to specific trusted domains.",
        cwe: "CWE-693",
        owasp: "A05:2021",
      });
    }
    // data: URI in script-src enables XSS
    if (effectiveScriptSrc.includes("data:")) {
      findings.push({
        id: "headers-csp-data-script",
        module: "Security Headers",
        severity: "high",
        title: "CSP script-src allows data: URIs",
        description: "Allowing data: URIs in script-src lets attackers inject scripts via data:text/javascript payloads.",
        evidence: `Effective script-src: ${effectiveScriptSrc.substring(0, 200)}`,
        remediation: "Remove data: from script-src.",
        cwe: "CWE-693",
        owasp: "A05:2021",
      });
    }

    // Check for missing critical CSP directives
    const missingDirectives: { name: string; why: string }[] = [];
    if (!csp.includes("base-uri")) missingDirectives.push({ name: "base-uri", why: "allows <base> tag injection to redirect relative URLs" });
    if (!csp.includes("form-action")) missingDirectives.push({ name: "form-action", why: "allows forms to submit to attacker-controlled URLs" });
    if (!csp.includes("object-src") && !defaultSrc.includes("'none'")) missingDirectives.push({ name: "object-src", why: "allows Flash/Java plugins that bypass CSP" });
    if (missingDirectives.length > 0) {
      findings.push({
        id: "headers-csp-missing-directives",
        module: "Security Headers",
        severity: "low",
        title: `CSP missing ${missingDirectives.length} recommended directive${missingDirectives.length > 1 ? "s" : ""}`,
        description: `Your CSP is missing: ${missingDirectives.map((d) => `${d.name} (${d.why})`).join("; ")}.`,
        evidence: `CSP: ${csp.substring(0, 300)}`,
        remediation: `Add: ${missingDirectives.map((d) => `${d.name} 'self'`).join("; ")}`,
        cwe: "CWE-693",
        owasp: "A05:2021",
      });
    }
  }

  // SRI check for external scripts
  const sriFinding = checkSriMissing(target);
  if (sriFinding) findings.push(sriFinding);

  return findings;
};
