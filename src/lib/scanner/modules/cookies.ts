import type { ScanModule, Finding } from "../types";

const SENSITIVE_COOKIE_NAMES = [
  /session/i, /token/i, /auth/i, /jwt/i, /sid/i,
  /csrf/i, /xsrf/i, /login/i, /user/i, /access/i,
  /refresh/i, /api.?key/i,
];

export const cookiesModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  for (const cookie of target.cookies) {
    const isSensitive = SENSITIVE_COOKIE_NAMES.some((p) => p.test(cookie.name));

    if (isSensitive && !cookie.httpOnly) {
      findings.push({
        id: `cookies-no-httponly-${cookie.name}`,
        module: "Cookies",
        severity: "high",
        title: `Session cookie "${cookie.name}" missing HttpOnly flag`,
        description: "This cookie can be read by JavaScript. If an XSS vulnerability exists, attackers can steal this cookie and hijack user sessions.",
        evidence: `Cookie: ${cookie.name}\nHttpOnly: false`,
        remediation: "Set the HttpOnly flag on this cookie to prevent JavaScript access.",
        cwe: "CWE-1004",
        owasp: "A05:2021",
      });
    }

    if (isSensitive && !cookie.secure) {
      findings.push({
        id: `cookies-no-secure-${cookie.name}`,
        module: "Cookies",
        severity: "medium",
        title: `Session cookie "${cookie.name}" missing Secure flag`,
        description: "This cookie can be sent over unencrypted HTTP connections, allowing interception by network attackers.",
        evidence: `Cookie: ${cookie.name}\nSecure: false`,
        remediation: "Set the Secure flag on this cookie to ensure it's only sent over HTTPS.",
        cwe: "CWE-614",
        owasp: "A05:2021",
      });
    }

    if (isSensitive && (!cookie.sameSite || cookie.sameSite === "none")) {
      findings.push({
        id: `cookies-no-samesite-${cookie.name}`,
        module: "Cookies",
        severity: "medium",
        title: `Session cookie "${cookie.name}" has weak SameSite policy`,
        description: "This cookie is sent on cross-site requests, making CSRF attacks possible.",
        evidence: `Cookie: ${cookie.name}\nSameSite: ${cookie.sameSite || "not set"}`,
        remediation: "Set SameSite=Lax or SameSite=Strict on this cookie.",
        cwe: "CWE-1275",
        owasp: "A05:2021",
      });
    }

    // Check for overly broad cookie scope
    if (cookie.path === "/" && cookie.domain && cookie.domain.startsWith(".")) {
      findings.push({
        id: `cookies-broad-scope-${cookie.name}`,
        module: "Cookies",
        severity: "low",
        title: `Cookie "${cookie.name}" has broad domain scope`,
        description: `This cookie is shared across all subdomains (${cookie.domain}). A compromised subdomain could access this cookie.`,
        evidence: `Cookie: ${cookie.name}\nDomain: ${cookie.domain}\nPath: ${cookie.path}`,
        remediation: "Restrict the cookie domain to the specific subdomain that needs it.",
        cwe: "CWE-1275",
      });
    }
  }

  return findings;
};
