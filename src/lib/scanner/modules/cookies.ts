import type { ScanModule, Finding } from "../types";

const SENSITIVE_COOKIE_NAMES = [
  /^session/i, /token$/i, /auth/i, /jwt/i, /^sid$/i,
  /csrf/i, /xsrf/i, /login/i, /^user$/i, /^user[_-]?id$/i,
  /access[_-]?token/i, /refresh[_-]?token/i, /api.?key/i,
];

// Preference/tracking cookies that are not security-sensitive
const NON_SENSITIVE_PATTERNS = /country|currency|locale|language|lang|theme|timezone|tz|consent|analytics|tracking|anonymous|preferences|pref|utm_|_ga|_gid|_fbp|ajs_/i;

export const cookiesModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  for (const cookie of target.cookies) {
    if (NON_SENSITIVE_PATTERNS.test(cookie.name)) continue;
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

  }

  // Consolidate broad domain scope into a single finding
  const broadCookies = target.cookies.filter(
    (c) => !NON_SENSITIVE_PATTERNS.test(c.name) && c.path === "/" && c.domain && c.domain.startsWith("."),
  );
  if (broadCookies.length > 0) {
    findings.push({
      id: "cookies-broad-scope",
      module: "Cookies",
      severity: "low",
      title: `${broadCookies.length} cookie${broadCookies.length > 1 ? "s" : ""} with broad domain scope`,
      description: `${broadCookies.length} cookie(s) are shared across all subdomains. A compromised subdomain could access these cookies.`,
      evidence: broadCookies.map((c) => `${c.name} (${c.domain})`).join(", "),
      remediation: "Restrict cookie domains to the specific subdomain that needs them.",
      cwe: "CWE-1275",
    });
  }

  // Check for auth tokens stored in localStorage (XSS-vulnerable)
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const localStoragePatterns = [
    /localStorage\.setItem\s*\(\s*["'](?:token|auth|jwt|access_token|refresh_token|session|api_key|apiKey|id_token|Bearer)["']/gi,
    /localStorage\s*\[\s*["'](?:token|auth|jwt|access_token|refresh_token|session|api_key|apiKey|id_token|Bearer)["']\s*\]/gi,
  ];

  for (const pat of localStoragePatterns) {
    const matches = allJs.match(pat);
    if (matches) {
      const unique = [...new Set(matches)];
      findings.push({
        id: "cookies-localstorage-token",
        module: "Cookies",
        severity: "medium",
        title: `Auth token stored in localStorage (${unique.length} instance${unique.length > 1 ? "s" : ""})`,
        description: "Your app stores authentication tokens in localStorage, which is accessible to any JavaScript on the page. If an XSS vulnerability exists, attackers can steal these tokens. HttpOnly cookies are the safer alternative.",
        evidence: `Found in JS bundle:\n${unique.slice(0, 3).join("\n")}`,
        remediation: "Store auth tokens in HttpOnly cookies instead of localStorage. If you must use localStorage, ensure robust XSS protection (CSP, input sanitization).",
        cwe: "CWE-922",
        owasp: "A07:2021",
      });
      break;
    }
  }

  return findings;
};
