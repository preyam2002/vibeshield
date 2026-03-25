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
        codeSnippet: `// Set-Cookie with HttpOnly\nres.cookies.set("${cookie.name}", value, {\n  httpOnly: true,\n  secure: true,\n  sameSite: "lax",\n});`,
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
        codeSnippet: `// Set-Cookie with Secure flag\nres.cookies.set("${cookie.name}", value, {\n  secure: true,\n  httpOnly: true,\n  sameSite: "lax",\n});`,
      });
    }

    // SameSite=None explicitly allows cross-site — flag it. Missing SameSite defaults to Lax in modern browsers.
    if (isSensitive && cookie.sameSite.toLowerCase() === "none") {
      findings.push({
        id: `cookies-no-samesite-${cookie.name}`,
        module: "Cookies",
        severity: "medium",
        title: `Session cookie "${cookie.name}" has SameSite=None`,
        description: "This cookie is explicitly set to SameSite=None, meaning it's sent on all cross-site requests. This enables CSRF attacks unless other protections are in place.",
        evidence: `Cookie: ${cookie.name}\nSameSite: None`,
        remediation: "Set SameSite=Lax or SameSite=Strict on this cookie.",
        cwe: "CWE-1275",
        owasp: "A05:2021",
        codeSnippet: `// Set SameSite to Lax or Strict\nres.cookies.set("${cookie.name}", value, {\n  sameSite: "lax", // or "strict"\n  httpOnly: true,\n  secure: true,\n});`,
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
      codeSnippet: `// Set cookies with specific domain scope\nres.cookies.set("session", token, {\n  domain: "app.yourdomain.com", // not ".yourdomain.com"\n  path: "/",\n  httpOnly: true,\n  secure: true,\n  sameSite: "lax",\n});`,
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
        codeSnippet: `// Instead of localStorage, use HttpOnly cookies\n// API route: set cookie on login\nexport async function POST(req: Request) {\n  const { token } = await req.json();\n  const res = NextResponse.json({ ok: true });\n  res.cookies.set("auth", token, { httpOnly: true, secure: true, sameSite: "lax" });\n  return res;\n}`,
      });
      break;
    }
  }

  return findings;
};
