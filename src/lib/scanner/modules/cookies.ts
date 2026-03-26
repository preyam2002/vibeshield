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

  // Check for overly persistent session cookies (>90 days)
  const longLivedSensitive = target.cookies.filter((c) => {
    if (!SENSITIVE_COOKIE_NAMES.some((p) => p.test(c.name))) return false;
    // Check for max-age or expires in raw value (cookie parsing may not extract these)
    const rawEntry = c.value || "";
    const maxAgeMatch = rawEntry.match(/max-age=(\d+)/i);
    if (maxAgeMatch && parseInt(maxAgeMatch[1]) > 90 * 86400) return true;
    return false;
  });
  if (longLivedSensitive.length > 0) {
    findings.push({
      id: "cookies-long-lived-session",
      module: "Cookies",
      severity: "low",
      title: `${longLivedSensitive.length} session cookie${longLivedSensitive.length > 1 ? "s" : ""} with excessive lifetime`,
      description: "Session cookies are set to persist for over 90 days. Long-lived sessions increase the window for session hijacking attacks.",
      evidence: longLivedSensitive.map((c) => c.name).join(", "),
      remediation: "Set session cookie Max-Age to 24 hours or less for security-sensitive applications. Use refresh tokens for longer sessions.",
      cwe: "CWE-613",
      codeSnippet: `// Set reasonable cookie expiration\nres.cookies.set("session", token, {\n  maxAge: 60 * 60 * 24, // 24 hours\n  httpOnly: true,\n  secure: true,\n  sameSite: "lax",\n});`,
    });
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

  // Check for cookie prefix misuse (__Host- and __Secure-)
  for (const cookie of target.cookies) {
    if (cookie.name.startsWith("__Host-")) {
      // __Host- cookies MUST have Secure, Path=/, and no Domain attribute
      if (!cookie.secure || cookie.path !== "/" || cookie.domain) {
        findings.push({
          id: `cookies-host-prefix-invalid-${cookie.name}`,
          module: "Cookies",
          severity: "medium",
          title: `__Host- cookie "${cookie.name}" violates prefix requirements`,
          description: "__Host- prefixed cookies must have the Secure flag, Path=/, and no Domain attribute. Browsers will reject cookies that don't meet these requirements, but misconfigured servers may still attempt to set them.",
          evidence: `Cookie: ${cookie.name}\nSecure: ${cookie.secure}\nPath: ${cookie.path}\nDomain: ${cookie.domain || "(not set)"}`,
          remediation: "Ensure __Host- cookies have Secure flag, Path=/, and no Domain attribute. Or use __Secure- prefix if you need a domain attribute.",
          cwe: "CWE-1275",
          codeSnippet: `// Correct __Host- cookie usage\nres.cookies.set("__Host-session", token, {\n  secure: true,\n  path: "/",\n  // NO domain attribute\n  httpOnly: true,\n  sameSite: "lax",\n});`,
        });
      }
    }
    if (cookie.name.startsWith("__Secure-") && !cookie.secure) {
      findings.push({
        id: `cookies-secure-prefix-no-flag-${cookie.name}`,
        module: "Cookies",
        severity: "medium",
        title: `__Secure- cookie "${cookie.name}" missing Secure flag`,
        description: "__Secure- prefixed cookies must have the Secure flag. Without it, browsers will reject the cookie.",
        evidence: `Cookie: ${cookie.name}\nSecure: false`,
        remediation: "Add the Secure flag to this __Secure- prefixed cookie.",
        cwe: "CWE-614",
      });
    }
  }

  // Detect potential session fixation: session cookies without rotation indicators
  const sessionCookies = target.cookies.filter((c) =>
    SENSITIVE_COOKIE_NAMES.some((p) => p.test(c.name)) && !NON_SENSITIVE_PATTERNS.test(c.name),
  );
  // Check if session cookies lack __Host- prefix (vulnerable to cookie tossing from subdomains)
  const unprefixedSessionCookies = sessionCookies.filter(
    (c) => !c.name.startsWith("__Host-") && !c.name.startsWith("__Secure-"),
  );
  if (unprefixedSessionCookies.length > 0) {
    findings.push({
      id: "cookies-no-prefix",
      module: "Cookies",
      severity: "low",
      title: `${unprefixedSessionCookies.length} session cookie${unprefixedSessionCookies.length > 1 ? "s" : ""} without __Host- or __Secure- prefix`,
      description: "Session cookies without the __Host- prefix are vulnerable to cookie tossing attacks. A compromised subdomain can set a cookie with the same name on the parent domain, overwriting the legitimate session cookie.",
      evidence: `Cookies: ${unprefixedSessionCookies.map((c) => c.name).join(", ")}`,
      remediation: "Use __Host- prefix for session cookies. This prevents subdomain cookie tossing and ensures Secure, Path=/, and no Domain.",
      cwe: "CWE-384", owasp: "A07:2021",
      codeSnippet: `// Use __Host- prefix for maximum cookie security\nres.cookies.set("__Host-session", token, {\n  secure: true,\n  path: "/",\n  httpOnly: true,\n  sameSite: "lax",\n});`,
    });
  }

  // Cookie size analysis — oversized cookies may indicate storing sensitive data directly
  const MAX_COOKIE_SIZE = 4096; // 4KB per cookie
  const MAX_TOTAL_COOKIE_SIZE = 10240; // ~10KB total
  let totalCookieSize = 0;
  const oversizedCookies: string[] = [];
  for (const cookie of target.cookies) {
    const cookieSize = new TextEncoder().encode(`${cookie.name}=${cookie.value}`).length;
    totalCookieSize += cookieSize;
    if (cookieSize > MAX_COOKIE_SIZE) {
      oversizedCookies.push(`${cookie.name} (${Math.round(cookieSize / 1024 * 10) / 10}KB)`);
    }
  }
  if (oversizedCookies.length > 0) {
    findings.push({
      id: "cookies-oversized",
      module: "Cookies",
      severity: "medium",
      title: `${oversizedCookies.length} oversized cookie${oversizedCookies.length > 1 ? "s" : ""} detected (>4KB)`,
      description: "One or more cookies exceed the 4KB size limit. Large cookies may indicate sensitive data (e.g., JWTs, user profiles) stored directly in cookies instead of server-side sessions. This wastes bandwidth on every request and risks data exposure.",
      evidence: oversizedCookies.join(", "),
      remediation: "Store large data in server-side sessions and use a small session ID cookie. Keep cookies under 4KB.",
      cwe: "CWE-539",
      owasp: "A05:2021",
      codeSnippet: `// Use server-side sessions instead of large cookies\n// Store only a session ID in the cookie\nres.cookies.set("session_id", shortSessionId, {\n  httpOnly: true,\n  secure: true,\n  sameSite: "lax",\n});\n// Store data server-side: await redis.set(sessionId, JSON.stringify(data));`,
    });
  }
  if (totalCookieSize > MAX_TOTAL_COOKIE_SIZE) {
    findings.push({
      id: "cookies-total-size-excessive",
      module: "Cookies",
      severity: "low",
      title: `Total cookie size excessive (${Math.round(totalCookieSize / 1024 * 10) / 10}KB)`,
      description: `The total size of all cookies is ${Math.round(totalCookieSize / 1024 * 10) / 10}KB. Excessive cookie data is sent with every HTTP request, degrading performance and increasing bandwidth costs.`,
      evidence: `Total cookie payload: ${totalCookieSize} bytes across ${target.cookies.length} cookies`,
      remediation: "Reduce cookie count and size. Use server-side sessions for large data. Remove unnecessary tracking cookies.",
      cwe: "CWE-400",
    });
  }

  // Duplicate cookie detection — same name set multiple times with different values
  const cookiesByName = new Map<string, string[]>();
  for (const cookie of target.cookies) {
    const existing = cookiesByName.get(cookie.name);
    if (existing) {
      if (!existing.includes(cookie.value)) {
        existing.push(cookie.value);
      }
    } else {
      cookiesByName.set(cookie.name, [cookie.value]);
    }
  }
  const duplicateCookies = [...cookiesByName.entries()].filter(([, values]) => values.length > 1);
  if (duplicateCookies.length > 0) {
    findings.push({
      id: "cookies-duplicate-names",
      module: "Cookies",
      severity: "medium",
      title: `${duplicateCookies.length} cookie${duplicateCookies.length > 1 ? "s" : ""} set multiple times with different values`,
      description: "The same cookie name is set multiple times with different values. This can indicate race conditions, middleware conflicts, or misconfigured backends overwriting each other's cookies. It may also enable session fixation if an attacker can influence which value the browser uses.",
      evidence: duplicateCookies.map(([name, values]) => `${name}: ${values.length} distinct values`).join("\n"),
      remediation: "Ensure each cookie name is set only once per response. Audit middleware and backend handlers for conflicting Set-Cookie headers.",
      cwe: "CWE-436",
      owasp: "A05:2021",
    });
  }

  // Cookie entropy check — low entropy on session cookies suggests weak random generation
  for (const cookie of sessionCookies) {
    if (cookie.value.length < 8) continue; // skip very short values
    const value = cookie.value;
    const charFreq = new Map<string, number>();
    for (const ch of value) {
      charFreq.set(ch, (charFreq.get(ch) || 0) + 1);
    }
    let entropy = 0;
    for (const count of charFreq.values()) {
      const p = count / value.length;
      entropy -= p * Math.log2(p);
    }
    // Low entropy threshold: less than 3.0 bits per character suggests predictable values
    if (entropy < 3.0 && value.length >= 8) {
      findings.push({
        id: `cookies-low-entropy-${cookie.name}`,
        module: "Cookies",
        severity: "high",
        title: `Session cookie "${cookie.name}" has low entropy`,
        description: `The session cookie value has only ${entropy.toFixed(2)} bits of entropy per character. Low entropy suggests the value may be generated using a weak or predictable random number generator, making session tokens guessable.`,
        evidence: `Cookie: ${cookie.name}\nValue length: ${value.length} chars\nEntropy: ${entropy.toFixed(2)} bits/char\nSample: ${value.substring(0, 16)}...`,
        remediation: "Use a cryptographically secure random number generator (CSPRNG) to generate session tokens. In Node.js, use crypto.randomBytes() or crypto.randomUUID().",
        cwe: "CWE-330",
        owasp: "A02:2021",
        codeSnippet: `// Generate secure session tokens\nimport { randomBytes } from "crypto";\nconst sessionToken = randomBytes(32).toString("hex"); // 256-bit token\n\n// Or use crypto.randomUUID()\nconst sessionId = crypto.randomUUID();`,
      });
    }
  }

  // Third-party cookie tracking — check for cookies from known tracking domains
  const TRACKING_DOMAINS = [
    "doubleclick.net", "google-analytics.com", "googleadservices.com",
    "facebook.com", "facebook.net", "fbcdn.net",
    "twitter.com", "t.co",
    "linkedin.com", "ads-twitter.com",
    "criteo.com", "outbrain.com", "taboola.com",
    "hotjar.com", "mouseflow.com", "fullstory.com",
    "mixpanel.com", "segment.com", "amplitude.com",
    "quantserve.com", "scorecardresearch.com",
    "adnxs.com", "adsrvr.org", "demdex.net",
    "amazon-adsystem.com", "rubiconproject.com",
  ];
  const trackingCookies = target.cookies.filter((c) => {
    const domain = (c.domain || "").replace(/^\./, "").toLowerCase();
    return TRACKING_DOMAINS.some((td) => domain === td || domain.endsWith(`.${td}`));
  });
  if (trackingCookies.length > 0) {
    const uniqueDomains = [...new Set(trackingCookies.map((c) => c.domain.replace(/^\./, "")))];
    findings.push({
      id: "cookies-third-party-tracking",
      module: "Cookies",
      severity: "low",
      title: `${trackingCookies.length} third-party tracking cookie${trackingCookies.length > 1 ? "s" : ""} detected`,
      description: `Found ${trackingCookies.length} cookies from ${uniqueDomains.length} known tracking domain(s). Third-party tracking cookies monitor users across websites and may violate privacy regulations (GDPR, CCPA) if set without explicit consent.`,
      evidence: `Tracking domains: ${uniqueDomains.slice(0, 5).join(", ")}${uniqueDomains.length > 5 ? ` ...and ${uniqueDomains.length - 5} more` : ""}\nCookies: ${trackingCookies.slice(0, 5).map((c) => `${c.name} (${c.domain})`).join(", ")}`,
      remediation: "Ensure tracking cookies are only set after obtaining user consent. Implement a cookie consent banner that blocks tracking scripts until the user opts in. Consider privacy-friendly analytics alternatives (Plausible, Fathom).",
      cwe: "CWE-359",
      codeSnippet: `// Load tracking scripts only after consent\nconst consent = getCookieConsent();\nif (consent.analytics) {\n  // Load analytics script\n  const script = document.createElement("script");\n  script.src = "https://www.googletagmanager.com/gtag/js?id=GA_ID";\n  document.head.appendChild(script);\n}`,
    });
  }

  // Cookie prefix validation — ensure __Host- and __Secure- prefixed cookies meet all requirements
  for (const cookie of target.cookies) {
    if (cookie.name.startsWith("__Host-")) {
      const issues: string[] = [];
      if (!cookie.secure) issues.push("missing Secure flag");
      if (cookie.path !== "/") issues.push(`Path is "${cookie.path}" instead of "/"`);
      if (cookie.domain) issues.push(`Domain is set to "${cookie.domain}" (must be omitted)`);
      if (cookie.sameSite.toLowerCase() === "none" && !cookie.secure) issues.push("SameSite=None without Secure");
      if (issues.length > 0 && !findings.some((f) => f.id === `cookies-host-prefix-invalid-${cookie.name}`)) {
        findings.push({
          id: `cookies-host-prefix-deep-${cookie.name}`,
          module: "Cookies",
          severity: "medium",
          title: `__Host- cookie "${cookie.name}" has ${issues.length} prefix violation${issues.length > 1 ? "s" : ""}`,
          description: `__Host- prefixed cookies enforce strict origin binding. Violations: ${issues.join("; ")}. Browsers will reject this cookie, meaning it provides no security benefit and may break functionality.`,
          evidence: `Cookie: ${cookie.name}\nViolations: ${issues.join(", ")}\nSecure: ${cookie.secure}\nPath: ${cookie.path}\nDomain: ${cookie.domain || "(not set)"}`,
          remediation: "Fix all __Host- prefix requirements: Secure flag, Path=/, no Domain attribute. If these constraints don't fit your use case, use __Secure- prefix instead.",
          cwe: "CWE-1275",
          confidence: 100,
          codeSnippet: `// Correct __Host- cookie\nres.cookies.set("__Host-session", token, {\n  secure: true,\n  path: "/",\n  httpOnly: true,\n  sameSite: "lax",\n  // No domain attribute!\n});`,
        });
      }
    }
    if (cookie.name.startsWith("__Secure-")) {
      const issues: string[] = [];
      if (!cookie.secure) issues.push("missing Secure flag");
      if (!cookie.httpOnly && SENSITIVE_COOKIE_NAMES.some((p) => p.test(cookie.name.replace(/^__Secure-/, "")))) {
        issues.push("sensitive __Secure- cookie without HttpOnly");
      }
      if (issues.length > 0 && !findings.some((f) => f.id === `cookies-secure-prefix-no-flag-${cookie.name}`)) {
        findings.push({
          id: `cookies-secure-prefix-deep-${cookie.name}`,
          module: "Cookies",
          severity: "medium",
          title: `__Secure- cookie "${cookie.name}" has prefix issues`,
          description: `__Secure- prefixed cookies must have the Secure flag. Issues: ${issues.join("; ")}. Without Secure, browsers reject this cookie entirely.`,
          evidence: `Cookie: ${cookie.name}\nIssues: ${issues.join(", ")}`,
          remediation: "Add the Secure flag to all __Secure- prefixed cookies. Consider also adding HttpOnly for sensitive data.",
          cwe: "CWE-614",
        });
      }
    }
  }

  // Cookie scope analysis — detect overly broad domain and path settings
  const targetHost = new URL(target.url).hostname;
  const targetParts = targetHost.split(".");
  const targetTld = targetParts.length >= 2 ? targetParts.slice(-2).join(".") : targetHost;
  const scopeIssues: { name: string; issue: string }[] = [];
  for (const cookie of target.cookies) {
    if (NON_SENSITIVE_PATTERNS.test(cookie.name)) continue;
    const domain = (cookie.domain || "").replace(/^\./, "");
    // Flag cookies scoped to a TLD or public suffix
    if (domain && (domain === targetTld || domain.split(".").length <= 2) && cookie.domain?.startsWith(".")) {
      const isSensitive = SENSITIVE_COOKIE_NAMES.some((p) => p.test(cookie.name));
      if (isSensitive) {
        scopeIssues.push({ name: cookie.name, issue: `domain=.${domain} (shared across all subdomains)` });
      }
    }
    // Flag cookies with overly broad path (path=/ when they should be scoped to /api, /app, etc.)
    if (cookie.path === "/" && SENSITIVE_COOKIE_NAMES.some((p) => p.test(cookie.name))) {
      const apiPaths = target.apiEndpoints.map((ep) => new URL(ep).pathname.split("/").slice(0, 2).join("/")).filter(Boolean);
      const uniquePaths = [...new Set(apiPaths)];
      if (uniquePaths.length === 1 && uniquePaths[0] !== "/") {
        scopeIssues.push({ name: cookie.name, issue: `path=/ but API lives at ${uniquePaths[0]}` });
      }
    }
  }
  if (scopeIssues.length > 0 && !findings.some((f) => f.id === "cookies-broad-scope")) {
    findings.push({
      id: "cookies-scope-overly-broad",
      module: "Cookies",
      severity: "medium",
      title: `${scopeIssues.length} cookie${scopeIssues.length > 1 ? "s" : ""} with overly broad scope`,
      description: "Sensitive cookies are scoped more broadly than necessary. Overly broad domain scope exposes cookies to all subdomains (including potentially compromised ones). Overly broad path scope sends cookies to endpoints that don't need them.",
      evidence: scopeIssues.map((i) => `${i.name}: ${i.issue}`).join("\n"),
      remediation: "Restrict cookie domain to the specific subdomain and path to the narrowest scope needed. Use __Host- prefix to lock cookies to the exact origin.",
      cwe: "CWE-1275",
      owasp: "A05:2021",
      codeSnippet: `// Scope cookies tightly\nres.cookies.set("session", token, {\n  domain: "app.yourdomain.com",  // not ".yourdomain.com"\n  path: "/api",                   // not "/"\n  httpOnly: true,\n  secure: true,\n  sameSite: "lax",\n});`,
    });
  }

  // Session cookie size analysis — individual and aggregate
  const SESSION_MAX_REASONABLE = 256; // session IDs should be short opaque tokens
  const largeSessionCookies = sessionCookies.filter((c) => {
    const size = new TextEncoder().encode(c.value).length;
    return size > SESSION_MAX_REASONABLE;
  });
  if (largeSessionCookies.length > 0 && !findings.some((f) => f.id === "cookies-oversized")) {
    findings.push({
      id: "cookies-session-too-large",
      module: "Cookies",
      severity: "medium",
      title: `${largeSessionCookies.length} session cookie${largeSessionCookies.length > 1 ? "s" : ""} with excessive value size`,
      description: "Session cookies should contain only an opaque session ID (typically 32-64 bytes). Larger values suggest the server is storing session data directly in the cookie (e.g., serialized objects, JWTs with large payloads), which increases attack surface, wastes bandwidth, and may leak sensitive data.",
      evidence: largeSessionCookies.map((c) => {
        const size = new TextEncoder().encode(c.value).length;
        return `${c.name}: ${size} bytes (expected <${SESSION_MAX_REASONABLE})`;
      }).join("\n"),
      remediation: "Use a short opaque session ID in the cookie and store session data server-side (Redis, database). If using JWTs, minimize claims and consider moving to opaque tokens for session management.",
      cwe: "CWE-539",
      owasp: "A05:2021",
      codeSnippet: `// Use short opaque session IDs\nimport { randomBytes } from "crypto";\nconst sessionId = randomBytes(32).toString("hex"); // 64 char hex string\nres.cookies.set("session", sessionId, { httpOnly: true, secure: true, sameSite: "lax" });\n// Store data server-side:\nawait redis.set(\`session:\${sessionId}\`, JSON.stringify(userData), "EX", 86400);`,
    });
  }

  // Cookie entropy check — extended analysis for all session cookies
  for (const cookie of sessionCookies) {
    if (cookie.value.length < 8) continue;
    if (findings.some((f) => f.id === `cookies-low-entropy-${cookie.name}`)) continue;
    const value = cookie.value;
    // Check for obviously sequential/predictable patterns
    const isNumericOnly = /^\d+$/.test(value);
    const isIncrementing = /^[0-9]{1,10}$/.test(value) && parseInt(value) < 1_000_000;
    const hasRepeatingPattern = /(.{2,8})\1{2,}/.test(value);

    if (isNumericOnly || isIncrementing || hasRepeatingPattern) {
      const reason = isIncrementing ? "appears to be a sequential numeric ID" :
        isNumericOnly ? "purely numeric (no alphabet characters)" :
        "contains a repeating pattern";
      findings.push({
        id: `cookies-predictable-session-${cookie.name}`,
        module: "Cookies",
        severity: "high",
        title: `Session cookie "${cookie.name}" appears predictable`,
        description: `The session cookie value ${reason}. Predictable session tokens allow attackers to enumerate valid sessions or guess other users' session IDs (session prediction attack).`,
        evidence: `Cookie: ${cookie.name}\nValue pattern: ${reason}\nSample: ${value.substring(0, 20)}${value.length > 20 ? "..." : ""}`,
        remediation: "Generate session tokens using a CSPRNG with at least 128 bits of entropy. Use crypto.randomBytes(32).toString('hex') or crypto.randomUUID().",
        cwe: "CWE-330",
        owasp: "A02:2021",
        confidence: isIncrementing ? 95 : 80,
        codeSnippet: `// Generate unpredictable session tokens\nimport { randomBytes } from "crypto";\nconst token = randomBytes(32).toString("hex"); // 256-bit random token`,
      });
    }

    // Also check minimum token length — session tokens should be at least 16 bytes (128 bits)
    const effectiveBytes = value.length * (Math.log2(new Set(value).size) / 8);
    if (effectiveBytes < 16 && value.length < 32) {
      findings.push({
        id: `cookies-short-session-${cookie.name}`,
        module: "Cookies",
        severity: "medium",
        title: `Session cookie "${cookie.name}" may have insufficient token length`,
        description: `The session token is only ${value.length} characters long with ~${Math.round(effectiveBytes)} effective bytes of entropy. OWASP recommends at least 128 bits (16 bytes) of entropy for session tokens to resist brute-force attacks.`,
        evidence: `Cookie: ${cookie.name}\nValue length: ${value.length} chars\nUnique chars: ${new Set(value).size}\nEffective entropy: ~${Math.round(effectiveBytes)} bytes`,
        remediation: "Use session tokens with at least 128 bits of randomness. A 32-character hex string (crypto.randomBytes(16).toString('hex')) provides 128 bits.",
        cwe: "CWE-331",
        owasp: "A02:2021",
        codeSnippet: `// Minimum 128-bit session token\nimport { randomBytes } from "crypto";\nconst sessionToken = randomBytes(16).toString("hex"); // 128-bit minimum\n// Better: 256-bit\nconst strongToken = randomBytes(32).toString("hex");`,
      });
    }
  }

  // Third-party cookie detection with SameSite implications
  const targetDomain = targetHost.split(".").slice(-2).join(".");
  const thirdPartyCookies = target.cookies.filter((c) => {
    const domain = (c.domain || "").replace(/^\./, "").toLowerCase();
    if (!domain) return false;
    return !domain.endsWith(targetDomain) && domain !== targetDomain;
  });
  const thirdPartyNone = thirdPartyCookies.filter((c) => c.sameSite.toLowerCase() === "none");
  const thirdPartyNoSameSite = thirdPartyCookies.filter((c) => !c.sameSite || c.sameSite === "");
  if (thirdPartyNone.length > 0) {
    findings.push({
      id: "cookies-third-party-samesite-none",
      module: "Cookies",
      severity: "medium",
      title: `${thirdPartyNone.length} third-party cookie${thirdPartyNone.length > 1 ? "s" : ""} with SameSite=None`,
      description: `Third-party cookies with SameSite=None are sent on all cross-site requests. With browsers phasing out third-party cookies (Chrome's Privacy Sandbox, Firefox ETP, Safari ITP), these cookies will stop working. Additionally, SameSite=None requires the Secure flag — without it, cookies are rejected.`,
      evidence: thirdPartyNone.slice(0, 5).map((c) => `${c.name} (${c.domain}) SameSite=None Secure=${c.secure}`).join("\n"),
      remediation: "Migrate away from third-party cookies. Use first-party alternatives (server-side sessions, CHIPS partitioned cookies, or the Storage Access API). Ensure all SameSite=None cookies have the Secure flag.",
      cwe: "CWE-1275",
      owasp: "A05:2021",
      codeSnippet: `// Use CHIPS (Partitioned cookies) for legitimate cross-site use\nres.headers.append("Set-Cookie",\n  "widget_session=abc; SameSite=None; Secure; Partitioned; Path=/"\n);\n// Or use Storage Access API in the browser\nawait document.requestStorageAccess();`,
    });
  }
  if (thirdPartyNoSameSite.length > 0) {
    findings.push({
      id: "cookies-third-party-missing-samesite",
      module: "Cookies",
      severity: "low",
      title: `${thirdPartyNoSameSite.length} third-party cookie${thirdPartyNoSameSite.length > 1 ? "s" : ""} without SameSite attribute`,
      description: "Third-party cookies without an explicit SameSite attribute default to Lax in modern browsers, which means they won't be sent in cross-site contexts. This may break functionality that depends on these cookies being available cross-site.",
      evidence: thirdPartyNoSameSite.slice(0, 5).map((c) => `${c.name} (${c.domain})`).join("\n"),
      remediation: "Explicitly set SameSite on all cookies. For cross-site cookies, use SameSite=None; Secure. For same-site only, use SameSite=Lax or Strict.",
      cwe: "CWE-1275",
    });
  }

  // Cookie manipulation via header injection — check for cookie values that could enable injection
  for (const cookie of target.cookies) {
    const value = cookie.value;
    // Check for newlines or carriage returns in cookie values (header injection)
    if (value.includes("\r") || value.includes("\n") || value.includes("%0d") || value.includes("%0a") ||
        value.includes("%0D") || value.includes("%0A")) {
      findings.push({
        id: `cookies-header-injection-${cookie.name}`,
        module: "Cookies",
        severity: "high",
        title: `Cookie "${cookie.name}" contains newline characters (header injection risk)`,
        description: "This cookie value contains CR/LF characters or their URL-encoded equivalents. If the server reflects cookie values in Set-Cookie headers without sanitization, an attacker could inject additional HTTP headers (HTTP Response Splitting) or set arbitrary cookies.",
        evidence: `Cookie: ${cookie.name}\nValue contains: ${value.includes("\r") || value.includes("%0d") || value.includes("%0D") ? "CR " : ""}${value.includes("\n") || value.includes("%0a") || value.includes("%0A") ? "LF" : ""}`,
        remediation: "Sanitize all cookie values to strip CR/LF characters. Use your framework's built-in cookie-setting functions which handle encoding. Never reflect raw user input in Set-Cookie headers.",
        cwe: "CWE-113",
        owasp: "A03:2021",
        confidence: 90,
        codeSnippet: `// Sanitize cookie values\nconst safeCookieValue = (val: string) =>\n  val.replace(/[\\r\\n%0d%0a]/gi, "");\nres.cookies.set("name", safeCookieValue(userInput), { httpOnly: true });`,
      });
    }
    // Check for semicolons or additional cookie attributes embedded in the value
    if (value.includes(";") && (value.toLowerCase().includes("path=") || value.toLowerCase().includes("domain=") ||
        value.toLowerCase().includes("expires=") || value.toLowerCase().includes("httponly"))) {
      findings.push({
        id: `cookies-attribute-injection-${cookie.name}`,
        module: "Cookies",
        severity: "high",
        title: `Cookie "${cookie.name}" value contains embedded cookie attributes`,
        description: "The cookie value appears to contain cookie attribute directives (path=, domain=, expires=, httponly). This suggests the server may be concatenating unsanitized input into Set-Cookie headers, allowing attackers to override security attributes.",
        evidence: `Cookie: ${cookie.name}\nValue: ${value.substring(0, 100)}${value.length > 100 ? "..." : ""}`,
        remediation: "Never concatenate user input into Set-Cookie headers. Use your framework's cookie API which properly encodes values and separates attributes.",
        cwe: "CWE-113",
        owasp: "A03:2021",
        confidence: 75,
      });
    }
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
