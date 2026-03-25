import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml, isSoft404 } from "../soft404";

const OIDC_PATHS = [
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
];

const AUTH_CALLBACK_PATHS = [
  "/api/auth/callback",
  "/auth/callback",
  "/oauth/callback",
  "/api/auth/callback/google",
  "/api/auth/callback/github",
  "/api/auth/callback/credentials",
  "/auth/v1/callback",
];

const AUTH_SIGNIN_PATHS = [
  "/api/auth/signin",
  "/api/auth/providers",
  "/api/auth/csrf",
  "/api/auth/session",
  "/auth/v1/token",
];

export const oauthModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Detect OAuth provider usage from JS bundles
  const usesNextAuth = allJs.includes("next-auth") || allJs.includes("NextAuth") || allJs.includes("/api/auth/");
  const usesAuth0 = allJs.includes("auth0") || allJs.includes("Auth0");
  const usesClerk = allJs.includes("clerk") || allJs.includes("__clerk");
  const usesSupabaseAuth = allJs.includes("supabase") && allJs.includes("auth");

  // Run all tests concurrently
  const [oidcResults, callbackResults, signinResults, stateResults, csrfResult] = await Promise.all([
    // 1. Check OIDC discovery endpoints for sensitive config exposure
    Promise.allSettled(
      OIDC_PATHS.map(async (path) => {
        const res = await scanFetch(target.baseUrl + path, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        try {
          const config = JSON.parse(text);
          if (config.issuer || config.authorization_endpoint) {
            const issues: string[] = [];
            if (!config.require_pkce && config.code_challenge_methods_supported === undefined) {
              issues.push("PKCE not required");
            }
            if (config.grant_types_supported?.includes("implicit")) {
              issues.push("Implicit grant enabled (deprecated, vulnerable to token leakage)");
            }
            if (config.registration_endpoint) {
              issues.push("Dynamic client registration enabled");
            }
            return { path, config, issues };
          }
        } catch { /* not JSON */ }
        return null;
      }),
    ),

    // 2. Test callback endpoints for redirect_uri validation
    Promise.allSettled(
      AUTH_CALLBACK_PATHS.map(async (path) => {
        const url = target.baseUrl + path;
        // Test with evil redirect_uri
        const testUrl = new URL(url);
        testUrl.searchParams.set("redirect_uri", "https://evil.com/steal");
        testUrl.searchParams.set("code", "test_code_123");
        testUrl.searchParams.set("state", "test_state");

        const res = await scanFetch(testUrl.href, { timeoutMs: 5000, redirect: "manual" });
        const location = res.headers.get("location") || "";

        if (location.includes("evil.com")) {
          return { path, type: "redirect_uri" as const, location };
        }

        // Check if callback exists and accepts arbitrary codes
        const res2 = await scanFetch(url + "?code=invalid_test_code&state=x", { timeoutMs: 5000 });
        const text = await res2.text();
        if (res2.ok && !looksLikeHtml(text) && text.includes("token")) {
          return { path, type: "token_leak" as const, text: text.substring(0, 200) };
        }

        return null;
      }),
    ),

    // 3. Check auth endpoints for info exposure
    Promise.allSettled(
      AUTH_SIGNIN_PATHS.map(async (path) => {
        const res = await scanFetch(target.baseUrl + path, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
        try {
          const data = JSON.parse(text);
          // NextAuth /api/auth/providers leaks provider config
          if (data && typeof data === "object") {
            const keys = Object.keys(data);
            if (keys.some((k) => /google|github|facebook|twitter|discord|apple|azure/i.test(k))) {
              const clientIds = keys.filter((k) => data[k]?.clientId || data[k]?.id);
              if (clientIds.length > 0) {
                return { path, providers: keys, hasClientIds: clientIds.length > 0 };
              }
            }
            // Session endpoint leaking user data without auth
            if (path.includes("session") && (data.user || data.email || data.accessToken)) {
              return { path, sessionLeak: true, keys: Object.keys(data) };
            }
          }
        } catch { /* not JSON */ }
        return null;
      }),
    ),

    // 4. Test OAuth state parameter validation
    Promise.allSettled(
      AUTH_CALLBACK_PATHS.slice(0, 4).map(async (path) => {
        // Send callback without state parameter
        const url = new URL(target.baseUrl + path);
        url.searchParams.set("code", "test_no_state");
        const res = await scanFetch(url.href, { timeoutMs: 5000, redirect: "manual" });
        const location = res.headers.get("location") || "";
        // If it redirects to a success page without validating state, that's a CSRF issue
        if ((res.status === 302 || res.status === 303) && !location.includes("error") && !location.includes("signin")) {
          return { path };
        }
        return null;
      }),
    ),

    // 5. Check CSRF token on NextAuth signin
    (async () => {
      if (!usesNextAuth) return null;
      const csrfRes = await scanFetch(target.baseUrl + "/api/auth/csrf", { timeoutMs: 5000 });
      if (!csrfRes.ok) return null;
      try {
        const data = JSON.parse(await csrfRes.text());
        if (data.csrfToken) {
          // Try signin without CSRF token
          const signinRes = await scanFetch(target.baseUrl + "/api/auth/signin/credentials", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: "test@test.com", password: "test" }),
            timeoutMs: 5000,
          });
          if (signinRes.ok) {
            return { csrfBypass: true };
          }
        }
      } catch { /* skip */ }
      return null;
    })(),
  ]);

  // Collect findings
  for (const r of oidcResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.issues.length > 0) {
      findings.push({
        id: `oauth-oidc-${findings.length}`, module: "OAuth", severity: "medium",
        title: `OAuth/OIDC configuration issues at ${v.path}`,
        description: `The OpenID Connect discovery endpoint exposes configuration with security concerns: ${v.issues.join("; ")}`,
        evidence: `GET ${target.baseUrl}${v.path}\nIssues: ${v.issues.join(", ")}`,
        remediation: "Disable implicit grant flow. Enforce PKCE for all OAuth flows. Disable dynamic client registration unless specifically needed.",
        cwe: "CWE-346", owasp: "A07:2021",
      });
    }
    if (v.config.registration_endpoint) {
      findings.push({
        id: `oauth-dyn-reg-${findings.length}`, module: "OAuth", severity: "high",
        title: "Dynamic OAuth client registration enabled",
        description: "The authorization server allows dynamic client registration. Attackers can register arbitrary clients and potentially gain unauthorized access.",
        evidence: `Registration endpoint: ${v.config.registration_endpoint}`,
        remediation: "Disable dynamic client registration or require authentication for it.",
        cwe: "CWE-287", owasp: "A07:2021",
      });
    }
  }

  for (const r of callbackResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.type === "redirect_uri") {
      findings.push({
        id: `oauth-redirect-${findings.length}`, module: "OAuth", severity: "critical",
        title: `OAuth redirect_uri bypass on ${v.path}`,
        description: "The OAuth callback accepts arbitrary redirect URIs. Attackers can steal authorization codes by redirecting to their server.",
        evidence: `GET ${target.baseUrl}${v.path}?redirect_uri=https://evil.com/steal\nRedirects to: ${v.location}`,
        remediation: "Strictly validate redirect_uri against a whitelist of pre-registered URLs. Use exact string matching, not prefix or subdomain matching.",
        cwe: "CWE-601", owasp: "A07:2021",
      });
    }
  }

  for (const r of signinResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.sessionLeak) {
      findings.push({
        id: `oauth-session-${findings.length}`, module: "OAuth", severity: "high",
        title: `Session data exposed at ${v.path}`,
        description: "The session endpoint returns user data without proper authentication. This may expose email, name, or tokens to unauthenticated requests.",
        evidence: `GET ${target.baseUrl}${v.path}\nExposed fields: ${v.keys.join(", ")}`,
        remediation: "Ensure session endpoints require valid authentication cookies. Return empty/null for unauthenticated requests.",
        cwe: "CWE-200", owasp: "A01:2021",
      });
    }
  }

  for (const r of stateResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `oauth-state-${findings.length}`, module: "OAuth", severity: "high",
      title: `Missing OAuth state validation on ${v.path}`,
      description: "The OAuth callback processes requests without a valid state parameter. This enables CSRF attacks — an attacker can force a victim to log in with the attacker's account.",
      evidence: `GET ${target.baseUrl}${v.path}?code=test_no_state (no state parameter)\nServer processed the request without error`,
      remediation: "Always validate the state parameter in OAuth callbacks. Generate a unique, unpredictable state value per authorization request and verify it matches on callback.",
      cwe: "CWE-352", owasp: "A07:2021",
    });
    break;
  }

  if (csrfResult && typeof csrfResult === "object" && "csrfBypass" in csrfResult) {
    findings.push({
      id: `oauth-csrf-bypass-${findings.length}`, module: "OAuth", severity: "medium",
      title: "NextAuth CSRF token not enforced on signin",
      description: "The credentials signin endpoint accepts requests without a valid CSRF token. This could allow cross-site login attacks.",
      evidence: "POST /api/auth/signin/credentials without csrfToken succeeded",
      remediation: "Ensure the NextAuth CSRF token is validated on all mutation endpoints. Check your NextAuth configuration.",
      cwe: "CWE-352", owasp: "A07:2021",
    });
  }

  // Check JS bundles for hardcoded OAuth client secrets
  const secretPatterns = [
    /client[_-]?secret\s*[:=]\s*["']([a-zA-Z0-9_-]{20,})["']/gi,
    /GOOGLE_CLIENT_SECRET\s*[:=]\s*["']([^"']+)["']/gi,
    /GITHUB_SECRET\s*[:=]\s*["']([^"']+)["']/gi,
    /AUTH0_SECRET\s*[:=]\s*["']([^"']+)["']/gi,
  ];
  for (const pattern of secretPatterns) {
    for (const m of allJs.matchAll(pattern)) {
      if (m[1] && m[1].length >= 20) {
        findings.push({
          id: `oauth-secret-${findings.length}`, module: "OAuth", severity: "critical",
          title: "OAuth client secret exposed in JavaScript bundle",
          description: "An OAuth client secret is hardcoded in the client-side JavaScript. Attackers can use this to impersonate your application.",
          evidence: `Pattern: ${m[0].substring(0, 50)}...`,
          remediation: "Move OAuth client secrets to server-side environment variables. Never include secrets in client-side code. Use NEXT_PUBLIC_ only for public values.",
          cwe: "CWE-798", owasp: "A07:2021",
        });
        break;
      }
    }
  }

  return findings;
};
