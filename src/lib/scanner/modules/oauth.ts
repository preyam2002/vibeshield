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

    // 2. Test callback endpoints for redirect_uri validation (including subdomain bypass)
    Promise.allSettled(
      AUTH_CALLBACK_PATHS.map(async (path) => {
        const url = target.baseUrl + path;
        const targetHost = new URL(target.baseUrl).hostname;
        const evilRedirects = [
          "https://evil.com/steal",
          `https://${targetHost}.evil.com/steal`,           // subdomain of attacker
          `https://evil.com/${targetHost}`,                 // path-based bypass
          `https://${targetHost}@evil.com/steal`,           // userinfo bypass
        ];

        for (const evilUri of evilRedirects) {
          const testUrl = new URL(url);
          testUrl.searchParams.set("redirect_uri", evilUri);
          testUrl.searchParams.set("code", "test_code_123");
          testUrl.searchParams.set("state", "test_state");

          const res = await scanFetch(testUrl.href, { timeoutMs: 5000, redirect: "manual" });
          const location = res.headers.get("location") || "";

          if (location.includes("evil.com")) {
            const bypass = evilUri.includes("@") ? "userinfo" : evilUri.includes(targetHost + ".") ? "subdomain" : "direct";
            return { path, type: "redirect_uri" as const, location, bypass, evilUri };
          }
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
        codeSnippet: `// Enforce PKCE in your OAuth client\nconst codeVerifier = crypto.randomBytes(32).toString("base64url");\nconst codeChallenge = crypto\n  .createHash("sha256").update(codeVerifier).digest("base64url");\n\nconst authUrl = new URL(authorizationEndpoint);\nauthUrl.searchParams.set("code_challenge", codeChallenge);\nauthUrl.searchParams.set("code_challenge_method", "S256");\nauthUrl.searchParams.set("response_type", "code"); // never "token"`,
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
        codeSnippet: `// Protect the registration endpoint with an access token\napp.post("/oauth/register", requireBearerToken, async (req, res) => {\n  // Only pre-authorized clients can register\n  const client = await registerClient(req.body);\n  res.json(client);\n});`,
        cwe: "CWE-287", owasp: "A07:2021",
      });
    }
  }

  for (const r of callbackResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.type === "redirect_uri") {
      const bypassDesc = v.bypass === "subdomain" ? " via subdomain spoofing" : v.bypass === "userinfo" ? " via URL userinfo bypass" : "";
      findings.push({
        id: `oauth-redirect-${findings.length}`, module: "OAuth", severity: "critical",
        title: `OAuth redirect_uri bypass${bypassDesc} on ${v.path}`,
        description: `The OAuth callback accepts ${v.bypass === "direct" ? "arbitrary" : "crafted"} redirect URIs${bypassDesc}. Attackers can steal authorization codes by redirecting to their server.`,
        evidence: `GET ${target.baseUrl}${v.path}?redirect_uri=${v.evilUri}\nRedirects to: ${v.location}`,
        remediation: "Strictly validate redirect_uri against a whitelist of pre-registered URLs. Use exact string matching, not prefix or subdomain matching.",
        codeSnippet: `// Validate redirect_uri with exact match\nconst ALLOWED_REDIRECTS = new Set([\n  "https://yourdomain.com/api/auth/callback",\n  "https://yourdomain.com/oauth/callback",\n]);\n\nconst redirectUri = req.query.redirect_uri;\nif (!ALLOWED_REDIRECTS.has(redirectUri)) {\n  return res.status(400).json({ error: "invalid_redirect_uri" });\n}`,
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
        codeSnippet: `// NextAuth — session endpoint returns null when unauthenticated\n// next-auth.config.ts\nexport const authOptions = {\n  callbacks: {\n    session({ session, token }) {\n      // Only expose minimal fields\n      return { user: { id: token.sub, name: session.user?.name } };\n    },\n  },\n};\n// Protect API: const session = await getServerSession(authOptions);\n// if (!session) return NextResponse.json(null, { status: 401 });`,
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
      codeSnippet: `// Generate state before redirect\nconst state = crypto.randomBytes(32).toString("hex");\ncookies().set("oauth_state", state, { httpOnly: true, sameSite: "lax" });\n// Include state in authorization URL\nauthUrl.searchParams.set("state", state);\n\n// Validate state in callback\nconst savedState = cookies().get("oauth_state")?.value;\nif (!savedState || savedState !== req.query.state) {\n  return res.status(403).json({ error: "Invalid state" });\n}`,
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
      codeSnippet: `// Include CSRF token in NextAuth signin requests\nimport { getCsrfToken } from "next-auth/react";\n\nconst csrfToken = await getCsrfToken();\nawait fetch("/api/auth/signin/credentials", {\n  method: "POST",\n  headers: { "Content-Type": "application/x-www-form-urlencoded" },\n  body: new URLSearchParams({ csrfToken, email, password }),\n});`,
      cwe: "CWE-352", owasp: "A07:2021",
    });
  }

  // Check for insecure response_type usage in JS bundles (implicit flow token leakage)
  const implicitFlowPatterns = [
    /response_type\s*[:=]\s*["'](token|id_token)["']/gi,
    /response_type=(?:token|id_token)(?:&|["'])/gi,
  ];
  let implicitFlagged = false;
  for (const pat of implicitFlowPatterns) {
    if (implicitFlagged) break;
    for (const m of allJs.matchAll(pat)) {
      if (!implicitFlagged) {
        implicitFlagged = true;
        findings.push({
          id: `oauth-implicit-${findings.length}`, module: "OAuth", severity: "high",
          title: "OAuth implicit flow (response_type=token) detected in client code",
          description: "The application uses the OAuth implicit flow which returns tokens in the URL fragment. Tokens are exposed to browser history, referrer headers, and browser extensions.",
          evidence: `Found in JS bundle: ${m[0]}`,
          remediation: "Use the Authorization Code flow with PKCE instead of the implicit flow. Set response_type=code and exchange the code for tokens server-side.",
          codeSnippet: `// Replace implicit flow with authorization code + PKCE\nconst authUrl = new URL(authorizationEndpoint);\nauthUrl.searchParams.set("response_type", "code"); // NOT "token"\nauthUrl.searchParams.set("code_challenge", codeChallenge);\nauthUrl.searchParams.set("code_challenge_method", "S256");`,
          cwe: "CWE-522", owasp: "A07:2021",
        });
      }
    }
  }

  // Check if OIDC config requires nonce (replay protection)
  for (const r of oidcResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.config.id_token_signing_alg_values_supported && !v.config.require_nonce) {
      const hasNonceInJs = /\bnonce\b.*(?:random|crypto|uuid)/i.test(allJs) || /nonce\s*[:=]\s*["'][a-zA-Z0-9]/i.test(allJs);
      if (!hasNonceInJs) {
        findings.push({
          id: `oauth-nonce-${findings.length}`, module: "OAuth", severity: "medium",
          title: "OIDC nonce parameter not enforced",
          description: "The OpenID Connect provider does not require a nonce parameter and no nonce usage was detected in client code. Without nonce validation, ID tokens are vulnerable to replay attacks.",
          evidence: `OIDC config at ${v.path}: id_token signing supported but require_nonce not set\nNo nonce generation detected in JS bundles`,
          remediation: "Generate a unique nonce per authorization request, include it in the auth URL, and validate it matches the nonce claim in the returned ID token.",
          codeSnippet: `// Generate and validate nonce\nconst nonce = crypto.randomBytes(16).toString("hex");\ncookies().set("oidc_nonce", nonce, { httpOnly: true });\nauthUrl.searchParams.set("nonce", nonce);\n\n// In callback, verify nonce in ID token\nconst decoded = jwt.decode(idToken);\nif (decoded.nonce !== cookies().get("oidc_nonce")?.value) {\n  throw new Error("Invalid nonce — possible token replay");\n}`,
          cwe: "CWE-294", owasp: "A07:2021",
        });
      }
    }
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
          codeSnippet: `// .env (server-side only — no NEXT_PUBLIC_ prefix)\nGOOGLE_CLIENT_SECRET=your-secret\n\n// app/api/auth/[...nextauth]/route.ts\nimport GoogleProvider from "next-auth/providers/google";\nexport const authOptions = {\n  providers: [\n    GoogleProvider({\n      clientId: process.env.GOOGLE_CLIENT_ID!,\n      clientSecret: process.env.GOOGLE_CLIENT_SECRET!, // server-only\n    }),\n  ],\n};`,
          cwe: "CWE-798", owasp: "A07:2021",
        });
        break;
      }
    }
  }

  // ── Phase 2: Advanced OAuth checks ──────────────────────────────────────

  const [pkceResults, stateValidationResults, redirectVariationResults, fragmentTokenResults, scopeEscalationResults] = await Promise.allSettled([

    // 6. OAuth PKCE enforcement — check if public clients use code_challenge
    (async (): Promise<{ missing: boolean; endpoints: string[] } | null> => {
      const authEndpoints: string[] = [];
      // Gather authorization endpoints from OIDC discovery
      for (const r of oidcResults) {
        if (r.status !== "fulfilled" || !r.value) continue;
        if (r.value.config.authorization_endpoint) {
          authEndpoints.push(r.value.config.authorization_endpoint);
        }
      }
      // Also check JS bundles for authorization URLs
      const authUrlPatterns = [
        /(?:authorize|authorization)[_-]?(?:endpoint|url|uri)\s*[:=]\s*["']([^"']+)["']/gi,
        /https?:\/\/[^"'\s]+\/(?:oauth2?|authorize)\b[^"'\s]*/gi,
      ];
      for (const pat of authUrlPatterns) {
        for (const m of allJs.matchAll(pat)) {
          const url = m[1] || m[0];
          if (url.startsWith("http")) authEndpoints.push(url);
        }
      }
      // Check if code_challenge is ever used in JS bundles
      const usesPkce = /code_challenge/i.test(allJs) || /pkce/i.test(allJs) || /code_verifier/i.test(allJs);
      if (!usesPkce && authEndpoints.length > 0) {
        return { missing: true, endpoints: authEndpoints.slice(0, 3) };
      }
      // If we found OIDC configs, check if server enforces PKCE
      for (const r of oidcResults) {
        if (r.status !== "fulfilled" || !r.value) continue;
        const cfg = r.value.config;
        if (cfg.code_challenge_methods_supported && !cfg.require_pkce && !usesPkce) {
          return { missing: true, endpoints: authEndpoints.slice(0, 3) };
        }
      }
      return null;
    })(),

    // 7. OAuth state parameter validation — check if state is present and random
    (async (): Promise<{ issue: string; evidence: string } | null> => {
      // Look for state parameter generation in JS bundles
      const stateGenPatterns = [
        /state\s*[:=]\s*["']([^"']{1,80})["']/gi,
      ];
      for (const pat of stateGenPatterns) {
        for (const m of allJs.matchAll(pat)) {
          const stateValue = m[1];
          // Skip dynamic/random-looking values or template literals
          if (!stateValue || stateValue.includes("${") || stateValue.includes("random")) continue;
          // Flag static/predictable state values
          if (/^[a-z_-]+$/i.test(stateValue) && stateValue.length < 20) {
            return {
              issue: "static",
              evidence: `Hardcoded state value found: state="${stateValue}"`,
            };
          }
        }
      }
      // Check if state is ever set in OAuth URLs
      const setsState = /[?&]state=/i.test(allJs) || /\.set\(\s*["']state["']/i.test(allJs) || /state\s*[:=]\s*(?:crypto|Math\.random|uuid|nanoid)/i.test(allJs);
      const hasOAuthFlow = /response_type\s*[:=]/i.test(allJs) || /authorize/i.test(allJs);
      if (hasOAuthFlow && !setsState) {
        return {
          issue: "missing",
          evidence: "OAuth authorization flow detected but no state parameter usage found in JS bundles",
        };
      }
      return null;
    })(),

    // 8. OAuth redirect URI validation — test subdomain variations, path traversal, open redirects
    Promise.allSettled(
      AUTH_CALLBACK_PATHS.slice(0, 3).map(async (path) => {
        const url = target.baseUrl + path;
        const targetHost = new URL(target.baseUrl).hostname;
        const advancedBypasses = [
          { uri: `${target.baseUrl}${path}/../../../evil`, technique: "path_traversal" },
          { uri: `${target.baseUrl}${path}?next=https://evil.com`, technique: "open_redirect_param" },
          { uri: `${target.baseUrl}${path}%00@evil.com`, technique: "null_byte" },
          { uri: `https://sub.${targetHost}${path}`, technique: "subdomain_variation" },
          { uri: `${target.baseUrl}${path}#@evil.com`, technique: "fragment_injection" },
        ];
        const results: { technique: string; evidence: string }[] = [];
        const checks = await Promise.allSettled(
          advancedBypasses.map(async ({ uri, technique }) => {
            const testUrl = new URL(url);
            testUrl.searchParams.set("redirect_uri", uri);
            testUrl.searchParams.set("code", "test_bypass");
            testUrl.searchParams.set("state", "test");
            const res = await scanFetch(testUrl.href, { timeoutMs: 5000, redirect: "manual" });
            const location = res.headers.get("location") || "";
            if (
              (res.status === 301 || res.status === 302 || res.status === 303) &&
              (location.includes("evil") || location.includes(".."))
            ) {
              return { technique, evidence: `redirect_uri=${uri} → Location: ${location}` };
            }
            return null;
          }),
        );
        for (const c of checks) {
          if (c.status === "fulfilled" && c.value) results.push(c.value);
        }
        return results.length > 0 ? { path, results } : null;
      }),
    ).then((settled) => {
      const hits: { path: string; results: { technique: string; evidence: string }[] }[] = [];
      for (const r of settled) {
        if (r.status === "fulfilled" && r.value) hits.push(r.value);
      }
      return hits;
    }),

    // 9. OAuth token in fragment — check if access tokens are exposed in URL fragments (implicit flow)
    (async (): Promise<{ found: boolean; evidence: string[] } | null> => {
      const evidence: string[] = [];
      // Check JS for fragment token extraction (indicates implicit flow handling)
      const fragmentPatterns = [
        /(?:location|window)\.hash.*access_token/gi,
        /(?:#|fragment).*access_token/gi,
        /getHashParam.*(?:access_token|token)/gi,
        /parseHash|getTokenFromHash/gi,
        /access_token\s*=\s*(?:location|window)\.hash/gi,
        /new URLSearchParams\(.*(?:hash|fragment).*\).*(?:get|access_token)/gi,
      ];
      for (const pat of fragmentPatterns) {
        for (const m of allJs.matchAll(pat)) {
          evidence.push(m[0].substring(0, 100));
        }
      }
      // Check redirect URLs for fragment tokens
      for (const rUrl of target.redirectUrls) {
        if (/#.*access_token=/.test(rUrl) || /#.*token=/.test(rUrl)) {
          evidence.push(`Redirect URL with fragment token: ${rUrl.substring(0, 150)}`);
        }
      }
      // Check link URLs for fragment tokens
      for (const link of target.linkUrls) {
        if (/#.*access_token=/.test(link)) {
          evidence.push(`Link with fragment token: ${link.substring(0, 150)}`);
        }
      }
      return evidence.length > 0 ? { found: true, evidence } : null;
    })(),

    // 10. OAuth scope escalation — test if requesting additional scopes is possible
    (async (): Promise<{ escalatable: boolean; evidence: string } | null> => {
      // Find authorization endpoints from OIDC discovery
      let authorizationEndpoint: string | null = null;
      for (const r of oidcResults) {
        if (r.status !== "fulfilled" || !r.value) continue;
        if (r.value.config.authorization_endpoint) {
          authorizationEndpoint = r.value.config.authorization_endpoint;
          break;
        }
      }
      if (!authorizationEndpoint) return null;
      // Detect configured scopes from JS bundles
      const scopeMatch = allJs.match(/scope\s*[:=]\s*["']([^"']+)["']/i);
      const configuredScopes = scopeMatch ? scopeMatch[1] : "openid profile email";
      // Test with escalated scopes
      const escalatedScopes = `${configuredScopes} admin write:all delete:all manage:users`;
      const testUrl = new URL(authorizationEndpoint);
      testUrl.searchParams.set("response_type", "code");
      testUrl.searchParams.set("client_id", "test_client");
      testUrl.searchParams.set("scope", escalatedScopes);
      testUrl.searchParams.set("redirect_uri", target.baseUrl + "/oauth/callback");
      const res = await scanFetch(testUrl.href, { timeoutMs: 5000, redirect: "manual" });
      const location = res.headers.get("location") || "";
      const body = res.status < 400 ? await res.text() : "";
      // If the server doesn't reject the escalated scopes, flag it
      if (
        (res.status === 302 || res.status === 301) &&
        !location.includes("error") &&
        !location.includes("invalid_scope")
      ) {
        return {
          escalatable: true,
          evidence: `Authorization endpoint accepted escalated scopes without error.\nRequested: ${escalatedScopes}\nRedirect: ${location.substring(0, 200)}`,
        };
      }
      if (res.ok && !body.includes("invalid_scope") && !body.includes("error")) {
        return {
          escalatable: true,
          evidence: `Authorization endpoint returned 200 with escalated scopes.\nRequested: ${escalatedScopes}`,
        };
      }
      return null;
    })(),
  ]);

  // Collect Phase 2 findings

  // PKCE enforcement
  if (pkceResults.status === "fulfilled" && pkceResults.value?.missing) {
    const v = pkceResults.value;
    findings.push({
      id: `oauth-pkce-${findings.length}`, module: "OAuth", severity: "high",
      title: "OAuth PKCE not enforced for public clients",
      description: "The OAuth flow does not use Proof Key for Code Exchange (PKCE). Without PKCE, authorization codes can be intercepted and exchanged by attackers, especially on mobile and SPA clients.",
      evidence: `No code_challenge or code_verifier usage detected in client code.\nAuthorization endpoints: ${v.endpoints.join(", ")}`,
      remediation: "Implement PKCE (RFC 7636) for all OAuth authorization code flows. Generate a code_verifier, derive a code_challenge with S256, and include both in the authorization and token requests.",
      codeSnippet: `// Generate PKCE parameters\nconst codeVerifier = crypto.randomBytes(32).toString("base64url");\nconst codeChallenge = crypto\n  .createHash("sha256").update(codeVerifier).digest("base64url");\n\n// Include in authorization request\nauthUrl.searchParams.set("code_challenge", codeChallenge);\nauthUrl.searchParams.set("code_challenge_method", "S256");\n\n// Include verifier in token exchange\nawait fetch(tokenEndpoint, {\n  method: "POST",\n  body: new URLSearchParams({ code, code_verifier: codeVerifier, grant_type: "authorization_code" }),\n});`,
      cwe: "CWE-345", owasp: "A07:2021",
    });
  }

  // State parameter validation
  if (stateValidationResults.status === "fulfilled" && stateValidationResults.value) {
    const v = stateValidationResults.value;
    const isStatic = v.issue === "static";
    findings.push({
      id: `oauth-state-validation-${findings.length}`, module: "OAuth", severity: isStatic ? "high" : "medium",
      title: isStatic ? "OAuth state parameter uses static/predictable value" : "OAuth state parameter missing from authorization flow",
      description: isStatic
        ? "The OAuth state parameter uses a hardcoded or predictable value. This defeats CSRF protection since an attacker can predict or reuse the state value."
        : "The OAuth authorization flow does not include a state parameter. Without state, the application is vulnerable to CSRF-based login attacks and authorization code injection.",
      evidence: v.evidence,
      remediation: "Generate a cryptographically random state value per authorization request. Store it in a secure, HTTP-only cookie and validate it matches on callback.",
      codeSnippet: `// Generate cryptographically random state\nconst state = crypto.randomBytes(32).toString("hex");\ncookies().set("oauth_state", state, {\n  httpOnly: true, secure: true, sameSite: "lax", maxAge: 600,\n});\nauthUrl.searchParams.set("state", state);\n\n// Validate in callback\nconst expected = cookies().get("oauth_state")?.value;\nif (!expected || expected !== req.query.state) {\n  throw new Error("Invalid OAuth state — possible CSRF attack");\n}`,
      cwe: "CWE-352", owasp: "A07:2021",
    });
  }

  // Redirect URI validation (advanced bypasses)
  if (redirectVariationResults.status === "fulfilled") {
    const hits = redirectVariationResults.value as { path: string; results: { technique: string; evidence: string }[] }[];
    if (hits && hits.length > 0) {
      for (const hit of hits) {
        const techniques = hit.results.map((r) => r.technique).join(", ");
        const allEvidence = hit.results.map((r) => r.evidence).join("\n");
        findings.push({
          id: `oauth-redirect-adv-${findings.length}`, module: "OAuth", severity: "critical",
          title: `OAuth redirect_uri bypass via ${techniques} on ${hit.path}`,
          description: `The OAuth callback endpoint is vulnerable to advanced redirect_uri manipulation techniques (${techniques}). Attackers can exploit these to steal authorization codes.`,
          evidence: allEvidence,
          remediation: "Use exact string matching for redirect_uri validation. Normalize and canonicalize URIs before comparison. Reject URIs with path traversal sequences, null bytes, fragments, or non-registered subdomains.",
          codeSnippet: `// Strict redirect_uri validation\nfunction validateRedirectUri(uri: string, allowed: string[]): boolean {\n  try {\n    const parsed = new URL(uri);\n    // Reject path traversal, null bytes, userinfo\n    if (parsed.pathname.includes("..") || uri.includes("%00") || parsed.username) {\n      return false;\n    }\n    // Exact match against registered URIs\n    return allowed.includes(parsed.origin + parsed.pathname);\n  } catch {\n    return false;\n  }\n}`,
          cwe: "CWE-601", owasp: "A07:2021",
        });
      }
    }
  }

  // Token in fragment
  if (fragmentTokenResults.status === "fulfilled" && fragmentTokenResults.value?.found) {
    const v = fragmentTokenResults.value;
    findings.push({
      id: `oauth-fragment-token-${findings.length}`, module: "OAuth", severity: "high",
      title: "Access token exposed in URL fragment (implicit flow)",
      description: "The application handles access tokens from URL fragments (#access_token=), indicating use of the OAuth implicit flow. Tokens in fragments are exposed to browser history, referrer headers, browser extensions, and any JavaScript on the page.",
      evidence: v.evidence.join("\n"),
      remediation: "Migrate from implicit flow to authorization code flow with PKCE. Never pass access tokens in URL fragments. Use server-side token exchange instead.",
      codeSnippet: `// Instead of parsing tokens from fragments:\n// BAD: const token = new URLSearchParams(location.hash.slice(1)).get("access_token");\n\n// Use authorization code flow with PKCE:\nconst authUrl = new URL(authorizationEndpoint);\nauthUrl.searchParams.set("response_type", "code"); // NOT "token"\nauthUrl.searchParams.set("code_challenge", codeChallenge);\nauthUrl.searchParams.set("code_challenge_method", "S256");\n\n// Exchange code for token server-side\nconst tokenRes = await fetch(tokenEndpoint, {\n  method: "POST",\n  body: new URLSearchParams({\n    grant_type: "authorization_code", code, code_verifier: codeVerifier,\n  }),\n});`,
      cwe: "CWE-522", owasp: "A07:2021",
    });
  }

  // Scope escalation
  if (scopeEscalationResults.status === "fulfilled" && scopeEscalationResults.value?.escalatable) {
    const v = scopeEscalationResults.value;
    findings.push({
      id: `oauth-scope-escalation-${findings.length}`, module: "OAuth", severity: "high",
      title: "OAuth scope escalation possible — server accepts unauthorized scopes",
      description: "The authorization server accepts scope values beyond what the client is authorized for without returning an error. Attackers can request elevated permissions (e.g., admin, write:all) to gain unauthorized access.",
      evidence: v.evidence,
      remediation: "Validate requested scopes against the client's pre-registered allowed scopes. Reject or downscope requests that include unauthorized scopes. Return an invalid_scope error for unrecognized scope values.",
      codeSnippet: `// Server-side scope validation\nconst ALLOWED_SCOPES: Record<string, string[]> = {\n  "my-spa-client": ["openid", "profile", "email"],\n  "my-backend-client": ["openid", "profile", "email", "api:read"],\n};\n\nfunction validateScopes(clientId: string, requested: string[]): string[] {\n  const allowed = ALLOWED_SCOPES[clientId] ?? [];\n  const invalid = requested.filter((s) => !allowed.includes(s));\n  if (invalid.length > 0) {\n    throw new OAuthError("invalid_scope", \`Unauthorized scopes: \${invalid.join(", ")}\`);\n  }\n  return requested;\n}`,
      cwe: "CWE-269", owasp: "A01:2021",
    });
  }

  return findings;
};
