import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

const decodeJwtPart = (part: string): Record<string, unknown> | null => {
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString());
  } catch {
    return null;
  }
};

export const jwtModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Find JWTs in cookies
  const jwts: { source: string; token: string }[] = [];

  for (const cookie of target.cookies) {
    if (cookie.value.match(/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/)) {
      jwts.push({ source: `cookie:${cookie.name}`, token: cookie.value });
    }
  }

  // Find JWTs in JS bundles (excluding Supabase anon keys which are expected)
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const jwtMatches = allJs.match(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g);
  if (jwtMatches) {
    for (const token of jwtMatches.slice(0, 5)) {
      jwts.push({ source: "js-bundle", token });
    }
  }

  for (const { source, token } of jwts) {
    const parts = token.split(".");
    if (parts.length < 2) continue;

    const header = decodeJwtPart(parts[0]);
    const payload = decodeJwtPart(parts[1]);

    if (!header || !payload) continue;

    // Check for alg:none vulnerability
    if (header.alg === "none" || header.alg === "None" || header.alg === "NONE") {
      findings.push({
        id: `jwt-alg-none-${findings.length}`,
        module: "JWT Security",
        severity: "critical",
        title: `JWT with algorithm "none" found (${source})`,
        description: 'This JWT uses the "none" algorithm, meaning it has no signature verification. Anyone can forge tokens.',
        evidence: `Source: ${source}\nHeader: ${JSON.stringify(header)}`,
        remediation: "Reject JWTs with alg:none. Explicitly require a specific algorithm (e.g., RS256 or HS256).",
        cwe: "CWE-347",
        owasp: "A02:2021",
        codeSnippet: `// Fix: Explicitly set allowed algorithms\nimport jwt from "jsonwebtoken";\nconst payload = jwt.verify(token, secret, {\n  algorithms: ["HS256"], // NEVER allow "none"\n});`,
      });
    }

    // Check for weak algorithms
    if (header.alg === "HS256" && source === "js-bundle") {
      findings.push({
        id: `jwt-weak-alg-${findings.length}`,
        module: "JWT Security",
        severity: "medium",
        title: "JWT uses HS256 (symmetric) algorithm",
        description: "HS256 uses a shared secret for signing and verification. If the secret is weak or exposed, anyone can forge tokens. RS256 (asymmetric) is more secure for client-facing JWTs.",
        evidence: `Algorithm: ${header.alg}`,
        remediation: "Consider using RS256 (asymmetric) for public-facing JWTs. Ensure HS256 secrets are at least 256 bits.",
        cwe: "CWE-326",
        codeSnippet: `// Use asymmetric RS256 for better security\nimport jwt from "jsonwebtoken";\nconst token = jwt.sign({ sub: userId }, privateKey, {\n  algorithm: "RS256",\n  expiresIn: "15m",\n});`,
      });
    }

    // Check for sensitive data in payload
    const sensitiveFields = Object.keys(payload).filter((k) =>
      /password|secret|ssn|credit|card|cvv|dob|date_of_birth|tax_id|passport|license_number|phone|address/i.test(k),
    );
    if (sensitiveFields.length > 0) {
      findings.push({
        id: `jwt-sensitive-data-${findings.length}`,
        module: "JWT Security",
        severity: "high",
        title: "JWT contains sensitive data",
        description: `JWT payload contains sensitive-looking fields: ${sensitiveFields.join(", ")}. JWTs are base64-encoded (not encrypted) — anyone can read the contents.`,
        evidence: `Sensitive fields: ${sensitiveFields.join(", ")}\nSource: ${source}`,
        remediation: "Never put sensitive data in JWT payloads. JWTs are readable by anyone — only store non-sensitive identifiers.",
        cwe: "CWE-312",
        codeSnippet: `// Only include non-sensitive identifiers in JWT\nconst token = jwt.sign(\n  { sub: user.id, role: user.role }, // NOT email, password, etc.\n  secret,\n  { expiresIn: "15m" }\n);\n// Look up sensitive data server-side from the user ID`,
      });
    }

    // Check for missing audience/issuer claims
    if (!payload.aud && !payload.iss) {
      findings.push({
        id: `jwt-no-aud-iss-${findings.length}`,
        module: "JWT Security",
        severity: "medium",
        title: "JWT missing audience and issuer claims",
        description: "This JWT has neither an 'aud' (audience) nor an 'iss' (issuer) claim. Without these, the token can be replayed across different services or environments.",
        evidence: `Source: ${source}\nPayload keys: ${Object.keys(payload).join(", ")}`,
        remediation: "Always include 'aud' and 'iss' claims and validate them on the server. This prevents token confusion attacks across services.",
        cwe: "CWE-345",
        codeSnippet: `// Include and validate audience/issuer\nconst token = jwt.sign({ sub: userId }, secret, {\n  issuer: "https://yourapp.com",\n  audience: "https://api.yourapp.com",\n  expiresIn: "15m",\n});\n\n// Verify with strict validation\njwt.verify(token, secret, {\n  issuer: "https://yourapp.com",\n  audience: "https://api.yourapp.com",\n  algorithms: ["HS256"],\n});`,
      });
    }

    // Check for JWK/JKU header injection vectors
    if (header.jku || header.jwk || header.x5u) {
      const param = header.jku ? "jku" : header.jwk ? "jwk" : "x5u";
      findings.push({
        id: `jwt-header-injection-${findings.length}`,
        module: "JWT Security",
        severity: "critical",
        title: `JWT contains ${param} header parameter`,
        description: `This JWT includes a '${param}' header parameter which specifies where to fetch the verification key. If the server trusts this parameter, an attacker can point it to their own key server and forge any token.`,
        evidence: `Source: ${source}\nHeader: ${JSON.stringify(header)}`,
        remediation: `Never trust ${param} from the JWT header. Use a pre-configured, server-side key or JWKS URL instead.`,
        cwe: "CWE-347", owasp: "A02:2021",
        codeSnippet: `// WRONG: fetching key from JWT header\nconst jwks = await fetch(header.jku); // attacker-controlled!\n\n// CORRECT: use a hardcoded, trusted JWKS URL\nconst JWKS_URL = "https://your-auth-server/.well-known/jwks.json";\nconst jwks = jose.createRemoteJWKSet(new URL(JWKS_URL));`,
      });
    }

    // Check for kid parameter with suspicious values
    if (header.kid && typeof header.kid === "string") {
      if (/[\/\\]|\.\.|\x00|;|'|"|SELECT|UNION/i.test(header.kid)) {
        findings.push({
          id: `jwt-kid-injection-${findings.length}`,
          module: "JWT Security",
          severity: "critical",
          title: "JWT kid parameter contains injection characters",
          description: "The JWT 'kid' (Key ID) header contains characters suggesting path traversal, SQL injection, or null byte injection. If the server uses 'kid' to look up keys without sanitization, this enables key confusion attacks.",
          evidence: `Source: ${source}\nkid: ${header.kid}`,
          remediation: "Sanitize the 'kid' parameter. Use it only as a lookup key against a pre-defined key store — never as a file path or database query parameter.",
          cwe: "CWE-347", owasp: "A02:2021",
          codeSnippet: `// Safe kid lookup via Map, not filesystem or DB query\nconst KEY_STORE = new Map([["key-1", publicKey1], ["key-2", publicKey2]]);\nconst key = KEY_STORE.get(header.kid);\nif (!key) throw new Error("Unknown key ID");`,
        });
      }
    }

    // Check expiration
    if (payload.exp) {
      const expDate = new Date((payload.exp as number) * 1000);
      const now = new Date();
      const daysUntilExpiry = (expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

      if (daysUntilExpiry > 365) {
        findings.push({
          id: `jwt-long-expiry-${findings.length}`,
          module: "JWT Security",
          severity: "medium",
          title: "JWT has very long expiration",
          description: `This JWT expires in ${Math.round(daysUntilExpiry)} days. Long-lived tokens are dangerous — if stolen, they remain valid for a long time.`,
          evidence: `Expires: ${expDate.toISOString()}\nDays until expiry: ${Math.round(daysUntilExpiry)}`,
          remediation: "Use short-lived access tokens (15-60 minutes) with refresh tokens for re-authentication.",
          cwe: "CWE-613",
          codeSnippet: `// Use short-lived tokens\nconst token = jwt.sign({ sub: userId }, secret, {\n  expiresIn: "15m", // short-lived access token\n});\n// Pair with a refresh token (7d) for seamless re-auth`,
        });
      }
    } else if (!payload.exp) {
      findings.push({
        id: `jwt-no-expiry-${findings.length}`,
        module: "JWT Security",
        severity: "high",
        title: "JWT has no expiration",
        description: "This JWT never expires. If stolen, it can be used forever.",
        evidence: `Source: ${source}\nNo 'exp' claim in payload`,
        remediation: "Always set an expiration (exp) claim on JWTs.",
        cwe: "CWE-613",
        codeSnippet: `// Use short-lived tokens with refresh pattern\nconst accessToken = jwt.sign(\n  { sub: userId },\n  secret,\n  { expiresIn: "15m", algorithm: "HS256" }\n);\nconst refreshToken = jwt.sign(\n  { sub: userId },\n  refreshSecret,\n  { expiresIn: "7d", algorithm: "HS256" }\n);`,
      });
    }
  }

  // Detect JWTs in URL parameters (insecure — logged by proxies, visible in referer headers)
  for (const link of target.linkUrls.slice(0, 50)) {
    try {
      const url = new URL(link);
      for (const [param, value] of url.searchParams) {
        if (/^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./.test(value)) {
          findings.push({
            id: `jwt-in-url-${findings.length}`,
            module: "JWT Security",
            severity: "high",
            title: `JWT exposed in URL parameter "${param}"`,
            description: "A JWT is passed as a URL query parameter. URLs are logged by proxies, browsers, and web servers, and leak via Referer headers. This exposes the token to interception.",
            evidence: `URL: ${url.pathname}?${param}=eyJ...`,
            remediation: "Pass JWTs in the Authorization header or as an HttpOnly cookie, never in URL parameters.",
            cwe: "CWE-598", owasp: "A02:2021",
            codeSnippet: `// WRONG: JWT in URL\nfetch(\`/api/data?token=\${jwt}\`);\n\n// CORRECT: JWT in Authorization header\nfetch("/api/data", {\n  headers: { Authorization: \`Bearer \${jwt}\` },\n});`,
          });
          break;
        }
      }
      if (findings.length > 0 && findings[findings.length - 1].id.startsWith("jwt-in-url")) break;
    } catch { /* skip */ }
  }

  // Check for JWT in JS bundle as hardcoded string (not in a variable assignment to a cookie)
  const hardcodedJwts = allJs.match(/["'`](eyJhbGciO[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)["'`]/g);
  if (hardcodedJwts && hardcodedJwts.length > 0) {
    // Decode to check if it's a real service token (not a Supabase anon key)
    for (const match of hardcodedJwts.slice(0, 3)) {
      const token = match.slice(1, -1);
      const tokenPayload = decodeJwtPart(token.split(".")[1]);
      if (!tokenPayload) continue;
      // Skip Supabase anon keys (role: "anon") — they're meant to be public
      if (tokenPayload.role === "anon") continue;
      // Skip tokens that appear to be test/example tokens
      if (tokenPayload.sub === "test" || tokenPayload.sub === "example") continue;
      findings.push({
        id: `jwt-hardcoded-${findings.length}`,
        module: "JWT Security",
        severity: "high",
        title: "Hardcoded JWT found in JavaScript bundle",
        description: `A JWT with role "${tokenPayload.role || "unknown"}" is hardcoded in a JavaScript file. This token is accessible to anyone viewing the source and should be treated as compromised.`,
        evidence: `Token payload keys: ${Object.keys(tokenPayload).join(", ")}\nRole: ${tokenPayload.role || "(none)"}${tokenPayload.exp ? `\nExpires: ${new Date((tokenPayload.exp as number) * 1000).toISOString()}` : ""}`,
        remediation: "Never hardcode JWTs in client-side code. Use API routes to issue tokens dynamically. Rotate any exposed tokens immediately.",
        cwe: "CWE-798", owasp: "A07:2021",
      });
      break;
    }
  }

  // Test alg:none bypass on API endpoints — all in parallel
  if (target.apiEndpoints.length > 0) {
    const fakeJwt = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url") +
      "." + Buffer.from('{"sub":"1","role":"admin"}').toString("base64url") +
      ".";

    const normalize = (s: string) => s.replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/g, "TIME").replace(/\d{10,13}/g, "TS");

    const bypassResults = await Promise.allSettled(
      target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
        const [baseRes, authRes] = await Promise.all([
          scanFetch(endpoint),
          scanFetch(endpoint, { headers: { Authorization: `Bearer ${fakeJwt}` } }),
        ]);
        const baseText = await baseRes.text();
        if (!authRes.ok) return null;
        const text = await authRes.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
        if (normalize(text) === normalize(baseText)) return null;
        if (text.length > 10 && !text.includes("unauthorized") && !text.includes("invalid")) {
          return { endpoint, pathname: new URL(endpoint).pathname, status: authRes.status, length: text.length };
        }
        return null;
      }),
    );

    for (const r of bypassResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `jwt-none-bypass-${findings.length}`, module: "JWT Security", severity: "critical",
        title: `API accepts alg:none JWT on ${v.pathname}`,
        description: "The API accepted a JWT with algorithm 'none' and no signature. Anyone can forge admin tokens.",
        evidence: `Sent forged JWT with alg:none, role:admin\nEndpoint: ${v.endpoint}\nStatus: ${v.status}\nResponse length: ${v.length}`,
        remediation: "Reject JWTs with alg:none. Use a JWT library that validates the algorithm.",
        cwe: "CWE-347", owasp: "A02:2021",
        codeSnippet: `// Reject alg:none — always specify algorithms\nimport jwt from "jsonwebtoken";\ntry {\n  const decoded = jwt.verify(token, secret, {\n    algorithms: ["HS256"], // NEVER include "none"\n  });\n} catch (err) {\n  return Response.json({ error: "Invalid token" }, { status: 401 });\n}`,
      });
    }
  }

  // Test algorithm confusion: send HS256 token when server expects RS256
  // If the server uses a public RSA key as the HMAC secret, we can sign arbitrary tokens
  if (target.apiEndpoints.length > 0 && findings.length < 8) {
    // Try with embedded JWK in header (if server trusts the jwk header, game over)
    const embeddedJwkJwt = Buffer.from(JSON.stringify({
      alg: "HS256",
      typ: "JWT",
      jwk: { kty: "oct", k: Buffer.from("vibeshield-test-key").toString("base64url") },
    })).toString("base64url") +
      "." + Buffer.from(JSON.stringify({ sub: "1", role: "admin", iat: Math.floor(Date.now() / 1000) })).toString("base64url") +
      ".fakesig";

    const jwkResults = await Promise.allSettled(
      target.apiEndpoints.slice(0, 3).map(async (endpoint) => {
        const res = await scanFetch(endpoint, {
          headers: { Authorization: `Bearer ${embeddedJwkJwt}` },
          timeoutMs: 5000,
        });
        if (!res.ok) return null;

        // Followed a redirect? Then the "endpoint" isn't actually an API — likely a
        // URL rewrite to a marketing page. Bail out to avoid FPs like /api/event → /event-info/.
        try {
          const finalPath = new URL(res.url || endpoint).pathname.replace(/\/$/, "");
          const origPath = new URL(endpoint).pathname.replace(/\/$/, "");
          if (finalPath !== origPath) return null;
        } catch { /* skip */ }

        const text = await res.text();
        // An API that trusts JWTs returns JSON/text — not a full HTML page.
        if (looksLikeHtml(text)) return null;
        if (/unauthorized|invalid|forbidden|expired/i.test(text.substring(0, 200))) return null;
        if (text.length > 10) {
          return { endpoint, pathname: new URL(endpoint).pathname };
        }
        return null;
      }),
    );

    for (const r of jwkResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      findings.push({
        id: `jwt-embedded-jwk-${findings.length}`,
        module: "JWT Security",
        severity: "critical",
        title: `API trusts embedded JWK header on ${r.value.pathname}`,
        description: "The API accepted a JWT with an embedded JWK (JSON Web Key) in the header. This means an attacker can provide their own signing key inside the token, completely bypassing signature verification.",
        evidence: `Sent JWT with embedded JWK header to ${r.value.endpoint}\nServer returned success response`,
        remediation: "Never trust the jwk/jku header from incoming JWTs. Always use a pre-configured, server-side key or JWKS endpoint.",
        cwe: "CWE-347", owasp: "A02:2021",
        codeSnippet: `// WRONG: trusting jwk from token header\nconst key = jwt.header.jwk; // attacker controls this!\n\n// CORRECT: use server-side JWKS\nconst JWKS = jose.createRemoteJWKSet(\n  new URL("https://your-auth/.well-known/jwks.json")\n);\nconst { payload } = await jose.jwtVerify(token, JWKS);`,
      });
      break;
    }
  }

  // Phase: JWT in URL parameters — check API endpoints and pages for tokens in query strings
  const urlsToCheck = [...target.apiEndpoints.slice(0, 20), ...target.pages.slice(0, 20)];
  const urlParamResults = await Promise.allSettled(
    urlsToCheck.map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      const finalUrl = res.url || endpoint;
      try {
        const parsed = new URL(finalUrl);
        for (const [param, value] of parsed.searchParams) {
          if (/^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./.test(value)) {
            return { endpoint: finalUrl, param, pathname: parsed.pathname };
          }
        }
      } catch { /* skip */ }
      // Also check if any redirect URLs contain JWTs in query params
      const text = await res.text();
      const redirectMatch = text.match(/(?:href|location|redirect)[=:]["' ]*([^"' >]+\?[^"' >]*eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+[^"' >]*)/i);
      if (redirectMatch) {
        try {
          const redirectUrl = new URL(redirectMatch[1], endpoint);
          for (const [param, value] of redirectUrl.searchParams) {
            if (/^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./.test(value)) {
              return { endpoint: redirectUrl.toString(), param, pathname: redirectUrl.pathname };
            }
          }
        } catch { /* skip */ }
      }
      return null;
    }),
  );

  for (const r of urlParamResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `jwt-url-param-${findings.length}`,
      module: "jwt-check",
      severity: "high",
      title: `JWT passed in URL parameter "${v.param}" on ${v.pathname}`,
      description: "A JWT is being transmitted as a URL query parameter. URLs are stored in browser history, server logs, proxy logs, and leak via the Referer header to third-party resources. This exposes the token to unintended parties.",
      evidence: `URL: ${v.endpoint}\nParameter: ${v.param}`,
      remediation: "Transmit JWTs via the Authorization header or as HttpOnly cookies. Never pass tokens in URL query parameters.",
      cwe: "CWE-598",
      owasp: "A02:2021",
      codeSnippet: `// WRONG: JWT in URL query parameter\nfetch(\`/api/data?token=\${jwt}\`);\nwindow.location = \`/callback?access_token=\${jwt}\`;\n\n// CORRECT: JWT in Authorization header\nfetch("/api/data", {\n  headers: { Authorization: \`Bearer \${jwt}\` },\n});`,
    });
    if (findings.filter((f) => f.id.startsWith("jwt-url-param")).length >= 3) break;
  }

  // Phase: JWT expiration too long — flag tokens expiring more than 24 hours from now
  for (const { source, token } of jwts) {
    const parts = token.split(".");
    if (parts.length < 2) continue;
    const payload = decodeJwtPart(parts[1]);
    if (!payload || !payload.exp) continue;

    const expDate = new Date((payload.exp as number) * 1000);
    const now = new Date();
    const hoursUntilExpiry = (expDate.getTime() - now.getTime()) / (1000 * 60 * 60);

    if (hoursUntilExpiry > 24 && hoursUntilExpiry <= 365 * 24) {
      findings.push({
        id: `jwt-exp-too-long-${findings.length}`,
        module: "jwt-check",
        severity: "medium",
        title: `JWT expires in ${Math.round(hoursUntilExpiry)} hours (${source})`,
        description: `This JWT has an expiration more than 24 hours in the future (${Math.round(hoursUntilExpiry / 24)} days). Access tokens should be short-lived (15-60 minutes). Long-lived tokens increase the window for token theft and replay attacks.`,
        evidence: `Source: ${source}\nExpires: ${expDate.toISOString()}\nHours until expiry: ${Math.round(hoursUntilExpiry)}`,
        remediation: "Use short-lived access tokens (15-60 minutes) paired with refresh tokens. Implement token rotation so that refresh tokens are single-use.",
        cwe: "CWE-613",
        codeSnippet: `// Short-lived access token (15 min) + refresh token pattern\nconst accessToken = jwt.sign({ sub: userId }, secret, {\n  expiresIn: "15m",\n});\nconst refreshToken = jwt.sign({ sub: userId, tokenFamily: familyId }, refreshSecret, {\n  expiresIn: "7d",\n});\n// Store refresh token hash server-side for rotation tracking`,
      });
    }
  }

  // Phase: JWT missing critical claims — check for missing iss, aud, nbf
  for (const { source, token } of jwts) {
    const parts = token.split(".");
    if (parts.length < 2) continue;
    const payload = decodeJwtPart(parts[1]);
    if (!payload) continue;

    const missingClaims: string[] = [];
    if (!payload.iss) missingClaims.push("iss (issuer)");
    if (!payload.aud) missingClaims.push("aud (audience)");
    if (!payload.nbf) missingClaims.push("nbf (not before)");

    // Only report if at least 2 claims are missing to reduce noise (iss+aud already checked above, this catches nbf)
    if (missingClaims.length >= 2 && missingClaims.some((c) => c.startsWith("nbf"))) {
      findings.push({
        id: `jwt-missing-claims-${findings.length}`,
        module: "jwt-check",
        severity: "low",
        title: `JWT missing security claims: ${missingClaims.map((c) => c.split(" ")[0]).join(", ")} (${source})`,
        description: `This JWT is missing ${missingClaims.length} recommended security claims: ${missingClaims.join(", ")}. The 'iss' claim prevents cross-service token reuse, 'aud' restricts which services accept the token, and 'nbf' prevents tokens from being used before a specified time.`,
        evidence: `Source: ${source}\nPresent claims: ${Object.keys(payload).join(", ")}\nMissing claims: ${missingClaims.join(", ")}`,
        remediation: "Include iss, aud, and nbf claims in all JWTs and validate them server-side. This provides defense-in-depth against token confusion and replay attacks.",
        cwe: "CWE-345",
        codeSnippet: `// Include all security claims when signing\nconst token = jwt.sign(\n  {\n    sub: userId,\n    iss: "https://yourapp.com",\n    aud: "https://api.yourapp.com",\n    nbf: Math.floor(Date.now() / 1000), // valid from now\n  },\n  secret,\n  { expiresIn: "15m", algorithm: "RS256" }\n);\n\n// Validate all claims when verifying\njwt.verify(token, publicKey, {\n  issuer: "https://yourapp.com",\n  audience: "https://api.yourapp.com",\n  algorithms: ["RS256"],\n  clockTolerance: 30, // 30s leeway for nbf\n});`,
      });
    }
  }

  // Phase: JWT weak signing — try common/guessable secrets against HS256 tokens
  if (jwts.length > 0) {
    const commonSecrets = ["secret", "password", "123456", "changeme", "key", "jwt_secret", "shhhhh", "test"];
    for (const { source, token } of jwts.slice(0, 3)) {
      const parts = token.split(".");
      if (parts.length < 3) continue;
      const header = decodeJwtPart(parts[0]);
      if (!header || header.alg !== "HS256") continue;

      const signingInput = `${parts[0]}.${parts[1]}`;
      const existingSig = parts[2];

      for (const secret of commonSecrets) {
        try {
          const { createHmac } = await import("node:crypto");
          const expectedSig = createHmac("sha256", secret)
            .update(signingInput)
            .digest("base64url");
          if (expectedSig === existingSig) {
            findings.push({
              id: `jwt-weak-secret-${findings.length}`,
              module: "jwt-check",
              severity: "critical",
              title: `JWT signed with guessable secret "${secret}" (${source})`,
              description: `This HS256 JWT was signed with the commonly-used secret "${secret}". An attacker can forge arbitrary tokens with full control over claims including roles and permissions.`,
              evidence: `Source: ${source}\nSecret: "${secret}"\nAlgorithm: HS256\nSignature verified against known weak secret`,
              remediation: "Use a cryptographically random secret of at least 256 bits for HS256, or switch to RS256 with a proper key pair. Rotate the compromised secret immediately and invalidate all existing tokens.",
              cwe: "CWE-1391",
              owasp: "A02:2021",
              codeSnippet: `// Generate a strong secret (run once, store securely)\nimport crypto from "node:crypto";\nconst secret = crypto.randomBytes(32).toString("base64");\n// Store in environment variable, NEVER in code\n// JWT_SECRET=<generated value>\n\n// Or better: use asymmetric RS256\nconst { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {\n  modulusLength: 2048,\n});`,
            });
            break;
          }
        } catch { /* skip */ }
      }
    }
  }

  // Phase: JWT refresh token exposure — check API responses for refresh tokens alongside access tokens
  if (target.apiEndpoints.length > 0) {
    const authEndpoints = target.apiEndpoints.filter((ep) =>
      /auth|login|token|session|oauth|signin|signup|register/i.test(ep),
    ).slice(0, 5);

    const refreshResults = await Promise.allSettled(
      authEndpoints.map(async (endpoint) => {
        const res = await scanFetch(endpoint, { timeoutMs: 5000 });
        const text = await res.text();
        if (looksLikeHtml(text) || isSoft404(text, target)) return null;

        // Check if response body contains both access and refresh tokens
        const hasAccessToken = /["']?access[_-]?token["']?\s*[:=]/i.test(text);
        const hasRefreshToken = /["']?refresh[_-]?token["']?\s*[:=]/i.test(text);

        if (hasAccessToken && hasRefreshToken) {
          // Verify it looks like actual JSON/API response with token values
          const hasJwtValues = /eyJ[A-Za-z0-9_-]{10,}/.test(text);
          const hasTokenValues = hasJwtValues || /"[A-Za-z0-9_-]{20,}"/.test(text);
          if (hasTokenValues) {
            return { endpoint, pathname: new URL(endpoint).pathname };
          }
        }
        return null;
      }),
    );

    for (const r of refreshResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `jwt-refresh-exposed-${findings.length}`,
        module: "jwt-check",
        severity: "high",
        title: `Refresh token exposed in API response body on ${v.pathname}`,
        description: "The API endpoint returns both access and refresh tokens in the response body. Refresh tokens in response bodies are vulnerable to XSS exfiltration. If an attacker steals the refresh token, they gain long-lived access to the account.",
        evidence: `Endpoint: ${v.endpoint}\nResponse contains both access_token and refresh_token fields`,
        remediation: "Return refresh tokens only in HttpOnly, Secure, SameSite=Strict cookies — never in the response body. This protects them from XSS attacks. Use the BFF (Backend-for-Frontend) pattern for SPAs.",
        cwe: "CWE-522",
        owasp: "A07:2021",
        codeSnippet: `// WRONG: both tokens in response body\nreturn Response.json({\n  access_token: accessJwt,\n  refresh_token: refreshJwt, // XSS can steal this!\n});\n\n// CORRECT: refresh token in HttpOnly cookie\nconst response = Response.json({ access_token: accessJwt });\nresponse.headers.set(\n  "Set-Cookie",\n  \`refresh_token=\${refreshJwt}; HttpOnly; Secure; SameSite=Strict; Path=/api/auth; Max-Age=604800\`\n);\nreturn response;`,
      });
    }
  }

  return findings;
};
