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

  return findings;
};
