import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const sessionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Phase 1: Session token in URL — check if any links/redirects contain session tokens
  const sessionInUrlPatterns = [
    /[?&](session|sid|sessionId|session_id|token|access_token|auth_token)=([a-zA-Z0-9_.-]{10,})/i,
  ];
  const urlsToCheck = [...target.linkUrls, ...target.redirectUrls, ...target.pages];
  for (const url of urlsToCheck.slice(0, 50)) {
    for (const pattern of sessionInUrlPatterns) {
      const match = url.match(pattern);
      if (match) {
        findings.push({
          id: `session-token-in-url-${findings.length}`,
          module: "Session Management",
          severity: "high",
          title: `Session token passed in URL parameter: ${match[1]}`,
          description: `The parameter "${match[1]}" in URL contains what appears to be a session token. Tokens in URLs are logged in server logs, browser history, referrer headers, and proxy logs — making them trivially accessible to attackers.`,
          evidence: `URL: ${url.substring(0, 200)}`,
          remediation: "Pass session tokens in HTTP-only cookies or Authorization headers, never in URL parameters.",
          cwe: "CWE-598",
          owasp: "A07:2021",
          codeSnippet: `// Use cookies instead of URL params for sessions\nexport async function GET(req: Request) {\n  const session = req.cookies.get("session")?.value;\n  if (!session) return Response.redirect("/login");\n  // Never: /dashboard?token=abc123\n}`,
        });
        break;
      }
    }
    if (findings.length > 0) break;
  }

  // Phase 2: Session fixation — check if the app accepts externally-set session cookies
  const sessionCookies = target.cookies.filter((c) =>
    /session|sid|connect\.sid|next-auth|__session|__Secure-session/i.test(c.name),
  );

  // Phase 3: Long-lived sessions — check cookie expiry
  for (const cookie of target.cookies) {
    if (!/session|sid|auth|token|jwt/i.test(cookie.name)) continue;
    // Check if Set-Cookie includes a very long max-age (>30 days)
    // We already parsed basic cookie info; check raw headers for max-age
    const rawCookies = target.headers["set-cookie"] || "";
    const cookieMatch = rawCookies.match(new RegExp(`${cookie.name}=[^;]*;[^\\n]*max-age=(\\d+)`, "i"));
    if (cookieMatch) {
      const maxAge = parseInt(cookieMatch[1]);
      if (maxAge > 30 * 24 * 3600) { // > 30 days
        findings.push({
          id: `session-long-lived-${findings.length}`,
          module: "Session Management",
          severity: "medium",
          title: `Session cookie "${cookie.name}" has excessive lifetime (${Math.round(maxAge / 86400)} days)`,
          description: `The session cookie has a max-age of ${Math.round(maxAge / 86400)} days. Long-lived sessions increase the window for session hijacking — if a token is stolen, it remains valid for an extended period.`,
          evidence: `Cookie: ${cookie.name}\nMax-Age: ${maxAge} seconds (${Math.round(maxAge / 86400)} days)`,
          remediation: "Set session cookie lifetime to 24 hours or less for sensitive apps. Use sliding sessions that refresh on activity.",
          cwe: "CWE-613",
          owasp: "A07:2021",
          codeSnippet: `// next-auth — set short session lifetime\nexport const authOptions = {\n  session: {\n    strategy: "jwt",\n    maxAge: 24 * 60 * 60, // 24 hours\n  },\n  jwt: {\n    maxAge: 24 * 60 * 60,\n  },\n};`,
        });
        break;
      }
    }
  }

  // Phase 4: Concurrent session testing — login from multiple "devices"
  const loginEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(login|signin|sign-in|auth\/callback|auth\/session)\b/i.test(ep),
  ).slice(0, 2);

  for (const endpoint of loginEndpoints) {
    // Send two login requests and see if both sessions are valid
    const [res1, res2] = await Promise.all([
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "test@vibeshield.dev", password: "test123" }),
        timeoutMs: 5000,
      }),
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "test@vibeshield.dev", password: "test123" }),
        timeoutMs: 5000,
      }),
    ]);

    // If both return tokens/sessions, check if they're different (concurrent sessions allowed)
    const text1 = await res1.text();
    const text2 = await res2.text();

    if (res1.ok && res2.ok) {
      const token1 = text1.match(/["'](eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']/);
      const token2 = text2.match(/["'](eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']/);
      if (token1 && token2 && token1[1] !== token2[1]) {
        findings.push({
          id: `session-concurrent-${findings.length}`,
          module: "Session Management",
          severity: "medium",
          title: `Unlimited concurrent sessions allowed on ${new URL(endpoint).pathname}`,
          description: "Multiple simultaneous login requests each produce a different valid session token. There's no limit on concurrent sessions per user. If an attacker compromises credentials, they can create sessions that persist even after the user changes their password.",
          evidence: `POST ${endpoint} → 200 (two different tokens issued simultaneously)`,
          remediation: "Track active sessions per user. Optionally invalidate previous sessions on new login. Always invalidate all sessions on password change.",
          cwe: "CWE-384",
          owasp: "A07:2021",
          codeSnippet: `// Invalidate other sessions on login\nexport async function login(userId: string) {\n  // Delete all existing sessions for this user\n  await db.session.deleteMany({ where: { userId } });\n  // Create new session\n  const session = await db.session.create({\n    data: { userId, expiresAt: addHours(new Date(), 24) },\n  });\n  return session.id;\n}`,
        });
      }
    }
  }

  // Phase 5: Session invalidation on logout — check if token is still valid after logout
  const logoutEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(logout|signout|sign-out|auth\/signout)\b/i.test(ep),
  ).slice(0, 1);

  if (logoutEndpoints.length > 0 && sessionCookies.length > 0) {
    const logoutEp = logoutEndpoints[0];
    // Check a protected endpoint with existing cookies
    const protectedEps = target.apiEndpoints.filter((ep) =>
      /\/(me|profile|user|account|dashboard)\b/i.test(ep) &&
      !/\/(login|register|signup)/i.test(ep),
    ).slice(0, 1);

    if (protectedEps.length > 0) {
      const cookieHeader = sessionCookies.map((c) => `${c.name}=${c.value}`).join("; ");

      // Step 1: Check protected endpoint with session
      const before = await scanFetch(protectedEps[0], {
        headers: { Cookie: cookieHeader },
        timeoutMs: 5000,
      });

      if (before.ok) {
        // Step 2: Call logout
        await scanFetch(logoutEp, {
          method: "POST",
          headers: { Cookie: cookieHeader },
          timeoutMs: 5000,
        });

        // Step 3: Check if the same session still works
        const after = await scanFetch(protectedEps[0], {
          headers: { Cookie: cookieHeader },
          timeoutMs: 5000,
        });

        if (after.ok) {
          findings.push({
            id: "session-no-invalidation",
            module: "Session Management",
            severity: "high",
            title: "Session not invalidated on logout",
            description: "After calling the logout endpoint, the session token remains valid. An attacker who steals a session token can continue using it even after the user logs out.",
            evidence: `Before logout: ${protectedEps[0]} → ${before.status}\nLogout: POST ${logoutEp}\nAfter logout: ${protectedEps[0]} → ${after.status} (still works!)`,
            remediation: "Invalidate the session server-side on logout. For JWTs, maintain a blocklist of revoked tokens or use short-lived tokens with refresh token rotation.",
            cwe: "CWE-613",
            owasp: "A07:2021",
            codeSnippet: `// Server-side session invalidation\nexport async function POST(req: Request) {\n  const session = await getSession(req);\n  if (session) {\n    // Delete from database\n    await db.session.delete({ where: { id: session.id } });\n    // For JWT: add to blocklist\n    await redis.set(\`blocked:\${session.jti}\`, "1", "EX", session.exp - now);\n  }\n  // Clear cookie\n  return new Response(null, {\n    status: 200,\n    headers: { "Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; Secure" },\n  });\n}`,
          });
        }
      }
    }
  }

  // Phase 6: Check for session-related JS patterns that suggest weak implementation
  const weakPatterns = [
    { pattern: /localStorage\.setItem\s*\(\s*["'](?:token|session|jwt|auth|access_token)["']/, name: "localStorage token storage", severity: "medium" as const },
    { pattern: /sessionStorage\.setItem\s*\(\s*["'](?:token|session|jwt|auth|access_token)["']/, name: "sessionStorage token storage", severity: "low" as const },
    { pattern: /document\.cookie\s*=\s*["'](?:token|session|jwt|auth)=/, name: "JS-set session cookie (not HttpOnly)", severity: "high" as const },
  ];

  for (const { pattern, name, severity } of weakPatterns) {
    if (pattern.test(allJs)) {
      findings.push({
        id: `session-weak-storage-${findings.length}`,
        module: "Session Management",
        severity,
        title: `Session token stored in ${name}`,
        description: name.includes("localStorage")
          ? "Session tokens in localStorage are accessible to any JavaScript on the page, including XSS payloads. They persist across tabs and sessions, and are never automatically sent with requests."
          : name.includes("sessionStorage")
            ? "Session tokens in sessionStorage are accessible to XSS but don't persist across tabs. Still preferable to use HttpOnly cookies."
            : "Setting session cookies via JavaScript means they can't have the HttpOnly flag, making them accessible to XSS attacks.",
        evidence: `Found in JS bundle: ${name}`,
        remediation: "Store session tokens in HttpOnly, Secure, SameSite=Lax cookies set by the server. Never manage sessions in client-side JavaScript.",
        cwe: "CWE-922",
        owasp: "A07:2021",
        codeSnippet: `// Set session cookie server-side with proper flags\nexport async function POST(req: Request) {\n  const { token } = await authenticate(req);\n  return new Response(JSON.stringify({ success: true }), {\n    headers: {\n      "Set-Cookie": \`session=\${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400\`,\n    },\n  });\n}\n\n// Client reads user state from an API call, not from the token itself\nconst { data: user } = useSWR("/api/me");`,
      });
    }
  }

  return findings;
};
