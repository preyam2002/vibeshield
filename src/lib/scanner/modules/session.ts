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

  // Phase 7: Session entropy analysis — check cookies for weak randomness
  for (const cookie of sessionCookies) {
    const val = cookie.value;
    const isUuidV1 = /^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val);
    const isTimestamp = /^1[6-9]\d{8}(\d{3})?$/.test(val);
    let weakReason = "";
    let desc = "";
    if (val.length < 16) {
      weakReason = `short value (${val.length} chars)`;
      desc = `Session cookie is only ${val.length} chars. Short IDs have low entropy and can be brute-forced. OWASP recommends at least 128 bits.`;
    } else if (/^\d+$/.test(val) && !isTimestamp) {
      weakReason = "purely numeric";
      desc = "A purely numeric session ID has drastically reduced keyspace, suggesting an auto-incrementing DB ID rather than cryptographic randomness.";
    } else if (isTimestamp) {
      weakReason = "timestamp-based";
      desc = "The session ID looks like a Unix timestamp. Timestamp-based IDs are fully predictable if an attacker knows the approximate login time.";
    } else if (isUuidV1) {
      weakReason = "UUID v1 (time-based)";
      desc = "UUID v1 is derived from timestamp and MAC address, making it predictable. An attacker who knows the approximate creation time can enumerate valid session IDs.";
    }
    if (weakReason) {
      findings.push({
        id: `session-weak-entropy-${findings.length}`,
        module: "Session Management",
        severity: "low",
        title: `Session cookie "${cookie.name}" has weak randomness: ${weakReason}`,
        description: desc,
        evidence: `Cookie: ${cookie.name}=${val.substring(0, 16)}${val.length > 16 ? "…" : ""}`,
        remediation: "Generate session IDs with at least 128 bits of cryptographic randomness using crypto.randomBytes or crypto.randomUUID.",
        cwe: "CWE-330",
        owasp: "A07:2021",
        codeSnippet: `import { randomBytes, randomUUID } from "crypto";\n// Option A: hex string with 256 bits of entropy\nconst sid = randomBytes(32).toString("hex");\n// Option B: UUID v4 (122 bits of randomness)\nconst sid2 = randomUUID();`,
      });
      break;
    }
  }

  // Phase 8: Cross-tab session leakage via BroadcastChannel/postMessage
  const crossTabChecks: { re: RegExp; id: string; title: string; desc: string; evidence: string; snippet: string }[] = [
    {
      re: /new\s+BroadcastChannel\s*\(\s*["'][^"']*(?:session|token|auth)[^"']*["']\s*\)/i,
      id: "broadcastchannel", title: "Session/auth data shared via BroadcastChannel",
      desc: "A BroadcastChannel with a session/token/auth channel name lets any XSS on the domain eavesdrop on tokens broadcast across tabs.",
      evidence: "Found BroadcastChannel with session/token/auth context in JS bundle",
      snippet: `// Bad: broadcasting tokens\nconst ch = new BroadcastChannel("auth");\nch.postMessage({ token: jwt });\n\n// Good: signal without the token\nconst ch = new BroadcastChannel("auth-sync");\nch.postMessage({ event: "login" }); // tabs re-read via /api/me`,
    },
    {
      re: /\.postMessage\s*\(\s*(?:JSON\.stringify\s*\()?\s*\{[^}]*(?:token|session|jwt|access_token|auth)[^}]*\}/i,
      id: "postmessage", title: "Session token sent via postMessage",
      desc: "A postMessage call sends token/session/auth data. If the target origin is \"*\" or unvalidated, any embedding page can intercept the token.",
      evidence: "Found postMessage sending token/session/auth data in JS bundle",
      snippet: `// Bad\nwindow.opener.postMessage({ token }, "*");\n// Good: use HttpOnly cookies, no postMessage needed`,
    },
    {
      re: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:function\s*\([^)]*\)|(?:\([^)]*\)|[a-zA-Z_$]\w*)\s*=>)\s*\{[^}]*\}/,
      id: "no-origin-check", title: "postMessage listener without origin validation",
      desc: "A message event listener processes messages without checking event.origin. Attacker-controlled iframes or popups can inject malicious session data.",
      evidence: "Found window.addEventListener(\"message\", ...) without origin check in JS bundle",
      snippet: `// Bad: no origin check\nwindow.addEventListener("message", (e) => { setToken(e.data.token); });\n\n// Good: validate origin\nwindow.addEventListener("message", (e) => {\n  if (e.origin !== "https://myapp.com") return;\n});`,
    },
  ];
  for (const check of crossTabChecks) {
    if (check.re.test(allJs)) {
      findings.push({
        id: `session-crosstab-${check.id}-${findings.length}`,
        module: "Session Management",
        severity: "medium",
        title: check.title,
        description: check.desc,
        evidence: check.evidence,
        remediation: "Avoid sending tokens via BroadcastChannel or postMessage. Use HttpOnly cookies for auth state. Always validate event.origin in message listeners.",
        cwe: "CWE-346",
        owasp: "A07:2021",
        codeSnippet: check.snippet,
      });
    }
  }

  // Phase 9: Session cookie with predictable name — framework fingerprinting
  const frameworkCookieNames: Record<string, string> = {
    PHPSESSID: "PHP",
    JSESSIONID: "Java (Tomcat/Spring)",
    "ASP.NET_SessionId": "ASP.NET",
    "connect.sid": "Express/Connect (Node.js)",
    laravel_session: "Laravel (PHP)",
    PLAY_SESSION: "Play Framework (Scala/Java)",
  };

  for (const cookie of target.cookies) {
    const framework = frameworkCookieNames[cookie.name];
    if (framework) {
      findings.push({
        id: `session-framework-fingerprint-${findings.length}`,
        module: "Session Management",
        severity: "info",
        title: `Default session cookie name "${cookie.name}" reveals ${framework}`,
        description: `The session cookie uses the default name for ${framework}. This leaks the backend technology stack, allowing attackers to target known vulnerabilities specific to ${framework}.`,
        evidence: `Cookie: ${cookie.name}`,
        remediation: `Rename the session cookie to a generic name like "sid" or "__session" that doesn't reveal the framework.`,
        cwe: "CWE-200",
        owasp: "A05:2021",
        codeSnippet: framework.includes("Express")
          ? `// Express: rename the default session cookie\napp.use(session({\n  name: "__session", // instead of "connect.sid"\n  secret: process.env.SESSION_SECRET,\n  cookie: { httpOnly: true, secure: true, sameSite: "lax" },\n}));`
          : framework.includes("PHP")
            ? `; php.ini — rename the default session cookie\nsession.name = __session ; instead of PHPSESSID`
            : framework.includes("Laravel")
              ? `// config/session.php — rename the default cookie\n'cookie' => '__session', // instead of 'laravel_session'`
              : `// Rename the default session cookie in your ${framework} configuration\n// Use a generic name like "__session" or "sid"`,
      });
      break; // one finding is enough
    }
  }

  // Phase 10: Session fixation — check if session tokens remain the same before and after authentication
  const loginPages = target.pages.filter((p) =>
    /\/(login|signin|sign-in|auth)\b/i.test(p),
  ).slice(0, 3);

  const fixationResults = await Promise.allSettled(
    loginPages.map(async (loginPage) => {
      // Step 1: GET the login page to receive a pre-auth session cookie
      const preAuthRes = await scanFetch(loginPage, {
        timeoutMs: 5000,
        noCache: true,
      });
      const preAuthSetCookie = preAuthRes.headers.get("set-cookie") || "";
      const preAuthTokens = preAuthSetCookie.match(
        /(?:session|sid|connect\.sid|__session|__Secure-session|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=([^;]+)/gi,
      );
      if (!preAuthTokens || preAuthTokens.length === 0) return null;

      // Step 2: POST a dummy login to see if the token changes
      const postAuthRes = await scanFetch(loginPage, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: preAuthSetCookie.split(";")[0] },
        body: "username=test@vibeshield.dev&password=test123",
        timeoutMs: 5000,
        noCache: true,
      });
      const postAuthSetCookie = postAuthRes.headers.get("set-cookie") || "";
      const postAuthTokens = postAuthSetCookie.match(
        /(?:session|sid|connect\.sid|__session|__Secure-session|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=([^;]+)/gi,
      );

      // If no new cookie is set, or the token value is the same, session fixation is possible
      if (!postAuthTokens) {
        return { loginPage, preAuth: preAuthTokens[0], postAuth: null, fixed: true };
      }
      const preVal = preAuthTokens[0].split("=")[1];
      const postVal = postAuthTokens[0].split("=")[1];
      if (preVal === postVal) {
        return { loginPage, preAuth: preVal, postAuth: postVal, fixed: true };
      }
      return null;
    }),
  );

  for (const result of fixationResults) {
    if (result.status === "fulfilled" && result.value?.fixed) {
      const { loginPage, preAuth, postAuth } = result.value;
      findings.push({
        id: `session-fixation-${findings.length}`,
        module: "Session Management",
        severity: "high",
        title: `Possible session fixation on ${new URL(loginPage).pathname}`,
        description: "The session token issued before authentication is not regenerated after login. An attacker can set a known session ID in the victim's browser (via XSS or subdomain cookie injection), wait for the victim to authenticate, then hijack the now-authenticated session.",
        evidence: postAuth
          ? `Pre-auth token: ${preAuth?.substring(0, 20)}…\nPost-auth token: ${postAuth.substring(0, 20)}… (unchanged)`
          : `Pre-auth token: ${preAuth?.substring(0, 20)}…\nNo new Set-Cookie after login POST`,
        remediation: "Always regenerate the session ID after successful authentication. Invalidate the old session on the server side.",
        cwe: "CWE-384",
        owasp: "A07:2021",
        codeSnippet: `// Express: regenerate session after login\napp.post("/login", (req, res) => {\n  authenticate(req.body).then((user) => {\n    req.session.regenerate((err) => {\n      req.session.userId = user.id;\n      req.session.save(() => res.redirect("/dashboard"));\n    });\n  });\n});`,
      });
      break;
    }
  }

  // Phase 11: Session cookie scope — check for overly broad domain/path that could leak to subdomains
  const targetHost = new URL(target.baseUrl).hostname;
  for (const cookie of sessionCookies) {
    const issues: string[] = [];
    // Check overly broad domain (leading dot means all subdomains)
    if (cookie.domain) {
      const cookieDomain = cookie.domain.startsWith(".") ? cookie.domain.slice(1) : cookie.domain;
      // If the cookie domain is a parent of the target host (e.g., .example.com for app.example.com)
      if (targetHost !== cookieDomain && targetHost.endsWith(`.${cookieDomain}`)) {
        issues.push(`Domain "${cookie.domain}" allows all subdomains of ${cookieDomain} to read this cookie`);
      }
      // Cookie set on bare domain with leading dot
      if (cookie.domain.startsWith(".")) {
        issues.push(`Leading-dot domain "${cookie.domain}" shares the cookie with all subdomains`);
      }
    }
    // Check overly broad path
    if (cookie.path === "/" || !cookie.path) {
      // Path=/ is default and common, only flag if combined with broad domain
      if (issues.length > 0) {
        issues.push(`Path="${cookie.path || "/"}" makes the cookie available to all routes`);
      }
    }
    if (issues.length > 0) {
      findings.push({
        id: `session-cookie-scope-${findings.length}`,
        module: "Session Management",
        severity: "medium",
        title: `Session cookie "${cookie.name}" has overly broad scope`,
        description: `The session cookie is scoped too broadly, meaning it will be sent to subdomains or paths that may not need it. A compromised or malicious subdomain could read or relay the session cookie, enabling session hijacking across the domain.`,
        evidence: issues.join("\n"),
        remediation: "Set the cookie Domain to the most specific hostname needed. Avoid leading-dot domains unless cross-subdomain auth is required. Use __Host- prefix to lock cookies to the exact origin.",
        cwe: "CWE-1275",
        owasp: "A07:2021",
        codeSnippet: `// Use __Host- prefix to lock cookie to exact origin (no Domain, Path=/)\nres.setHeader("Set-Cookie", [\n  "__Host-session=<token>; Secure; HttpOnly; SameSite=Lax; Path=/",\n]);\n\n// Or scope to the specific subdomain\nres.setHeader("Set-Cookie", [\n  "session=<token>; Domain=app.example.com; Secure; HttpOnly; SameSite=Lax; Path=/app",\n]);`,
      });
      break;
    }
  }

  // Phase 12: Concurrent session limits — verify the app enforces session limits via parallel login attempts
  const concurrentLoginEps = target.apiEndpoints.filter((ep) =>
    /\/(login|signin|sign-in|auth\/callback|auth\/session)\b/i.test(ep),
  ).slice(0, 2);

  const concurrentResults = await Promise.allSettled(
    concurrentLoginEps.map(async (endpoint) => {
      // Fire 3 simultaneous login requests to check if all produce distinct valid sessions
      const requests = Array.from({ length: 3 }, () =>
        scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: "test@vibeshield.dev", password: "test123" }),
          timeoutMs: 5000,
          noCache: true,
        }),
      );
      const responses = await Promise.all(requests);
      const setCookies: string[] = [];
      for (const res of responses) {
        const sc = res.headers.get("set-cookie") || "";
        if (sc) setCookies.push(sc);
      }
      // Extract session token values from Set-Cookie headers
      const tokenValues = setCookies
        .map((sc) => {
          const m = sc.match(/(?:session|sid|connect\.sid|__session|token)=([^;]+)/i);
          return m ? m[1] : null;
        })
        .filter(Boolean);
      const uniqueTokens = new Set(tokenValues);
      // If we got 3 distinct session tokens, no concurrent session limit is enforced
      if (uniqueTokens.size >= 3) {
        return { endpoint, count: uniqueTokens.size };
      }
      return null;
    }),
  );

  for (const result of concurrentResults) {
    if (result.status === "fulfilled" && result.value) {
      const { endpoint, count } = result.value;
      findings.push({
        id: `session-no-concurrent-limit-${findings.length}`,
        module: "Session Management",
        severity: "medium",
        title: `No concurrent session limit on ${new URL(endpoint).pathname}`,
        description: `${count} simultaneous login requests each produced a distinct session cookie, indicating no limit on concurrent sessions per user. An attacker with stolen credentials can create persistent sessions that survive password changes if old sessions are not invalidated.`,
        evidence: `POST ${endpoint} × ${count} → ${count} unique session tokens issued concurrently`,
        remediation: "Enforce a maximum number of active sessions per user. Invalidate all existing sessions on password change. Consider notifying users of new logins from unrecognized devices.",
        cwe: "CWE-384",
        owasp: "A07:2021",
        codeSnippet: `// Limit concurrent sessions on login\nexport async function login(userId: string, maxSessions = 3) {\n  const existing = await db.session.findMany({ where: { userId }, orderBy: { createdAt: "asc" } });\n  if (existing.length >= maxSessions) {\n    // Remove oldest sessions to stay within limit\n    const toRemove = existing.slice(0, existing.length - maxSessions + 1);\n    await db.session.deleteMany({ where: { id: { in: toRemove.map((s) => s.id) } } });\n  }\n  return db.session.create({ data: { userId, expiresAt: addHours(new Date(), 24) } });\n}`,
      });
      break;
    }
  }

  // Phase 13: Session token in URL parameters — deep check across HTML content, JS bundles, and link patterns
  const sessionUrlPatterns = [
    /[;?&](jsessionid|JSESSIONID)=([a-zA-Z0-9._-]{10,})/,
    /[;?&](phpsessid|PHPSESSID)=([a-zA-Z0-9._-]{10,})/,
    /[;?&](sid|SID)=([a-zA-Z0-9._-]{16,})/,
    /[;?&](token|TOKEN)=([a-zA-Z0-9._-]{16,})/,
    /[;?&](session_id|sessionid|SESSION_ID)=([a-zA-Z0-9._-]{10,})/,
  ];

  // Check JS bundles for URL construction that embeds session tokens
  const jsSessionUrlPatterns = [
    /["'`][^"'`]*[?&](?:jsessionid|sid|session_id|sessionid|token)=[^"'`]+["'`]/i,
    /url\s*[+=]\s*["'`].*[?&](?:jsessionid|sid|session_id|token)=/i,
    /location\.href\s*=\s*.*[?&](?:jsessionid|sid|session_id|token)=/i,
    /window\.location\s*=\s*.*[?&](?:jsessionid|sid|session_id|token)=/i,
  ];

  // Check redirect URLs and link URLs for embedded session params
  const allUrlsToScan = [...target.linkUrls, ...target.redirectUrls, ...target.pages].slice(0, 100);
  let sessionInUrlFound = false;
  for (const url of allUrlsToScan) {
    for (const pattern of sessionUrlPatterns) {
      const match = url.match(pattern);
      if (match && !sessionInUrlFound) {
        findings.push({
          id: `session-url-param-${findings.length}`,
          module: "Session Management",
          severity: "high",
          title: `Session ID "${match[1]}" embedded in URL parameter`,
          description: `The URL contains a session identifier in the "${match[1]}" parameter. Session IDs in URLs are leaked via Referer headers to third-party resources, stored in browser history, cached by proxies, and recorded in server access logs — all of which are accessible to attackers.`,
          evidence: `URL: ${url.substring(0, 200)}`,
          remediation: "Never pass session identifiers in URL parameters. Use HttpOnly cookies or the Authorization header. Configure URL rewriting to strip session parameters.",
          cwe: "CWE-598",
          owasp: "A07:2021",
          codeSnippet: `// Java/Spring: disable URL-based session tracking\n@Configuration\npublic class SecurityConfig {\n  @Bean\n  public ServletContextInitializer servletContextInitializer() {\n    return ctx -> ctx.setSessionTrackingModes(\n      EnumSet.of(SessionTrackingMode.COOKIE) // disable URL rewriting\n    );\n  }\n}`,
        });
        sessionInUrlFound = true;
        break;
      }
    }
    if (sessionInUrlFound) break;
  }

  // Also check JS bundles for URL construction embedding sessions
  if (!sessionInUrlFound) {
    for (const pattern of jsSessionUrlPatterns) {
      const match = allJs.match(pattern);
      if (match) {
        findings.push({
          id: `session-url-param-js-${findings.length}`,
          module: "Session Management",
          severity: "medium",
          title: "JavaScript constructs URLs containing session parameters",
          description: "Client-side JavaScript builds URLs that embed session tokens as query parameters. These URLs leak session data through Referer headers, browser history, and server logs.",
          evidence: `Found in JS bundle: ${match[0].substring(0, 120)}`,
          remediation: "Refactor client-side code to use cookies or Authorization headers for session management. Remove URL-based session parameter construction.",
          cwe: "CWE-598",
          owasp: "A07:2021",
          codeSnippet: `// Bad: session token in URL\nfetch(\`/api/data?token=\${sessionToken}\`);\n\n// Good: session token in header\nfetch("/api/data", {\n  headers: { Authorization: \`Bearer \${sessionToken}\` },\n});`,
        });
        break;
      }
    }
  }

  // Phase 14: Insecure session storage — check if session cookies lack HttpOnly flag
  for (const cookie of sessionCookies) {
    if (!cookie.httpOnly) {
      findings.push({
        id: `session-no-httponly-${findings.length}`,
        module: "Session Management",
        severity: "high",
        title: `Session cookie "${cookie.name}" is missing HttpOnly flag`,
        description: `The session cookie "${cookie.name}" does not have the HttpOnly attribute. This means JavaScript can access it via document.cookie, allowing XSS attacks to trivially steal the session token and exfiltrate it to an attacker-controlled server.`,
        evidence: `Cookie: ${cookie.name}\nHttpOnly: false\nAccessible via: document.cookie`,
        remediation: "Set the HttpOnly flag on all session cookies to prevent JavaScript access. This is a critical defense-in-depth measure against XSS-based session theft.",
        cwe: "CWE-1004",
        owasp: "A07:2021",
        codeSnippet: `// Always set HttpOnly on session cookies\nres.setHeader("Set-Cookie", [\n  "session=<token>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",\n]);\n\n// Express session middleware\napp.use(session({\n  cookie: {\n    httpOnly: true, // Prevent document.cookie access\n    secure: true,\n    sameSite: "lax",\n  },\n}));`,
      });
      break;
    }
  }

  // Also check if JS code reads session data from document.cookie
  const docCookieReadPatterns = [
    /document\.cookie\.(?:match|split|indexOf|includes)\s*\(\s*["'](?:session|sid|token|auth|jwt)/i,
    /document\.cookie\b[^=]*\.(?:match|split)\b/,
    /(?:getCookie|parseCookies?|readCookie)\s*\(\s*["'](?:session|sid|token|auth|jwt)/i,
  ];

  for (const pattern of docCookieReadPatterns) {
    const match = allJs.match(pattern);
    if (match) {
      findings.push({
        id: `session-js-cookie-read-${findings.length}`,
        module: "Session Management",
        severity: "medium",
        title: "JavaScript reads session data from document.cookie",
        description: "Client-side JavaScript explicitly reads session/auth cookie values via document.cookie. This confirms the session cookie is accessible to scripts, which means any XSS vulnerability can exfiltrate the session token.",
        evidence: `Found in JS bundle: ${match[0].substring(0, 100)}`,
        remediation: "Make session cookies HttpOnly so JavaScript cannot read them. If the client needs user info, expose it via a /api/me endpoint instead of reading the session cookie directly.",
        cwe: "CWE-1004",
        owasp: "A07:2021",
        codeSnippet: `// Bad: reading session from document.cookie\nconst session = document.cookie.match(/session=([^;]+)/)?.[1];\n\n// Good: fetch user state from API (cookie sent automatically)\nconst res = await fetch("/api/me", { credentials: "include" });\nconst user = await res.json();`,
      });
      break;
    }
  }

  return findings;
};
