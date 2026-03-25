import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const AUTH_PATHS = [
  "/api/auth/signin", "/api/auth/signup", "/api/auth/login",
  "/api/auth/register", "/api/login", "/api/register",
  "/api/auth/forgot-password", "/api/forgot-password",
  "/api/auth/reset-password", "/api/users/check",
  "/auth/login", "/auth/register", "/auth/forgot-password",
];

export const emailEnumModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  const testEmails = [
    "definitely-not-a-real-user-1234@test.com",
    "admin@" + new URL(target.url).hostname,
  ];

  // Probe all paths in parallel to find which ones exist
  const probeResults = await Promise.allSettled(
    AUTH_PATHS.map(async (path) => {
      const url = target.baseUrl + path;
      const discovered = target.apiEndpoints.some((ep) => new URL(ep).pathname === path || ep.endsWith(path));
      if (!discovered) {
        const probe = await scanFetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}", timeoutMs: 3000 });
        if (probe.status === 404 || probe.status === 405) return null;
        const probeText = await probe.text();
        if (probeText.includes("<!DOCTYPE") || probeText.includes("<html")) return null;
      }
      return path;
    }),
  );

  const validPaths = probeResults
    .filter((r): r is PromiseFulfilledResult<string | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is string => v !== null);

  // Test all valid paths in parallel
  const enumResults = await Promise.allSettled(
    validPaths.map(async (path) => {
      const url = target.baseUrl + path;

      const [res1, res2] = await Promise.all([
        scanFetch(url, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: testEmails[0], password: "TestPassword123!" }), timeoutMs: 5000,
        }),
        scanFetch(url, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: testEmails[1], password: "TestPassword123!" }), timeoutMs: 5000,
        }),
      ]);

      const text1 = await res1.text();
      const text2 = await res2.text();

      if (res1.status !== res2.status || text1 !== text2) {
        const differsBy = res1.status !== res2.status ? "status code" : "response body";
        const enumPhrases = [
          /user not found/i, /email not found/i, /no account/i,
          /doesn't exist/i, /does not exist/i, /not registered/i,
          /invalid email/i, /unknown email/i, /email already/i,
          /already registered/i, /already exists/i, /account exists/i,
        ];
        const hasEnumPhrase = enumPhrases.some((p) => p.test(text1) || p.test(text2));

        if (hasEnumPhrase || differsBy === "status code") {
          return { type: "response" as const, path, status1: res1.status, status2: res2.status, differsBy, hasEnumPhrase };
        }
      }

      // Timing test: baseline (3 parallel) vs real (3 parallel)
      const [baseTimings, realTimings] = await Promise.all([
        Promise.all(
          [0, 1, 2].map(async (i) => {
            const bs = Date.now();
            try {
              await scanFetch(url, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: `nonexistent-timing-test-${i}@test.com`, password: "x" }), timeoutMs: 5000,
              });
            } catch { /* skip */ }
            return Date.now() - bs;
          }),
        ),
        Promise.all(
          [0, 1, 2].map(async () => {
            const rs = Date.now();
            try {
              await scanFetch(url, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: testEmails[1], password: "x" }), timeoutMs: 5000,
              });
            } catch { /* skip */ }
            return Date.now() - rs;
          }),
        ),
      ]);

      const sortedBase = [...baseTimings].sort((a, b) => a - b);
      const baselineMedian = sortedBase[1] || 500;
      const baselineVariance = sortedBase[sortedBase.length - 1] - sortedBase[0];
      const sortedReal = [...realTimings].sort((a, b) => a - b);
      const realMedian = sortedReal[1] || 500;
      const diff = Math.abs(realMedian - baselineMedian);

      if (diff > 300 && diff > baselineVariance * 2 && diff > baselineMedian * 0.5) {
        return { type: "timing" as const, path, baselineMedian, baselineVariance, realMedian, diff };
      }

      return null;
    }),
  );

  // Test password reset endpoints specifically — these commonly leak user existence
  const resetPaths = validPaths.filter((p) => /forgot|reset|recover/i.test(p));
  if (resetPaths.length > 0) {
    const resetResults = await Promise.allSettled(
      resetPaths.map(async (path) => {
        const url = target.baseUrl + path;
        const [fakeRes, realRes] = await Promise.all([
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: "nonexistent-reset-test-9876@test.com" }), timeoutMs: 5000,
          }),
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: testEmails[1] }), timeoutMs: 5000,
          }),
        ]);
        const fakeText = await fakeRes.text();
        const realText = await realRes.text();
        // Check for different status codes or response lengths diverging significantly
        if (fakeRes.status !== realRes.status) {
          return { path, fakeStatus: fakeRes.status, realStatus: realRes.status, type: "status" as const };
        }
        // Check if response body lengths differ significantly (>30% difference)
        if (fakeText.length > 20 && realText.length > 20) {
          const ratio = Math.abs(fakeText.length - realText.length) / Math.max(fakeText.length, realText.length);
          if (ratio > 0.3) {
            return { path, fakeStatus: fakeRes.status, realStatus: realRes.status, type: "body-length" as const };
          }
        }
        // Check for explicit enumeration phrases in reset responses
        const resetEnumPhrases = [/no account/i, /not found/i, /doesn't exist/i, /not registered/i, /unknown/i, /invalid email/i];
        if (resetEnumPhrases.some((p) => p.test(fakeText) && !p.test(realText))) {
          return { path, fakeStatus: fakeRes.status, realStatus: realRes.status, type: "phrase" as const };
        }
        return null;
      }),
    );
    for (const r of resetResults) {
      if (findings.length >= 3) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `email-enum-reset-${findings.length}`, module: "Email Enumeration", severity: "medium",
        title: `Password reset leaks user existence on ${v.path}`,
        description: `The password reset endpoint returns different responses for registered vs unregistered emails (${v.type === "status" ? `status ${v.fakeStatus} vs ${v.realStatus}` : v.type === "phrase" ? "explicit error message" : "different response body size"}). Attackers can enumerate valid accounts.`,
        evidence: `Fake email → status ${v.fakeStatus}\nReal email → status ${v.realStatus}\nDifference type: ${v.type}`,
        remediation: 'Always return the same response: "If an account exists, a reset link has been sent." Never reveal whether the email is registered.',
        cwe: "CWE-204", owasp: "A07:2021",
        codeSnippet: `// Always return 200 with generic message\napp.post("/api/auth/forgot-password", async (req, res) => {\n  const user = await db.users.findByEmail(req.body.email);\n  if (user) await sendResetEmail(user); // silently skip if not found\n  res.json({ message: "If an account exists, we'll send a reset link." });\n});`,
      });
    }
  }

  for (const r of enumResults) {
    if (findings.length >= 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;

    if (v.type === "response") {
      findings.push({
        id: `email-enum-${findings.length}`, module: "Email Enumeration", severity: "medium",
        title: `Email enumeration possible on ${v.path}`,
        description: `Different responses for existing vs non-existing emails allow attackers to determine which email addresses are registered. Differs by: ${v.differsBy}.`,
        evidence: `Path: ${v.path}\nFake email status: ${v.status1}\nReal email status: ${v.status2}\n${v.hasEnumPhrase ? "Response contains explicit user existence message" : ""}`,
        remediation: 'Return identical responses for valid and invalid emails. Use a generic message like "If an account exists, we\'ll send a reset link."',
        codeSnippet: `// Return the same response regardless of whether the user exists
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await db.users.findByEmail(email);
  if (user) {
    await sendPasswordResetEmail(user);
  }
  // Always return 200 with a generic message
  res.status(200).json({ message: "If an account with that email exists, a reset link has been sent." });
});`,
        cwe: "CWE-204", owasp: "A07:2021",
      });
    } else {
      findings.push({
        id: `email-enum-timing-${findings.length}`, module: "Email Enumeration", severity: "low",
        title: `Timing-based email enumeration on ${v.path}`,
        description: `Response times differ significantly for existing vs non-existing emails (baseline: ${v.baselineMedian}ms, real: ${v.realMedian}ms). Attackers can determine valid emails by measuring response times.`,
        evidence: `Baseline median: ${v.baselineMedian}ms (variance: ${v.baselineVariance}ms)\nReal email median: ${v.realMedian}ms\nDifference: ${v.diff}ms`,
        remediation: "Normalize response times for auth endpoints. Add a consistent delay regardless of whether the user exists.",
        codeSnippet: `// Enforce constant-time responses to prevent timing attacks
app.post("/api/auth/login", async (req, res) => {
  const start = Date.now();
  const MIN_RESPONSE_MS = 500;
  try {
    const user = await db.users.findByEmail(req.body.email);
    // Always run password hash comparison, even for missing users
    const valid = user
      ? await bcrypt.compare(req.body.password, user.passwordHash)
      : await bcrypt.compare(req.body.password, DUMMY_HASH);
    if (!user || !valid) throw new Error();
    res.json({ token: signJwt(user) });
  } catch {
    const elapsed = Date.now() - start;
    await new Promise((r) => setTimeout(r, Math.max(0, MIN_RESPONSE_MS - elapsed)));
    res.status(401).json({ error: "Invalid credentials" });
  }
});`,
        cwe: "CWE-208",
      });
    }
  }

  // Phase 4: GraphQL user lookup enumeration
  if (findings.length < 3) {
    const gqlEndpoints = target.apiEndpoints.filter((ep) => /graphql|gql/i.test(ep));
    if (gqlEndpoints.length > 0) {
      const gqlResults = await Promise.allSettled(
        gqlEndpoints.slice(0, 2).map(async (ep) => {
          // Try checking if a user query reveals existence
          const queries = [
            { query: `query { user(email: "${testEmails[0]}") { id } }` },
            { query: `query { user(email: "${testEmails[1]}") { id } }` },
          ];
          const [res1, res2] = await Promise.all(
            queries.map((q) => scanFetch(ep, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify(q), timeoutMs: 5000,
            })),
          );
          const [text1, text2] = await Promise.all([res1.text(), res2.text()]);
          // Different responses = enumeration
          if (text1 !== text2 && text1.length > 5 && text2.length > 5) {
            const hasNull = text1.includes('"user":null') || text2.includes('"user":null');
            const hasData = text1.includes('"user":{') || text2.includes('"user":{');
            if (hasNull || hasData) {
              return { endpoint: new URL(ep).pathname };
            }
          }
          return null;
        }),
      );
      for (const r of gqlResults) {
        if (r.status !== "fulfilled" || !r.value) continue;
        findings.push({
          id: `email-enum-graphql-${findings.length}`, module: "Email Enumeration", severity: "medium",
          title: `GraphQL user lookup enables email enumeration on ${r.value.endpoint}`,
          description: "The GraphQL user query returns null for non-existent users and data for existing users, allowing attackers to enumerate valid email addresses.",
          evidence: `GraphQL query: { user(email: "...") { id } }\nDifferent responses for existing vs non-existing users`,
          remediation: "Require authentication for user lookup queries. Return consistent errors for both found and not-found cases.",
          cwe: "CWE-204", owasp: "A07:2021",
          codeSnippet: `// Require auth for user queries\nconst resolvers = {\n  Query: {\n    user: (_, { email }, ctx) => {\n      if (!ctx.currentUser) throw new AuthenticationError("Login required");\n      if (ctx.currentUser.email !== email && !ctx.currentUser.isAdmin)\n        throw new ForbiddenError("Access denied");\n      return db.users.findByEmail(email);\n    },\n  },\n};`,
        });
        break;
      }
    }
  }

  // Phase 5: Signup endpoint enumeration — different error for existing emails
  if (findings.length < 3) {
    const signupPaths = validPaths.filter((p) => /signup|register|create/i.test(p));
    const signupResults = await Promise.allSettled(
      signupPaths.map(async (path) => {
        const url = target.baseUrl + path;
        const [fakeRes, realRes] = await Promise.all([
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: "nonexistent-signup-test-777@test.com", password: "TestPassword123!", name: "Test" }),
            timeoutMs: 5000,
          }),
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: testEmails[1], password: "TestPassword123!", name: "Test" }),
            timeoutMs: 5000,
          }),
        ]);
        const fakeText = await fakeRes.text();
        const realText = await realRes.text();
        const alreadyExists = /already (exists|registered|in use|taken)|email.*(in use|taken|exists)|duplicate.*email|account.*exists/i;
        if (alreadyExists.test(realText) && !alreadyExists.test(fakeText)) {
          return { path, fakeStatus: fakeRes.status, realStatus: realRes.status };
        }
        if (fakeRes.status !== realRes.status && (realRes.status === 409 || realRes.status === 422)) {
          return { path, fakeStatus: fakeRes.status, realStatus: realRes.status };
        }
        return null;
      }),
    );
    for (const r of signupResults) {
      if (findings.length >= 3) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      findings.push({
        id: `email-enum-signup-${findings.length}`, module: "Email Enumeration", severity: "medium",
        title: `Signup endpoint reveals existing accounts on ${r.value.path}`,
        description: `The signup endpoint returns "email already exists" for registered emails (status ${r.value.realStatus}) but a different response for new emails (status ${r.value.fakeStatus}). Attackers can enumerate all registered emails.`,
        evidence: `New email → ${r.value.fakeStatus}\nExisting email → ${r.value.realStatus}`,
        remediation: 'Use a two-step signup: accept the email, send a verification link. If already registered, send a "someone tried to create an account" email instead of showing an error.',
        cwe: "CWE-204", owasp: "A07:2021",
        codeSnippet: `// Two-step signup prevents enumeration\napp.post("/api/auth/signup", async (req, res) => {\n  const { email, password } = req.body;\n  const existing = await db.users.findByEmail(email);\n  if (existing) {\n    // Send "someone tried to register" email\n    await sendAlreadyRegisteredEmail(email);\n  } else {\n    const user = await db.users.create({ email, password });\n    await sendVerificationEmail(user);\n  }\n  // Always return the same response\n  res.json({ message: "Check your email to continue." });\n});`,
      });
    }
  }

  return findings;
};
