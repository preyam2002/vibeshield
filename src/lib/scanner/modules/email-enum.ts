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

  // Phase 6: Password reset enumeration — dedicated deep check on reset endpoints
  if (findings.length < 5) {
    const resetDeepPaths = validPaths.filter((p) => /forgot|reset|recover|password/i.test(p));
    const resetDeepResults = await Promise.allSettled(
      resetDeepPaths.map(async (path) => {
        const url = target.baseUrl + path;
        const payloads = [
          { email: "nonexistent-deep-reset-abc@test.com" },
          { email: testEmails[1] },
          { email: "" },
          { email: "invalid-email-format" },
        ];
        const responses = await Promise.allSettled(
          payloads.map((body) =>
            scanFetch(url, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body), timeoutMs: 5000,
            }).then(async (res) => ({ status: res.status, body: await res.text() })),
          ),
        );
        const settled = responses
          .filter((r): r is PromiseFulfilledResult<{ status: number; body: string }> => r.status === "fulfilled")
          .map((r) => r.value);
        if (settled.length < 2) return null;

        const nonexistent = settled[0];
        const existing = settled[1];

        // Check for different success/failure messaging
        const resetRevealPhrases = [
          /email (has been|was) sent/i, /check your (email|inbox)/i, /reset link/i, /instructions sent/i,
        ];
        const resetDenyPhrases = [
          /no account/i, /not found/i, /doesn't exist/i, /does not exist/i, /not registered/i,
          /unknown email/i, /invalid email/i, /no user/i,
        ];

        const existingGetsSuccess = resetRevealPhrases.some((p) => p.test(existing.body));
        const nonexistentGetsDenied = resetDenyPhrases.some((p) => p.test(nonexistent.body));

        if (existingGetsSuccess && nonexistentGetsDenied) {
          return { path, type: "message-divergence" as const, nonexistentStatus: nonexistent.status, existingStatus: existing.status };
        }

        // Check if status codes diverge (e.g. 200 vs 404, 200 vs 400)
        if (nonexistent.status !== existing.status && Math.abs(nonexistent.status - existing.status) >= 100) {
          return { path, type: "status-divergence" as const, nonexistentStatus: nonexistent.status, existingStatus: existing.status };
        }

        // Check JSON error field differences
        try {
          const j1 = JSON.parse(nonexistent.body);
          const j2 = JSON.parse(existing.body);
          const errField1 = j1.error || j1.message || j1.msg || "";
          const errField2 = j2.error || j2.message || j2.msg || "";
          if (errField1 !== errField2 && errField1.length > 0 && errField2.length > 0) {
            return { path, type: "json-error-diff" as const, nonexistentStatus: nonexistent.status, existingStatus: existing.status };
          }
        } catch { /* not JSON */ }

        return null;
      }),
    );
    for (const r of resetDeepResults) {
      if (findings.length >= 5) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `email-enum-reset-deep-${findings.length}`, module: "email-enum", severity: "medium",
        title: `Password reset endpoint leaks account existence on ${v.path}`,
        description: `The password reset endpoint at ${v.path} returns distinguishable responses for registered vs unregistered emails (${v.type}). Non-existent email returned status ${v.nonexistentStatus}, existing email returned status ${v.existingStatus}. Attackers can use this to enumerate valid accounts.`,
        evidence: `Non-existent email → status ${v.nonexistentStatus}\nExisting email → status ${v.existingStatus}\nDetection method: ${v.type}`,
        remediation: 'Always return the same HTTP status and response body: "If an account exists, a password reset link has been sent to your email." Never vary the response based on account existence.',
        cwe: "CWE-204",
        owasp: "A07:2021",
        codeSnippet: `// Secure password reset — identical response regardless of account existence
app.post("/api/auth/forgot-password", async (req, res) => {
  const user = await db.users.findByEmail(req.body.email);
  if (user) await sendResetEmail(user); // silently skip if not found
  res.status(200).json({ message: "If an account exists, a reset link has been sent." });
});`,
      });
    }
  }

  // Phase 7: Registration enumeration — deep signup endpoint analysis
  if (findings.length < 5) {
    const signupDeepPaths = validPaths.filter((p) => /signup|register|create|join/i.test(p));
    const signupDeepResults = await Promise.allSettled(
      signupDeepPaths.map(async (path) => {
        const url = target.baseUrl + path;
        const fakeEmail = `nonexist-reg-probe-${Date.now()}@test.com`;
        const [newRes, existingRes] = await Promise.all([
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: fakeEmail, password: "SecurePass123!!", name: "Probe User", username: "probeuser999" }),
            timeoutMs: 5000,
          }),
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: testEmails[1], password: "SecurePass123!!", name: "Probe User", username: "probeuser999" }),
            timeoutMs: 5000,
          }),
        ]);
        const newText = await newRes.text();
        const existingText = await existingRes.text();

        const registrationRevealPhrases = [
          /already (exists|registered|in use|taken|has an account)/i,
          /email.*(in use|taken|exists|registered)/i,
          /duplicate.*(email|account|user)/i,
          /account.*already/i,
          /user.*already/i,
          /try (logging in|signing in|another email)/i,
        ];

        if (registrationRevealPhrases.some((p) => p.test(existingText) && !p.test(newText))) {
          return { path, type: "explicit-message" as const, newStatus: newRes.status, existingStatus: existingRes.status };
        }

        // HTTP 409 Conflict or 422 for existing accounts
        if (existingRes.status === 409 || (existingRes.status === 422 && newRes.status !== 422)) {
          return { path, type: "status-code" as const, newStatus: newRes.status, existingStatus: existingRes.status };
        }

        // Check if response body structure differs (different JSON keys present)
        try {
          const j1 = JSON.parse(newText);
          const j2 = JSON.parse(existingText);
          const keys1 = Object.keys(j1).sort().join(",");
          const keys2 = Object.keys(j2).sort().join(",");
          if (keys1 !== keys2 && keys1.length > 0 && keys2.length > 0) {
            return { path, type: "json-structure" as const, newStatus: newRes.status, existingStatus: existingRes.status };
          }
        } catch { /* not JSON */ }

        return null;
      }),
    );
    for (const r of signupDeepResults) {
      if (findings.length >= 5) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `email-enum-reg-${findings.length}`, module: "email-enum", severity: "medium",
        title: `Registration endpoint reveals existing accounts on ${v.path}`,
        description: `The registration endpoint at ${v.path} returns different responses for new vs existing emails (${v.type}). New email → status ${v.newStatus}, existing email → status ${v.existingStatus}. Attackers can enumerate registered accounts by attempting to register with target emails.`,
        evidence: `New email → status ${v.newStatus}\nExisting email → status ${v.existingStatus}\nDetection: ${v.type}`,
        remediation: 'Use a two-step registration flow: always accept the email, then send a verification link. If the email is already registered, send an "account already exists" notification to that email instead of showing an error to the requester.',
        cwe: "CWE-204",
        owasp: "A07:2021",
        codeSnippet: `// Two-step registration prevents enumeration
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  const existing = await db.users.findByEmail(email);
  if (existing) {
    await sendAlreadyRegisteredNotification(email);
  } else {
    const user = await db.users.create({ email, password });
    await sendVerificationEmail(user);
  }
  res.status(200).json({ message: "Check your email to continue registration." });
});`,
      });
    }
  }

  // Phase 8: Timing-based enumeration — dedicated timing analysis across auth endpoints
  if (findings.length < 5) {
    const authTimingPaths = validPaths.filter((p) => /login|signin|auth/i.test(p));
    const timingResults = await Promise.allSettled(
      authTimingPaths.slice(0, 3).map(async (path) => {
        const url = target.baseUrl + path;
        const SAMPLES = 5;

        const measure = async (email: string): Promise<number[]> => {
          const times: number[] = [];
          for (let i = 0; i < SAMPLES; i++) {
            const start = Date.now();
            try {
              await scanFetch(url, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password: "TimingProbe123!" }), timeoutMs: 5000,
              });
            } catch { /* skip */ }
            times.push(Date.now() - start);
          }
          return times;
        };

        const [fakeTimes, realTimes] = await Promise.all([
          measure(`timing-probe-fake-${Date.now()}@test.com`),
          measure(testEmails[1]),
        ]);

        const median = (arr: number[]) => {
          const s = [...arr].sort((a, b) => a - b);
          return s[Math.floor(s.length / 2)] || 0;
        };
        const fakeMedian = median(fakeTimes);
        const realMedian = median(realTimes);
        const fakeVariance = Math.max(...fakeTimes) - Math.min(...fakeTimes);
        const diff = Math.abs(realMedian - fakeMedian);

        // Significant timing difference: > 200ms, > 2x variance, > 40% of baseline
        if (diff > 200 && diff > fakeVariance * 2 && diff > fakeMedian * 0.4) {
          return { path, fakeMedian, realMedian, diff, fakeVariance, samples: SAMPLES };
        }
        return null;
      }),
    );
    for (const r of timingResults) {
      if (findings.length >= 5) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `email-enum-timing-deep-${findings.length}`, module: "email-enum", severity: "low",
        title: `Timing-based email enumeration detected on ${v.path}`,
        description: `Auth endpoint at ${v.path} shows statistically significant response time differences between existing and non-existing emails. Non-existing median: ${v.fakeMedian}ms, existing median: ${v.realMedian}ms (${v.diff}ms difference over ${v.samples} samples). This typically occurs when password hashing is only performed for existing accounts.`,
        evidence: `Non-existing email median: ${v.fakeMedian}ms (variance: ${v.fakeVariance}ms)\nExisting email median: ${v.realMedian}ms\nDifference: ${v.diff}ms (${v.samples} samples per email)`,
        remediation: "Normalize auth response times by always performing a password hash comparison, even for non-existent accounts. Use a pre-computed dummy hash for missing users.",
        cwe: "CWE-208",
        owasp: "A07:2021",
        codeSnippet: `// Constant-time auth prevents timing enumeration
const DUMMY_HASH = await bcrypt.hash("dummy", 12); // pre-compute at startup
app.post("/api/auth/login", async (req, res) => {
  const start = Date.now();
  const MIN_MS = 500;
  const user = await db.users.findByEmail(req.body.email);
  // Always compare against a hash — dummy if user not found
  const valid = await bcrypt.compare(req.body.password, user?.passwordHash ?? DUMMY_HASH);
  if (!user || !valid) {
    const elapsed = Date.now() - start;
    await new Promise((r) => setTimeout(r, Math.max(0, MIN_MS - elapsed)));
    return res.status(401).json({ error: "Invalid credentials" });
  }
  res.json({ token: signJwt(user) });
});`,
      });
    }
  }

  // Phase 9: OAuth provider enumeration — detect which social auth providers are configured
  if (findings.length < 5) {
    const oauthDiscoveryPaths = [
      "/api/auth/providers", "/api/auth/signin", "/.auth/login",
      "/api/auth/csrf", "/api/auth/session",
      "/auth/providers", "/oauth/providers", "/api/oauth/providers",
      "/.well-known/openid-configuration",
    ];
    const oauthResults = await Promise.allSettled(
      oauthDiscoveryPaths.map(async (path) => {
        const url = target.baseUrl + path;
        const res = await scanFetch(url, { method: "GET", timeoutMs: 5000 });
        if (res.status !== 200) return null;
        const text = await res.text();
        if (text.includes("<!DOCTYPE") && !text.includes('"providers"')) return null;

        const providerPatterns = [
          { name: "Google", pattern: /google|googleapis\.com|accounts\.google/i },
          { name: "GitHub", pattern: /github|github\.com\/login\/oauth/i },
          { name: "Facebook", pattern: /facebook|fb\.com|graph\.facebook/i },
          { name: "Twitter/X", pattern: /twitter|x\.com\/i\/oauth/i },
          { name: "Apple", pattern: /apple|appleid\.apple\.com/i },
          { name: "Microsoft", pattern: /microsoft|login\.microsoftonline|azure/i },
          { name: "Discord", pattern: /discord|discord\.com\/api\/oauth/i },
          { name: "LinkedIn", pattern: /linkedin|linkedin\.com\/oauth/i },
          { name: "Auth0", pattern: /auth0|\.auth0\.com/i },
          { name: "Okta", pattern: /okta|\.okta\.com/i },
        ];
        const detected = providerPatterns.filter((p) => p.pattern.test(text)).map((p) => p.name);
        if (detected.length === 0) return null;

        // Check if provider config details are exposed (client IDs, callback URLs)
        const leaksClientId = /client_?id["'\s:=]+[a-zA-Z0-9\-_.]{10,}/i.test(text);
        const leaksCallbackUrl = /callback_?url|redirect_?uri/i.test(text);

        return { path, providers: detected, leaksClientId, leaksCallbackUrl };
      }),
    );
    for (const r of oauthResults) {
      if (findings.length >= 5) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      const severity = v.leaksClientId ? "medium" as const : "low" as const;
      findings.push({
        id: `email-enum-oauth-${findings.length}`, module: "email-enum", severity,
        title: `OAuth provider configuration exposed on ${v.path}`,
        description: `The endpoint ${v.path} reveals configured authentication providers: ${v.providers.join(", ")}. ${v.leaksClientId ? "OAuth client IDs are also exposed. " : ""}${v.leaksCallbackUrl ? "Callback URLs are visible. " : ""}This information helps attackers understand the authentication surface and craft targeted phishing or social engineering attacks.`,
        evidence: `Providers detected: ${v.providers.join(", ")}\nClient ID leaked: ${v.leaksClientId}\nCallback URL leaked: ${v.leaksCallbackUrl}\nEndpoint: ${v.path}`,
        remediation: "Restrict the auth providers endpoint to authenticated sessions only. Never expose OAuth client IDs or callback URLs in unauthenticated API responses. Use server-side rendering for login buttons rather than a public API.",
        cwe: "CWE-200",
        owasp: "A01:2021",
        codeSnippet: `// Restrict provider info to authenticated users
app.get("/api/auth/providers", requireAuth, (req, res) => {
  // Only return provider names, not client IDs or config
  res.json({ providers: ["google", "github"] });
});
// For login page, render buttons server-side
// <SignInButton provider="google" /> — no client-side API call needed`,
      });
    }
  }

  // Phase 10: Username vs email confusion — test if login accepts both formats
  if (findings.length < 5) {
    const loginPaths = validPaths.filter((p) => /login|signin|auth/i.test(p));
    const usernameResults = await Promise.allSettled(
      loginPaths.slice(0, 3).map(async (path) => {
        const url = target.baseUrl + path;
        const hostname = new URL(target.url).hostname;

        // Send requests with different identifier formats
        const [emailRes, usernameRes, bothRes] = await Promise.allSettled([
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: `admin@${hostname}`, password: "TestProbe123!" }), timeoutMs: 5000,
          }),
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: "admin", password: "TestProbe123!" }), timeoutMs: 5000,
          }),
          scanFetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ identifier: "admin", password: "TestProbe123!" }), timeoutMs: 5000,
          }),
        ]);

        const getText = async (r: PromiseSettledResult<Response>): Promise<{ status: number; body: string } | null> => {
          if (r.status !== "fulfilled") return null;
          return { status: r.value.status, body: await r.value.text() };
        };

        const [emailData, usernameData, bothData] = await Promise.all([
          getText(emailRes), getText(usernameRes), getText(bothRes),
        ]);

        const detections: string[] = [];

        // Check if username field is accepted (not rejected as unknown field)
        if (usernameData && usernameData.status !== 400) {
          const usernameAccepted = !/unknown.*(field|param)|unexpected.*(field|key)|invalid.*field/i.test(usernameData.body);
          if (usernameAccepted) detections.push("username-field-accepted");
        }

        // Check if "identifier" field works (generic login field)
        if (bothData && bothData.status !== 400) {
          const identifierAccepted = !/unknown.*(field|param)|unexpected.*(field|key)|invalid.*field/i.test(bothData.body);
          if (identifierAccepted) detections.push("identifier-field-accepted");
        }

        // Check if error messages differ between email and username login
        if (emailData && usernameData) {
          const emailErrors = /invalid email|email.*required|must be.*email/i.test(emailData.body);
          const usernameHints = /user.*not found|username.*not found|invalid username/i.test(usernameData.body);
          if (usernameHints && !emailErrors) detections.push("username-existence-leak");
          if (emailData.body !== usernameData.body && emailData.status === usernameData.status) {
            detections.push("response-divergence");
          }
        }

        if (detections.length === 0) return null;
        return {
          path,
          detections,
          emailStatus: emailData?.status ?? 0,
          usernameStatus: usernameData?.status ?? 0,
          identifierStatus: bothData?.status ?? 0,
        };
      }),
    );
    for (const r of usernameResults) {
      if (findings.length >= 5) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      const hasLeak = v.detections.includes("username-existence-leak") || v.detections.includes("response-divergence");
      findings.push({
        id: `email-enum-username-${findings.length}`, module: "email-enum", severity: hasLeak ? "medium" : "low",
        title: `Username/email login confusion on ${v.path}`,
        description: `The login endpoint at ${v.path} accepts multiple identifier formats (${v.detections.join(", ")}). ${hasLeak ? "Error messages differ between username and email login, potentially revealing valid usernames." : "Accepting both usernames and emails increases the attack surface for enumeration."} Email → ${v.emailStatus}, username → ${v.usernameStatus}, identifier → ${v.identifierStatus}.`,
        evidence: `Detections: ${v.detections.join(", ")}\nEmail login → status ${v.emailStatus}\nUsername login → status ${v.usernameStatus}\nIdentifier login → status ${v.identifierStatus}`,
        remediation: "Use a single identifier field and return identical error messages regardless of whether the input is an email or username. Never reveal whether a username exists separately from email existence.",
        cwe: "CWE-204",
        owasp: "A07:2021",
        codeSnippet: `// Unified login — same response for all identifier types
app.post("/api/auth/login", async (req, res) => {
  const { identifier, password } = req.body; // accept email OR username
  const user = identifier.includes("@")
    ? await db.users.findByEmail(identifier)
    : await db.users.findByUsername(identifier);
  const valid = await bcrypt.compare(password, user?.passwordHash ?? DUMMY_HASH);
  if (!user || !valid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  res.json({ token: signJwt(user) });
});`,
      });
    }
  }

  return findings;
};
