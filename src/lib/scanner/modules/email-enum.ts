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

  for (const r of enumResults) {
    if (findings.length >= 2) break;
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

  return findings;
};
