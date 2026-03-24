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

  // Only test paths that exist (discovered by recon or return non-404)
  const MAX_FINDINGS = 2;
  for (const path of AUTH_PATHS) {
    if (findings.length >= MAX_FINDINGS) break;
    const url = target.baseUrl + path;
    // Skip paths not discovered by recon (likely don't exist)
    const discovered = target.apiEndpoints.some((ep) => ep.includes(path));
    if (!discovered) {
      // Quick check if the path exists
      try {
        const probe = await scanFetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}", timeoutMs: 3000 });
        if (probe.status === 404 || probe.status === 405) continue;
        const probeText = await probe.text();
        // Skip HTML responses (SPA shell, not a real auth endpoint)
        if (probeText.includes("<!DOCTYPE") || probeText.includes("<html")) continue;
      } catch { continue; }
    }
    try {
      // Test with fake email
      const res1 = await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: testEmails[0], password: "TestPassword123!" }),
      });
      const text1 = await res1.text();

      // Test with potentially real email
      const res2 = await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: testEmails[1], password: "TestPassword123!" }),
      });
      const text2 = await res2.text();

      // If responses differ, email enumeration is possible
      if (res1.status !== res2.status || text1 !== text2) {
        const differsBy = res1.status !== res2.status ? "status code" : "response body";

        // Check for explicit messages
        const enumPhrases = [
          /user not found/i, /email not found/i, /no account/i,
          /doesn't exist/i, /does not exist/i, /not registered/i,
          /invalid email/i, /unknown email/i, /email already/i,
          /already registered/i, /already exists/i, /account exists/i,
        ];

        const hasEnumPhrase = enumPhrases.some((p) => p.test(text1) || p.test(text2));

        if (hasEnumPhrase || differsBy === "status code") {
          findings.push({
            id: `email-enum-${findings.length}`,
            module: "Email Enumeration",
            severity: "medium",
            title: `Email enumeration possible on ${path}`,
            description: `Different responses for existing vs non-existing emails allow attackers to determine which email addresses are registered. Differs by: ${differsBy}.`,
            evidence: `Path: ${path}\nFake email status: ${res1.status}\nReal email status: ${res2.status}\n${hasEnumPhrase ? "Response contains explicit user existence message" : ""}`,
            remediation: 'Return identical responses for valid and invalid emails. Use a generic message like "If an account exists, we\'ll send a reset link."',
            cwe: "CWE-204",
            owasp: "A07:2021",
          });
        }
      }

      // Check timing difference with baseline normalization
      if (findings.length >= MAX_FINDINGS) break;
      // Measure baseline variance (3 requests with fake email, take median)
      const baseTimes: number[] = [];
      for (let i = 0; i < 3; i++) {
        const bs = Date.now();
        try {
          await scanFetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: `nonexistent-timing-test-${i}@test.com`, password: "x" }),
            timeoutMs: 5000,
          });
        } catch { /* skip */ }
        baseTimes.push(Date.now() - bs);
      }
      const baselineMedian = baseTimes.sort((a, b) => a - b)[1] || 500;
      const baselineVariance = Math.max(...baseTimes) - Math.min(...baseTimes);

      // Now measure "real" email timing (3 requests, take median)
      const realTimes: number[] = [];
      for (let i = 0; i < 3; i++) {
        const rs = Date.now();
        try {
          await scanFetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: testEmails[1], password: "x" }),
            timeoutMs: 5000,
          });
        } catch { /* skip */ }
        realTimes.push(Date.now() - rs);
      }
      const realMedian = realTimes.sort((a, b) => a - b)[1] || 500;
      const diff = Math.abs(realMedian - baselineMedian);

      // Only flag if: diff > 300ms AND diff > 2x baseline variance AND diff > 50% of baseline
      if (diff > 300 && diff > baselineVariance * 2 && diff > baselineMedian * 0.5) {
        findings.push({
          id: `email-enum-timing-${findings.length}`,
          module: "Email Enumeration",
          severity: "low",
          title: `Timing-based email enumeration on ${path}`,
          description: `Response times differ significantly for existing vs non-existing emails (baseline: ${baselineMedian}ms, real: ${realMedian}ms). Attackers can determine valid emails by measuring response times.`,
          evidence: `Baseline median: ${baselineMedian}ms (variance: ${baselineVariance}ms)\nReal email median: ${realMedian}ms\nDifference: ${diff}ms`,
          remediation: "Normalize response times for auth endpoints. Add a consistent delay regardless of whether the user exists.",
          cwe: "CWE-208",
        });
      }
    } catch {
      // endpoint doesn't exist, skip
    }
  }

  return findings;
};
