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

  for (const path of AUTH_PATHS) {
    const url = target.baseUrl + path;
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

      // Check timing difference (significant = >200ms)
      const start1 = Date.now();
      await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: testEmails[0], password: "x" }),
      });
      const time1 = Date.now() - start1;

      const start2 = Date.now();
      await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: testEmails[1], password: "x" }),
      });
      const time2 = Date.now() - start2;

      if (Math.abs(time1 - time2) > 200) {
        findings.push({
          id: `email-enum-timing-${findings.length}`,
          module: "Email Enumeration",
          severity: "low",
          title: `Timing-based email enumeration on ${path}`,
          description: `Response times differ significantly for existing vs non-existing emails (${time1}ms vs ${time2}ms). Attackers can determine valid emails by measuring response times.`,
          evidence: `Non-existing email: ${time1}ms\nPotentially existing email: ${time2}ms\nDifference: ${Math.abs(time1 - time2)}ms`,
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
