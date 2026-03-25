import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const hostHeaderModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const hostname = new URL(target.url).hostname;

  // Run all tests in parallel: host payloads, X-Forwarded-Host, password reset
  const hostPayloads = [
    { host: "evil.com", desc: "arbitrary host" },
    { host: `${hostname}.evil.com`, desc: "subdomain of evil" },
    { host: `evil.com/${hostname}`, desc: "path injection" },
  ];

  const [hostResults, xfhResult, resetResults] = await Promise.all([
    // Test 1: Host header overrides in parallel
    Promise.allSettled(
      hostPayloads.map(async ({ host, desc }) => {
        const res = await scanFetch(target.url, { headers: { Host: host }, redirect: "manual", timeoutMs: 5000 });
        const location = res.headers.get("location") || "";
        const text = await res.text();
        if (location.includes("evil.com")) return { type: "redirect" as const, host, desc, location };
        if (text.includes("evil.com") && !text.includes(hostname)) return { type: "body" as const, host, desc };
        return null;
      }),
    ),
    // Test 2: X-Forwarded-Host
    scanFetch(target.url, { headers: { "X-Forwarded-Host": "evil.com" }, redirect: "manual", timeoutMs: 5000 })
      .then((res) => ({ location: res.headers.get("location") || "" }))
      .catch(() => ({ location: "" })),
    // Test 3: Password reset poisoning — probe and test in parallel
    Promise.allSettled(
      ["/forgot-password", "/auth/forgot-password", "/api/auth/forgot-password", "/reset-password"].map(async (path) => {
        const res = await scanFetch(`${target.baseUrl}${path}`, { timeoutMs: 3000 });
        if (!res.ok && res.status !== 405) return null;
        const testRes = await scanFetch(`${target.baseUrl}${path}`, {
          method: "POST", headers: { "Content-Type": "application/json", Host: "evil.com" },
          body: JSON.stringify({ email: "test@example.com" }), redirect: "manual", timeoutMs: 5000,
        });
        const loc = testRes.headers.get("location") || "";
        if (loc.includes("evil.com")) return { path, loc };
        return null;
      }),
    ),
  ]);

  // Collect host header findings (first match only)
  for (const r of hostResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.type === "redirect") {
      findings.push({
        id: `host-header-redirect-0`, module: "Host Header Injection", severity: "high",
        title: "Host header injection causes redirect to attacker domain",
        description: "The application uses the Host header to generate redirect URLs.",
        evidence: `Host: ${v.host} (${v.desc})\nLocation: ${v.location}`,
        remediation: "Never use the Host header to build URLs. Use a configured/hardcoded base URL.",
        cwe: "CWE-644", owasp: "A05:2021",
      });
    } else {
      findings.push({
        id: `host-header-body-0`, module: "Host Header Injection", severity: "medium",
        title: "Host header reflected in response body",
        description: "The application uses the Host header to generate URLs in the response body.",
        evidence: `Host: ${v.host} (${v.desc})\nAttacker domain appears in response body`,
        remediation: "Use a configured base URL instead of trusting the Host header.",
        cwe: "CWE-644", owasp: "A05:2021",
      });
    }
    break;
  }

  if (xfhResult.location.includes("evil.com")) {
    findings.push({
      id: `host-header-xfh-0`, module: "Host Header Injection", severity: "high",
      title: "X-Forwarded-Host injection causes redirect to attacker domain",
      description: "The application trusts the X-Forwarded-Host header for URL generation.",
      evidence: `X-Forwarded-Host: evil.com\nLocation: ${xfhResult.location}`,
      remediation: "Only trust X-Forwarded-Host from known reverse proxies. Use a hardcoded base URL.",
      cwe: "CWE-644", owasp: "A05:2021",
    });
  }

  for (const r of resetResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `host-header-reset-0`, module: "Host Header Injection", severity: "critical",
      title: `Password reset poisoning via Host header on ${r.value.path}`,
      description: "The password reset endpoint uses the Host header to generate reset links.",
      evidence: `POST ${r.value.path} with Host: evil.com\nLocation: ${r.value.loc}`,
      remediation: "Hardcode the application URL for password reset links.",
      cwe: "CWE-644", owasp: "A05:2021",
    });
    break;
  }

  return findings;
};
