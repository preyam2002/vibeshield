import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const hostHeaderModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const hostname = new URL(target.url).hostname;

  // Test 1: Host header override — does the app trust a spoofed Host header?
  const hostPayloads = [
    { host: "evil.com", desc: "arbitrary host" },
    { host: `${hostname}.evil.com`, desc: "subdomain of evil" },
    { host: `evil.com/${hostname}`, desc: "path injection" },
  ];

  for (const { host, desc } of hostPayloads) {
    try {
      const res = await scanFetch(target.url, {
        headers: { Host: host },
        redirect: "manual",
        timeoutMs: 5000,
      });

      const location = res.headers.get("location") || "";
      const text = await res.text();

      // Check if the spoofed host appears in redirect or response
      if (location.includes("evil.com")) {
        findings.push({
          id: `host-header-redirect-${findings.length}`,
          module: "Host Header Injection",
          severity: "high",
          title: "Host header injection causes redirect to attacker domain",
          description: "The application uses the Host header to generate redirect URLs. Attackers can poison password reset links, OAuth callbacks, or cache entries.",
          evidence: `Host: ${host} (${desc})\nLocation: ${location}`,
          remediation: "Never use the Host header to build URLs. Use a configured/hardcoded base URL for your application. In Next.js, use NEXTAUTH_URL or a NEXT_PUBLIC_BASE_URL env var.",
          cwe: "CWE-644",
          owasp: "A05:2021",
        });
        break;
      }

      // Check if evil.com appears in response body (link generation)
      if (text.includes("evil.com") && !text.includes(hostname)) {
        findings.push({
          id: `host-header-body-${findings.length}`,
          module: "Host Header Injection",
          severity: "medium",
          title: "Host header reflected in response body",
          description: "The application uses the Host header to generate URLs in the response body. This can be exploited for phishing via password reset or email verification links.",
          evidence: `Host: ${host} (${desc})\nAttacker domain appears in response body`,
          remediation: "Use a configured base URL instead of trusting the Host header. Set NEXTAUTH_URL or equivalent in your environment.",
          cwe: "CWE-644",
          owasp: "A05:2021",
        });
        break;
      }
    } catch {
      // skip
    }
  }

  // Test 2: X-Forwarded-Host override (common in reverse proxy setups)
  try {
    const res = await scanFetch(target.url, {
      headers: { "X-Forwarded-Host": "evil.com" },
      redirect: "manual",
      timeoutMs: 5000,
    });

    const location = res.headers.get("location") || "";
    if (location.includes("evil.com")) {
      findings.push({
        id: `host-header-xfh-${findings.length}`,
        module: "Host Header Injection",
        severity: "high",
        title: "X-Forwarded-Host injection causes redirect to attacker domain",
        description: "The application trusts the X-Forwarded-Host header for URL generation. Attackers behind a shared proxy can poison URLs.",
        evidence: `X-Forwarded-Host: evil.com\nLocation: ${location}`,
        remediation: "Only trust X-Forwarded-Host from known reverse proxies. Configure a trusted proxy list or use a hardcoded base URL.",
        cwe: "CWE-644",
        owasp: "A05:2021",
      });
    }
  } catch {
    // skip
  }

  // Test 3: Password reset poisoning — if there's a forgot-password endpoint
  const resetPaths = ["/forgot-password", "/auth/forgot-password", "/api/auth/forgot-password", "/reset-password"];
  for (const path of resetPaths) {
    try {
      const res = await scanFetch(`${target.baseUrl}${path}`, { timeoutMs: 3000 });
      if (res.ok || res.status === 405) {
        // Endpoint exists, test with spoofed host
        const testRes = await scanFetch(`${target.baseUrl}${path}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Host: "evil.com",
          },
          body: JSON.stringify({ email: "test@example.com" }),
          redirect: "manual",
          timeoutMs: 5000,
        });

        const loc = testRes.headers.get("location") || "";
        if (loc.includes("evil.com")) {
          findings.push({
            id: `host-header-reset-${findings.length}`,
            module: "Host Header Injection",
            severity: "critical",
            title: `Password reset poisoning via Host header on ${path}`,
            description: "The password reset endpoint uses the Host header to generate reset links. Attackers can send reset emails with links pointing to their domain, capturing reset tokens.",
            evidence: `POST ${path} with Host: evil.com\nLocation: ${loc}`,
            remediation: "Hardcode the application URL for password reset links. Never derive it from the Host header.",
            cwe: "CWE-644",
            owasp: "A05:2021",
          });
          break;
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};
