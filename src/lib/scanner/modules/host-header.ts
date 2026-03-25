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

  const [hostResults, proxyHeaderResults, resetResults] = await Promise.all([
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
    // Test 2: Proxy headers (X-Forwarded-Host, X-Forwarded-Proto, X-Original-Host)
    Promise.allSettled(
      [
        { header: "X-Forwarded-Host", value: "evil.com" },
        { header: "X-Original-Host", value: "evil.com" },
        { header: "X-Forwarded-Proto", value: "http" },
        { header: "X-Host", value: "evil.com" },
        { header: "X-Real-IP", value: "127.0.0.1" },
        { header: "X-Client-IP", value: "127.0.0.1" },
        { header: "X-Forwarded-For", value: "127.0.0.1" },
        { header: "True-Client-IP", value: "127.0.0.1" },
        { header: "X-Originating-IP", value: "127.0.0.1" },
        { header: "CF-Connecting-IP", value: "127.0.0.1" },
      ].map(async ({ header, value }) => {
        const res = await scanFetch(target.url, { headers: { [header]: value }, redirect: "manual", timeoutMs: 5000 });
        const location = res.headers.get("location") || "";
        if (header === "X-Forwarded-Proto" && location.startsWith("http://")) {
          return { header, value, location, type: "proto-downgrade" as const };
        }
        if (location.includes("evil.com")) return { header, value, location, type: "redirect" as const };
        // IP spoofing: check if setting IP to 127.0.0.1 grants access to normally restricted content
        if (value === "127.0.0.1" && res.ok) {
          const normalRes = await scanFetch(target.url, { timeoutMs: 5000 });
          // If response differs significantly (e.g., admin panel or different content)
          const normalText = await normalRes.text();
          const spoofText = await res.text();
          if (spoofText.length > normalText.length * 1.5 && spoofText.length > 500) {
            return { header, value, location: "", type: "ip-spoof" as const };
          }
          if (/admin|dashboard|internal|debug/i.test(spoofText) && !/admin|dashboard|internal|debug/i.test(normalText)) {
            return { header, value, location: "", type: "ip-spoof" as const };
          }
        }
        return null;
      }),
    ),
    // Test 3: Password reset poisoning — probe and test in parallel
    Promise.allSettled(
      ["/forgot-password", "/auth/forgot-password", "/api/auth/forgot-password", "/reset-password", "/api/auth/reset"].map(async (path) => {
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
        codeSnippet: `// Use environment variable instead of Host header\nconst BASE_URL = process.env.NEXT_PUBLIC_APP_URL || "https://yourdomain.com";\n\n// Bad: const url = \`https://\${req.headers.host}/path\`\n// Good:\nconst url = \`\${BASE_URL}/path\`;`,
      });
    } else {
      findings.push({
        id: `host-header-body-0`, module: "Host Header Injection", severity: "medium",
        title: "Host header reflected in response body",
        description: "The application uses the Host header to generate URLs in the response body.",
        evidence: `Host: ${v.host} (${v.desc})\nAttacker domain appears in response body`,
        remediation: "Use a configured base URL instead of trusting the Host header.",
        cwe: "CWE-644", owasp: "A05:2021",
        codeSnippet: `// Use environment variable instead of Host header\nconst BASE_URL = process.env.NEXT_PUBLIC_APP_URL || "https://yourdomain.com";\n\n// Bad: const url = \`https://\${req.headers.host}/path\`\n// Good:\nconst url = \`\${BASE_URL}/path\`;`,
      });
    }
    break;
  }

  for (const r of proxyHeaderResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.type === "proto-downgrade") {
      findings.push({
        id: `host-header-proto-0`, module: "Host Header Injection", severity: "medium",
        title: "X-Forwarded-Proto downgrade to HTTP",
        description: "The application trusts X-Forwarded-Proto and can be tricked into generating HTTP URLs.",
        evidence: `X-Forwarded-Proto: http\nLocation: ${v.location}`,
        remediation: "Only trust X-Forwarded-Proto from known reverse proxies. Enforce HTTPS at the application level.",
        cwe: "CWE-644", owasp: "A05:2021",
        codeSnippet: `// next.config.ts — force HTTPS redirects\nconst securityHeaders = [\n  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }\n];\nexport default { async headers() { return [{ source: "/(.*)", headers: securityHeaders }]; } };`,
      });
    } else if (v.type === "ip-spoof") {
      findings.push({
        id: `host-header-ip-spoof-0`, module: "Host Header Injection", severity: "high",
        title: `IP-based access control bypass via ${v.header}`,
        description: `Setting ${v.header}: 127.0.0.1 returns different (possibly privileged) content. The application trusts client-supplied IP headers for access control, allowing attackers to impersonate internal/trusted IPs.`,
        evidence: `${v.header}: 127.0.0.1\nResponse contains additional content or admin indicators not present in normal response`,
        remediation: "Never trust client-supplied IP headers for access control. Configure your reverse proxy to overwrite these headers. Use authentication instead of IP-based restrictions.",
        cwe: "CWE-290", owasp: "A01:2021",
        codeSnippet: `// Only trust IP from your reverse proxy, not client headers\n// In your reverse proxy (nginx):\n// proxy_set_header X-Real-IP $remote_addr;\n// proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\n// In your app — don't use these for auth:\n// BAD: if (req.headers['x-real-ip'] === '127.0.0.1') { grantAdmin(); }\n// GOOD: Use proper authentication (sessions, JWTs, etc.)`,
      });
    } else {
      findings.push({
        id: `host-header-proxy-0`, module: "Host Header Injection", severity: "high",
        title: `${v.header} injection causes redirect to attacker domain`,
        description: `The application trusts the ${v.header} header for URL generation.`,
        evidence: `${v.header}: evil.com\nLocation: ${v.location}`,
        remediation: "Only trust proxy headers from known reverse proxies. Use a hardcoded base URL.",
        cwe: "CWE-644", owasp: "A05:2021",
        codeSnippet: `// middleware.ts — validate Host header\nimport { NextResponse } from "next/server";\nconst ALLOWED_HOSTS = new Set([process.env.HOSTNAME, "localhost:3000"]);\nexport function middleware(req) {\n  const host = req.headers.get("host") || "";\n  if (!ALLOWED_HOSTS.has(host)) return new NextResponse("Invalid host", { status: 400 });\n  return NextResponse.next();\n}`,
      });
    }
    break;
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
      codeSnippet: `// Hardcode reset link base URL — never use Host header\nconst APP_URL = process.env.APP_URL; // e.g. "https://yourdomain.com"\nconst resetLink = \`\${APP_URL}/reset-password?token=\${token}\`;\nawait sendEmail({ to: email, subject: "Reset password", html: \`<a href="\${resetLink}">Reset</a>\` });`,
    });
    break;
  }

  return findings;
};
