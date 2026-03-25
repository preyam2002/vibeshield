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
      ].map(async ({ header, value }) => {
        const res = await scanFetch(target.url, { headers: { [header]: value }, redirect: "manual", timeoutMs: 5000 });
        const location = res.headers.get("location") || "";
        if (header === "X-Forwarded-Proto" && location.startsWith("http://")) {
          return { header, value, location, type: "proto-downgrade" as const };
        }
        if (location.includes("evil.com")) return { header, value, location, type: "redirect" as const };
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
