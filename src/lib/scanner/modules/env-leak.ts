import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

const ENV_ENDPOINTS = [
  "/__ENV",
  "/env",
  "/api/env",
  "/api/config",
  "/env.json",
  "/.env",
  "/config",
  "/api/settings",
];

/** NEXT_PUBLIC_ vars that should never be public — they indicate a misconfigured build or copy-paste mistake */
const DANGEROUS_PUBLIC_VARS = [
  /NEXT_PUBLIC_[A-Z_]{0,30}(?:DATABASE|DB)_URL/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}PRIVATE.?KEY/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}SECRET/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}WEBHOOK/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}SERVICE.?ROLE/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}PASSWORD/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}ADMIN/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}SMTP/i,
  /NEXT_PUBLIC_[A-Z_]{0,30}REDIS/i,
];

/** Patterns to find in JS bundles that indicate env leaks */
const JS_ENV_PATTERNS: {
  name: string;
  pattern: RegExp;
  severity: Finding["severity"];
  description: string;
  remediation: string;
}[] = [
  {
    name: "Database URL in bundle",
    pattern: /(?:DATABASE_URL|DB_URL|MONGO_URI|POSTGRES_URL|MYSQL_URL)["':\s]*=?\s*["']([^"']+)/gi,
    severity: "critical",
    description: "A database connection URL was found in client-side JavaScript. This likely means a server-only environment variable leaked into the client bundle.",
    remediation: "Ensure database URLs are only used in server-side code. In Next.js, do NOT prefix database env vars with NEXT_PUBLIC_.",
  },
  {
    name: "Private key reference in bundle",
    pattern: /(?:PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY)["':\s]*=?\s*["']([^"']{8,})/gi,
    severity: "critical",
    description: "A private or signing key was found in client-side JavaScript.",
    remediation: "Remove private keys from client bundles. These must only be accessed server-side.",
  },
  {
    name: "Localhost/dev backend URL",
    pattern: /https?:\/\/(?:localhost|127\.0\.0\.1):\d{4,5}\/api\/[^\s"']+/g,
    severity: "medium",
    description: "A localhost API URL was found in the production JavaScript bundle. This indicates development backend URLs were left in the code, which can expose internal architecture and cause functionality issues.",
    remediation: "Use environment variables for API base URLs. Ensure build configuration replaces development URLs with production ones.",
  },
  {
    name: "DEBUG=true in production",
    pattern: /["']?DEBUG["']?\s*[:=]\s*["']?true["']?/gi,
    severity: "medium",
    description: "DEBUG mode is enabled in production JavaScript. Debug mode often enables verbose logging, disables security features, and exposes internal state.",
    remediation: "Set DEBUG=false in production. Use build-time environment variables to strip debug code.",
  },
  {
    name: "NODE_ENV=development in production",
    pattern: /NODE_ENV["':\s]*=?\s*["']development["']/gi,
    severity: "medium",
    description: "NODE_ENV is set to 'development' in the production bundle. This may disable optimizations and enable debug features.",
    remediation: "Ensure NODE_ENV=production in your build and deployment pipeline.",
  },
  {
    name: "Webhook secret in bundle",
    pattern: /(?:WEBHOOK_SECRET|WEBHOOK_KEY|SIGNING_SECRET)["':\s]*=?\s*["']([^"']{8,})/gi,
    severity: "high",
    description: "A webhook secret was found in client-side JavaScript. Attackers can use this to forge webhook payloads.",
    remediation: "Webhook secrets must never be in client code. Only verify webhooks on the server side.",
  },
  {
    name: "SMTP/email credentials in bundle",
    pattern: /(?:SMTP_PASS|EMAIL_PASSWORD|MAIL_PASSWORD|SENDGRID_KEY)["':\s]*=?\s*["']([^"']{4,})/gi,
    severity: "high",
    description: "Email/SMTP credentials were found in client-side JavaScript.",
    remediation: "Move email sending to server-side. Never expose SMTP credentials in the browser.",
  },
  {
    name: "Non-production environment detected",
    pattern: /["']?(?:ENVIRONMENT|APP_ENV|DEPLOY_ENV|STAGE)["']?\s*[:=]\s*["'](staging|test|dev|development|local|sandbox)["']/gi,
    severity: "medium",
    description: "The JavaScript bundle indicates this may be a staging/test environment exposed to the public internet.",
    remediation: "Restrict non-production environments to internal networks. Use IP allowlists or VPN access.",
  },
  {
    name: "Internal API URL in bundle",
    pattern: /https?:\/\/(?:internal|staging|dev|test|sandbox)[.-][^\s"']{5,}/gi,
    severity: "medium",
    description: "An internal or staging API URL was found in the production bundle, revealing infrastructure details.",
    remediation: "Use environment variables for API URLs. Ensure production builds only reference production endpoints.",
  },
];

const ENV_LEAK_HEADERS = [
  "x-debug",
  "x-debug-token",
  "x-environment",
  "x-env",
  "x-node-env",
  "x-powered-by-detail",
  "x-debug-info",
];

export const envLeakModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // 1. Check known env/config endpoints in parallel
  const envResults = await Promise.allSettled(
    ENV_ENDPOINTS.map(async (path) => {
      const url = target.baseUrl + path;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (res.status !== 200) return null;

      const text = await res.text();
      if (isSoft404(text, target)) return null;
      if (looksLikeHtml(text)) return null;

      const looksLikeEnv =
        /(?:DATABASE|SECRET|KEY|TOKEN|PASSWORD|API_KEY|REDIS|MONGO|POSTGRES|SMTP)/i.test(text) ||
        /(?:process\.env|NODE_ENV|PORT\s*[:=])/i.test(text);

      return looksLikeEnv ? { path, url, text } : null;
    }),
  );

  for (const r of envResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, url, text } = r.value;
    findings.push({
      id: `env-leak-endpoint-${findings.length}`,
      module: "Environment Leak",
      severity: "critical",
      title: `Environment variables exposed at ${path}`,
      description: "An endpoint is serving environment configuration data that may include secrets, database credentials, and API keys.",
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 400)}`,
      remediation: "Remove this endpoint from production. Environment variables should never be served over HTTP.",
      cwe: "CWE-215",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts — restrict env to server-side only
export default {
  serverRuntimeConfig: {
    DATABASE_URL: process.env.DATABASE_URL,
    API_SECRET: process.env.API_SECRET,
  },
};`,
    });
  }

  // 2. Scan JS bundles for env leaks
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Check for dangerous NEXT_PUBLIC_ vars
  for (const pattern of DANGEROUS_PUBLIC_VARS) {
    const matches = allJs.match(pattern);
    if (matches) {
      const unique = [...new Set(matches)];
      for (const match of unique.slice(0, 2)) {
        findings.push({
          id: `env-leak-nextpublic-${findings.length}`,
          module: "Environment Leak",
          severity: "high",
          title: `Dangerous NEXT_PUBLIC_ variable: ${match}`,
          description: "A NEXT_PUBLIC_ environment variable exposes a value that should be server-only. Variables prefixed with NEXT_PUBLIC_ are embedded into the client bundle and visible to all users.",
          evidence: `Found in JS bundle: ${match}`,
          remediation: "Remove the NEXT_PUBLIC_ prefix from this variable. Access it only in server-side code (API routes, getServerSideProps, Server Components).",
          cwe: "CWE-215",
          owasp: "A05:2021",
          codeSnippet: `# .env.local — never prefix secrets with NEXT_PUBLIC_
DATABASE_URL="postgres://..."   # server-only (correct)
# NEXT_PUBLIC_DATABASE_URL=...  # exposed to browser (wrong)

# Access in server code only:
# app/api/route.ts or getServerSideProps
const url = process.env.DATABASE_URL;`,
        });
      }
    }
  }

  // Check for other env patterns in bundles — one finding per pattern type
  for (const check of JS_ENV_PATTERNS) {
    const matches = allJs.match(check.pattern);
    if (matches) {
      const unique = [...new Set(matches)];
      const sample = unique[0];
      const redacted = sample.length > 60
        ? sample.substring(0, 30) + "..." + sample.substring(sample.length - 10)
        : sample;
      findings.push({
        id: `env-leak-js-${check.name.toLowerCase().replace(/[\s/]+/g, "-")}-${findings.length}`,
        module: "Environment Leak",
        severity: check.severity,
        title: `${check.name}${unique.length > 1 ? ` (${unique.length} instances)` : ""}`,
        description: check.description,
        evidence: `Found in JS bundle: ${redacted}${unique.length > 1 ? `\n...and ${unique.length - 1} more` : ""}`,
        remediation: check.remediation,
        cwe: "CWE-215",
        owasp: "A05:2021",
        codeSnippet: `// Use server-only package to prevent client imports
// npm install server-only
import "server-only";

// This file can now safely use secrets
const secret = process.env.API_SECRET;
export async function fetchData() {
  return fetch(url, { headers: { Authorization: secret } });
}`,
      });
    }
  }

  // 3. Check response headers for env leaks
  for (const header of ENV_LEAK_HEADERS) {
    const value = target.headers[header];
    if (value) {
      findings.push({
        id: `env-leak-header-${header}-${findings.length}`,
        module: "Environment Leak",
        severity: "low",
        title: `Sensitive header exposed: ${header}`,
        description: `The response includes a "${header}" header that may reveal environment or debug information to attackers.`,
        evidence: `Header: ${header}: ${value}`,
        remediation: "Remove debug and environment headers in production. Configure your web server or framework to strip these headers.",
        cwe: "CWE-200",
        owasp: "A05:2021",
        codeSnippet: `// next.config.ts — strip debug headers in production
export default {
  async headers() {
    return [{
      source: "/:path*",
      headers: [
        { key: "X-Debug", value: "" },
        { key: "X-Environment", value: "" },
      ],
    }];
  },
};`,
      });
    }
  }

  return findings;
};
