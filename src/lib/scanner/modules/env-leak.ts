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
    pattern: /https?:\/\/(?:localhost|127\.0\.0\.1):\d{4,5}(?:\/[^\s"']*)?/g,
    severity: "medium",
    description: "A localhost URL with port was found in the production JavaScript bundle. This indicates development backend URLs were left in the code, which can expose internal architecture and cause functionality issues.",
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

  // 1. Check known env/config endpoints
  for (const path of ENV_ENDPOINTS) {
    try {
      const url = target.baseUrl + path;
      const res = await scanFetch(url);
      if (res.status !== 200) continue;

      const text = await res.text();
      if (isSoft404(text, target)) continue;
      // Real env endpoints return plain text or JSON, not HTML
      if (looksLikeHtml(text)) continue;

      // Check if response looks like env vars or config
      const looksLikeEnv =
        /(?:DATABASE|SECRET|KEY|TOKEN|PASSWORD|API_KEY|REDIS|MONGO|POSTGRES|SMTP)/i.test(text) ||
        /(?:process\.env|NODE_ENV|PORT\s*[:=])/i.test(text);

      if (!looksLikeEnv) continue;

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
      });
    } catch {
      // skip
    }
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
        });
      }
    }
  }

  // Check for other env patterns in bundles
  for (const check of JS_ENV_PATTERNS) {
    const matches = allJs.match(check.pattern);
    if (matches) {
      const unique = [...new Set(matches)];
      for (const match of unique.slice(0, 2)) {
        const redacted = match.length > 60
          ? match.substring(0, 30) + "..." + match.substring(match.length - 10)
          : match;
        findings.push({
          id: `env-leak-js-${check.name.toLowerCase().replace(/[\s/]+/g, "-")}-${findings.length}`,
          module: "Environment Leak",
          severity: check.severity,
          title: `${check.name}`,
          description: check.description,
          evidence: `Found in JS bundle: ${redacted}`,
          remediation: check.remediation,
          cwe: "CWE-215",
          owasp: "A05:2021",
        });
      }
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
      });
    }
  }

  return findings;
};
