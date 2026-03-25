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

/** Public env var prefixes that should never contain secrets — they get bundled into client JS */
const PUBLIC_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "NUXT_PUBLIC_", "PUBLIC_"];
const DANGEROUS_SUFFIXES = ["DATABASE_URL", "DB_URL", "PRIVATE_KEY", "PRIVATE.KEY", "SECRET", "WEBHOOK", "SERVICE_ROLE", "SERVICE.ROLE", "PASSWORD", "ADMIN_KEY", "SMTP", "REDIS", "SIGNING_KEY", "ENCRYPTION_KEY"];

const DANGEROUS_PUBLIC_VARS = PUBLIC_PREFIXES.flatMap((prefix) =>
  DANGEROUS_SUFFIXES.map((suffix) =>
    new RegExp(`${prefix.replace(/_$/, "_")}[A-Z_]{0,30}${suffix.replace(/\./g, ".?")}`, "i"),
  ),
);

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

const FRAMEWORK_DEBUG_ENDPOINTS: {
  path: string;
  name: string;
  description: string;
  remediation: string;
}[] = [
  {
    path: "/_next/data/",
    name: "Next.js data endpoint",
    description: "The Next.js internal data endpoint is accessible, potentially exposing server-side props and page data to attackers.",
    remediation: "Restrict access to /_next/data/ in production or ensure no sensitive data is returned in getServerSideProps/getStaticProps.",
  },
  {
    path: "/rails/info/routes",
    name: "Rails route info page",
    description: "The Rails route debugging page is exposed, revealing all application routes, controllers, and URL patterns.",
    remediation: "Ensure config.consider_all_requests_local is false in production. Remove or restrict access to Rails info routes.",
  },
  {
    path: "/__debug__/",
    name: "Django Debug Toolbar",
    description: "The Django Debug Toolbar is accessible in production, exposing SQL queries, request data, settings, and internal state.",
    remediation: "Set DEBUG=False in Django production settings. Remove django-debug-toolbar from INSTALLED_APPS in production.",
  },
  {
    path: "/_debugbar",
    name: "Laravel Debugbar",
    description: "The Laravel Debugbar is exposed, leaking database queries, route information, session data, and application internals.",
    remediation: "Set APP_DEBUG=false in .env for production. Remove or disable barryvdh/laravel-debugbar in production.",
  },
  {
    path: "/phpinfo.php",
    name: "PHP info page",
    description: "A phpinfo() page is publicly accessible, revealing PHP version, loaded modules, environment variables, and server configuration.",
    remediation: "Delete phpinfo.php from the web root. Never deploy phpinfo() to production servers.",
  },
  {
    path: "/elmah.axd",
    name: "ASP.NET ELMAH error log",
    description: "The ELMAH error logging handler is publicly accessible, exposing application errors, stack traces, and server details.",
    remediation: "Restrict elmah.axd access with authorization rules in web.config. Only allow authenticated admin users.",
  },
];

const PACKAGE_MANAGER_FILES: {
  path: string;
  name: string;
  contentCheck: RegExp;
}[] = [
  { path: "/package.json", name: "npm package.json", contentCheck: /"dependencies"|"devDependencies"|"name"\s*:/ },
  { path: "/composer.json", name: "Composer config", contentCheck: /"require"|"autoload"/ },
  { path: "/Gemfile", name: "Ruby Gemfile", contentCheck: /gem\s+['"]|source\s+['"]/ },
  { path: "/requirements.txt", name: "Python requirements.txt", contentCheck: /==|>=|~=/ },
  { path: "/go.mod", name: "Go module file", contentCheck: /^module\s|require\s/m },
  { path: "/Cargo.toml", name: "Rust Cargo.toml", contentCheck: /\[dependencies\]|\[package\]/ },
];

const CLOUD_CONFIG_FILES: {
  path: string;
  name: string;
  contentCheck: RegExp;
}[] = [
  { path: "/.aws/credentials", name: "AWS credentials", contentCheck: /aws_access_key_id|aws_secret_access_key/i },
  { path: "/firebase.json", name: "Firebase config", contentCheck: /"hosting"|"firestore"|"functions"/ },
  { path: "/vercel.json", name: "Vercel config", contentCheck: /"builds"|"routes"|"rewrites"|"redirects"/ },
  { path: "/netlify.toml", name: "Netlify config", contentCheck: /\[build\]|\[redirects\]/ },
  { path: "/fly.toml", name: "Fly.io config", contentCheck: /\[env\]|app\s*=/ },
  { path: "/railway.json", name: "Railway config", contentCheck: /"build"|"deploy"|"start"/ },
];

const LOG_FILES = [
  "/error.log",
  "/debug.log",
  "/access.log",
  "/npm-debug.log",
  "/yarn-error.log",
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

  // 4. Check framework debug pages
  const debugResults = await Promise.allSettled(
    FRAMEWORK_DEBUG_ENDPOINTS.map(async (ep) => {
      const url = target.baseUrl + ep.path;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (res.status !== 200) return null;

      const text = await res.text();
      if (isSoft404(text, target)) return null;

      return { ep, url, text };
    }),
  );

  for (const r of debugResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { ep, url, text } = r.value;
    findings.push({
      id: `env-leak-debug-${ep.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "Environment Leak",
      severity: "high",
      title: `${ep.name} exposed at ${ep.path}`,
      description: ep.description,
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 400)}`,
      remediation: ep.remediation,
      cwe: "CWE-215",
      owasp: "A05:2021",
    });
  }

  // 5. Check package manager files
  const pkgResults = await Promise.allSettled(
    PACKAGE_MANAGER_FILES.map(async (file) => {
      const url = target.baseUrl + file.path;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (res.status !== 200) return null;

      const text = await res.text();
      if (isSoft404(text, target)) return null;
      if (looksLikeHtml(text)) return null;
      if (!file.contentCheck.test(text)) return null;

      return { file, url, text };
    }),
  );

  for (const r of pkgResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { file, url, text } = r.value;
    findings.push({
      id: `env-leak-pkg-${file.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "Environment Leak",
      severity: "medium",
      title: `Package manager file exposed: ${file.path}`,
      description: `The ${file.name} file is publicly accessible. This reveals dependency names and exact versions, allowing attackers to identify known CVEs in your stack.`,
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 400)}`,
      remediation: "Block access to package manager files via web server configuration. Add rules to deny requests for dependency manifests.",
      cwe: "CWE-200",
      owasp: "A05:2021",
    });
  }

  // 6. Check cloud config exposure
  const cloudResults = await Promise.allSettled(
    CLOUD_CONFIG_FILES.map(async (file) => {
      const url = target.baseUrl + file.path;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (res.status !== 200) return null;

      const text = await res.text();
      if (isSoft404(text, target)) return null;
      if (looksLikeHtml(text)) return null;
      if (!file.contentCheck.test(text)) return null;

      return { file, url, text };
    }),
  );

  for (const r of cloudResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { file, url, text } = r.value;
    const isCredential = file.path.includes("credentials");
    findings.push({
      id: `env-leak-cloud-${file.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "Environment Leak",
      severity: isCredential ? "critical" : "high",
      title: `Cloud config exposed: ${file.path}`,
      description: `The ${file.name} file is publicly accessible. ${isCredential ? "This file contains cloud provider credentials that grant direct access to your infrastructure." : "This reveals deployment configuration, environment settings, and potentially internal service details."}`,
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 400)}`,
      remediation: `Remove ${file.path} from the web root. Add it to .gitignore and block access via web server rules. ${isCredential ? "Rotate all exposed credentials immediately." : ""}`,
      cwe: isCredential ? "CWE-798" : "CWE-200",
      owasp: "A05:2021",
    });
  }

  // 7. Check log file exposure
  const logResults = await Promise.allSettled(
    LOG_FILES.map(async (path) => {
      const url = target.baseUrl + path;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (res.status !== 200) return null;

      const text = await res.text();
      if (isSoft404(text, target)) return null;
      if (looksLikeHtml(text)) return null;

      const looksLikeLog =
        /\[\d{4}[-/]\d{2}[-/]\d{2}|error|warn|exception|stack trace|at\s+\S+\s+\(/i.test(text);
      if (!looksLikeLog) return null;

      return { path, url, text };
    }),
  );

  for (const r of logResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, url, text } = r.value;
    findings.push({
      id: `env-leak-log-${path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "Environment Leak",
      severity: "high",
      title: `Log file exposed: ${path}`,
      description: "A log file is publicly accessible. Log files often contain stack traces, internal paths, user data, session tokens, and database queries that aid attackers in reconnaissance.",
      evidence: `GET ${url}\nStatus: 200\nResponse preview: ${text.substring(0, 400)}`,
      remediation: "Move log files outside the web root. Block access to *.log files via web server configuration. Use a centralized logging service instead of file-based logging.",
      cwe: "CWE-532",
      owasp: "A09:2021",
    });
  }

  return findings;
};
