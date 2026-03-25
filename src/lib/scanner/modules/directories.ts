import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

interface DirCheck {
  path: string;
  severity: Finding["severity"];
  title: string;
  description: string;
  remediation: string;
  contentCheck?: RegExp;
}

const CHECKS: DirCheck[] = [
  // Environment/Config files
  { path: "/.env", severity: "critical", title: "Exposed .env file", description: "Your .env file is publicly accessible. It likely contains database passwords, API keys, and other secrets.", remediation: "Block access to .env in your web server config or hosting provider.", contentCheck: /[A-Z_]+=/ },
  { path: "/.env.local", severity: "critical", title: "Exposed .env.local file", description: "Local environment file is accessible.", remediation: "Block access to .env files.", contentCheck: /[A-Z_]+=/ },
  { path: "/.env.production", severity: "critical", title: "Exposed .env.production file", description: "Production env file is accessible.", remediation: "Block access to .env files.", contentCheck: /[A-Z_]+=/ },
  { path: "/.env.development", severity: "high", title: "Exposed .env.development file", description: "Dev environment file is accessible.", remediation: "Block access to .env files.", contentCheck: /[A-Z_]+=/ },

  // Git
  { path: "/.git/config", severity: "critical", title: "Exposed .git directory", description: "Your .git directory is accessible. Attackers can download your entire repository including commit history and potentially secrets.", remediation: "Block access to .git/ in your web server.", contentCheck: /\[core\]|\[remote/ },
  { path: "/.git/HEAD", severity: "critical", title: "Exposed .git/HEAD", description: "Git HEAD file accessible — full repo can likely be reconstructed.", remediation: "Block access to .git/.", contentCheck: /ref:/ },

  // Config files
  { path: "/wp-config.php", severity: "critical", title: "Exposed wp-config.php", description: "WordPress config file accessible.", remediation: "Block direct access to wp-config.php." },
  { path: "/config.php", severity: "high", title: "Exposed config.php", description: "PHP config file accessible.", remediation: "Move config outside web root." },
  { path: "/configuration.php", severity: "high", title: "Exposed configuration.php", description: "Configuration file accessible.", remediation: "Move outside web root." },

  // Debug/dev tools
  { path: "/__nextapi", severity: "medium", title: "Next.js internal API exposed", description: "Next.js internal API endpoint is accessible.", remediation: "Ensure internal Next.js routes are not publicly accessible." },
  { path: "/_next/data", severity: "info", title: "Next.js data routes accessible", description: "Next.js SSR data routes are accessible.", remediation: "Review what data is being sent via SSR props." },
  { path: "/graphql", severity: "medium", title: "GraphQL endpoint found", description: "GraphQL endpoint discovered. Will be tested for introspection.", remediation: "Disable introspection in production." },
  { path: "/graphiql", severity: "high", title: "GraphiQL IDE exposed", description: "GraphQL IDE is publicly accessible, making it easy to explore and exploit your API.", remediation: "Disable GraphiQL in production." },
  { path: "/playground", severity: "high", title: "API Playground exposed", description: "An API playground/explorer is publicly accessible.", remediation: "Disable API playgrounds in production." },

  // Backup files
  { path: "/backup.sql", severity: "critical", title: "SQL backup file exposed", description: "A database backup file is publicly downloadable.", remediation: "Remove backup files from web-accessible directories.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
  { path: "/dump.sql", severity: "critical", title: "SQL dump file exposed", description: "A database dump is publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
  { path: "/database.sql", severity: "critical", title: "Database file exposed", description: "Database file publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
  { path: "/db.sqlite", severity: "critical", title: "SQLite database exposed", description: "SQLite database file is downloadable.", remediation: "Move database outside web root.", contentCheck: /SQLite/ },
  { path: "/data.json", severity: "medium", title: "Data file exposed", description: "A data file is publicly accessible.", remediation: "Review if this should be public." },

  // Package/dependency files
  { path: "/package.json", severity: "low", title: "package.json exposed", description: "Your package.json is readable, revealing dependencies and potentially private package names.", remediation: "Block access or ensure no sensitive info is present.", contentCheck: /"dependencies"/ },
  { path: "/composer.json", severity: "low", title: "composer.json exposed", description: "PHP dependencies file accessible.", remediation: "Block access to composer.json." },

  // Server info
  { path: "/phpinfo.php", severity: "high", title: "phpinfo() page exposed", description: "PHP configuration is publicly readable, revealing server details, paths, and extensions.", remediation: "Remove phpinfo.php from production." },
  { path: "/server-status", severity: "medium", title: "Apache server-status exposed", description: "Server status page is accessible.", remediation: "Restrict access to localhost." },
  { path: "/server-info", severity: "medium", title: "Apache server-info exposed", description: "Server info page is accessible.", remediation: "Restrict access." },
  { path: "/.well-known/security.txt", severity: "info", title: "security.txt found", description: "A security.txt file was found (this is a good practice!).", remediation: "No action needed — this is a positive finding." },

  // Vercel/Next.js specific
  { path: "/api/auth/providers", severity: "info", title: "NextAuth providers endpoint", description: "NextAuth.js providers list is accessible.", remediation: "This is expected behavior for NextAuth." },
  { path: "/_next/static/chunks/app", severity: "info", title: "Next.js chunk directory listable", description: "Next.js static chunks directory may be listable.", remediation: "Ensure directory listing is disabled." },

  // Docker/CI
  { path: "/Dockerfile", severity: "medium", title: "Dockerfile exposed", description: "Dockerfile is accessible, revealing your build configuration and potentially base images with known vulnerabilities.", remediation: "Block access to Dockerfile." },
  { path: "/docker-compose.yml", severity: "high", title: "docker-compose.yml exposed", description: "Docker Compose config may contain service passwords and internal network details.", remediation: "Block access." },
  { path: "/.github/workflows", severity: "low", title: "GitHub Actions workflows exposed", description: "CI/CD configuration is accessible.", remediation: "Block access to .github directory." },

  // Logs
  { path: "/error.log", severity: "high", title: "Error log exposed", description: "Application error log is accessible. May contain stack traces, file paths, and sensitive data.", remediation: "Move logs outside web root." },
  { path: "/access.log", severity: "medium", title: "Access log exposed", description: "Web server access log is accessible.", remediation: "Move logs outside web root." },
  { path: "/debug.log", severity: "high", title: "Debug log exposed", description: "Debug log is publicly accessible.", remediation: "Remove or move outside web root." },

  // Prisma / Drizzle
  { path: "/prisma/schema.prisma", severity: "medium", title: "Prisma schema exposed", description: "Your Prisma schema reveals database models, relations, and field types.", remediation: "Block access to /prisma/ directory.", contentCheck: /model|datasource|generator/i },
  { path: "/drizzle", severity: "medium", title: "Drizzle migrations directory", description: "Drizzle migration files may reveal your database schema.", remediation: "Block access to /drizzle/ directory." },

  // Wrangler / Cloudflare
  { path: "/wrangler.toml", severity: "high", title: "Wrangler config exposed", description: "Cloudflare Workers config may contain secrets, KV namespaces, and D1 database bindings.", remediation: "Block access to wrangler.toml.", contentCheck: /\[|name|compatibility_date/i },

  // Next.js internal
  { path: "/.next/BUILD_ID", severity: "low", title: ".next directory exposed", description: "Next.js build directory is accessible, revealing build ID and potentially server code.", remediation: "Block access to .next/ directory." },
  { path: "/.next/server/pages-manifest.json", severity: "medium", title: "Next.js pages manifest exposed", description: "Server-side pages manifest reveals all routes and their compiled file paths.", remediation: "Block access to .next/ directory.", contentCheck: /\// },
  { path: "/.next/server/middleware-manifest.json", severity: "medium", title: "Next.js middleware manifest exposed", description: "Middleware manifest reveals all middleware matchers and their configuration.", remediation: "Block access to .next/ directory.", contentCheck: /middleware|matchers/i },

  // Turborepo / monorepo
  { path: "/turbo.json", severity: "low", title: "turbo.json exposed", description: "Turborepo config reveals pipeline structure and dependencies.", remediation: "Block access to turbo.json.", contentCheck: /pipeline|tasks/i },

  // Supabase
  { path: "/supabase/config.toml", severity: "high", title: "Supabase local config exposed", description: "Supabase local configuration may contain project settings and connection details.", remediation: "Block access to /supabase/ directory.", contentCheck: /\[|project_id|api/i },
];

export const directoriesModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  const results = await Promise.allSettled(
    CHECKS.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 5000, redirect: "follow" });
      const text = res.ok ? await res.text() : "";
      return { check, url, status: res.status, text };
    }),
  );

  for (const r of results) {
    if (r.status !== "fulfilled") continue;
    const { check, url, status, text } = r.value;

    if (status !== 200) continue;
    if (text.length < 2) continue;

    // If there's a content check pattern, verify it matches
    if (check.contentCheck && !check.contentCheck.test(text)) continue;

    // Skip if it looks like a custom 404 page
    if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) continue;

    // Skip if this is a SPA returning its shell for any route (soft 404)
    if (isSoft404(text, target)) continue;
    // Skip HTML responses — real exposed files (.env, .sql, .log) are not HTML
    if (looksLikeHtml(text) && check.severity !== "info") continue;

    findings.push({
      id: `dir-${check.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "Directory & File Exposure",
      severity: check.severity,
      title: check.title,
      description: check.description,
      evidence: `GET ${url}\nStatus: ${status}\nSize: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
      remediation: check.remediation,
      cwe: "CWE-538",
      owasp: "A05:2021",
    });
  }

  return findings;
};
