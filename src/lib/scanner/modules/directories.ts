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

  // AI/LLM config
  { path: "/.cursorrules", severity: "low", title: "Cursor rules file exposed", description: "AI coding assistant configuration is accessible, revealing project conventions and architecture details.", remediation: "Block access to dotfiles in production." },
  { path: "/.cursor/rules", severity: "low", title: "Cursor rules directory exposed", description: "AI coding assistant rules directory is accessible.", remediation: "Block access to dotfiles." },
  { path: "/CLAUDE.md", severity: "low", title: "Claude Code config exposed", description: "Claude Code project instructions are accessible, revealing architecture decisions and coding conventions.", remediation: "Block access to CLAUDE.md in production." },
  { path: "/.github/copilot-instructions.md", severity: "low", title: "Copilot instructions exposed", description: "GitHub Copilot instructions reveal project conventions.", remediation: "Block access to .github/ directory." },

  // Sensitive backup patterns
  { path: "/backup.zip", severity: "critical", title: "Backup archive exposed", description: "A backup archive is publicly downloadable — may contain source code, configs, and secrets.", remediation: "Remove backup files from web root.", contentCheck: /PK/ },
  { path: "/backup.tar.gz", severity: "critical", title: "Backup archive exposed", description: "A backup tar.gz is publicly downloadable.", remediation: "Remove backup files from web root." },
  { path: "/site.sql", severity: "critical", title: "SQL export exposed", description: "A database export is publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },

  // IDE/editor config
  { path: "/.vscode/settings.json", severity: "low", title: "VS Code settings exposed", description: "IDE configuration may reveal project structure and development tools.", remediation: "Block access to .vscode/ directory.", contentCheck: /\{/ },
  { path: "/.idea/workspace.xml", severity: "low", title: "JetBrains workspace exposed", description: "IDE workspace config may contain file paths and project settings.", remediation: "Block access to .idea/ directory." },

  // Additional .env variants
  { path: "/.env.production.local", severity: "critical", title: "Exposed .env.production.local", description: "Production local override env file is accessible — likely contains real secrets.", remediation: "Block access to .env files.", contentCheck: /[A-Z_]+=/ },
  { path: "/.env.staging", severity: "critical", title: "Exposed .env.staging", description: "Staging environment file is accessible.", remediation: "Block access to .env files.", contentCheck: /[A-Z_]+=/ },
  { path: "/.env.test", severity: "high", title: "Exposed .env.test", description: "Test environment file is accessible.", remediation: "Block access to .env files.", contentCheck: /[A-Z_]+=/ },
  { path: "/.env.backup", severity: "critical", title: "Exposed .env backup", description: "Backup of environment file is accessible.", remediation: "Remove .env backups from web root.", contentCheck: /[A-Z_]+=/ },
  { path: "/.env.example", severity: "low", title: "Exposed .env.example", description: "Example env file may reveal expected variable names and configuration structure.", remediation: "Review if variable names reveal sensitive architecture.", contentCheck: /[A-Z_]+=/ },

  // Terraform / IaC
  { path: "/terraform.tfstate", severity: "critical", title: "Terraform state file exposed", description: "Terraform state contains all resource IDs, secrets, and infrastructure details in plaintext.", remediation: "Never serve .tfstate files. Use remote state backends.", contentCheck: /terraform|resources/i },
  { path: "/.terraform/terraform.tfstate", severity: "critical", title: "Terraform state in .terraform dir exposed", description: "Terraform state file accessible from .terraform directory.", remediation: "Block access to .terraform directory.", contentCheck: /terraform|resources/i },
  { path: "/terraform.tfvars", severity: "critical", title: "Terraform variables file exposed", description: "Terraform variables file may contain secrets, API keys, and infrastructure credentials.", remediation: "Remove from web root.", contentCheck: /=/ },

  // Package manager auth
  { path: "/.npmrc", severity: "high", title: ".npmrc exposed", description: "npm config may contain private registry auth tokens.", remediation: "Block access to .npmrc.", contentCheck: /registry|token|auth/i },
  { path: "/.yarnrc.yml", severity: "high", title: ".yarnrc.yml exposed", description: "Yarn config may contain private registry auth tokens.", remediation: "Block access to .yarnrc.yml." },

  // Secrets files
  { path: "/secrets.json", severity: "critical", title: "secrets.json exposed", description: "Secrets file is publicly accessible.", remediation: "Remove from web root.", contentCheck: /\{/ },
  { path: "/secrets.yml", severity: "critical", title: "secrets.yml exposed", description: "Secrets YAML file is publicly accessible.", remediation: "Remove from web root." },
  { path: "/credentials.json", severity: "critical", title: "credentials.json exposed", description: "Credentials file is publicly accessible — may contain service account keys.", remediation: "Remove from web root.", contentCheck: /\{/ },
  { path: "/service-account.json", severity: "critical", title: "GCP service account key exposed", description: "Google Cloud service account key file is publicly downloadable.", remediation: "Remove immediately and rotate the key.", contentCheck: /private_key|client_email/i },

  // Cloud configs
  { path: "/vercel.json", severity: "low", title: "vercel.json exposed", description: "Vercel config reveals rewrites, redirects, and env var hints.", remediation: "Block access or review for sensitive info.", contentCheck: /\{/ },

  // BI / Admin tools
  { path: "/metabase", severity: "high", title: "Metabase dashboard exposed", description: "Metabase analytics dashboard is publicly accessible.", remediation: "Restrict access to authenticated users." },
  { path: "/airflow", severity: "high", title: "Apache Airflow UI exposed", description: "Airflow job scheduler UI is publicly accessible.", remediation: "Restrict access behind authentication." },
];

export const directoriesModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  const results = await Promise.allSettled(
    CHECKS.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 3000, redirect: "follow" });
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
      codeSnippet: check.path.includes(".env")
        ? `// next.config.ts — block .env files\nexport default {\n  async headers() {\n    return [{ source: "/.env:path*", headers: [{ key: "X-Robots-Tag", value: "noindex" }] }];\n  },\n  async rewrites() {\n    return [{ source: "/.env:path*", destination: "/404" }];\n  },\n};`
        : check.path.includes(".git")
        ? `// vercel.json or next.config.ts\n// Block .git directory access\n{ "rewrites": [{ "source": "/.git/:path*", "destination": "/404" }] }\n// Or nginx: location ~ /\\.git { deny all; }`
        : check.severity === "critical"
        ? `// Remove sensitive files from web root\n// Add to .gitignore and deployment ignore:\n${check.path}\n// Or block in middleware:\nif (req.nextUrl.pathname.startsWith("${check.path}")) return new Response(null, { status: 404 });`
        : undefined,
    });
  }

  return findings;
};
