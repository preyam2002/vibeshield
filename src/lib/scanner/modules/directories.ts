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
  { path: "/.git/refs/heads/main", severity: "critical", title: "Exposed .git refs", description: "Git refs are accessible — attackers can enumerate branches and reconstruct the full repository with tools like git-dumper.", remediation: "Block access to .git/ directory.", contentCheck: /^[0-9a-f]{40}/ },

  // Config files
  { path: "/wp-config.php", severity: "critical", title: "Exposed wp-config.php", description: "WordPress config file accessible.", remediation: "Block direct access to wp-config.php." },
  { path: "/config.php", severity: "high", title: "Exposed config.php", description: "PHP config file accessible.", remediation: "Move config outside web root." },
  { path: "/configuration.php", severity: "high", title: "Exposed configuration.php", description: "Configuration file accessible.", remediation: "Move outside web root." },

  // WordPress/CMS detection
  { path: "/wp-admin/", severity: "medium", title: "WordPress admin panel found", description: "WordPress admin login is publicly accessible — attackers can attempt brute-force or credential stuffing attacks.", remediation: "Restrict wp-admin access by IP or add two-factor authentication.", contentCheck: /wordpress|wp-login|log in/i },
  { path: "/wp-config.php.bak", severity: "critical", title: "WordPress config backup exposed", description: "A backup of wp-config.php is accessible — contains database credentials, auth keys, and salts in plaintext.", remediation: "Remove .bak files from web root immediately and rotate all credentials.", contentCheck: /DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY/i },
  { path: "/xmlrpc.php", severity: "medium", title: "WordPress XML-RPC enabled", description: "XML-RPC interface is accessible — can be used for brute-force amplification attacks and DDoS pingback abuse.", remediation: "Disable XML-RPC if not needed. Block in .htaccess or use a security plugin.", contentCheck: /XML-RPC|xmlrpc/i },
  { path: "/wp-json/wp/v2/users", severity: "medium", title: "WordPress user enumeration via REST API", description: "WordPress REST API exposes user list including usernames — attackers can use these for targeted login attacks.", remediation: "Disable the users endpoint or restrict access. Use a security plugin to block user enumeration.", contentCheck: /"slug"|"name"|"id"/i },

  // Debug/dev tools
  { path: "/__nextapi", severity: "medium", title: "Next.js internal API exposed", description: "Next.js internal API endpoint is accessible.", remediation: "Ensure internal Next.js routes are not publicly accessible." },
  { path: "/_next/data", severity: "info", title: "Next.js data routes accessible", description: "Next.js SSR data routes are accessible.", remediation: "Review what data is being sent via SSR props." },
  { path: "/graphql", severity: "medium", title: "GraphQL endpoint found", description: "GraphQL endpoint discovered. Will be tested for introspection.", remediation: "Disable introspection in production." },
  { path: "/graphiql", severity: "high", title: "GraphiQL IDE exposed", description: "GraphQL IDE is publicly accessible, making it easy to explore and exploit your API.", remediation: "Disable GraphiQL in production." },
  { path: "/playground", severity: "high", title: "API Playground exposed", description: "An API playground/explorer is publicly accessible.", remediation: "Disable API playgrounds in production." },

  // Backup files
  { path: "/index.php.bak", severity: "high", title: "PHP backup file exposed", description: "A backup of index.php is accessible — may contain database credentials, API keys, or application logic.", remediation: "Remove .bak files from web root.", contentCheck: /php|<\?/i },
  { path: "/app.js.old", severity: "high", title: "Old JS file exposed", description: "An old copy of app.js is accessible — may reveal application logic or embedded secrets.", remediation: "Remove .old files from web root." },
  { path: "/config.yml.bak", severity: "high", title: "Config backup file exposed", description: "A backup of config.yml is accessible — likely contains sensitive configuration values.", remediation: "Remove .bak files from web root." },
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
  { path: "/Dockerfile", severity: "medium", title: "Dockerfile exposed", description: "Dockerfile is accessible, revealing your build configuration and potentially base images with known vulnerabilities.", remediation: "Block access to Dockerfile.", contentCheck: /FROM|RUN|COPY|EXPOSE/i },
  { path: "/docker-compose.yml", severity: "high", title: "docker-compose.yml exposed", description: "Docker Compose config may contain service passwords and internal network details.", remediation: "Block access.", contentCheck: /services|version|volumes/i },
  { path: "/.dockerenv", severity: "medium", title: "Docker environment marker exposed", description: "The .dockerenv file confirms the application is running inside a Docker container — useful for attackers to tailor container escape exploits.", remediation: "Block access to .dockerenv." },
  { path: "/.github/workflows", severity: "low", title: "GitHub Actions workflows exposed", description: "CI/CD configuration is accessible.", remediation: "Block access to .github directory." },
  { path: "/Jenkinsfile", severity: "medium", title: "Jenkinsfile exposed", description: "Jenkins pipeline config is accessible — reveals build steps, deployment targets, and potentially credential IDs.", remediation: "Block access to Jenkinsfile.", contentCheck: /pipeline|node|stage/i },
  { path: "/.gitlab-ci.yml", severity: "medium", title: "GitLab CI config exposed", description: "GitLab CI/CD configuration reveals build pipeline, deployment targets, and environment variables.", remediation: "Block access to .gitlab-ci.yml.", contentCheck: /stages|script|image/i },
  { path: "/.circleci/config.yml", severity: "medium", title: "CircleCI config exposed", description: "CircleCI configuration reveals build pipeline, orbs, and deployment workflow.", remediation: "Block access to .circleci/ directory.", contentCheck: /version|jobs|workflows/i },

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
  { path: "/.editorconfig", severity: "info", title: "EditorConfig file exposed", description: "EditorConfig reveals coding style preferences and project structure.", remediation: "Block access to dotfiles in production.", contentCheck: /root|indent_style|charset/i },
  { path: "/.sublime-project", severity: "low", title: "Sublime Text project exposed", description: "Sublime Text project file may reveal folder structure and build system configuration.", remediation: "Block access to dotfiles in production.", contentCheck: /folders|settings/i },

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

  // Modern vibe-coded stack configs
  { path: "/convex.json", severity: "medium", title: "Convex config exposed", description: "Convex backend configuration is accessible, revealing project structure.", remediation: "Block access to convex.json.", contentCheck: /\{/ },
  { path: "/.clerk", severity: "medium", title: "Clerk config directory exposed", description: "Clerk auth configuration directory is accessible.", remediation: "Block access to .clerk/ directory." },
  { path: "/biome.json", severity: "info", title: "Biome config exposed", description: "Biome linter config reveals code conventions and rules.", remediation: "Block access to config files.", contentCheck: /\{/ },
  { path: "/.sentryclirc", severity: "high", title: "Sentry CLI config exposed", description: "Sentry CLI config may contain auth tokens and org details.", remediation: "Remove .sentryclirc from web root.", contentCheck: /token|org|project/i },
  { path: "/fly.toml", severity: "medium", title: "Fly.io config exposed", description: "Fly.io deployment config reveals app name, region, and service settings.", remediation: "Block access to fly.toml.", contentCheck: /app|primary_region/i },
  { path: "/railway.json", severity: "medium", title: "Railway config exposed", description: "Railway deployment config is accessible.", remediation: "Block access to railway.json.", contentCheck: /\{/ },
  { path: "/.env.sentry-build-plugin", severity: "high", title: "Sentry build plugin env exposed", description: "Sentry build env may contain auth tokens.", remediation: "Block access to .env files.", contentCheck: /SENTRY/ },

  // AI coding assistant artifacts
  { path: "/.claude/CLAUDE.md", severity: "low", title: "Claude Code memory exposed", description: "Claude Code project memory file reveals architecture decisions and coding conventions.", remediation: "Block access to .claude/ directory." },
  { path: "/.windsurf/rules", severity: "low", title: "Windsurf rules exposed", description: "Windsurf AI coding rules reveal project architecture.", remediation: "Block access to dotfiles." },
  { path: "/.bolt", severity: "low", title: "Bolt project config exposed", description: "Bolt.new project configuration is accessible.", remediation: "Block access to dotfiles." },
  { path: "/codegen.yml", severity: "low", title: "GraphQL Codegen config exposed", description: "GraphQL code generation config reveals API schema and endpoints.", remediation: "Block access to config files.", contentCheck: /schema|generates|documents/i },

  // Modern deployment/infra
  { path: "/render.yaml", severity: "medium", title: "Render config exposed", description: "Render deployment config reveals service architecture, env vars, and scaling settings.", remediation: "Block access to render.yaml.", contentCheck: /services|envVars/i },
  { path: "/coolify.json", severity: "medium", title: "Coolify config exposed", description: "Coolify self-hosted deployment config is accessible.", remediation: "Block access to coolify.json.", contentCheck: /\{/ },
  { path: "/kamal.yml", severity: "medium", title: "Kamal deploy config exposed", description: "Kamal deployment config may contain server addresses, registry credentials.", remediation: "Block access to kamal.yml.", contentCheck: /service|image|servers/i },
  { path: "/.kamal/secrets", severity: "critical", title: "Kamal secrets file exposed", description: "Kamal deployment secrets are publicly accessible.", remediation: "Immediately rotate all credentials. Block .kamal/ directory.", contentCheck: /=/ },

  // More backup patterns common in vibe-coded apps
  { path: "/db.json", severity: "high", title: "JSON database exposed", description: "A JSON database file (lowdb/json-server) is publicly accessible.", remediation: "Move outside web root or behind authentication.", contentCheck: /\{|\[/ },
  { path: "/data.db", severity: "critical", title: "SQLite database exposed", description: "SQLite database file is publicly downloadable.", remediation: "Move outside web root." },
  { path: "/dev.db", severity: "critical", title: "Dev SQLite database exposed", description: "Development database is publicly accessible — may contain test credentials or real data.", remediation: "Remove from production deployment." },
  { path: "/prisma/dev.db", severity: "critical", title: "Prisma dev.db exposed", description: "Prisma development SQLite database is accessible.", remediation: "Remove dev.db from production. Block /prisma/ directory." },

  // Source maps (explicit check for production builds)
  { path: "/main.js.map", severity: "medium", title: "Source map at root", description: "JavaScript source map at root exposes original source code.", remediation: "Remove .map files from production builds." },
  { path: "/app.js.map", severity: "medium", title: "Source map at root", description: "JavaScript source map exposes original source code.", remediation: "Remove .map files from production builds." },
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

  // ── Phase 2: Cloud provider metadata exposure ──────────────────────
  const cloudChecks: DirCheck[] = [
    { path: "/.aws/credentials", severity: "critical", title: "AWS credentials file exposed", description: "AWS credentials file is publicly accessible — contains access key IDs and secret keys that grant direct access to AWS resources.", remediation: "Remove immediately. Rotate all AWS access keys. Block access to dotfiles.", contentCheck: /aws_access_key_id|aws_secret_access_key|\[default\]/i },
    { path: "/.aws/config", severity: "high", title: "AWS config file exposed", description: "AWS CLI config is accessible — reveals region, output format, and profile names that aid targeted attacks.", remediation: "Block access to .aws/ directory.", contentCheck: /\[default\]|region|output/i },
    { path: "/.gcloud/credentials.json", severity: "critical", title: "GCloud credentials exposed", description: "Google Cloud credentials file is publicly accessible — may contain OAuth tokens or service account keys.", remediation: "Remove immediately. Revoke tokens and rotate credentials.", contentCheck: /client_id|client_secret|refresh_token|type/i },
    { path: "/.gcloud/properties", severity: "high", title: "GCloud properties exposed", description: "Google Cloud SDK properties file reveals project ID, account, and region configuration.", remediation: "Block access to .gcloud/ directory.", contentCheck: /\[core\]|project|account/i },
    { path: "/.azure/config", severity: "high", title: "Azure CLI config exposed", description: "Azure CLI configuration is accessible — reveals subscription details and tenant information.", remediation: "Block access to .azure/ directory.", contentCheck: /\[cloud\]|subscription|tenant/i },
    { path: "/.azure/accessTokens.json", severity: "critical", title: "Azure access tokens exposed", description: "Azure CLI cached access tokens are publicly accessible — grants direct API access to Azure resources.", remediation: "Remove immediately. Revoke all tokens. Block .azure/ directory.", contentCheck: /accessToken|tokenType|expiresOn/i },
    { path: "/.config/gcloud/credentials.db", severity: "critical", title: "GCloud credentials DB exposed", description: "Google Cloud credentials database is publicly accessible.", remediation: "Block access to .config/ directory." },
    { path: "/.config/gcloud/application_default_credentials.json", severity: "critical", title: "GCloud application default credentials exposed", description: "Application default credentials for Google Cloud are publicly accessible.", remediation: "Block access to .config/ directory. Rotate credentials immediately.", contentCheck: /client_id|client_secret|refresh_token/i },
  ];

  const cloudResults = await Promise.allSettled(
    cloudChecks.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 3000, redirect: "follow" });
      const text = res.ok ? await res.text() : "";
      return { check, url, status: res.status, text };
    }),
  );

  for (const r of cloudResults) {
    if (r.status !== "fulfilled") continue;
    const { check, url, status, text } = r.value;
    if (status !== 200) continue;
    if (text.length < 2) continue;
    if (check.contentCheck && !check.contentCheck.test(text)) continue;
    if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) continue;
    if (isSoft404(text, target)) continue;
    if (looksLikeHtml(text)) continue;

    findings.push({
      id: `dir-cloud-${check.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "directories",
      severity: check.severity,
      title: check.title,
      description: check.description,
      evidence: `GET ${url}\nStatus: ${status}\nSize: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
      remediation: check.remediation,
      cwe: "CWE-552",
    });
  }

  // ── Phase 3: Package manager lock files ───────────────────────────
  const lockfileChecks: DirCheck[] = [
    { path: "/yarn.lock", severity: "low", title: "yarn.lock exposed", description: "Yarn lock file is publicly accessible — reveals exact dependency versions, enabling attackers to identify packages with known vulnerabilities.", remediation: "Block access to yarn.lock in production.", contentCheck: /# yarn lockfile|resolved|integrity/i },
    { path: "/package-lock.json", severity: "low", title: "package-lock.json exposed", description: "npm lock file is publicly accessible — reveals the full dependency tree with exact versions, aiding targeted vulnerability exploitation.", remediation: "Block access to package-lock.json.", contentCheck: /"lockfileVersion"|"dependencies"|"resolved"/i },
    { path: "/pnpm-lock.yaml", severity: "low", title: "pnpm-lock.yaml exposed", description: "pnpm lock file is publicly accessible — reveals exact dependency versions and registry sources.", remediation: "Block access to pnpm-lock.yaml.", contentCheck: /lockfileVersion|dependencies|specifiers/i },
    { path: "/Gemfile.lock", severity: "low", title: "Gemfile.lock exposed", description: "Ruby Gemfile.lock is publicly accessible — reveals exact gem versions used, enabling targeted attacks on known vulnerabilities.", remediation: "Block access to Gemfile.lock.", contentCheck: /GEM|BUNDLED WITH|specs:/i },
    { path: "/composer.lock", severity: "low", title: "composer.lock exposed", description: "PHP Composer lock file is publicly accessible — reveals exact package versions and source URLs.", remediation: "Block access to composer.lock.", contentCheck: /"packages"|"hash"|"content-hash"/i },
    { path: "/Pipfile.lock", severity: "low", title: "Pipfile.lock exposed", description: "Python Pipfile.lock is publicly accessible — reveals exact package versions and hashes.", remediation: "Block access to Pipfile.lock.", contentCheck: /"default"|"_meta"|"hashes"/i },
    { path: "/poetry.lock", severity: "low", title: "poetry.lock exposed", description: "Python Poetry lock file is publicly accessible — reveals exact dependency versions.", remediation: "Block access to poetry.lock.", contentCheck: /\[\[package\]\]|name|version/i },
    { path: "/Cargo.lock", severity: "low", title: "Cargo.lock exposed", description: "Rust Cargo lock file is publicly accessible — reveals exact crate versions.", remediation: "Block access to Cargo.lock.", contentCheck: /\[\[package\]\]|name|version|checksum/i },
  ];

  const lockfileResults = await Promise.allSettled(
    lockfileChecks.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 3000, redirect: "follow" });
      const text = res.ok ? await res.text() : "";
      return { check, url, status: res.status, text };
    }),
  );

  for (const r of lockfileResults) {
    if (r.status !== "fulfilled") continue;
    const { check, url, status, text } = r.value;
    if (status !== 200) continue;
    if (text.length < 2) continue;
    if (check.contentCheck && !check.contentCheck.test(text)) continue;
    if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) continue;
    if (isSoft404(text, target)) continue;
    if (looksLikeHtml(text)) continue;

    findings.push({
      id: `dir-lockfile-${check.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "directories",
      severity: check.severity,
      title: check.title,
      description: check.description,
      evidence: `GET ${url}\nStatus: ${status}\nSize: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
      remediation: check.remediation,
      cwe: "CWE-200",
    });
  }

  // ── Phase 4: Infrastructure config exposure ───────────────────────
  const infraChecks: DirCheck[] = [
    { path: "/terraform.tfstate", severity: "critical", title: "Terraform state file exposed", description: "Terraform state contains all resource IDs, secrets, and full infrastructure details in plaintext.", remediation: "Never serve .tfstate files publicly. Use remote state backends (S3, GCS, Terraform Cloud).", contentCheck: /terraform|resources|serial/i },
    { path: "/terraform.tfstate.backup", severity: "critical", title: "Terraform state backup exposed", description: "Terraform state backup file is publicly accessible — contains the same sensitive data as the primary state file.", remediation: "Remove .tfstate.backup from web root. Use remote state backends.", contentCheck: /terraform|resources|serial/i },
    { path: "/ansible.cfg", severity: "medium", title: "Ansible config exposed", description: "Ansible configuration is publicly accessible — reveals inventory paths, SSH settings, and privilege escalation configuration.", remediation: "Block access to ansible.cfg.", contentCheck: /\[defaults\]|inventory|remote_user/i },
    { path: "/ansible/hosts", severity: "high", title: "Ansible inventory exposed", description: "Ansible inventory file reveals server hostnames, IP addresses, and group structure.", remediation: "Block access to ansible/ directory.", contentCheck: /\[|ansible_/i },
    { path: "/Vagrantfile", severity: "medium", title: "Vagrantfile exposed", description: "Vagrantfile is publicly accessible — reveals VM configuration, provisioning scripts, and network settings.", remediation: "Block access to Vagrantfile.", contentCheck: /Vagrant\.configure|config\.vm/i },
    { path: "/docker-compose.override.yml", severity: "high", title: "docker-compose.override.yml exposed", description: "Docker Compose override file may contain development secrets, debug ports, and volume mounts that differ from production.", remediation: "Block access to docker-compose files.", contentCheck: /services|version|volumes/i },
    { path: "/k8s/deployment.yml", severity: "high", title: "Kubernetes deployment manifest exposed", description: "Kubernetes deployment manifest reveals container images, resource limits, environment variables, and service architecture.", remediation: "Block access to k8s/ directory.", contentCheck: /apiVersion|kind|metadata|spec/i },
    { path: "/k8s/secrets.yml", severity: "critical", title: "Kubernetes secrets manifest exposed", description: "Kubernetes secrets manifest may contain base64-encoded credentials and API keys.", remediation: "Block access to k8s/ directory immediately. Rotate exposed secrets.", contentCheck: /kind:\s*Secret|data:|apiVersion/i },
    { path: "/kubernetes/deployment.yaml", severity: "high", title: "Kubernetes deployment exposed", description: "Kubernetes deployment manifest reveals container images, environment variables, and service configuration.", remediation: "Block access to kubernetes/ directory.", contentCheck: /apiVersion|kind|metadata|spec/i },
    { path: "/helm/values.yaml", severity: "high", title: "Helm values file exposed", description: "Helm values file may contain passwords, connection strings, and infrastructure configuration.", remediation: "Block access to helm/ directory.", contentCheck: /replicaCount|image|service|ingress/i },
    { path: "/pulumi.yaml", severity: "medium", title: "Pulumi project config exposed", description: "Pulumi project configuration reveals infrastructure-as-code project structure and runtime.", remediation: "Block access to pulumi.yaml.", contentCheck: /name|runtime|description/i },
    { path: "/Pulumi.prod.yaml", severity: "high", title: "Pulumi production stack config exposed", description: "Pulumi production stack configuration may contain encrypted secrets and resource configuration.", remediation: "Block access to Pulumi stack configs.", contentCheck: /config:|encryptedkey/i },
  ];

  const infraResults = await Promise.allSettled(
    infraChecks.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 3000, redirect: "follow" });
      const text = res.ok ? await res.text() : "";
      return { check, url, status: res.status, text };
    }),
  );

  for (const r of infraResults) {
    if (r.status !== "fulfilled") continue;
    const { check, url, status, text } = r.value;
    if (status !== 200) continue;
    if (text.length < 2) continue;
    if (check.contentCheck && !check.contentCheck.test(text)) continue;
    if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) continue;
    if (isSoft404(text, target)) continue;
    if (looksLikeHtml(text)) continue;

    findings.push({
      id: `dir-infra-${check.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "directories",
      severity: check.severity,
      title: check.title,
      description: check.description,
      evidence: `GET ${url}\nStatus: ${status}\nSize: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
      remediation: check.remediation,
      cwe: "CWE-552",
    });
  }

  // ── Phase 5: IDE and editor config exposure ───────────────────────
  const ideChecks: DirCheck[] = [
    { path: "/.idea/workspace.xml", severity: "low", title: "JetBrains workspace config exposed", description: "JetBrains IDE workspace configuration reveals project structure, run configurations, and recently opened files.", remediation: "Block access to .idea/ directory.", contentCheck: /<?xml|component|project/i },
    { path: "/.idea/modules.xml", severity: "low", title: "JetBrains modules config exposed", description: "JetBrains modules file reveals project module structure and source roots.", remediation: "Block access to .idea/ directory.", contentCheck: /<?xml|module|project/i },
    { path: "/.idea/datasources.xml", severity: "high", title: "JetBrains datasources config exposed", description: "JetBrains datasources configuration may contain database connection URLs, usernames, and cached credentials.", remediation: "Block access to .idea/ directory. Rotate any exposed database credentials.", contentCheck: /database|jdbc|url|username/i },
    { path: "/.idea/webServers.xml", severity: "medium", title: "JetBrains web servers config exposed", description: "JetBrains web server configuration reveals deployment targets, server URLs, and upload paths.", remediation: "Block access to .idea/ directory.", contentCheck: /webServer|fileTransfer|url/i },
    { path: "/.vscode/settings.json", severity: "low", title: "VS Code settings exposed", description: "VS Code settings file reveals project configuration, extension settings, and potentially custom paths.", remediation: "Block access to .vscode/ directory.", contentCheck: /\{/ },
    { path: "/.vscode/launch.json", severity: "medium", title: "VS Code launch config exposed", description: "VS Code launch configuration reveals debug settings, environment variables, and program arguments.", remediation: "Block access to .vscode/ directory.", contentCheck: /configurations|type|request/i },
    { path: "/.vscode/extensions.json", severity: "info", title: "VS Code extensions list exposed", description: "VS Code extensions file reveals recommended extensions and development tooling.", remediation: "Block access to .vscode/ directory.", contentCheck: /recommendations/i },
    { path: "/.editorconfig", severity: "info", title: "EditorConfig exposed", description: "EditorConfig file reveals coding style preferences, indentation rules, and file type configurations.", remediation: "Block access to dotfiles in production.", contentCheck: /root|indent_style|charset|end_of_line/i },
    { path: "/.prettierrc", severity: "info", title: "Prettier config exposed", description: "Prettier configuration reveals code formatting preferences and project conventions.", remediation: "Block access to dotfiles in production.", contentCheck: /semi|singleQuote|tabWidth|trailingComma/i },
    { path: "/.prettierrc.json", severity: "info", title: "Prettier JSON config exposed", description: "Prettier configuration reveals code formatting rules.", remediation: "Block access to dotfiles in production.", contentCheck: /\{/ },
    { path: "/.eslintrc.json", severity: "info", title: "ESLint config exposed", description: "ESLint configuration reveals linting rules and project code conventions.", remediation: "Block access to dotfiles in production.", contentCheck: /rules|extends|plugins/i },
    { path: "/.stylelintrc", severity: "info", title: "Stylelint config exposed", description: "Stylelint configuration reveals CSS linting rules.", remediation: "Block access to dotfiles in production." },
  ];

  const ideResults = await Promise.allSettled(
    ideChecks.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 3000, redirect: "follow" });
      const text = res.ok ? await res.text() : "";
      return { check, url, status: res.status, text };
    }),
  );

  for (const r of ideResults) {
    if (r.status !== "fulfilled") continue;
    const { check, url, status, text } = r.value;
    if (status !== 200) continue;
    if (text.length < 2) continue;
    if (check.contentCheck && !check.contentCheck.test(text)) continue;
    if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) continue;
    if (isSoft404(text, target)) continue;
    if (looksLikeHtml(text) && check.severity !== "info") continue;

    findings.push({
      id: `dir-ide-${check.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "directories",
      severity: check.severity,
      title: check.title,
      description: check.description,
      evidence: `GET ${url}\nStatus: ${status}\nSize: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
      remediation: check.remediation,
      cwe: "CWE-538",
    });
  }

  // ── Phase 6: Database dump files ──────────────────────────────────
  const dbDumpChecks: DirCheck[] = [
    { path: "/dump.sql", severity: "critical", title: "SQL dump file exposed", description: "A database dump is publicly accessible — may contain full table structures, user records, passwords, and sensitive business data.", remediation: "Remove dump files from web root immediately.", contentCheck: /CREATE|INSERT|TABLE|DROP|--.*dump/i },
    { path: "/backup.sql", severity: "critical", title: "SQL backup file exposed", description: "A database backup file is publicly downloadable — contains complete database contents.", remediation: "Remove backup files from web-accessible directories.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/db-export.sql", severity: "critical", title: "Database export file exposed", description: "A database export is publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/database-backup.sql", severity: "critical", title: "Database backup file exposed", description: "A named database backup is publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/export.sql", severity: "critical", title: "SQL export file exposed", description: "A SQL export is publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/mysql.sql", severity: "critical", title: "MySQL dump exposed", description: "A MySQL dump file is publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP|mysqldump/i },
    { path: "/db.sql", severity: "critical", title: "Database SQL file exposed", description: "A database SQL file is publicly accessible.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/data.sql", severity: "critical", title: "Data SQL file exposed", description: "A SQL data file is publicly accessible — may contain INSERT statements with real user data.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/production.sql", severity: "critical", title: "Production SQL dump exposed", description: "A production database dump is publicly accessible — contains real production data.", remediation: "Remove immediately. Audit for exposed PII.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/staging.sql", severity: "critical", title: "Staging SQL dump exposed", description: "A staging database dump is publicly accessible — may contain production-like data.", remediation: "Remove from web root.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/backups/db.sql", severity: "critical", title: "SQL backup in backups directory exposed", description: "Database backup in /backups/ directory is publicly accessible.", remediation: "Block access to /backups/ directory.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/backup/database.sql", severity: "critical", title: "SQL backup in backup directory exposed", description: "Database backup in /backup/ directory is publicly accessible.", remediation: "Block access to /backup/ directory.", contentCheck: /CREATE|INSERT|TABLE|DROP/i },
    { path: "/db/seed.sql", severity: "high", title: "Database seed file exposed", description: "Database seed file is publicly accessible — reveals table structure and may contain test credentials.", remediation: "Block access to /db/ directory.", contentCheck: /CREATE|INSERT|TABLE/i },
    { path: "/schema.sql", severity: "high", title: "Database schema file exposed", description: "Database schema file reveals complete table structures, relationships, and column types.", remediation: "Remove from web root.", contentCheck: /CREATE|TABLE|ALTER|INDEX/i },
    { path: "/migrations/", severity: "medium", title: "Database migrations directory exposed", description: "Database migrations directory is accessible — reveals schema evolution and table structures.", remediation: "Block access to /migrations/ directory." },
  ];

  const dbDumpResults = await Promise.allSettled(
    dbDumpChecks.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 3000, redirect: "follow" });
      const text = res.ok ? await res.text() : "";
      return { check, url, status: res.status, text };
    }),
  );

  for (const r of dbDumpResults) {
    if (r.status !== "fulfilled") continue;
    const { check, url, status, text } = r.value;
    if (status !== 200) continue;
    if (text.length < 2) continue;
    if (check.contentCheck && !check.contentCheck.test(text)) continue;
    if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) continue;
    if (isSoft404(text, target)) continue;
    if (looksLikeHtml(text)) continue;

    findings.push({
      id: `dir-dbdump-${check.path.replace(/[^a-z0-9]/gi, "-")}-${findings.length}`,
      module: "directories",
      severity: check.severity,
      title: check.title,
      description: check.description,
      evidence: `GET ${url}\nStatus: ${status}\nSize: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
      remediation: check.remediation,
      cwe: "CWE-530",
    });
  }

  return findings;
};
