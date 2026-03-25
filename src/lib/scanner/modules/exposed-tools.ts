import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

interface ToolCheck {
  path: string;
  name: string;
  /** Regex patterns that indicate the real tool is present (not just an SPA shell) */
  contentPatterns: RegExp[];
  severity: Finding["severity"];
  description: string;
  remediation: string;
  /** If true, response must have JSON content-type to be a real finding */
  requireJson?: boolean;
}

const TOOL_CHECKS: ToolCheck[] = [
  // Prisma Studio
  {
    path: "/prisma-studio",
    name: "Prisma Studio",
    contentPatterns: [/prisma/i, /studio/i, /model/i, /schema/i],
    severity: "critical",
    description: "Prisma Studio is publicly accessible. This gives anyone direct read/write access to your entire database through a visual editor.",
    remediation: "Remove Prisma Studio from production. It should only run locally during development. If needed in staging, restrict access by IP or VPN.",
  },
  {
    path: "/_prisma",
    name: "Prisma Studio (_prisma)",
    contentPatterns: [/prisma/i, /studio/i, /schema/i],
    severity: "critical",
    description: "Prisma Studio is accessible at /_prisma. This exposes direct database management to the public internet.",
    remediation: "Remove Prisma Studio from production deployments entirely.",
  },
  // Drizzle Studio
  {
    path: "/drizzle-studio",
    name: "Drizzle Studio",
    contentPatterns: [/drizzle/i, /studio/i, /table/i, /schema/i],
    severity: "critical",
    description: "Drizzle Studio is publicly accessible, providing direct database access to anyone who finds this URL.",
    remediation: "Remove Drizzle Studio from production. Only use it locally during development.",
  },
  // Swagger / OpenAPI
  {
    path: "/api-docs",
    name: "Swagger/OpenAPI Docs",
    contentPatterns: [/swagger/i, /openapi/i, /api/i, /paths/i],
    severity: "medium",
    description: "API documentation (Swagger/OpenAPI) is publicly accessible. This reveals your full API surface including endpoints, parameters, and data models.",
    remediation: "Restrict API docs to authenticated users or internal networks. Remove from production if not needed publicly.",
  },
  {
    path: "/swagger",
    name: "Swagger UI",
    contentPatterns: [/swagger/i, /openapi/i, /api/i],
    severity: "medium",
    description: "Swagger UI is publicly accessible, revealing your API structure and allowing interactive testing.",
    remediation: "Restrict Swagger UI access in production or disable it entirely.",
  },
  {
    path: "/swagger.json",
    name: "Swagger JSON Spec",
    contentPatterns: [/swagger/i, /openapi/i, /paths/i, /info/i],
    severity: "medium",
    description: "Swagger/OpenAPI JSON specification is publicly accessible.",
    remediation: "Remove or restrict access to the API specification file in production.",
    requireJson: true,
  },
  {
    path: "/openapi.json",
    name: "OpenAPI JSON Spec",
    contentPatterns: [/openapi/i, /paths/i, /info/i],
    severity: "medium",
    description: "OpenAPI specification file is publicly accessible, revealing your complete API schema.",
    remediation: "Remove or restrict access to the OpenAPI spec in production.",
    requireJson: true,
  },
  {
    path: "/docs",
    name: "API Docs (FastAPI/Redoc)",
    contentPatterns: [/swagger-ui/i, /openapi.*version/i, /redoc/i, /fastapi/i],
    severity: "medium",
    description: "API documentation endpoint is publicly accessible.",
    remediation: "Disable the docs endpoint in production or restrict access.",
  },
  {
    path: "/redoc",
    name: "ReDoc API Docs",
    contentPatterns: [/redoc/i, /openapi/i, /api/i],
    severity: "medium",
    description: "ReDoc API documentation is publicly accessible.",
    remediation: "Restrict ReDoc access in production.",
  },
  // Storybook
  {
    path: "/_storybook",
    name: "Storybook",
    contentPatterns: [/storybook/i, /story/i, /component/i],
    severity: "low",
    description: "Storybook component library is publicly accessible. This exposes your UI components and can reveal internal design patterns.",
    remediation: "Remove Storybook from production builds. Deploy it to a separate authenticated URL if needed.",
  },
  {
    path: "/storybook",
    name: "Storybook",
    contentPatterns: [/storybook/i, /story/i, /component/i],
    severity: "low",
    description: "Storybook component library is publicly accessible.",
    remediation: "Remove Storybook from production builds.",
  },
  // NextAuth debug
  {
    path: "/api/auth/debug",
    name: "NextAuth Debug Endpoint",
    contentPatterns: [/session/i, /provider/i, /callback/i, /csrf/i, /nextauth/i],
    severity: "high",
    description: "NextAuth debug endpoint is accessible. This can expose session details, provider configuration, and internal auth state.",
    remediation: "Set debug: false in your NextAuth config for production. Ensure NEXTAUTH_URL is set correctly.",
  },
  // Health/debug endpoints with sensitive info
  {
    path: "/api/debug",
    name: "Debug API Endpoint",
    contentPatterns: [/debug/i, /env/i, /config/i, /version/i, /database/i, /memory/i, /uptime/i],
    severity: "high",
    description: "A debug API endpoint is accessible and may expose internal application state, environment details, or configuration.",
    remediation: "Remove debug endpoints from production or protect them with authentication.",
  },
  {
    path: "/api/health",
    name: "Health Check (Verbose)",
    contentPatterns: [/database/i, /redis/i, /memory/i, /uptime/i, /version/i, /disk/i, /cpu/i],
    severity: "low",
    description: "Health check endpoint exposes detailed system information beyond a simple OK/healthy status.",
    remediation: "Limit health check responses to a simple status. Move detailed diagnostics behind authentication.",
    requireJson: true,
  },
  {
    path: "/health",
    name: "Health Check (Verbose)",
    contentPatterns: [/database/i, /redis/i, /memory/i, /uptime/i, /version/i, /disk/i, /cpu/i],
    severity: "low",
    description: "Health check endpoint exposes detailed system information.",
    remediation: "Return only a simple status from public health endpoints.",
    requireJson: true,
  },
  {
    path: "/status",
    name: "Status Page (Verbose)",
    contentPatterns: [/database/i, /redis/i, /memory/i, /uptime/i, /version/i, /config/i],
    severity: "low",
    description: "Status endpoint exposes detailed system information.",
    remediation: "Limit public status information. Move detailed diagnostics behind authentication.",
    requireJson: true,
  },
  // Spring Boot Actuator
  {
    path: "/actuator",
    name: "Spring Boot Actuator",
    contentPatterns: [/actuator/i, /health/i, /info/i, /beans/i, /env/i, /metrics/i],
    severity: "high",
    description: "Spring Boot Actuator is publicly accessible, exposing application internals, environment variables, and health data.",
    remediation: "Restrict actuator endpoints to internal networks. Set management.endpoints.web.exposure.include to only 'health'.",
    requireJson: true,
  },
  {
    path: "/actuator/env",
    name: "Spring Boot Actuator Env",
    contentPatterns: [/property/i, /value/i, /source/i, /activeProfiles/i],
    severity: "critical",
    description: "Spring Boot Actuator /env endpoint is exposed, potentially leaking environment variables and secrets.",
    remediation: "Disable the env actuator endpoint in production.",
    requireJson: true,
  },
  // phpMyAdmin
  {
    path: "/phpmyadmin",
    name: "phpMyAdmin",
    contentPatterns: [/phpmyadmin/i, /mysql/i, /database/i, /sql/i],
    severity: "critical",
    description: "phpMyAdmin is publicly accessible, providing direct database management via the browser.",
    remediation: "Remove phpMyAdmin from production or restrict access by IP/VPN.",
  },
  {
    path: "/pma",
    name: "phpMyAdmin (pma)",
    contentPatterns: [/phpmyadmin/i, /mysql/i, /database/i, /sql/i],
    severity: "critical",
    description: "phpMyAdmin is publicly accessible at /pma.",
    remediation: "Remove phpMyAdmin from production or restrict access by IP/VPN.",
  },
  // Adminer
  {
    path: "/adminer",
    name: "Adminer",
    contentPatterns: [/adminer/i, /login/i, /server/i, /database/i],
    severity: "critical",
    description: "Adminer database manager is publicly accessible.",
    remediation: "Remove Adminer from production deployments.",
  },
  // Webpack HMR in production
  {
    path: "/__webpack_hmr",
    name: "Webpack HMR",
    contentPatterns: [/webpack/i, /hmr/i, /hot/i, /module/i],
    severity: "medium",
    description: "Webpack Hot Module Replacement is active, indicating the app may be running in development mode in production.",
    remediation: "Ensure NODE_ENV=production in your deployment. Never deploy development builds.",
  },
  // Inngest dev server
  {
    path: "/api/inngest",
    name: "Inngest Dev Server",
    contentPatterns: [/inngest/i, /event/i, /function/i, /step/i],
    severity: "medium",
    description: "Inngest endpoint is accessible. If the dev server UI is exposed, attackers can trigger background functions.",
    remediation: "Protect Inngest endpoints with signing keys in production.",
    requireJson: true,
  },
  // tRPC panel
  {
    path: "/api/trpc-panel",
    name: "tRPC Panel",
    contentPatterns: [/trpc/i, /panel/i, /procedure/i, /router/i],
    severity: "high",
    description: "tRPC Panel is publicly accessible, allowing anyone to explore and invoke your tRPC procedures.",
    remediation: "Remove tRPC Panel from production. Only use it in development.",
  },
  // BullMQ / Bull Board
  {
    path: "/admin/queues",
    name: "Bull Board (Job Queue)",
    contentPatterns: [/bull/i, /queue/i, /job/i, /redis/i],
    severity: "high",
    description: "Bull Board job queue dashboard is publicly accessible. Attackers can see job payloads and retry/delete jobs.",
    remediation: "Protect Bull Board with authentication middleware.",
  },
  {
    path: "/queues",
    name: "Bull Board (Job Queue)",
    contentPatterns: [/bull/i, /queue/i, /job/i, /completed/i],
    severity: "high",
    description: "Job queue dashboard is publicly accessible.",
    remediation: "Protect queue dashboards with authentication.",
  },
  // Payload CMS
  {
    path: "/admin",
    name: "CMS Admin Panel",
    contentPatterns: [/payload/i, /strapi/i, /directus/i, /sanity/i, /admin/i],
    severity: "medium",
    description: "A CMS admin panel login page is accessible. While login-protected, it confirms the CMS in use and may be brute-forced.",
    remediation: "Add rate limiting and IP restrictions to admin panels. Consider moving to a separate subdomain.",
  },
  // Vite dev server
  {
    path: "/@vite/client",
    name: "Vite Dev Server",
    contentPatterns: [/vite/i, /hmr/i, /import\.meta/i],
    severity: "high",
    description: "Vite development server is running in production. This exposes source code and HMR functionality.",
    remediation: "Deploy production builds, not the Vite dev server. Run `vite build` for production.",
  },
  // Convex config
  {
    path: "/.convex/_generated/api.js",
    name: "Convex Generated API",
    contentPatterns: [/convex/i, /mutation/i, /query/i, /action/i],
    severity: "high",
    description: "Convex generated API code is publicly accessible, revealing all backend functions and their signatures.",
    remediation: "Block access to .convex directory in production.",
  },
  // Metabase / BI Tools
  {
    path: "/metabase",
    name: "Metabase",
    contentPatterns: [/metabase/i, /dashboard/i, /query/i],
    severity: "high",
    description: "Metabase analytics dashboard is publicly accessible. May expose business data and database queries.",
    remediation: "Restrict Metabase access behind authentication and VPN.",
  },
  // DevTools / admin paths
  {
    path: "/devtools",
    name: "Developer Tools Panel",
    contentPatterns: [/dev/i, /tool/i, /debug/i, /admin/i],
    severity: "high",
    description: "A developer tools panel is publicly accessible.",
    remediation: "Remove developer tools from production or protect behind authentication.",
  },
  {
    path: "/api/debug",
    name: "Debug API Endpoint",
    contentPatterns: [/debug/i, /env/i, /config/i, /version/i],
    severity: "high",
    description: "A debug API endpoint is publicly accessible and may expose internal state, environment variables, or configuration.",
    remediation: "Remove debug endpoints from production builds.",
    requireJson: true,
  },
  {
    path: "/api/internal",
    name: "Internal API",
    contentPatterns: [/.+/],
    severity: "medium",
    description: "An internal API endpoint is publicly accessible. Internal APIs often lack the same security controls as public APIs.",
    remediation: "Block access to internal API routes or protect with authentication.",
    requireJson: true,
  },
  // Webpack Bundle Analyzer
  {
    path: "/report.html",
    name: "Webpack Bundle Analyzer",
    contentPatterns: [/webpack/i, /bundle/i, /module/i, /chunk/i],
    severity: "medium",
    description: "Webpack Bundle Analyzer report is publicly accessible, revealing all bundled modules and their sizes.",
    remediation: "Remove bundle analysis reports from production builds.",
  },
  // Trigger.dev dashboard
  {
    path: "/api/trigger",
    name: "Trigger.dev Endpoint",
    contentPatterns: [/trigger/i, /job/i, /event/i, /run/i],
    severity: "medium",
    description: "Trigger.dev endpoint is publicly accessible. Without signing key validation, attackers can invoke background jobs.",
    remediation: "Set TRIGGER_SECRET_KEY and verify signatures on incoming requests.",
    requireJson: true,
  },
  // Expo DevTools
  {
    path: "/_expo/plugins",
    name: "Expo Dev Plugins",
    contentPatterns: [/expo/i, /plugin/i, /devtools/i],
    severity: "medium",
    description: "Expo development plugins endpoint is accessible, indicating a development build may be deployed.",
    remediation: "Deploy production builds (expo build / eas build) instead of development server.",
  },
  // Supabase Studio via proxy
  {
    path: "/supabase",
    name: "Supabase Studio",
    contentPatterns: [/supabase/i, /studio/i, /table/i, /editor/i],
    severity: "critical",
    description: "Supabase Studio is accessible from the app, providing direct database access including table editing and SQL execution.",
    remediation: "Remove Supabase Studio access from production. Access it via the Supabase dashboard instead.",
  },
  // LocalStack / mock AWS
  {
    path: "/_localstack/health",
    name: "LocalStack (Mock AWS)",
    contentPatterns: [/running|available|services/i],
    severity: "high",
    description: "LocalStack mock AWS service is publicly accessible. This is a development tool that should never be in production.",
    remediation: "Remove LocalStack from production deployments.",
    requireJson: true,
  },
  // Grafana
  {
    path: "/grafana",
    name: "Grafana Dashboard",
    contentPatterns: [/grafana/i, /dashboard/i, /datasource/i, /panel/i],
    severity: "high",
    description: "Grafana monitoring dashboard is publicly accessible. May expose infrastructure metrics, alert rules, and database connection info.",
    remediation: "Restrict Grafana access behind VPN or authentication. Disable anonymous access in grafana.ini.",
  },
  // Prometheus metrics
  {
    path: "/metrics",
    name: "Prometheus Metrics",
    contentPatterns: [/HELP|TYPE|go_|process_|http_request/],
    severity: "medium",
    description: "Prometheus metrics endpoint is exposed, revealing application performance data, request counts, error rates, and potentially sensitive labels.",
    remediation: "Restrict /metrics to internal networks. Use a service mesh or reverse proxy to control access.",
  },
  // Apollo Studio / GraphQL Playground
  {
    path: "/graphql",
    name: "GraphQL Playground/Explorer",
    contentPatterns: [/playground|graphiql|explorer|apollo/i],
    severity: "medium",
    description: "GraphQL Playground or Explorer is publicly accessible, allowing anyone to interactively query your GraphQL API.",
    remediation: "Disable GraphQL Playground in production. Set playground: false and introspection: false in your Apollo/GraphQL config.",
  },
  // Sentry debug endpoint
  {
    path: "/api/sentry",
    name: "Sentry Debug",
    contentPatterns: [/sentry|dsn|event|exception/i],
    severity: "medium",
    description: "Sentry debug endpoint is publicly accessible. May expose error tracking configuration or DSN.",
    remediation: "Remove Sentry debug endpoints from production.",
    requireJson: true,
  },
  // MailHog / MailPit (email capture)
  {
    path: "/mailhog",
    name: "MailHog (Dev Email)",
    contentPatterns: [/mailhog|message|inbox|smtp/i],
    severity: "high",
    description: "MailHog development email server UI is publicly accessible. All captured emails are viewable.",
    remediation: "Remove MailHog from production. Use a real email service.",
  },
  {
    path: "/mailpit",
    name: "Mailpit (Dev Email)",
    contentPatterns: [/mailpit|message|inbox|smtp/i],
    severity: "high",
    description: "Mailpit development email UI is publicly accessible. All captured emails including password resets are viewable.",
    remediation: "Remove Mailpit from production. Use a real email service.",
  },
  // MinIO Console
  {
    path: "/minio",
    name: "MinIO Console",
    contentPatterns: [/minio|console|bucket|object/i],
    severity: "critical",
    description: "MinIO object storage console is publicly accessible, providing direct access to stored files and buckets.",
    remediation: "Restrict MinIO console access. Use authentication and network-level controls.",
  },
  // Redis Commander / RedisInsight
  {
    path: "/redis",
    name: "Redis Commander",
    contentPatterns: [/redis|commander|key|value|database/i],
    severity: "critical",
    description: "Redis management UI is publicly accessible, allowing direct access to cache/session data.",
    remediation: "Remove Redis management UIs from production. Access via VPN only.",
  },
  // Next.js ISR cache invalidation
  {
    path: "/api/revalidate",
    name: "ISR Revalidation Endpoint",
    contentPatterns: [/revalidat/i, /cache/i, /success/i, /true/i],
    severity: "medium",
    description: "ISR revalidation endpoint is accessible without authentication. Attackers can force cache invalidation, causing unnecessary rebuilds.",
    remediation: "Protect revalidation endpoints with a secret token.",
    requireJson: true,
  },
  // Directus admin
  {
    path: "/admin/content",
    name: "Directus CMS",
    contentPatterns: [/directus/i, /collection/i, /content/i],
    severity: "high",
    description: "Directus CMS admin panel is publicly accessible.",
    remediation: "Restrict Directus admin access. Configure ADMIN_PASSWORD and access controls.",
  },
];

export const exposedToolsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  const results = await Promise.allSettled(
    TOOL_CHECKS.map(async (check) => {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (res.status !== 200) return null;

      const text = await res.text();
      if (isSoft404(text, target)) return null;
      if (check.requireJson && looksLikeHtml(text)) return null;

      if (looksLikeHtml(text)) {
        const matchCount = check.contentPatterns.filter((p) => p.test(text)).length;
        if (matchCount < 2) return null;
      }

      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("json")) {
        if (text.length < 10) return null;
        if (!check.contentPatterns.some((p) => p.test(text))) return null;
      }

      return { check, url, contentType, text };
    }),
  );

  for (const r of results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { check, url, contentType, text } = r.value;
    findings.push({
      id: `exposed-tools-${check.name.toLowerCase().replace(/[\s/()]+/g, "-")}-${findings.length}`,
      module: "Exposed Dev Tools",
      severity: check.severity,
      title: `${check.name} exposed at ${check.path}`,
      description: check.description,
      evidence: `GET ${url}\nStatus: 200\nContent-Type: ${contentType}\nResponse preview: ${text.substring(0, 300)}`,
      remediation: check.remediation,
      cwe: "CWE-489",
      owasp: "A05:2021",
      codeSnippet: check.severity === "critical"
        ? `// middleware.ts — block access to dev tools in production\nif (req.nextUrl.pathname.startsWith("${check.path}")) {\n  return new Response(null, { status: 404 });\n}`
        : check.path.includes("debug") || check.path.includes("actuator")
        ? `// Remove or protect debug endpoints in production\n// next.config.ts rewrites:\n{ source: "${check.path}", destination: "/404" }`
        : undefined,
    });
  }

  return findings;
};
