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
];

export const exposedToolsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  for (const check of TOOL_CHECKS) {
    try {
      const url = target.baseUrl + check.path;
      const res = await scanFetch(url);
      if (res.status !== 200) continue;

      const text = await res.text();

      // Skip SPA soft 404s
      if (isSoft404(text, target)) continue;

      // If this check requires JSON response, reject HTML
      if (check.requireJson && looksLikeHtml(text)) continue;

      // For HTML responses, require content patterns to confirm it's a real tool page
      if (looksLikeHtml(text)) {
        const matchCount = check.contentPatterns.filter((p) => p.test(text)).length;
        // Require at least 2 pattern matches to avoid false positives from generic pages
        if (matchCount < 2) continue;
      }

      // For JSON responses, verify it's not empty/trivial
      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("json")) {
        if (text.length < 10) continue;
        const hasToolContent = check.contentPatterns.some((p) => p.test(text));
        if (!hasToolContent) continue;
      }

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
      });
    } catch {
      // skip unreachable paths
    }
  }

  return findings;
};
