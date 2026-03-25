import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const ERROR_PATTERNS: { pattern: RegExp; tech: string }[] = [
  { pattern: /Traceback \(most recent call last\)/i, tech: "Python" },
  { pattern: /at [\w.]+\([\w/.]+:\d+:\d+\)/i, tech: "Node.js" },
  { pattern: /(?:Fatal error|Warning):.*on line \d+/i, tech: "PHP" },
  { pattern: /Exception in thread/i, tech: "Java" },
  { pattern: /panic:.*goroutine/i, tech: "Go" },
  { pattern: /ActionView::Template::Error/i, tech: "Ruby on Rails" },
  { pattern: /Microsoft\.AspNetCore/i, tech: ".NET" },
  { pattern: /SQLSTATE\[/i, tech: "Database" },
  { pattern: /pg_connect|pg_query/i, tech: "PostgreSQL" },
  { pattern: /mysql_connect|mysqli/i, tech: "MySQL" },
  { pattern: /at\s+.*\.java:\d+/i, tech: "Java" },
  { pattern: /PrismaClientKnownRequestError|prisma\..*\.findUnique/i, tech: "Prisma" },
  { pattern: /DrizzleError|drizzle-orm/i, tech: "Drizzle ORM" },
  { pattern: /TRPCError|tRPC.*error/i, tech: "tRPC" },
  { pattern: /SupabaseError|supabase.*error.*policy/i, tech: "Supabase" },
  { pattern: /MongoServerError|MongoError/i, tech: "MongoDB" },
  { pattern: /AxiosError.*ERR_/i, tech: "Axios" },
  { pattern: /ConvexError|convex.*internal/i, tech: "Convex" },
];

const SENSITIVE_INFO_PATTERNS: { pattern: RegExp; description: string }[] = [
  { pattern: /\/home\/\w+\/|\/var\/www\/|\/app\/|C:\\Users\\/i, description: "Server file paths" },
  { pattern: /internal server error.*stack/i, description: "Stack trace in error" },
  { pattern: /debug\s*=\s*True|DEBUG\s*=\s*true/i, description: "Debug mode enabled" },
  { pattern: /django\.core|django\.db/i, description: "Django framework details" },
  { pattern: /express-session/i, description: "Express session details" },
  { pattern: /DATABASE_URL|POSTGRES_|MYSQL_|REDIS_URL/i, description: "Database connection strings" },
  { pattern: /node_modules\/.*\/lib\//i, description: "Node.js module paths" },
  { pattern: /\.prisma\/client/i, description: "Prisma client internals" },
];

export const infoLeakModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Test error triggering on API endpoints
  const errorPayloads = [
    { suffix: "/undefined", desc: "non-existent resource" },
    { suffix: "?id=aaa", desc: "invalid parameter type" },
    { suffix: "?__proto__=test", desc: "prototype pollution probe" },
    { suffix: "/../../etc/passwd", desc: "path traversal" },
    { suffix: "/%00", desc: "null byte" },
  ];

  // Test all endpoint+payload combos and malformed input in parallel
  const endpoints = target.apiEndpoints.slice(0, 8);
  const seenEndpoints = new Set<string>();

  const [errorResults, malformedResults] = await Promise.all([
    // Error payload tests — one task per endpoint (payloads sequential per endpoint for early-exit)
    Promise.allSettled(
      endpoints.map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        for (const payload of errorPayloads) {
          try {
            const url = endpoint + payload.suffix;
            const res = await scanFetch(url, { timeoutMs: 5000 });
            const text = await res.text();

            for (const ep of ERROR_PATTERNS) {
              if (ep.pattern.test(text)) {
                return { type: "stacktrace" as const, pathname, tech: ep.tech, desc: payload.desc, url, text };
              }
            }

            for (const si of SENSITIVE_INFO_PATTERNS) {
              if (si.pattern.test(text)) {
                return { type: "sensitive" as const, pathname, description: si.description, url };
              }
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Malformed input tests — all in parallel
    Promise.allSettled(
      target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
        const res = await scanFetch(endpoint, { method: "POST", body: "{invalid json", timeoutMs: 5000 });
        const text = await res.text();
        if (text.length > 100 && (res.status === 500 || res.status === 400)) {
          for (const ep of ERROR_PATTERNS) {
            if (ep.pattern.test(text)) {
              return { pathname: new URL(endpoint).pathname, tech: ep.tech, status: res.status, text };
            }
          }
        }
        return null;
      }),
    ),
  ]);

  for (const r of errorResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (seenEndpoints.has(v.pathname)) continue;
    seenEndpoints.add(v.pathname);

    if (v.type === "stacktrace") {
      findings.push({
        id: `infoleak-stacktrace-${findings.length}`,
        module: "Information Leakage",
        severity: "medium",
        title: `Stack trace leaked (${v.tech}) on ${v.pathname}`,
        description: `A ${v.tech} stack trace was returned when sending ${v.desc}. Stack traces reveal internal file paths, function names, and application structure.`,
        evidence: `URL: ${v.url}\nTech: ${v.tech}\nResponse excerpt: ${v.text.substring(0, 400)}`,
        remediation: "Implement proper error handling that returns generic error messages in production. Never expose stack traces to users.",
        codeSnippet: `// app/error.tsx — global error boundary\n"use client";\nexport default function GlobalError({ reset }: { reset: () => void }) {\n  return (\n    <html><body>\n      <h2>Something went wrong</h2>\n      <button onClick={() => reset()}>Try again</button>\n    </body></html>\n  );\n}\n\n// middleware.ts — catch API errors\nimport { NextResponse } from "next/server";\nexport function middleware() {\n  // Never leak stack traces; log server-side only\n}`,
        cwe: "CWE-209",
        owasp: "A05:2021",
      });
    } else {
      const existingCount = findings.filter((f) => f.title.includes(v.description)).length;
      if (existingCount < 2) {
        findings.push({
          id: `infoleak-sensitive-${findings.length}`,
          module: "Information Leakage",
          severity: "low",
          title: `${v.description} leaked on ${v.pathname}`,
          description: `Sensitive information (${v.description}) was found in the response.`,
          evidence: `URL: ${v.url}\nPattern: ${v.description}`,
          remediation: "Sanitize error responses in production. Use a global error handler.",
          codeSnippet: `// next.config.ts — disable verbose errors in production\nconst nextConfig: NextConfig = {\n  poweredByHeader: false,\n  // Errors are sanitized automatically in production builds\n};\n\n// API route — never expose internals\nexport async function GET() {\n  try {\n    const data = await db.query(...);\n    return NextResponse.json(data);\n  } catch (err) {\n    console.error(err); // log server-side only\n    return NextResponse.json({ error: "Internal error" }, { status: 500 });\n  }\n}`,
          cwe: "CWE-200",
        });
      }
    }
  }

  for (const r of malformedResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `infoleak-malformed-${findings.length}`,
      module: "Information Leakage",
      severity: "medium",
      title: `Verbose error on malformed input to ${v.pathname}`,
      description: `Sending malformed data triggers detailed error output revealing ${v.tech} internals.`,
      evidence: `POST with malformed JSON\nStatus: ${v.status}\nResponse: ${v.text.substring(0, 300)}`,
      remediation: "Return generic 400/500 errors. Log details server-side only.",
      codeSnippet: `// API route — validate JSON before processing\nimport { NextRequest, NextResponse } from "next/server";\n\nexport async function POST(req: NextRequest) {\n  let body: unknown;\n  try {\n    body = await req.json();\n  } catch {\n    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });\n  }\n  // process validated body...\n}`,
      cwe: "CWE-209",
    });
  }

  // Path traversal is handled by the dedicated path-traversal module

  // Check for dangerouslySetInnerHTML — only flag if excessive and no CSP
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const dangerousMatches = allJs.match(/dangerouslySetInnerHTML/g);
  const hasCSP = !!target.headers["content-security-policy"];
  if (dangerousMatches && dangerousMatches.length > 15 && !hasCSP) {
    findings.push({
      id: "infoleak-dangerous-innerhtml",
      module: "Information Leakage",
      severity: "low",
      title: `dangerouslySetInnerHTML used ${dangerousMatches.length} times without CSP`,
      description: `Your React app uses dangerouslySetInnerHTML ${dangerousMatches.length} times and has no Content-Security-Policy header. If any render user-controlled content, it's a direct XSS vulnerability with no CSP mitigation.`,
      evidence: `Found ${dangerousMatches.length} instances of dangerouslySetInnerHTML in JS bundles`,
      remediation: "Audit each dangerouslySetInnerHTML usage. If rendering user content, sanitize with DOMPurify first. Add a CSP header to mitigate XSS risk.",
      codeSnippet: `// Sanitize before rendering user content\nimport DOMPurify from "isomorphic-dompurify";\n\nconst SafeHTML = ({ html }: { html: string }) => (\n  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />\n);\n\n// middleware.ts — add CSP header\nimport { NextResponse } from "next/server";\nexport function middleware() {\n  const res = NextResponse.next();\n  res.headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'");\n  return res;\n}`,
      cwe: "CWE-79",
      owasp: "A03:2021",
    });
  }

  return findings;
};
