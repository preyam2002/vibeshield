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
  { pattern: /ZodError|"issues":\s*\[.*"code":\s*"invalid_type"/i, tech: "Zod Validation" },
  { pattern: /NextRouter.*error|NEXT_NOT_FOUND|getServerSideProps.*error/i, tech: "Next.js" },
  { pattern: /ClerkAPIError|clerk.*error/i, tech: "Clerk Auth" },
  { pattern: /ResendError|resend\.emails/i, tech: "Resend" },
  { pattern: /UploadThingError|uploadthing/i, tech: "UploadThing" },
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

  // Check for verbose response headers that leak server information
  const leakyHeaders: { name: string; value: string; description: string }[] = [];
  const headers = target.headers;
  if (headers["x-powered-by"]) leakyHeaders.push({ name: "X-Powered-By", value: headers["x-powered-by"], description: "reveals server framework" });
  if (headers["server"] && !/^(cloudflare|vercel|netlify|next\.js)$/i.test(headers["server"])) {
    const ver = headers["server"];
    if (/\d+\.\d+/.test(ver)) leakyHeaders.push({ name: "Server", value: ver, description: "reveals server software version" });
  }
  if (headers["x-aspnet-version"]) leakyHeaders.push({ name: "X-AspNet-Version", value: headers["x-aspnet-version"], description: "reveals ASP.NET version" });
  if (headers["x-debug-token"]) leakyHeaders.push({ name: "X-Debug-Token", value: headers["x-debug-token"], description: "debug mode active in production" });
  if (headers["x-debug-token-link"]) leakyHeaders.push({ name: "X-Debug-Token-Link", value: headers["x-debug-token-link"], description: "Symfony profiler link exposed" });

  if (leakyHeaders.length > 0) {
    findings.push({
      id: "infoleak-verbose-headers",
      module: "Information Leakage",
      severity: leakyHeaders.some((h) => h.name.includes("Debug")) ? "medium" : "low",
      title: `Verbose response headers (${leakyHeaders.length})`,
      description: `The server exposes headers that reveal internal technology details: ${leakyHeaders.map((h) => `${h.name} ${h.description}`).join(", ")}. Attackers use this to target known vulnerabilities.`,
      evidence: leakyHeaders.map((h) => `${h.name}: ${h.value}`).join("\n"),
      remediation: "Remove or hide these headers in production.",
      cwe: "CWE-200",
      codeSnippet: `// next.config.ts\nconst nextConfig = {\n  poweredByHeader: false, // removes X-Powered-By: Next.js\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Server", value: "web" }, // generic value\n    ]}];\n  },\n};`,
    });
  }

  // Check for environment variable leaks in HTML/JS responses
  const envLeakPatterns: { pattern: RegExp; name: string }[] = [
    { pattern: /NEXT_PUBLIC_[A-Z_]+=(?!["']?\$\{)/g, name: "NEXT_PUBLIC_ env assignment" },
    { pattern: /process\.env\.((?!NODE_ENV|NEXT_PUBLIC_)[A-Z_]{5,})/g, name: "server-only env reference" },
    { pattern: /VERCEL_[A-Z_]+=.{5,}/g, name: "Vercel deployment env" },
    { pattern: /RAILWAY_[A-Z_]+=.{5,}/g, name: "Railway deployment env" },
    { pattern: /FLY_[A-Z_]+=.{5,}/g, name: "Fly.io deployment env" },
    { pattern: /RENDER_[A-Z_]+=.{5,}/g, name: "Render deployment env" },
  ];

  const allJs = Array.from(target.jsContents.values()).join("\n");
  for (const ep of envLeakPatterns) {
    const matches = allJs.match(ep.pattern);
    if (matches && matches.length > 0) {
      // Filter out expected public env vars
      const suspicious = matches.filter((m) => !/NEXT_PUBLIC_|VERCEL_URL|VERCEL_ENV/i.test(m));
      if (suspicious.length > 0) {
        findings.push({
          id: `infoleak-env-${ep.name.replace(/\s+/g, "-")}`,
          module: "Information Leakage",
          severity: "medium",
          title: `${ep.name} exposed in client JS (${suspicious.length} instances)`,
          description: `Found ${suspicious.length} instance(s) of ${ep.name} in client-side JavaScript. Server-only environment variables should never appear in the client bundle.`,
          evidence: `Found: ${suspicious.slice(0, 3).join(", ")}${suspicious.length > 3 ? `, +${suspicious.length - 3} more` : ""}`,
          remediation: "Only prefix client-safe env vars with NEXT_PUBLIC_. Server-only vars should be accessed only in server components, API routes, or middleware.",
          cwe: "CWE-200", owasp: "A05:2021",
          codeSnippet: `// .env.local — separate public and private vars\nNEXT_PUBLIC_API_URL=https://api.example.com  # safe for client\nDATABASE_URL=postgres://...                   # server only\n\n// Access server-only vars only in server code:\n// app/api/route.ts or server components\nconst db = process.env.DATABASE_URL; // only available server-side`,
        });
      }
    }
  }

  // Check for internal API/service URLs leaked in JS bundles
  const internalUrlPatterns = [
    /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?(?:\/\S*)?/gi,
    /https?:\/\/[a-z0-9-]+\.(?:internal|local|corp|private|dev|staging)(?:\.[a-z]+)?(?::\d+)?(?:\/\S*)?/gi,
  ];

  const internalUrls = new Set<string>();
  for (const pat of internalUrlPatterns) {
    const matches = allJs.match(pat);
    if (matches) matches.forEach((m: string) => internalUrls.add(m.substring(0, 100)));
  }

  if (internalUrls.size > 0) {
    const urls = [...internalUrls].slice(0, 5);
    findings.push({
      id: "infoleak-internal-urls",
      module: "Information Leakage",
      severity: "medium",
      title: `${internalUrls.size} internal/localhost URL${internalUrls.size > 1 ? "s" : ""} in client code`,
      description: "Internal service URLs (localhost, private IPs, internal domains) were found in client-side code. These reveal your internal infrastructure and can be used for SSRF or targeted attacks.",
      evidence: urls.join("\n"),
      remediation: "Replace hardcoded internal URLs with environment variables. Use relative URLs or proxy through your API.",
      cwe: "CWE-200",
      codeSnippet: `// Use environment variables for API URLs\nconst API_URL = process.env.NEXT_PUBLIC_API_URL || "/api";\n\n// Or proxy through Next.js rewrites:\n// next.config.ts\nasync rewrites() {\n  return [{ source: "/api/:path*", destination: process.env.BACKEND_URL + "/:path*" }];\n}`,
    });
  }

  // Version fingerprinting — check for specific software version disclosure in headers
  const versionHeaders: { name: string; value: string; software: string }[] = [];
  const versionHeaderChecks: { key: string; name: string; pattern: RegExp }[] = [
    { key: "server", name: "Server", pattern: /\d+\.\d+/ },
    { key: "x-powered-by", name: "X-Powered-By", pattern: /.+/ },
    { key: "x-aspnet-version", name: "X-AspNet-Version", pattern: /.+/ },
    { key: "x-generator", name: "X-Generator", pattern: /.+/ },
    { key: "x-drupal-cache", name: "X-Drupal-Cache", pattern: /.+/ },
  ];

  for (const check of versionHeaderChecks) {
    const val = headers[check.key];
    if (val && check.pattern.test(val)) {
      versionHeaders.push({ name: check.name, value: val, software: val });
    }
  }

  if (versionHeaders.length > 0) {
    findings.push({
      id: "infoleak-version-fingerprint",
      module: "Information Leakage",
      severity: "medium",
      title: `Software version disclosed via ${versionHeaders.length} header${versionHeaders.length > 1 ? "s" : ""}`,
      description: `The server discloses specific software versions through response headers: ${versionHeaders.map((h) => `${h.name}: ${h.value}`).join(", ")}. Attackers use version information to find known CVEs and exploits for the exact software version.`,
      evidence: versionHeaders.map((h) => `${h.name}: ${h.value}`).join("\n"),
      remediation: "Remove or genericize version-disclosing headers. Configure your web server or reverse proxy to strip these headers in production.",
      cwe: "CWE-200",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts — remove version headers\nconst nextConfig = {\n  poweredByHeader: false,\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "X-Powered-By", value: "" },\n      { key: "Server", value: "web" },\n    ]}];\n  },\n};\n\n// nginx — hide version info\nserver_tokens off;\nproxy_hide_header X-Powered-By;\nproxy_hide_header X-AspNet-Version;\nproxy_hide_header X-Generator;`,
    });
  }

  // Error page information leak — trigger error pages with malformed requests
  const errorPagePayloads: { url: string; headers?: Record<string, string>; desc: string }[] = [
    { url: target.baseUrl + "/%ff", desc: "invalid URL encoding" },
    { url: target.baseUrl + "/", headers: { Accept: "../../../etc/passwd" }, desc: "path traversal in Accept header" },
    { url: target.baseUrl + "/", headers: { "Content-Type": "application/x-www-form-urlencoded\r\nX-Injected: true" }, desc: "header injection via Content-Type" },
  ];

  const errorPageResults = await Promise.allSettled(
    errorPagePayloads.map(async (payload) => {
      try {
        const res = await scanFetch(payload.url, {
          headers: payload.headers,
          timeoutMs: 5000,
        });
        const text = await res.text();
        if (text.length < 50) return null;

        // Check for stack traces, file paths, or framework names in error responses
        const leakPatterns: { pattern: RegExp; label: string }[] = [
          { pattern: /Traceback \(most recent call last\)/i, label: "Python stack trace" },
          { pattern: /at [\w.]+\([\w/.]+:\d+:\d+\)/i, label: "Node.js stack trace" },
          { pattern: /(?:Fatal error|Warning):.*on line \d+/i, label: "PHP error" },
          { pattern: /Exception in thread/i, label: "Java exception" },
          { pattern: /panic:.*goroutine/i, label: "Go panic" },
          { pattern: /\/home\/\w+\/|\/var\/www\/|\/app\/|C:\\Users\\/i, label: "server file path" },
          { pattern: /django|laravel|express|flask|rails|spring|asp\.net/i, label: "framework name" },
          { pattern: /node_modules\/|vendor\/|site-packages\//i, label: "dependency path" },
        ];

        for (const lp of leakPatterns) {
          if (lp.pattern.test(text)) {
            return { desc: payload.desc, label: lp.label, url: payload.url, text: text.substring(0, 400) };
          }
        }
      } catch { /* skip */ }
      return null;
    }),
  );

  for (const r of errorPageResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `infoleak-errorpage-${findings.length}`,
      module: "Information Leakage",
      severity: "medium",
      title: `Error page leaks ${v.label} via ${v.desc}`,
      description: `Sending a malformed request (${v.desc}) triggered an error page that reveals ${v.label}. Attackers craft invalid requests to extract server internals from verbose error pages.`,
      evidence: `URL: ${v.url}\nTrigger: ${v.desc}\nLeak: ${v.label}\nResponse excerpt: ${v.text}`,
      remediation: "Configure custom error pages that return generic messages. Ensure your web server and application framework do not expose internals in any error condition.",
      cwe: "CWE-209",
      owasp: "A05:2021",
      codeSnippet: `// app/not-found.tsx — custom 404\nexport default function NotFound() {\n  return <div><h2>Page not found</h2></div>;\n}\n\n// app/error.tsx — custom error boundary\n"use client";\nexport default function Error({ reset }: { reset: () => void }) {\n  return <div><h2>Something went wrong</h2><button onClick={reset}>Retry</button></div>;\n}`,
    });
    break; // One finding is enough
  }

  // HTML comment leak — scan HTML responses for comments containing sensitive patterns
  const COMMENT_LEAK_PATTERNS: { pattern: RegExp; label: string }[] = [
    { pattern: /\bTODO\b/i, label: "TODO" },
    { pattern: /\bFIXME\b/i, label: "FIXME" },
    { pattern: /\bHACK\b/i, label: "HACK" },
    { pattern: /\bpassword\b/i, label: "password" },
    { pattern: /\btoken\b/i, label: "token" },
    { pattern: /\bapi[_-]?key\b/i, label: "api_key" },
    { pattern: /\binternal\b/i, label: "internal" },
    { pattern: /\bsecret\b/i, label: "secret" },
  ];

  // Fetch the main page and a few pages to check for HTML comments
  const pagesToCheck = [target.url, ...target.pages.slice(0, 4)];
  const commentLeaks: { page: string; comment: string; label: string }[] = [];

  const commentResults = await Promise.allSettled(
    pagesToCheck.map(async (pageUrl) => {
      try {
        const res = await scanFetch(pageUrl, { timeoutMs: 5000 });
        const text = await res.text();
        // Extract HTML comments
        const commentRegex = /<!--([\s\S]*?)-->/g;
        let match: RegExpExecArray | null;
        const found: { comment: string; label: string }[] = [];
        while ((match = commentRegex.exec(text)) !== null && found.length < 5) {
          const comment = match[1].trim();
          if (comment.length < 3 || comment.startsWith("[if ") || comment.startsWith("[endif")) continue;
          for (const lp of COMMENT_LEAK_PATTERNS) {
            if (lp.pattern.test(comment)) {
              found.push({ comment: comment.substring(0, 150), label: lp.label });
              break;
            }
          }
        }
        return { pageUrl, found };
      } catch { /* skip */ }
      return null;
    }),
  );

  for (const r of commentResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    for (const f of v.found) {
      commentLeaks.push({ page: v.pageUrl, comment: f.comment, label: f.label });
    }
  }

  if (commentLeaks.length > 0) {
    const grouped = new Map<string, string[]>();
    for (const cl of commentLeaks) {
      const existing = grouped.get(cl.label) ?? [];
      existing.push(cl.comment);
      grouped.set(cl.label, existing);
    }
    findings.push({
      id: "infoleak-html-comments",
      module: "Information Leakage",
      severity: "low",
      title: `Sensitive HTML comments found (${commentLeaks.length} across ${new Set(commentLeaks.map((c) => c.page)).size} page${new Set(commentLeaks.map((c) => c.page)).size > 1 ? "s" : ""})`,
      description: `HTML comments containing sensitive keywords (${[...grouped.keys()].join(", ")}) were found in page source. These comments may reveal internal notes, credentials, or implementation details to anyone viewing page source.`,
      evidence: commentLeaks.slice(0, 5).map((c) => `[${c.label}] ${c.comment}`).join("\n"),
      remediation: "Strip HTML comments from production builds. Use a build step or minifier that removes comments. Never include passwords, tokens, or internal notes in HTML comments.",
      cwe: "CWE-615",
      codeSnippet: `// next.config.ts — ensure comments are stripped in production\n// Next.js automatically minifies HTML in production builds.\n// For custom HTML, use a post-processing step:\nconst sanitized = html.replace(/<!--[\\s\\S]*?-->/g, "");\n\n// Or use terser/html-minifier in your build pipeline\n// to strip all comments from production output.`,
    });
  }

  // Check for dangerouslySetInnerHTML — only flag if excessive and no CSP
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
