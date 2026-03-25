import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const nextjsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  if (!target.technologies.includes("Next.js")) return findings;

  // Check for _next/data routes leaking SSR data
  const buildId = target.headers["x-nextjs-build-id"] || "";
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const buildIdMatch = allJs.match(/"buildId"\s*:\s*"([^"]+)"/);
  const detectedBuildId = buildId || buildIdMatch?.[1];

  const secretPatterns = [
    /[a-z_]*(?:password|passwd)['":\s]*['"][^'"]{4,}/i,
    /(?:sk-|sk_live_|sk_test_)[a-zA-Z0-9]{10,}/,
    /(?:AKIA|ASIA)[A-Z0-9]{16}/,
    /(?:mongodb\+srv|postgres|mysql|redis):\/\/[^\s"']+/,
    /(?:ghp_|ghs_)[a-zA-Z0-9]{36,}/,
    /eyJhbGciOi[A-Za-z0-9_-]{50,}/,
  ];

  const bypassHeaders = [
    { header: "x-middleware-prefetch", value: "1" },
    { header: "x-nextjs-data", value: "1" },
    { header: "purpose", value: "prefetch" },
    { header: "x-middleware-subrequest", value: "middleware" },
    { header: "x-middleware-subrequest", value: "src/middleware" },
    { header: "x-middleware-subrequest", value: "middleware:middleware:middleware:middleware:middleware" },
  ];

  // Run all checks in parallel
  const [ssrResults, nextDataResults, bypassResults, internalResults, rscResult, serverActionResult, imageSSRFResult, catchAllResult, previewResult, metadataResult] = await Promise.all([
    // SSR data routes
    detectedBuildId ? Promise.allSettled(
      target.pages.slice(0, 10).map(async (page) => {
        const pathname = new URL(page).pathname.replace(/\/$/, "") || "/index";
        const dataUrl = `${target.baseUrl}/_next/data/${detectedBuildId}${pathname}.json`;
        const res = await scanFetch(dataUrl);
        if (!res.ok) return null;
        const text = await res.text();
        if (text.length > 50 && /password|secret|token|api.?key|private/i.test(text)) {
          return { pathname, dataUrl, text: text.substring(0, 300) };
        }
        return null;
      }),
    ) : Promise.resolve([]),

    // __NEXT_DATA__ checks
    Promise.allSettled(
      [target.url, ...target.pages.slice(0, 5)].map(async (page) => {
        const res = await scanFetch(page);
        const html = await res.text();
        const nextDataMatch = html.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);
        if (!nextDataMatch) return null;
        const foundSecrets = secretPatterns.filter((p) => p.test(nextDataMatch[1]));
        if (foundSecrets.length > 0) return { pathname: new URL(page).pathname, count: foundSecrets.length };
        return null;
      }),
    ),

    // Middleware bypass — all endpoint+header combos in parallel
    Promise.allSettled(
      target.apiEndpoints.slice(0, 5).flatMap((endpoint) =>
        bypassHeaders.map(async ({ header, value }) => {
          const [res, normalRes] = await Promise.all([
            scanFetch(endpoint, { headers: { [header]: value } }),
            scanFetch(endpoint),
          ]);
          if (res.status === 200 && normalRes.status !== 200) {
            return { header, value, endpoint, pathname: new URL(endpoint).pathname, normalStatus: normalRes.status };
          }
          return null;
        }),
      ),
    ),

    // Internal routes
    Promise.allSettled(
      ["/_next/webpack-hmr", "/_next/static/development", "/__nextjs_original-stack-frame", "/_next/image?url="].map(async (path) => {
        const res = await scanFetch(target.baseUrl + path);
        if (res.ok && path.includes("development")) return { path, status: res.status };
        return null;
      }),
    ),

    // RSC payload
    scanFetch(target.url, { headers: { RSC: "1", "Next-Router-State-Tree": "%5B%22%22%5D" } })
      .then(async (res) => {
        if (!res.ok) return null;
        const text = await res.text();
        if (text.includes(":") && !text.startsWith("<!DOCTYPE") && /password|secret|api.?key|token|private/i.test(text)) {
          return { text: text.substring(0, 300) };
        }
        return null;
      }).catch(() => null),

    // Server Action enumeration — look for action IDs in JS bundles and test them
    (async () => {
      const actionIdPattern = /["']([a-f0-9]{40})["']/g;
      const actionIds: string[] = [];
      let m;
      while ((m = actionIdPattern.exec(allJs)) !== null && actionIds.length < 15) {
        if (!actionIds.includes(m[1])) actionIds.push(m[1]);
      }
      if (actionIds.length === 0) return null;

      // Test payloads — empty, proto pollution, and type confusion
      const payloads = [
        { body: JSON.stringify([]), desc: "empty args" },
        { body: JSON.stringify([{ __proto__: { admin: true } }]), desc: "proto pollution" },
        { body: JSON.stringify([null, null, null]), desc: "null args" },
      ];

      const results = await Promise.allSettled(
        actionIds.slice(0, 8).map(async (actionId) => {
          // First test: unauthenticated empty call
          const res = await scanFetch(target.url, {
            method: "POST",
            headers: {
              "Content-Type": "text/plain;charset=UTF-8",
              "Next-Action": actionId,
            },
            body: payloads[0].body,
            timeoutMs: 5000,
          });
          if (res.status !== 200 && res.status !== 303) return null;
          const text = await res.text();
          if (text.length <= 5) return null;

          // Check for sensitive data in response
          const hasSensitive = /password|secret|token|api.?key|private_key|credit|ssn|email.*@/i.test(text);

          // Second test: proto pollution via Server Action
          let protoVuln = false;
          try {
            const protoRes = await scanFetch(target.url, {
              method: "POST",
              headers: { "Content-Type": "text/plain;charset=UTF-8", "Next-Action": actionId },
              body: payloads[1].body,
              timeoutMs: 5000,
            });
            if (protoRes.ok) {
              const protoText = await protoRes.text();
              if (protoText.includes("admin") && !text.includes("admin")) protoVuln = true;
            }
          } catch { /* skip */ }

          return { actionId, status: res.status, text, hasSensitive, protoVuln };
        }),
      );

      const accepted: { actionId: string; status: number; text: string; hasSensitive: boolean; protoVuln: boolean }[] = [];
      for (const r of results) {
        if (r.status === "fulfilled" && r.value) accepted.push(r.value);
      }

      return accepted.length > 0 ? { count: accepted.length, total: actionIds.length, sample: accepted[0], hasSensitive: accepted.some((a) => a.hasSensitive), hasProtoVuln: accepted.some((a) => a.protoVuln) } : null;
    })(),

    // _next/image SSRF — test if image optimizer accepts arbitrary URLs
    scanFetch(`${target.baseUrl}/_next/image?url=${encodeURIComponent("https://example.com/test.png")}&w=64&q=75`, { timeoutMs: 5000 })
      .then(async (res) => {
        if (res.status === 200) {
          const ct = res.headers.get("content-type") || "";
          if (ct.includes("image")) return { status: 200, external: true };
        }
        return null;
      }).catch(() => null),

    // Catch-all API route exposure — [...slug] routes that accept arbitrary paths
    (async () => {
      const catchAllPaths = [
        "/api/[...slug]", "/api/[...catchAll]", "/api/[...params]",
        "/api/proxy/test", "/api/webhook/test", "/api/graphql",
        "/api/trpc/test", "/api/auth/test", "/api/v1/test",
      ];
      const results: { path: string; status: number; text: string }[] = [];
      const settled = await Promise.allSettled(
        catchAllPaths.map(async (path) => {
          const res = await scanFetch(`${target.baseUrl}${path}`, { timeoutMs: 5000 });
          if (res.ok) {
            const text = await res.text();
            // Skip if it's a generic 404 page served as 200
            if (text.length > 50 && !/not found|404/i.test(text.substring(0, 200))) {
              return { path, status: res.status, text: text.substring(0, 300) };
            }
          }
          return null;
        }),
      );
      for (const r of settled) {
        if (r.status === "fulfilled" && r.value) results.push(r.value);
      }
      return results.length > 0 ? results : null;
    })(),

    // ISR/Preview mode token leak — check for __prerender_bypass and __next_preview_data cookies
    (async () => {
      // Check if preview mode endpoints leak tokens
      const previewPaths = ["/api/preview", "/api/draft", "/api/enable-preview", "/api/exit-preview"];
      const results: { path: string; cookies: string[] }[] = [];
      const settled = await Promise.allSettled(
        previewPaths.map(async (path) => {
          const res = await scanFetch(`${target.baseUrl}${path}`, { timeoutMs: 5000 });
          const setCookies = res.headers.get("set-cookie") || "";
          const leaked: string[] = [];
          if (setCookies.includes("__prerender_bypass")) leaked.push("__prerender_bypass");
          if (setCookies.includes("__next_preview_data")) leaked.push("__next_preview_data");
          if (leaked.length > 0) return { path, cookies: leaked };
          return null;
        }),
      );
      for (const r of settled) {
        if (r.status === "fulfilled" && r.value) results.push(r.value);
      }
      // Also check JS bundles for leaked preview tokens
      const previewBypassMatch = allJs.match(/__prerender_bypass["']\s*[:=]\s*["']([^"']{10,})["']/);
      const previewDataMatch = allJs.match(/__next_preview_data["']\s*[:=]\s*["']([^"']{10,})["']/);
      if (previewBypassMatch || previewDataMatch) {
        results.push({ path: "JS bundle", cookies: [previewBypassMatch ? "__prerender_bypass" : "", previewDataMatch ? "__next_preview_data" : ""].filter(Boolean) });
      }
      return results.length > 0 ? results : null;
    })(),

    // App directory metadata exposure — check for leaked metadata, sitemap, robots with internal paths
    (async () => {
      const metaPaths = [
        "/sitemap.xml", "/robots.txt", "/manifest.json", "/manifest.webmanifest",
        "/.well-known/openid-configuration", "/opengraph-image", "/twitter-image",
        "/favicon.ico", "/apple-icon",
      ];
      const leaks: { path: string; issue: string }[] = [];
      const settled = await Promise.allSettled(
        metaPaths.map(async (path) => {
          const res = await scanFetch(`${target.baseUrl}${path}`, { timeoutMs: 5000 });
          if (!res.ok) return null;
          const text = await res.text();
          // Check sitemap for internal/staging URLs
          if (path === "/sitemap.xml") {
            const internalUrls = text.match(/https?:\/\/(?:localhost|127\.0\.0\.1|staging|dev|internal)[^\s<]*/gi);
            if (internalUrls && internalUrls.length > 0) {
              return { path, issue: `Sitemap contains internal URLs: ${internalUrls.slice(0, 3).join(", ")}` };
            }
            // Check for admin/internal paths in sitemap
            const adminPaths = text.match(/<loc>[^<]*(?:admin|internal|debug|test|staging)[^<]*<\/loc>/gi);
            if (adminPaths && adminPaths.length > 0) {
              return { path, issue: `Sitemap exposes sensitive paths: ${adminPaths.slice(0, 3).join(", ")}` };
            }
          }
          // Check robots.txt for sensitive Disallow entries
          if (path === "/robots.txt") {
            const disallowed = text.match(/Disallow:\s*\/\S+/gi) || [];
            const sensitive = disallowed.filter((d) => /admin|api|internal|secret|private|dashboard|debug|staging/i.test(d));
            if (sensitive.length >= 3) {
              return { path, issue: `robots.txt reveals ${sensitive.length} sensitive paths: ${sensitive.slice(0, 5).join(", ")}` };
            }
          }
          // Check manifest for internal URLs or debug info
          if (path.includes("manifest")) {
            if (/localhost|127\.0\.0\.1|staging\.|internal\./i.test(text)) {
              return { path, issue: "Manifest contains internal/staging URLs" };
            }
          }
          return null;
        }),
      );
      for (const r of settled) {
        if (r.status === "fulfilled" && r.value) leaks.push(r.value);
      }
      return leaks.length > 0 ? leaks : null;
    })(),
  ]);

  // Collect SSR data leak findings
  for (const r of ssrResults) {
    if ((r as PromiseSettledResult<unknown>).status !== "fulfilled") continue;
    const v = (r as PromiseFulfilledResult<{ pathname: string; dataUrl: string; text: string } | null>).value;
    if (!v) continue;
    findings.push({
      id: `nextjs-data-leak-${findings.length}`, module: "Next.js", severity: "high",
      title: `Sensitive data in SSR props for ${v.pathname}`,
      description: "Next.js SSR data route contains sensitive-looking fields.",
      evidence: `URL: ${v.dataUrl}\nPreview: ${v.text}`,
      remediation: "Only pass necessary data to the client via getServerSideProps.",
      cwe: "CWE-200",
      codeSnippet: `// Only return what the client needs\nexport const getServerSideProps: GetServerSideProps = async (ctx) => {\n  const user = await getUser(ctx);\n  return { props: { name: user.name } }; // not the full user object\n};`,
    });
  }

  // Collect __NEXT_DATA__ findings (first hit only)
  for (const r of nextDataResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `nextjs-next-data-leak-0`, module: "Next.js", severity: "critical",
      title: `Secrets leaked in __NEXT_DATA__ on ${r.value.pathname}`,
      description: "The __NEXT_DATA__ script tag contains real secrets.",
      evidence: `Found ${r.value.count} secret pattern(s) in __NEXT_DATA__`,
      remediation: "Never return secrets in getServerSideProps/getStaticProps.",
      cwe: "CWE-200", owasp: "A01:2021",
      codeSnippet: `// Move secrets to server-only code\nimport "server-only";\n\n// Use environment variables only on the server\nconst data = await fetch(url, {\n  headers: { Authorization: \`Bearer \${process.env.API_SECRET}\` },\n});\nreturn { props: { items: data.items } }; // never forward the token`,
    });
    break;
  }

  // Collect middleware bypass findings (deduplicate by header)
  const seenBypassHeaders = new Set<string>();
  for (const r of bypassResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (seenBypassHeaders.has(v.header)) continue;
    seenBypassHeaders.add(v.header);
    findings.push({
      id: `nextjs-middleware-bypass-${findings.length}`, module: "Next.js", severity: "high",
      title: `Middleware bypass via ${v.header} header`,
      description: `Adding ${v.header}: ${v.value} bypasses middleware on ${v.pathname}.`,
      evidence: `Without header: ${v.normalStatus}\nWith ${v.header}: ${v.value}: 200`,
      remediation: "Don't rely solely on middleware for authentication.",
      cwe: "CWE-863", owasp: "A01:2021",
      codeSnippet: `// Verify auth in the route handler, not just middleware\n// app/api/admin/route.ts\nimport { getServerSession } from "next-auth";\n\nexport async function GET(req: Request) {\n  const session = await getServerSession();\n  if (!session?.user) return Response.json({ error: "Unauthorized" }, { status: 401 });\n}`,
    });
  }

  // Collect internal route findings
  for (const r of internalResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `nextjs-dev-exposed-${findings.length}`, module: "Next.js", severity: "high",
      title: `Next.js development artifacts accessible: ${r.value.path}`,
      description: "Development-only routes are accessible in production.",
      evidence: `GET ${target.baseUrl + r.value.path} → ${r.value.status}`,
      remediation: "Ensure NODE_ENV=production in your deployment.",
      cwe: "CWE-489",
      codeSnippet: `// Dockerfile\nENV NODE_ENV=production\nRUN npm run build\nCMD ["npm", "start"]\n\n// next.config.ts — block dev routes in production\nconst nextConfig = { poweredByHeader: false };`,
    });
  }

  // Server Action findings
  if (serverActionResult) {
    const severity = serverActionResult.hasProtoVuln ? "critical" : serverActionResult.hasSensitive ? "high" : serverActionResult.count >= 3 ? "medium" : "low";
    const extraInfo = [
      serverActionResult.hasProtoVuln && "Prototype pollution accepted via Server Action",
      serverActionResult.hasSensitive && "Sensitive data returned in Server Action response",
    ].filter(Boolean).join(". ");
    findings.push({
      id: "nextjs-server-actions-exposed", module: "Next.js", severity,
      title: `${serverActionResult.count}/${serverActionResult.total} Server Actions accept unauthenticated requests`,
      description: `Next.js Server Actions were found to accept POST requests without authentication. Server Actions are direct function calls from client to server — if they perform sensitive operations (database writes, payments, etc.), they should validate the caller's identity.${extraInfo ? ` ${extraInfo}.` : ""}`,
      evidence: `Tested ${serverActionResult.total} action IDs found in JS bundle.\n${serverActionResult.count} accepted requests.\nSample action: ${serverActionResult.sample.actionId}\nResponse: ${serverActionResult.sample.text.substring(0, 200)}`,
      remediation: "Add authentication checks inside each Server Action. Don't rely on middleware alone. Validate and sanitize all input — Server Actions are public API endpoints.",
      cwe: serverActionResult.hasProtoVuln ? "CWE-1321" : "CWE-306", owasp: "A07:2021",
      codeSnippet: `// Always verify auth inside Server Actions\n"use server";\nimport { getServerSession } from "next-auth";\nimport { z } from "zod";\n\nconst schema = z.object({ name: z.string().max(100) });\n\nexport async function updateProfile(data: FormData) {\n  const session = await getServerSession();\n  if (!session) throw new Error("Unauthorized");\n  const parsed = schema.parse(Object.fromEntries(data));\n  // ... safe to proceed with validated input\n}`,
    });
  }

  // _next/image SSRF finding
  if (imageSSRFResult?.external) {
    findings.push({
      id: "nextjs-image-ssrf", module: "Next.js", severity: "medium",
      title: "Next.js Image Optimization accepts external URLs",
      description: "The /_next/image endpoint proxies arbitrary external URLs. This can be abused for SSRF (scanning internal networks), bandwidth amplification, or accessing internal services.",
      evidence: `/_next/image?url=https://example.com/test.png → 200 (image proxied)`,
      remediation: "Restrict allowed image domains in next.config.ts using the remotePatterns option.",
      cwe: "CWE-918", owasp: "A10:2021",
      codeSnippet: `// next.config.ts — restrict image optimization to known domains\nconst nextConfig = {\n  images: {\n    remotePatterns: [\n      { protocol: "https", hostname: "your-cdn.com" },\n      { protocol: "https", hostname: "avatars.githubusercontent.com" },\n    ],\n  },\n};`,
    });
  }

  // Catch-all API route findings
  if (catchAllResult) {
    const paths = catchAllResult.map((r) => r.path).join(", ");
    findings.push({
      id: "nextjs-catchall-routes", module: "Next.js", severity: "medium",
      title: `${catchAllResult.length} catch-all API route(s) accepting arbitrary paths`,
      description: `Catch-all routes (like [...slug]) were found responding to arbitrary path segments. These routes often proxy requests or handle dynamic routing — if they don't validate the path, they can be abused for SSRF, path traversal, or accessing unintended resources.`,
      evidence: catchAllResult.map((r) => `${r.path} → ${r.status}: ${r.text.substring(0, 100)}`).join("\n"),
      remediation: "Validate and allowlist accepted path segments in catch-all routes. Don't forward arbitrary paths to backends.",
      cwe: "CWE-20", owasp: "A01:2021",
      codeSnippet: `// Validate catch-all route params\nexport async function GET(req: Request, { params }: { params: { slug: string[] } }) {\n  const ALLOWED = new Set(["users", "posts", "products"]);\n  if (!ALLOWED.has(params.slug[0])) {\n    return Response.json({ error: "Not found" }, { status: 404 });\n  }\n  // ... handle known routes only\n}`,
      confidence: 65,
    });
  }

  // Preview/ISR token leak findings
  if (previewResult) {
    const leaked = previewResult.flatMap((r) => r.cookies);
    const paths = previewResult.map((r) => r.path).join(", ");
    findings.push({
      id: "nextjs-preview-token-leak", module: "Next.js",
      severity: previewResult.some((r) => r.path === "JS bundle") ? "high" : "medium",
      title: "Next.js preview/ISR tokens exposed",
      description: `Preview mode tokens (${[...new Set(leaked)].join(", ")}) were found ${previewResult.some((r) => r.path === "JS bundle") ? "in client-side JavaScript" : `via unauthenticated requests to ${paths}`}. These tokens allow bypassing ISR cache and viewing draft content. An attacker with these tokens can see unpublished content or bypass caching.`,
      evidence: previewResult.map((r) => `${r.path}: ${r.cookies.join(", ")}`).join("\n"),
      remediation: "Protect preview mode endpoints with authentication. Never expose preview tokens in client-side code. Use Next.js Draft Mode with proper auth checks.",
      cwe: "CWE-200", owasp: "A01:2021",
      codeSnippet: `// Protect preview endpoint with a secret\nexport async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  if (searchParams.get("secret") !== process.env.PREVIEW_SECRET) {\n    return Response.json({ error: "Invalid token" }, { status: 401 });\n  }\n  // Enable draft mode\n  const draft = await import("next/headers").then((m) => m.draftMode());\n  draft.enable();\n  return Response.redirect("/");\n}`,
      confidence: 85,
    });
  }

  // App directory metadata exposure findings
  if (metadataResult) {
    for (const leak of metadataResult.slice(0, 2)) {
      findings.push({
        id: `nextjs-metadata-leak-${findings.length}`, module: "Next.js",
        severity: leak.path === "/sitemap.xml" ? "medium" : "low",
        title: `Information disclosure via ${leak.path}`,
        description: leak.issue,
        evidence: `GET ${target.baseUrl}${leak.path}\n${leak.issue}`,
        remediation: leak.path === "/robots.txt"
          ? "Review robots.txt — Disallow entries reveal paths to attackers. Use authentication instead of obscurity."
          : "Remove internal/staging URLs from public metadata files. Use environment-aware generation.",
        cwe: "CWE-200",
        confidence: 90,
      });
    }
  }

  // Check for process.env or config objects leaked in API responses
  const envLeakResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 8).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const text = await res.text();
      // Look for patterns suggesting full env/config dump
      const envIndicators = [
        /DATABASE_URL.*postgres/i,
        /NEXT_PUBLIC_[\s\S]*NEXT_PUBLIC_[\s\S]*NEXT_PUBLIC_/,
        /NODE_ENV[\s\S]*HOSTNAME[\s\S]*HOME/,
        /AWS_SECRET_ACCESS_KEY/i,
        /SUPABASE_SERVICE_ROLE_KEY/i,
        /process\.env/i,
      ];
      const matched = envIndicators.filter((p) => p.test(text));
      if (matched.length >= 2) {
        return { pathname: new URL(endpoint).pathname, text: text.substring(0, 300) };
      }
      return null;
    }),
  );

  for (const r of envLeakResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `nextjs-env-dump-${findings.length}`,
      module: "Next.js",
      severity: "critical",
      title: `Environment variables leaked via ${r.value.pathname}`,
      description: "An API route appears to return server environment variables. This exposes database credentials, API keys, and other secrets.",
      evidence: `GET ${r.value.pathname}\nResponse: ${r.value.text}`,
      remediation: "Never return process.env or config objects from API routes. Only return specific, safe values.",
      cwe: "CWE-200",
      owasp: "A01:2021",
      codeSnippet: `// BAD: returning env in API route\nexport async function GET() {\n  return Response.json(process.env); // NEVER do this\n}\n\n// GOOD: return only what's needed\nexport async function GET() {\n  return Response.json({ version: "1.0.0", env: "production" });\n}`,
    });
    break;
  }

  // RSC finding
  if (rscResult) {
    findings.push({
      id: "nextjs-rsc-data-leak", module: "Next.js", severity: "high",
      title: "Sensitive data in React Server Component payload",
      description: "RSC payload contains sensitive-looking data.",
      evidence: `RSC payload preview: ${rscResult.text}`,
      remediation: "Audit what data your Server Components pass to Client Components.",
      cwe: "CWE-200",
      codeSnippet: `// Only pass serializable, non-sensitive props to Client Components\n// app/dashboard/page.tsx (Server Component)\nimport { ClientView } from "./client-view";\n\nexport default async function Page() {\n  const data = await getSecureData();\n  return <ClientView summary={data.publicSummary} />; // not the full object\n}`,
    });
  }

  return findings;
};
