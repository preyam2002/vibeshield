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
  const [ssrResults, nextDataResults, bypassResults, internalResults, rscResult, serverActionResult, imageSSRFResult] = await Promise.all([
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
      while ((m = actionIdPattern.exec(allJs)) !== null && actionIds.length < 10) {
        if (!actionIds.includes(m[1])) actionIds.push(m[1]);
      }
      if (actionIds.length === 0) return null;

      const results = await Promise.allSettled(
        actionIds.slice(0, 5).map(async (actionId) => {
          const res = await scanFetch(target.url, {
            method: "POST",
            headers: {
              "Content-Type": "text/plain;charset=UTF-8",
              "Next-Action": actionId,
            },
            body: JSON.stringify([]),
            timeoutMs: 5000,
          });
          if (res.status === 200 || res.status === 303) {
            const text = await res.text();
            if (text.length > 5) return { actionId, status: res.status, text };
          }
          return null;
        }),
      );

      const accepted: { actionId: string; status: number; text: string }[] = [];
      for (const r of results) {
        if (r.status === "fulfilled" && r.value) accepted.push(r.value);
      }

      return accepted.length > 0 ? { count: accepted.length, total: actionIds.length, sample: accepted[0] } : null;
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
    findings.push({
      id: "nextjs-server-actions-exposed", module: "Next.js",
      severity: serverActionResult.count >= 3 ? "medium" : "low",
      title: `${serverActionResult.count}/${serverActionResult.total} Server Actions accept unauthenticated requests`,
      description: "Next.js Server Actions were found to accept POST requests without authentication. Server Actions are direct function calls from client to server — if they perform sensitive operations (database writes, payments, etc.), they should validate the caller's identity.",
      evidence: `Tested ${serverActionResult.total} action IDs found in JS bundle.\n${serverActionResult.count} accepted requests.\nSample action: ${serverActionResult.sample.actionId}\nResponse: ${serverActionResult.sample.text.substring(0, 200)}`,
      remediation: "Add authentication checks inside each Server Action. Don't rely on middleware alone.",
      cwe: "CWE-306", owasp: "A07:2021",
      codeSnippet: `// Always verify auth inside Server Actions\n"use server";\nimport { getServerSession } from "next-auth";\n\nexport async function updateProfile(data: FormData) {\n  const session = await getServerSession();\n  if (!session) throw new Error("Unauthorized");\n  // ... safe to proceed\n}`,
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
