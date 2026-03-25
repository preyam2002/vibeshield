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
  const [ssrResults, nextDataResults, bypassResults, internalResults, rscResult] = await Promise.all([
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
    });
  }

  return findings;
};
