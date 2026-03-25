import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const sourceMapsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const exposedMaps: string[] = [];
  const conventionMaps: string[] = [];
  const inlineSourceMaps: string[] = [];

  // Build list of source map URLs from JS bundles
  const mapUrlsToCheck: string[] = [];
  for (const [scriptUrl, content] of target.jsContents) {
    const mapMatch = content.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
    if (!mapMatch) continue;
    let mapUrl = mapMatch[1];
    // Track inline source maps (data: URIs) — full source code embedded in the bundle
    if (mapUrl.startsWith("data:")) {
      inlineSourceMaps.push(scriptUrl);
      continue;
    }
    if (!mapUrl.startsWith("http")) mapUrl = new URL(mapUrl, scriptUrl).href;
    mapUrlsToCheck.push(mapUrl);
  }

  // Check SourceMap HTTP headers on JS files (some servers serve maps via header instead of comment)
  const headerMapUrls: string[] = [];
  const headerResults = await Promise.allSettled(
    target.scripts.slice(0, 15).map(async (scriptUrl) => {
      const res = await scanFetch(scriptUrl, { method: "HEAD", timeoutMs: 5000 });
      const mapHeader = res.headers.get("sourcemap") || res.headers.get("x-sourcemap");
      if (mapHeader) {
        const mapUrl = mapHeader.startsWith("http") ? mapHeader : new URL(mapHeader, scriptUrl).href;
        return mapUrl;
      }
      return null;
    }),
  );
  for (const r of headerResults) {
    if (r.status === "fulfilled" && r.value && !mapUrlsToCheck.includes(r.value)) {
      headerMapUrls.push(r.value);
      mapUrlsToCheck.push(r.value);
    }
  }

  // Check all source maps and convention maps in parallel
  const conventionUrls = target.scripts.slice(0, 25).map((s) => s + ".map");

  const [mapResults, conventionResults] = await Promise.all([
    Promise.allSettled(
      mapUrlsToCheck.map(async (mapUrl) => {
        const res = await scanFetch(mapUrl, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        try {
          const json = JSON.parse(text) as { version?: number; sources?: string[]; mappings?: string; sourcesContent?: string[] };
          if (json.version && json.sources && json.mappings) {
            const sensitiveFiles = json.sources.filter((s) =>
              /\.env|config|secret|credential|password|\.pem|\.key|admin|internal/i.test(s),
            );
            const leakedSecrets: string[] = [];
            if (json.sourcesContent) {
              for (const content of json.sourcesContent.slice(0, 20)) {
                if (!content) continue;
                if (/(?:sk_live|sk_test)_[a-zA-Z0-9]{20,}/.test(content)) leakedSecrets.push("Stripe secret key");
                if (/(?:SUPABASE_SERVICE_ROLE|service_role).*eyJ/.test(content)) leakedSecrets.push("Supabase service role key");
                if (/(?:DATABASE_URL|MONGO_URI|REDIS_URL)\s*=\s*\S+/.test(content)) leakedSecrets.push("Database connection string");
                if (/-----BEGIN (?:RSA )?PRIVATE KEY-----/.test(content)) leakedSecrets.push("Private key");
              }
            }
            return { url: mapUrl, sourceCount: json.sources.length, sensitiveFiles, leakedSecrets };
          }
        } catch { /* skip */ }
        return null;
      }),
    ),
    Promise.allSettled(
      conventionUrls.map(async (mapUrl) => {
        const res = await scanFetch(mapUrl, { timeoutMs: 5000 });
        if (res.ok && (res.headers.get("content-type") || "").includes("json")) return mapUrl;
        return null;
      }),
    ),
  ]);

  const mapData: { url: string; sourceCount: number; sensitiveFiles: string[]; leakedSecrets: string[] }[] = [];
  for (const r of mapResults) {
    if (r.status === "fulfilled" && r.value) {
      mapData.push(r.value);
      exposedMaps.push(r.value.url);
    }
  }

  const allSensitiveFiles = mapData.flatMap((m) => m.sensitiveFiles);
  const allLeakedSecrets = [...new Set(mapData.flatMap((m) => m.leakedSecrets))];
  const totalSources = mapData.reduce((sum, m) => sum + m.sourceCount, 0);

  if (exposedMaps.length > 0) {
    const severity = allLeakedSecrets.length > 0 ? "critical" : "high";
    findings.push({
      id: "sourcemaps-exposed",
      module: "Source Maps",
      severity,
      title: `${exposedMaps.length} source map${exposedMaps.length > 1 ? "s" : ""} publicly accessible${allLeakedSecrets.length > 0 ? " (secrets found!)" : ""}`,
      description: `Source maps are accessible, exposing ${totalSources} source files including comments, variable names, and business logic.${allSensitiveFiles.length > 0 ? ` Sensitive files found: ${allSensitiveFiles.slice(0, 5).join(", ")}.` : ""}${allLeakedSecrets.length > 0 ? ` SECRETS LEAKED: ${allLeakedSecrets.join(", ")}.` : ""}`,
      evidence: `Accessible source maps:\n${exposedMaps.slice(0, 5).join("\n")}${exposedMaps.length > 5 ? `\n...and ${exposedMaps.length - 5} more` : ""}${allLeakedSecrets.length > 0 ? `\n\nLeaked secrets: ${allLeakedSecrets.join(", ")}` : ""}${allSensitiveFiles.length > 0 ? `\n\nSensitive source files: ${allSensitiveFiles.slice(0, 10).join(", ")}` : ""}`,
      remediation: `Disable source maps in production.${allLeakedSecrets.length > 0 ? " IMMEDIATELY rotate all leaked secrets." : ""} For Next.js: set productionBrowserSourceMaps: false in next.config.js. For Vite: set build.sourcemap: false.`,
      cwe: "CWE-540",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts\nexport default {\n  productionBrowserSourceMaps: false,\n};\n\n// vite.config.ts\nexport default defineConfig({\n  build: { sourcemap: false },\n});`,
    });
  }

  const knownMaps = new Set(exposedMaps);
  for (const r of conventionResults) {
    if (r.status === "fulfilled" && r.value && !knownMaps.has(r.value)) conventionMaps.push(r.value);
  }

  if (conventionMaps.length > 0) {
    findings.push({
      id: "sourcemaps-convention",
      module: "Source Maps",
      severity: "high",
      title: `${conventionMaps.length} source map${conventionMaps.length > 1 ? "s" : ""} found via .js.map convention`,
      description: "Source map files were found by appending .map to JavaScript URLs. Your source code may be fully readable.",
      evidence: `Accessible:\n${conventionMaps.slice(0, 5).join("\n")}${conventionMaps.length > 5 ? `\n...and ${conventionMaps.length - 5} more` : ""}`,
      remediation: "Block access to .map files in production or disable source map generation.",
      cwe: "CWE-540",
      codeSnippet: `// next.config.ts\nexport default {\n  productionBrowserSourceMaps: false,\n};\n\n// Or block in middleware:\nif (req.nextUrl.pathname.endsWith(".map")) {\n  return new Response(null, { status: 404 });\n}`,
    });
  }

  // Inline source maps — full source embedded as base64 data: URI in the bundle
  if (inlineSourceMaps.length > 0) {
    findings.push({
      id: "sourcemaps-inline",
      module: "Source Maps",
      severity: "high",
      title: `${inlineSourceMaps.length} inline source map${inlineSourceMaps.length > 1 ? "s" : ""} embedded in JS bundles`,
      description: "Source maps are embedded directly in JavaScript bundles as base64 data: URIs. Anyone downloading the JS file gets full access to your original source code — no separate .map file request needed.",
      evidence: `Scripts with inline source maps:\n${inlineSourceMaps.slice(0, 5).map((u) => new URL(u).pathname).join("\n")}${inlineSourceMaps.length > 5 ? `\n...and ${inlineSourceMaps.length - 5} more` : ""}`,
      remediation: "Disable inline source maps in production. For webpack: devtool: false. For Vite: build.sourcemap: false. For Next.js: productionBrowserSourceMaps: false.",
      cwe: "CWE-540",
      owasp: "A05:2021",
      confidence: 95,
      codeSnippet: `// webpack.config.js\nmodule.exports = {\n  mode: "production",\n  devtool: false, // No source maps in production\n};\n\n// vite.config.ts\nexport default defineConfig({\n  build: { sourcemap: false },\n});`,
    });
  }

  // SourceMap HTTP header exposure
  if (headerMapUrls.length > 0) {
    findings.push({
      id: "sourcemaps-header",
      module: "Source Maps",
      severity: "medium",
      title: `SourceMap header exposes ${headerMapUrls.length} source map URL${headerMapUrls.length > 1 ? "s" : ""}`,
      description: "JavaScript files return a SourceMap or X-SourceMap HTTP header pointing to source map files. Even if the sourceMappingURL comment is stripped, browser DevTools and attackers can find source maps via this header.",
      evidence: `SourceMap headers found:\n${headerMapUrls.slice(0, 5).join("\n")}`,
      remediation: "Remove SourceMap and X-SourceMap response headers in production. Configure your CDN/reverse proxy to strip these headers.",
      cwe: "CWE-540",
      confidence: 90,
      codeSnippet: `// Vercel — vercel.json\n{\n  "headers": [\n    {\n      "source": "/(.*)\\\\.js$",\n      "headers": [\n        { "key": "SourceMap", "value": "" },\n        { "key": "X-SourceMap", "value": "" }\n      ]\n    }\n  ]\n}\n\n// Nginx\nlocation ~* \\.js$ {\n  more_clear_headers "SourceMap" "X-SourceMap";\n}`,
    });
  }

  // Build manifest / chunk map discovery — exposes internal module structure
  const origin = new URL(target.url).origin;
  const manifestPaths = [
    "/_next/static/build-manifest.json",         // Next.js
    "/_next/static/react-loadable-manifest.json", // Next.js
    "/asset-manifest.json",                       // CRA
    "/manifest.json",                             // Various (skip if it's a PWA manifest)
    "/stats.json",                                // Webpack stats
    "/webpack-manifest.json",                     // Webpack
    "/build/asset-manifest.json",                 // CRA alt
  ];

  const manifestResults = await Promise.allSettled(
    manifestPaths.map(async (path) => {
      const res = await scanFetch(`${origin}${path}`, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const text = await res.text();
      try {
        const json = JSON.parse(text);
        // Skip PWA manifests (they have "name" and "icons" but not build info)
        if (json.name && json.icons && !json.pages && !json.files && !json.entrypoints) return null;
        const keys = Object.keys(json);
        // Must look like a build manifest (has pages, files, entrypoints, assets, etc.)
        if (keys.some((k) => /pages|files|entrypoints|assets|chunks|modules/i.test(k))) {
          return { path, keyCount: keys.length, sampleKeys: keys.slice(0, 10) };
        }
      } catch { /* skip */ }
      return null;
    }),
  );

  const foundManifests = manifestResults
    .filter((r) => r.status === "fulfilled" && r.value)
    .map((r) => (r as PromiseFulfilledResult<{ path: string; keyCount: number; sampleKeys: string[] }>).value);

  if (foundManifests.length > 0) {
    const isStats = foundManifests.some((m) => m.path.includes("stats.json"));
    findings.push({
      id: "sourcemaps-manifest",
      module: "Source Maps",
      severity: isStats ? "high" : "medium",
      title: `Build manifest${foundManifests.length > 1 ? "s" : ""} exposed: ${foundManifests.map((m) => m.path).join(", ")}`,
      description: `Build manifest files are publicly accessible, revealing internal module structure, route names, and chunk mappings.${isStats ? " The webpack stats.json file is especially sensitive — it contains the full module dependency tree and can expose internal paths." : ""} Attackers use this to map your application's architecture.`,
      evidence: foundManifests.map((m) => `${m.path} (${m.keyCount} keys): ${m.sampleKeys.join(", ")}`).join("\n"),
      remediation: "Block access to build manifests in production. For Next.js, these are served by default — use middleware to block requests to /_next/static/*-manifest.json.",
      cwe: "CWE-200",
      owasp: "A05:2021",
      confidence: 85,
      codeSnippet: `// Next.js middleware to block manifest access\nimport { NextResponse, type NextRequest } from "next/server";\n\nexport function middleware(req: NextRequest) {\n  if (req.nextUrl.pathname.match(/manifest\\.json$|stats\\.json$/)) {\n    return new NextResponse(null, { status: 404 });\n  }\n}`,
    });
  }

  // Environment leak detection in source content — scan for .env patterns in JS bundles
  const envLeaks: { file: string; vars: string[] }[] = [];
  const envPattern = /(?:process\.env\.(?!NODE_ENV|NEXT_PUBLIC_)([A-Z][A-Z0-9_]{2,}))\s*(?:===?\s*["']([^"']+)["']|:\s*["']([^"']+)["'])/g;
  for (const [scriptUrl, content] of target.jsContents) {
    const matches: string[] = [];
    let m: RegExpExecArray | null;
    while ((m = envPattern.exec(content)) !== null) {
      const varName = m[1];
      if (/^(DATABASE|SUPABASE_SERVICE|STRIPE_SECRET|SECRET|PRIVATE|AWS_SECRET|OPENAI_API|ANTHROPIC_API|REDIS|MONGO)/i.test(varName)) {
        matches.push(varName);
      }
    }
    if (matches.length > 0) {
      envLeaks.push({ file: new URL(scriptUrl).pathname, vars: [...new Set(matches)] });
    }
  }

  if (envLeaks.length > 0) {
    const allVars = [...new Set(envLeaks.flatMap((e) => e.vars))];
    findings.push({
      id: "sourcemaps-env-leak",
      module: "Source Maps",
      severity: "critical",
      title: `Server-side environment variables referenced in client JS: ${allVars.slice(0, 3).join(", ")}${allVars.length > 3 ? ` +${allVars.length - 3} more` : ""}`,
      description: `Client-side JavaScript bundles contain references to server-only environment variables (${allVars.join(", ")}). These may have been accidentally included in client bundles via improper env configuration. Even if the actual values aren't present, the variable names reveal your infrastructure.`,
      evidence: envLeaks.map((e) => `${e.file}: ${e.vars.join(", ")}`).join("\n"),
      remediation: "Ensure server-only env vars are never imported in client code. In Next.js, only NEXT_PUBLIC_ prefixed vars are safe for client bundles. Use server-only packages to prevent accidental client imports.",
      cwe: "CWE-200",
      owasp: "A05:2021",
      confidence: 70,
      codeSnippet: `// next.config.ts — don't expose server env vars\n// Only NEXT_PUBLIC_ vars are included in client bundles\n// If you see DATABASE_URL in client code, you have a leak\n\n// Use the "server-only" package to prevent client imports\n// lib/db.ts\nimport "server-only";\nimport { createClient } from "@supabase/supabase-js";\nexport const adminClient = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);`,
    });
  }

  return findings;
};
