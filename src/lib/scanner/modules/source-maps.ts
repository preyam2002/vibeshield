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

  // Webpack chunk source maps — probe well-known paths for bundler source maps
  const chunkMapPaths = [
    "/static/js/main.js.map",
    "/static/js/bundle.js.map",
    "/static/js/vendor.js.map",
    "/static/js/runtime.js.map",
    "/static/js/0.chunk.js.map",
    "/static/js/1.chunk.js.map",
    "/static/js/2.chunk.js.map",
    "/_next/static/chunks/main.js.map",
    "/_next/static/chunks/webpack.js.map",
    "/_next/static/chunks/framework.js.map",
    "/_next/static/chunks/pages/_app.js.map",
    "/_next/static/chunks/pages/index.js.map",
  ];

  const chunkMapResults = await Promise.allSettled(
    chunkMapPaths.map(async (path) => {
      const url = `${new URL(target.url).origin}${path}`;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const text = await res.text();
      try {
        const json = JSON.parse(text) as { version?: number; sources?: string[]; mappings?: string };
        if (json.version && json.sources && json.mappings) {
          return { path, sourceCount: json.sources.length };
        }
      } catch { /* skip */ }
      return null;
    }),
  );

  const foundChunkMaps = chunkMapResults
    .filter((r) => r.status === "fulfilled" && r.value)
    .map((r) => (r as PromiseFulfilledResult<{ path: string; sourceCount: number }>).value);

  if (foundChunkMaps.length > 0) {
    const totalSrc = foundChunkMaps.reduce((sum, m) => sum + m.sourceCount, 0);
    findings.push({
      id: "sourcemaps-chunk-maps",
      module: "Source Maps",
      severity: "high",
      title: `${foundChunkMaps.length} webpack/Next.js chunk source map${foundChunkMaps.length > 1 ? "s" : ""} exposed`,
      description: `Source map files for bundled chunks are accessible at well-known paths, exposing ${totalSrc} source files. Attackers can reconstruct your full application source code.`,
      evidence: `Accessible chunk source maps:\n${foundChunkMaps.map((m) => `${m.path} (${m.sourceCount} sources)`).join("\n")}`,
      remediation: "Disable source map generation in production builds. For Next.js: productionBrowserSourceMaps: false. For CRA: set GENERATE_SOURCEMAP=false. For webpack: devtool: false.",
      cwe: "CWE-540",
      owasp: "A05:2021",
      confidence: 90,
      codeSnippet: `// .env (Create React App)\nGENERATE_SOURCEMAP=false\n\n// next.config.ts\nexport default {\n  productionBrowserSourceMaps: false,\n};\n\n// webpack.config.js\nmodule.exports = {\n  mode: "production",\n  devtool: false,\n};`,
    });
  }

  // Hidden directory source maps & webpack internals
  const hiddenMapPaths = [
    { path: "/__webpack_hmr", title: "Webpack HMR endpoint exposed", description: "Webpack Hot Module Replacement endpoint is accessible in production — indicates a development server is running publicly, exposing module update streams and internal build details." },
    { path: "/.webpack/", title: "Webpack internal directory exposed", description: "The .webpack directory is accessible, potentially exposing compiled bundles, module manifests, and build configuration." },
    { path: "/webpack-stats.json", title: "Webpack stats file exposed", description: "Webpack stats.json contains the full module dependency tree, chunk mappings, asset sizes, and internal file paths — a complete blueprint of your application architecture." },
  ];

  const hiddenMapResults = await Promise.allSettled(
    hiddenMapPaths.map(async (check) => {
      const url = `${new URL(target.url).origin}${check.path}`;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const text = await res.text();
      if (text.length < 2) return null;
      if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) return null;
      return { ...check, url, size: text.length };
    }),
  );

  for (const r of hiddenMapResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, title, description, url, size } = r.value;
    findings.push({
      id: `sourcemaps-hidden-${path.replace(/[^a-z0-9]/gi, "-")}`,
      module: "Source Maps",
      severity: path.includes("stats") ? "high" : "medium",
      title,
      description,
      evidence: `GET ${url}\nStatus: 200\nSize: ${size} bytes`,
      remediation: "Remove webpack development artifacts from production. Ensure __webpack_hmr and .webpack/ are not publicly accessible. Never deploy stats.json to production.",
      cwe: "CWE-540",
      owasp: "A05:2021",
      confidence: 85,
      codeSnippet: `// webpack.config.js — don't generate stats in production\nmodule.exports = {\n  mode: "production",\n  devtool: false,\n  // Don't use webpack-dev-server in production\n};`,
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
    "/build-manifest.json",                       // Next.js at root
    "/react-loadable.json",                       // React Loadable manifest
    "/.next/build-manifest.json",                 // Next.js .next dir
    "/.next/react-loadable-manifest.json",        // Next.js .next dir
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

  // CSS source map detection — check for .css.map files alongside stylesheets
  const cssUrls: string[] = [];
  for (const page of target.pages.slice(0, 5)) {
    try {
      const res = await scanFetch(page, { timeoutMs: 5000 });
      const html = await res.text();
      const cssMatches = html.matchAll(/<link[^>]+href=["']([^"']+\.css)["']/gi);
      for (const m of cssMatches) {
        const href = m[1];
        const cssUrl = href.startsWith("http") ? href : new URL(href, page).href;
        if (!cssUrls.includes(cssUrl)) cssUrls.push(cssUrl);
      }
    } catch { /* skip */ }
  }

  const cssMapResults = await Promise.allSettled(
    cssUrls.slice(0, 20).flatMap((cssUrl) => {
      const checks = [cssUrl + ".map"];
      // Also check for sourceMappingURL comment inside the CSS
      const checkInline = async (): Promise<{ url: string; type: "inline" } | null> => {
        const res = await scanFetch(cssUrl, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        const mapMatch = text.match(/\/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*\//);
        if (mapMatch && !mapMatch[1].startsWith("data:")) {
          const mapUrl = mapMatch[1].startsWith("http") ? mapMatch[1] : new URL(mapMatch[1], cssUrl).href;
          const mapRes = await scanFetch(mapUrl, { timeoutMs: 5000 });
          if (mapRes.ok) {
            const mapText = await mapRes.text();
            try {
              const json = JSON.parse(mapText);
              if (json.version && json.sources) return { url: mapUrl, type: "inline" as const };
            } catch { /* skip */ }
          }
        }
        return null;
      };
      const checkConvention = async (): Promise<{ url: string; type: "convention" } | null> => {
        const mapUrl = checks[0];
        const res = await scanFetch(mapUrl, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        try {
          const json = JSON.parse(text);
          if (json.version && json.sources) return { url: mapUrl, type: "convention" as const };
        } catch { /* skip */ }
        return null;
      };
      return [checkInline(), checkConvention()];
    }),
  );

  const foundCssMaps: string[] = [];
  for (const r of cssMapResults) {
    if (r.status === "fulfilled" && r.value && !foundCssMaps.includes(r.value.url)) {
      foundCssMaps.push(r.value.url);
    }
  }

  if (foundCssMaps.length > 0) {
    findings.push({
      id: "sourcemaps-css",
      module: "Source Maps",
      severity: "medium",
      title: `${foundCssMaps.length} CSS source map${foundCssMaps.length > 1 ? "s" : ""} publicly accessible`,
      description: "CSS source map files are accessible in production. These expose original SCSS/SASS/Less source files, including variable names, mixin structures, and potentially internal class naming conventions that reveal component architecture.",
      evidence: `Accessible CSS source maps:\n${foundCssMaps.slice(0, 5).join("\n")}${foundCssMaps.length > 5 ? `\n...and ${foundCssMaps.length - 5} more` : ""}`,
      remediation: "Disable CSS source map generation in production builds. For webpack: css-loader options.sourceMap: false. Block .css.map files at the CDN/reverse proxy level.",
      cwe: "CWE-540",
      owasp: "A05:2021",
      confidence: 90,
      codeSnippet: `// webpack.config.js\nmodule.exports = {\n  module: {\n    rules: [{\n      test: /\\.css$/,\n      use: [\n        "style-loader",\n        { loader: "css-loader", options: { sourceMap: false } },\n      ],\n    }],\n  },\n};\n\n// Nginx — block CSS source maps\nlocation ~* \\.css\\.map$ {\n  return 404;\n}`,
    });
  }

  // Source map via sourceMappingURL in inline scripts
  const inlineScriptMaps: { page: string; mapUrl: string }[] = [];
  for (const page of target.pages.slice(0, 5)) {
    try {
      const res = await scanFetch(page, { timeoutMs: 5000 });
      const html = await res.text();
      const scriptMatches = html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi);
      for (const m of scriptMatches) {
        const scriptContent = m[1];
        if (scriptContent.length < 50) continue;
        const mapMatch = scriptContent.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
        if (mapMatch && !mapMatch[1].startsWith("data:")) {
          const mapUrl = mapMatch[1].startsWith("http") ? mapMatch[1] : new URL(mapMatch[1], page).href;
          inlineScriptMaps.push({ page, mapUrl });
        }
      }
    } catch { /* skip */ }
  }

  if (inlineScriptMaps.length > 0) {
    // Verify the source maps are actually accessible
    const inlineMapVerifyResults = await Promise.allSettled(
      inlineScriptMaps.slice(0, 10).map(async (entry) => {
        const res = await scanFetch(entry.mapUrl, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        try {
          const json = JSON.parse(text);
          if (json.version && json.sources) return entry;
        } catch { /* skip */ }
        return null;
      }),
    );

    const verifiedInlineMaps = inlineMapVerifyResults
      .filter((r) => r.status === "fulfilled" && r.value)
      .map((r) => (r as PromiseFulfilledResult<{ page: string; mapUrl: string }>).value);

    if (verifiedInlineMaps.length > 0) {
      findings.push({
        id: "sourcemaps-inline-script-ref",
        module: "Source Maps",
        severity: "high",
        title: `${verifiedInlineMaps.length} inline script${verifiedInlineMaps.length > 1 ? "s" : ""} reference accessible source maps`,
        description: "Inline <script> blocks in HTML pages contain sourceMappingURL comments pointing to accessible source map files. This exposes original source code for scripts embedded directly in the page.",
        evidence: verifiedInlineMaps.slice(0, 5).map((e) => `Page: ${new URL(e.page).pathname}\n  Map: ${e.mapUrl}`).join("\n"),
        remediation: "Strip sourceMappingURL comments from inline scripts during the build process. Use a post-processing step or CSP to prevent source map exposure.",
        cwe: "CWE-540",
        owasp: "A05:2021",
        confidence: 90,
      });
    }
  }

  // Source map content analysis — look for sensitive paths and API key variable names
  const sensitivePatterns = [
    { pattern: /(?:api[_-]?key|apiKey|API_KEY)\s*[:=]\s*["']([^"']{8,})["']/i, label: "API key assignment" },
    { pattern: /(?:secret|SECRET|token|TOKEN)\s*[:=]\s*["']([^"']{8,})["']/i, label: "Secret/token assignment" },
    { pattern: /(?:password|PASSWORD|passwd)\s*[:=]\s*["']([^"']{4,})["']/i, label: "Password assignment" },
    { pattern: /(?:aws_access_key_id|AWS_ACCESS)\s*[:=]\s*["']([A-Z0-9]{16,})["']/i, label: "AWS access key" },
    { pattern: /(?:firebase|FIREBASE).*?["']AIza[A-Za-z0-9_-]{35}["']/i, label: "Firebase API key" },
    { pattern: /(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})/i, label: "GitHub token" },
  ];

  const sensitivePathPatterns = [
    /\/(?:internal|private|admin|secret|hidden)\//i,
    /\/(?:\.env|\.config|credentials|secrets)\//i,
    /\/(?:node_modules|vendor)\//i,
    /(?:\/src\/(?:server|backend|api|db|database|auth)\/)/i,
  ];

  const contentAnalysisFindings: { mapUrl: string; secrets: string[]; sensitivePaths: string[] }[] = [];
  for (const data of mapData) {
    const sensitivePaths = data.sensitiveFiles.length > 0 ? data.sensitiveFiles : [];
    // Also check source paths against sensitive patterns
    try {
      const mapRes = await scanFetch(data.url, { timeoutMs: 8000 });
      if (!mapRes.ok) continue;
      const mapText = await mapRes.text();
      const json = JSON.parse(mapText) as { sources?: string[]; sourcesContent?: string[] };

      // Check paths
      for (const src of json.sources || []) {
        for (const pp of sensitivePathPatterns) {
          if (pp.test(src) && !sensitivePaths.includes(src)) {
            sensitivePaths.push(src);
          }
        }
      }

      // Check source content for secrets
      const secrets: string[] = [];
      for (const content of (json.sourcesContent || []).slice(0, 30)) {
        if (!content) continue;
        for (const sp of sensitivePatterns) {
          if (sp.pattern.test(content) && !secrets.includes(sp.label)) {
            secrets.push(sp.label);
          }
        }
      }

      if (secrets.length > 0 || sensitivePaths.length > 3) {
        contentAnalysisFindings.push({ mapUrl: data.url, secrets, sensitivePaths: sensitivePaths.slice(0, 10) });
      }
    } catch { /* skip */ }
  }

  if (contentAnalysisFindings.length > 0) {
    const hasSecrets = contentAnalysisFindings.some((f) => f.secrets.length > 0);
    const allSecrets = [...new Set(contentAnalysisFindings.flatMap((f) => f.secrets))];
    const allPaths = [...new Set(contentAnalysisFindings.flatMap((f) => f.sensitivePaths))];
    findings.push({
      id: "sourcemaps-content-analysis",
      module: "Source Maps",
      severity: hasSecrets ? "critical" : "high",
      title: `Source map content analysis: ${hasSecrets ? `secrets detected (${allSecrets.join(", ")})` : `${allPaths.length} sensitive file paths exposed`}`,
      description: `Deep analysis of source map contents revealed ${hasSecrets ? `potential hardcoded secrets (${allSecrets.join(", ")})` : "sensitive internal file paths"} in the original source code.${allPaths.length > 0 ? ` Exposed paths include: ${allPaths.slice(0, 5).join(", ")}.` : ""}`,
      evidence: contentAnalysisFindings.slice(0, 3).map((f) =>
        `${f.mapUrl}:\n${f.secrets.length > 0 ? `  Secrets: ${f.secrets.join(", ")}\n` : ""}${f.sensitivePaths.length > 0 ? `  Sensitive paths: ${f.sensitivePaths.slice(0, 5).join(", ")}` : ""}`,
      ).join("\n"),
      remediation: hasSecrets
        ? "IMMEDIATELY rotate all secrets found in source maps. Disable source maps in production and audit your codebase for hardcoded credentials. Use environment variables for all secrets."
        : "Disable source maps in production to prevent exposure of internal file structure and sensitive paths.",
      cwe: hasSecrets ? "CWE-798" : "CWE-540",
      owasp: "A05:2021",
      confidence: hasSecrets ? 80 : 70,
    });
  }

  // Hidden source map endpoint patterns
  const hiddenSourceMapPaths = [
    "/debug/source-maps", "/debug/sourcemaps", "/debug/maps",
    "/.sourcemaps/", "/.source-maps/", "/sourcemaps/",
    "/.maps/", "/source-maps/", "/__sourcemaps/",
    "/dev/sourcemaps", "/dev/source-maps",
    "/_debug/sourcemaps", "/_sourcemaps/",
  ];
  const hiddenSmResults = await Promise.allSettled(
    hiddenSourceMapPaths.map(async (path) => {
      const url = `${origin}${path}`;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const text = await res.text();
      if (text.length < 10) return null;
      if (/not found|404|page doesn't exist/i.test(text) && text.length < 5000) return null;
      // Check if it looks like a directory listing or source map content
      const isSourceMapRelated = /\.map|sourceMappingURL|sources|mappings|version/i.test(text);
      if (!isSourceMapRelated && text.length < 200) return null;
      return { path, size: text.length, isSourceMapRelated };
    }),
  );

  const foundHiddenSm = hiddenSmResults
    .filter((r) => r.status === "fulfilled" && r.value)
    .map((r) => (r as PromiseFulfilledResult<{ path: string; size: number; isSourceMapRelated: boolean }>).value);

  if (foundHiddenSm.length > 0) {
    findings.push({
      id: "sourcemaps-hidden-endpoints",
      module: "Source Maps",
      severity: "high",
      title: `${foundHiddenSm.length} hidden source map endpoint${foundHiddenSm.length > 1 ? "s" : ""} detected`,
      description: "Source map files or directories are accessible at non-standard/debug paths. These hidden endpoints are often left behind after disabling standard source map serving and can expose full application source code.",
      evidence: foundHiddenSm.map((s) => `${s.path} (${s.size} bytes)`).join("\n"),
      remediation: "Remove all source map debug endpoints from production. Audit your server configuration for any paths serving .map files. Use automated checks to detect source map leaks.",
      cwe: "CWE-540",
      owasp: "A05:2021",
      confidence: 75,
    });
  }

  // Framework-specific source map paths — probe well-known paths for Vite, CRA, and other frameworks
  const frameworkMapPaths = [
    // Vite
    { path: "/assets/index.js.map", framework: "Vite" },
    { path: "/assets/vendor.js.map", framework: "Vite" },
    { path: "/assets/index.css.map", framework: "Vite" },
    { path: "/.vite/deps/_metadata.json", framework: "Vite" },
    { path: "/.vite/deps/package.json", framework: "Vite" },
    // Next.js additional paths
    { path: "/_next/static/chunks/app/layout.js.map", framework: "Next.js" },
    { path: "/_next/static/chunks/app/page.js.map", framework: "Next.js" },
    { path: "/_next/static/chunks/polyfills.js.map", framework: "Next.js" },
    { path: "/_next/static/development/_buildManifest.js", framework: "Next.js" },
    { path: "/_next/static/development/_ssgManifest.js", framework: "Next.js" },
    // Create React App
    { path: "/static/js/main.chunk.js.map", framework: "CRA" },
    { path: "/static/js/vendors~main.chunk.js.map", framework: "CRA" },
    { path: "/static/js/runtime-main.js.map", framework: "CRA" },
    { path: "/static/css/main.chunk.css.map", framework: "CRA" },
    // Webpack numbered chunks
    { path: "/static/js/3.chunk.js.map", framework: "Webpack" },
    { path: "/static/js/4.chunk.js.map", framework: "Webpack" },
    { path: "/static/js/5.chunk.js.map", framework: "Webpack" },
    { path: "/static/js/6.chunk.js.map", framework: "Webpack" },
    { path: "/static/js/7.chunk.js.map", framework: "Webpack" },
    // Angular
    { path: "/main.js.map", framework: "Angular" },
    { path: "/polyfills.js.map", framework: "Angular" },
    { path: "/runtime.js.map", framework: "Angular" },
    { path: "/vendor.js.map", framework: "Angular" },
    { path: "/styles.css.map", framework: "Angular" },
    // Nuxt
    { path: "/_nuxt/entry.js.map", framework: "Nuxt" },
    { path: "/_nuxt/vendor.js.map", framework: "Nuxt" },
  ];

  const frameworkResults = await Promise.allSettled(
    frameworkMapPaths.map(async (check) => {
      const url = `${origin}${check.path}`;
      const res = await scanFetch(url, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const text = await res.text();
      if (text.length < 20) return null;
      // For .map files, verify valid source map JSON
      if (check.path.endsWith(".map")) {
        try {
          const json = JSON.parse(text);
          if (json.version && json.sources && json.mappings) {
            return { ...check, sourceCount: (json.sources as string[]).length };
          }
        } catch { /* skip */ }
        return null;
      }
      // For metadata/config files, just verify they have content
      if (/not found|404/i.test(text) && text.length < 5000) return null;
      return { ...check, sourceCount: 0 };
    }),
  );

  const foundFrameworkMaps = frameworkResults
    .filter((r) => r.status === "fulfilled" && r.value)
    .map((r) => (r as PromiseFulfilledResult<{ path: string; framework: string; sourceCount: number }>).value);

  // Only report if not already covered by the chunk maps check above
  const alreadyReported = new Set(foundChunkMaps.map((m) => m.path));
  const newFrameworkMaps = foundFrameworkMaps.filter((m) => !alreadyReported.has(m.path));

  if (newFrameworkMaps.length > 0) {
    const frameworks = [...new Set(newFrameworkMaps.map((m) => m.framework))];
    const totalSrc = newFrameworkMaps.reduce((sum, m) => sum + m.sourceCount, 0);
    findings.push({
      id: "sourcemaps-framework-specific",
      module: "Source Maps",
      severity: "high",
      title: `${newFrameworkMaps.length} ${frameworks.join("/")} source map${newFrameworkMaps.length > 1 ? "s" : ""} exposed at framework-specific paths`,
      description: `Source maps were found at paths specific to ${frameworks.join(", ")} builds${totalSrc > 0 ? `, exposing ${totalSrc} source files` : ""}. These framework-specific paths are well-known to attackers and automated scanners.`,
      evidence: `Framework source maps:\n${newFrameworkMaps.slice(0, 8).map((m) => `[${m.framework}] ${m.path}${m.sourceCount > 0 ? ` (${m.sourceCount} sources)` : ""}`).join("\n")}${newFrameworkMaps.length > 8 ? `\n...and ${newFrameworkMaps.length - 8} more` : ""}`,
      remediation: `Disable source maps in production for ${frameworks.join(", ")}. ${frameworks.includes("Vite") ? "Vite: set build.sourcemap: false. " : ""}${frameworks.includes("Angular") ? "Angular: set sourceMap: false in angular.json production config. " : ""}${frameworks.includes("Nuxt") ? "Nuxt: set sourcemap: false in nuxt.config.ts. " : ""}${frameworks.includes("CRA") ? "CRA: set GENERATE_SOURCEMAP=false in .env. " : ""}Block access at the CDN/proxy level as defense in depth.`,
      cwe: "CWE-540",
      owasp: "A05:2021",
      confidence: 90,
      codeSnippet: `// Vite\nexport default defineConfig({ build: { sourcemap: false } });\n\n// Angular (angular.json)\n"production": { "sourceMap": false }\n\n// Nuxt (nuxt.config.ts)\nexport default defineNuxtConfig({ sourcemap: false });\n\n// CRA (.env)\nGENERATE_SOURCEMAP=false`,
    });
  }

  return findings;
};
