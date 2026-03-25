import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const sourceMapsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const exposedMaps: string[] = [];
  const conventionMaps: string[] = [];

  // Build list of source map URLs from JS bundles
  const mapUrlsToCheck: string[] = [];
  for (const [scriptUrl, content] of target.jsContents) {
    const mapMatch = content.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
    if (!mapMatch) continue;
    let mapUrl = mapMatch[1];
    if (mapUrl.startsWith("data:")) continue;
    if (!mapUrl.startsWith("http")) mapUrl = new URL(mapUrl, scriptUrl).href;
    mapUrlsToCheck.push(mapUrl);
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
          const json = JSON.parse(text);
          if (json.version && json.sources && json.mappings) return mapUrl;
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

  for (const r of mapResults) {
    if (r.status === "fulfilled" && r.value) exposedMaps.push(r.value);
  }

  if (exposedMaps.length > 0) {
    findings.push({
      id: "sourcemaps-exposed",
      module: "Source Maps",
      severity: "high",
      title: `${exposedMaps.length} source map${exposedMaps.length > 1 ? "s" : ""} publicly accessible`,
      description: "Source maps are accessible, allowing anyone to view your unminified source code including comments, variable names, and business logic.",
      evidence: `Accessible source maps:\n${exposedMaps.slice(0, 5).join("\n")}${exposedMaps.length > 5 ? `\n...and ${exposedMaps.length - 5} more` : ""}`,
      remediation: "Disable source maps in production. For Next.js: set productionBrowserSourceMaps: false in next.config.js. For Vite: set build.sourcemap: false.",
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

  return findings;
};
