import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const sourceMapsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const exposedMaps: string[] = [];
  const conventionMaps: string[] = [];

  // Check for sourceMappingURL in JS bundles
  for (const [scriptUrl, content] of target.jsContents) {
    const mapMatch = content.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
    if (!mapMatch) continue;

    let mapUrl = mapMatch[1];
    if (mapUrl.startsWith("data:")) continue;

    if (!mapUrl.startsWith("http")) {
      mapUrl = new URL(mapUrl, scriptUrl).href;
    }

    try {
      const res = await scanFetch(mapUrl);
      if (res.ok) {
        const text = await res.text();
        // Validate it's an actual source map (has required fields)
        try {
          const json = JSON.parse(text);
          if (json.version && json.sources && json.mappings) {
            exposedMaps.push(mapUrl);
          }
        } catch {
          // Not valid JSON — not a real source map
        }
      }
    } catch {}
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
    });
  }

  // Also try common source map paths (skip already-found maps)
  const knownMaps = new Set(exposedMaps);
  for (const scriptUrl of target.scripts.slice(0, 10)) {
    const mapUrl = scriptUrl + ".map";
    if (knownMaps.has(mapUrl)) continue;
    try {
      const res = await scanFetch(mapUrl);
      if (res.ok && (res.headers.get("content-type") || "").includes("json")) {
        conventionMaps.push(mapUrl);
      }
    } catch {}
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
    });
  }

  return findings;
};
