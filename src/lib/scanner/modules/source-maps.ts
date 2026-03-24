import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const sourceMapsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Check for sourceMappingURL in JS bundles
  for (const [scriptUrl, content] of target.jsContents) {
    const mapMatch = content.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
    if (!mapMatch) continue;

    let mapUrl = mapMatch[1];
    if (mapUrl.startsWith("data:")) continue; // inline source maps are fine (sort of)

    if (!mapUrl.startsWith("http")) {
      mapUrl = new URL(mapUrl, scriptUrl).href;
    }

    try {
      const res = await scanFetch(mapUrl);
      if (res.ok) {
        const text = await res.text();
        const hasSourceContent = text.includes('"sourcesContent"');
        findings.push({
          id: `sourcemaps-exposed-${findings.length}`,
          module: "Source Maps",
          severity: "high",
          title: "Source maps are publicly accessible",
          description: hasSourceContent
            ? "Source maps with full source code are accessible. Anyone can view your complete, unminified source code including comments, variable names, and business logic."
            : "Source maps are accessible. Attackers can use these to understand your code structure and find vulnerabilities more easily.",
          evidence: `Accessible source map: ${mapUrl}\n${hasSourceContent ? "Contains full source code (sourcesContent present)" : "Contains file mappings"}`,
          remediation: "Disable source maps in production. For Next.js: set productionBrowserSourceMaps: false in next.config.js. For Vite: set build.sourcemap: false.",
          cwe: "CWE-540",
          owasp: "A05:2021",
        });
      }
    } catch {
      // not accessible, which is good
    }
  }

  // Also try common source map paths
  for (const scriptUrl of target.scripts.slice(0, 10)) {
    const mapUrl = scriptUrl + ".map";
    try {
      const res = await scanFetch(mapUrl);
      if (res.ok && (res.headers.get("content-type") || "").includes("json")) {
        findings.push({
          id: `sourcemaps-convention-${findings.length}`,
          module: "Source Maps",
          severity: "high",
          title: "Source map found via convention (.js.map)",
          description: "A source map file was found by appending .map to a JavaScript URL. Your source code may be fully readable.",
          evidence: `Accessible: ${mapUrl}`,
          remediation: "Block access to .map files in production or disable source map generation.",
          cwe: "CWE-540",
        });
      }
    } catch {
      // fine
    }
  }

  return findings;
};
