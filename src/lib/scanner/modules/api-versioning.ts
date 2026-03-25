import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml, isSoft404 } from "../soft404";

const VERSION_PREFIXES = ["v1", "v2", "v3", "v0", "V1", "V2"];

export const apiVersioningModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Collect API endpoints without version prefixes
  const unversionedEndpoints: string[] = [];
  const versionedEndpoints = new Map<string, string[]>(); // base path -> found versions

  for (const ep of target.apiEndpoints) {
    try {
      const pathname = new URL(ep).pathname;
      const vMatch = pathname.match(/\/(v\d+)\//i);
      if (vMatch) {
        const base = pathname.replace(/\/v\d+\//i, "/VERSION/");
        if (!versionedEndpoints.has(base)) versionedEndpoints.set(base, []);
        versionedEndpoints.get(base)!.push(vMatch[1]);
      } else if (pathname.startsWith("/api/")) {
        unversionedEndpoints.push(ep);
      }
    } catch { /* skip */ }
  }

  // Test 1: Try version prefixes on unversioned API endpoints
  const versionProbeResults = await Promise.allSettled(
    unversionedEndpoints.slice(0, 8).flatMap((ep) => {
      const url = new URL(ep);
      const apiPath = url.pathname.replace(/^\/api\//, "");
      return VERSION_PREFIXES.slice(0, 4).map(async (ver) => {
        const testUrl = `${target.baseUrl}/api/${ver}/${apiPath}`;
        const res = await scanFetch(testUrl, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
        if (text.length < 10) return null;
        // Check it returns different content than the original
        const origRes = await scanFetch(ep, { timeoutMs: 5000 });
        const origText = await origRes.text();
        if (text === origText) return null; // Same response — just routing alias
        return { original: url.pathname, versioned: `/api/${ver}/${apiPath}`, ver };
      });
    }),
  );

  // Test 2: For versioned endpoints, check if older versions have weaker auth
  const olderVersionResults = await Promise.allSettled(
    Array.from(versionedEndpoints.entries()).slice(0, 5).flatMap(([basePath, versions]) => {
      const highestVer = Math.max(...versions.map((v) => parseInt(v.replace(/\D/g, ""), 10)));
      return Array.from({ length: highestVer }, (_, i) => i + 1)
        .filter((v) => !versions.includes(`v${v}`))
        .slice(0, 3)
        .map(async (v) => {
          const testPath = basePath.replace("VERSION", `v${v}`);
          const testUrl = target.baseUrl + testPath;
          const res = await scanFetch(testUrl, { timeoutMs: 5000 });
          if (!res.ok) return null;
          const text = await res.text();
          if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
          if (text.length < 10) return null;

          // Auth comparison: check if the older version responds without auth
          // while the current version rejects unauthenticated requests
          let weakerAuth = false;
          const currentPath = basePath.replace("VERSION", `v${highestVer}`);
          const currentUrl = target.baseUrl + currentPath;
          try {
            const [noAuthOld, noAuthCurrent] = await Promise.all([
              scanFetch(testUrl, { timeoutMs: 5000, headers: {} }),
              scanFetch(currentUrl, { timeoutMs: 5000, headers: {} }),
            ]);
            // Old version returns 200 without auth, but current version returns 401/403
            if (noAuthOld.ok && (noAuthCurrent.status === 401 || noAuthCurrent.status === 403)) {
              weakerAuth = true;
            }
          } catch { /* skip auth comparison */ }

          return { basePath, version: `v${v}`, knownVersions: versions, text: text.substring(0, 200), weakerAuth };
        });
    }),
  );

  // Test 3: Path normalization bypass — double slashes, dot segments, case variation
  const bypassResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 10).flatMap((ep) => {
      const url = new URL(ep);
      const pathname = url.pathname;
      const bypasses = [
        pathname.replace("/api/", "/API/"),
        pathname.replace("/api/", "/Api/"),
        pathname.replace("/api/", "//api/"),
        pathname.replace("/api/", "/./api/"),
        pathname + "/",
        pathname + "/..",
        // URL-encoded dot segments
        pathname.replace("/api/", "/%2e/api/"),
        pathname.replace("/api/", "/%2e%2e/api/"),
        // Double-encoded dot segments
        pathname.replace("/api/", "/%252e/api/"),
        pathname.replace("/api/", "/%252e%252e/api/"),
        // Backslash variants (IIS / reverse-proxy confusion)
        pathname.replace("/api/", "/api\\/"),
        pathname.replace("/api/", "\\api/"),
        // Semicolon path parameter tricks (Tomcat / Spring)
        pathname.replace("/api/", "/api;/"),
        pathname + ";.json",
      ];
      return bypasses.map(async (bypassPath) => {
        const testUrl = target.baseUrl + bypassPath;
        const res = await scanFetch(testUrl, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
        if (text.length < 10) return null;
        // Get original response for comparison
        const origRes = await scanFetch(ep, { timeoutMs: 5000 });
        if (!origRes.ok) return null;
        const origText = await origRes.text();
        // Only flag if bypass returns similar data (auth bypass)
        if (Math.abs(text.length - origText.length) < origText.length * 0.3 && text.length > 20) {
          return { original: pathname, bypass: bypassPath };
        }
        return null;
      });
    }),
  );

  // Collect findings
  const versionProbes = new Set<string>();
  for (const r of versionProbeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (versionProbes.has(v.original)) continue;
    versionProbes.add(v.original);
    findings.push({
      id: `api-ver-shadow-${findings.length}`, module: "API Versioning", severity: "medium",
      title: `Hidden API version at ${v.versioned}`,
      description: `The endpoint ${v.original} also responds at ${v.versioned} with different content. Older API versions may have weaker security controls, missing auth, or expose more data.`,
      evidence: `Original: GET ${v.original}\nHidden: GET ${v.versioned} (version ${v.ver}) returns different response`,
      remediation: "Explicitly disable or redirect old API versions. Ensure all versions have the same security controls. Return 404 for unsupported versions.",
      cwe: "CWE-284", owasp: "A01:2021",
      codeSnippet: `// Disable old versions in your router\napp.all('/api/${v.ver}/*', (req, res) => res.status(404).json({ error: 'Version not supported' }));`,
    });
    if (findings.length >= 2) break;
  }

  for (const r of olderVersionResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const severity = v.weakerAuth ? "critical" as const : "high" as const;
    const authNote = v.weakerAuth
      ? `\nAUTH BYPASS: ${v.version} responds without authentication while the current version requires it.`
      : "";
    findings.push({
      id: `api-ver-old-${findings.length}`, module: "API Versioning", severity,
      title: `Accessible older API version: ${v.version}${v.weakerAuth ? " (weaker auth)" : ""} (known: ${v.knownVersions.join(", ")})`,
      description: `An older API version (${v.version}) is still accessible alongside current versions (${v.knownVersions.join(", ")}). Older versions often lack security patches and may expose deprecated functionality.${authNote}`,
      evidence: `GET ${v.basePath.replace("VERSION", v.version)}\nResponse: ${v.text}`,
      remediation: v.weakerAuth
        ? "URGENT: The older API version allows unauthenticated access. Decommission it immediately or apply the same auth middleware as the current version."
        : "Decommission old API versions. If backward compatibility is needed, apply the same security controls to all versions.",
      cwe: v.weakerAuth ? "CWE-306" : "CWE-284", owasp: "A01:2021",
      codeSnippet: `// Apply auth middleware to all API versions\napp.use('/api/v:version/*', authMiddleware);\n// Or block old versions entirely\napp.all('/api/${v.version}/*', (req, res) => res.status(410).json({ error: 'Version deprecated' }));`,
    });
    break;
  }

  const bypassPaths = new Set<string>();
  for (const r of bypassResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (bypassPaths.has(v.original)) continue;
    bypassPaths.add(v.original);
    findings.push({
      id: `api-ver-bypass-${findings.length}`, module: "API Versioning", severity: "medium",
      title: `Path normalization bypass on ${v.original}`,
      description: `The endpoint responds to a path variation (${v.bypass}) with similar content. If auth middleware only checks exact paths, this could bypass access controls.`,
      evidence: `Original: ${v.original}\nBypass: ${v.bypass}\nBoth return similar responses`,
      remediation: "Normalize request paths before routing and auth checks. Use framework middleware that handles path normalization. Test with double slashes, dot segments, URL-encoded dots, backslashes, and semicolons.",
      cwe: "CWE-706", owasp: "A01:2021",
      codeSnippet: `// Normalize paths before auth checks\napp.use((req, res, next) => {\n  req.url = decodeURIComponent(req.url)\n    .replace(/\\\\/g, '/')\n    .replace(/\\/+/g, '/')\n    .replace(/;[^/]*/g, '')\n    .replace(/\\/(\\.|%2e){1,2}\\//gi, '/');\n  next();\n});`,
    });
    if (bypassPaths.size >= 2) break;
  }

  return findings;
};
