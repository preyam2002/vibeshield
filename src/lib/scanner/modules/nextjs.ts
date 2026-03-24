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

  if (detectedBuildId) {
    // Try fetching SSR data for known pages
    for (const page of target.pages.slice(0, 10)) {
      try {
        const pathname = new URL(page).pathname.replace(/\/$/, "") || "/index";
        const dataUrl = `${target.baseUrl}/_next/data/${detectedBuildId}${pathname}.json`;
        const res = await scanFetch(dataUrl);
        if (res.ok) {
          const text = await res.text();
          if (text.length > 50) {
            // Check if SSR data contains sensitive info
            const hasSensitive = /password|secret|token|api.?key|private/i.test(text);
            if (hasSensitive) {
              findings.push({
                id: `nextjs-data-leak-${findings.length}`,
                module: "Next.js",
                severity: "high",
                title: `Sensitive data in SSR props for ${pathname}`,
                description: "Next.js SSR data route contains sensitive-looking fields. Data passed via getServerSideProps is accessible via /_next/data/ URLs.",
                evidence: `URL: ${dataUrl}\nSensitive patterns found in response\nPreview: ${text.substring(0, 300)}`,
                remediation: "Only pass necessary data to the client via getServerSideProps. Filter out sensitive fields before returning props.",
                cwe: "CWE-200",
              });
            }
          }
        }
      } catch {
        // skip
      }
    }
  }

  // Check middleware bypass
  const bypassHeaders = [
    { header: "x-middleware-prefetch", value: "1" },
    { header: "x-nextjs-data", value: "1" },
    { header: "purpose", value: "prefetch" },
  ];

  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    for (const { header, value } of bypassHeaders) {
      try {
        const res = await scanFetch(endpoint, {
          headers: { [header]: value },
        });
        // Compare with normal request
        const normalRes = await scanFetch(endpoint);

        if (res.status === 200 && normalRes.status !== 200) {
          findings.push({
            id: `nextjs-middleware-bypass-${findings.length}`,
            module: "Next.js",
            severity: "high",
            title: `Middleware bypass via ${header} header`,
            description: `Adding the ${header}: ${value} header bypasses middleware on ${new URL(endpoint).pathname}. If your auth logic is in middleware, this bypasses authentication.`,
            evidence: `Without header: ${normalRes.status}\nWith ${header}: ${value}: ${res.status}`,
            remediation: "Don't rely solely on middleware for authentication. Add auth checks in API route handlers too.",
            cwe: "CWE-863",
            owasp: "A01:2021",
          });
        }
      } catch {
        // skip
      }
    }
  }

  // Check for exposed internal routes
  const internalPaths = [
    "/_next/webpack-hmr", "/_next/static/development",
    "/__nextjs_original-stack-frame", "/_next/image?url=",
  ];

  for (const path of internalPaths) {
    try {
      const res = await scanFetch(target.baseUrl + path);
      if (res.ok && path.includes("development")) {
        findings.push({
          id: `nextjs-dev-exposed-${findings.length}`,
          module: "Next.js",
          severity: "high",
          title: `Next.js development artifacts accessible: ${path}`,
          description: "Development-only routes are accessible in production. This suggests the app is running in development mode.",
          evidence: `GET ${target.baseUrl + path} → ${res.status}`,
          remediation: "Ensure NODE_ENV=production in your deployment. Never deploy development builds.",
          cwe: "CWE-489",
        });
      }
    } catch {
      // skip
    }
  }

  // Check for RSC payload exposure
  try {
    const res = await scanFetch(target.url, {
      headers: { RSC: "1", "Next-Router-State-Tree": "%5B%22%22%5D" },
    });
    if (res.ok) {
      const text = await res.text();
      if (text.includes(":") && !text.startsWith("<!DOCTYPE")) {
        const hasSensitive = /password|secret|api.?key|token|private/i.test(text);
        if (hasSensitive) {
          findings.push({
            id: "nextjs-rsc-data-leak",
            module: "Next.js",
            severity: "high",
            title: "Sensitive data in React Server Component payload",
            description: "RSC payload contains sensitive-looking data that may not be intended for client consumption.",
            evidence: `RSC payload preview: ${text.substring(0, 300)}`,
            remediation: "Audit what data your Server Components pass to Client Components. Use 'server only' imports for sensitive logic.",
            cwe: "CWE-200",
          });
        }
      }
    }
  } catch {
    // skip
  }

  return findings;
};
