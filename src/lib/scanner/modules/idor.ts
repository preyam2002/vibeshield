import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const ID_PATH_PATTERNS = [
  /\/api\/\w+\/(\d+)$/,
  /\/api\/v\d\/\w+\/(\d+)$/,
  /\/\w+\/(\d+)$/,
];

export const idorModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Find endpoints that look like they use sequential IDs
  const idEndpoints: { base: string; currentId: number }[] = [];

  for (const endpoint of target.apiEndpoints) {
    for (const pattern of ID_PATH_PATTERNS) {
      const match = endpoint.match(pattern);
      if (match) {
        const id = parseInt(match[1]);
        if (!isNaN(id)) {
          idEndpoints.push({ base: endpoint.replace(/\/\d+$/, ""), currentId: id });
        }
      }
    }
  }

  // Also look for ID-based endpoints in discovered links
  for (const link of target.linkUrls) {
    try {
      const url = new URL(link);
      for (const pattern of ID_PATH_PATTERNS) {
        const match = url.pathname.match(pattern);
        if (match) {
          const id = parseInt(match[1]);
          if (!isNaN(id)) {
            idEndpoints.push({ base: url.origin + url.pathname.replace(/\/\d+$/, ""), currentId: id });
          }
        }
      }
    } catch {
      // skip invalid URLs
    }
  }

  // Test sequential ID access
  for (const ep of idEndpoints.slice(0, 10)) {
    const testIds = [1, 2, 3, ep.currentId + 1, ep.currentId + 2];
    let accessibleCount = 0;
    const evidenceLines: string[] = [];

    for (const id of testIds) {
      try {
        const url = `${ep.base}/${id}`;
        const res = await scanFetch(url);
        if (res.ok) {
          const ct = res.headers.get("content-type") || "";
          if (ct.includes("json")) {
            accessibleCount++;
            evidenceLines.push(`GET ${url} → ${res.status}`);
          }
        }
      } catch {
        // skip
      }
    }

    if (accessibleCount >= 2) {
      findings.push({
        id: `idor-sequential-${findings.length}`,
        module: "IDOR",
        severity: "high",
        title: `Sequential ID enumeration on ${ep.base}/[id]`,
        description: `${accessibleCount} different IDs returned data without any access control check. An attacker can enumerate all records by iterating through IDs. This is the #1 vulnerability in vibe-coded apps.`,
        evidence: evidenceLines.join("\n"),
        remediation: "Use UUIDs instead of sequential IDs. Always verify the requesting user has permission to access the specific resource.",
        cwe: "CWE-639",
        owasp: "A01:2021",
      });
    }
  }

  // Test IDOR via query parameters
  for (const endpoint of target.apiEndpoints.slice(0, 10)) {
    const url = new URL(endpoint);
    if (url.searchParams.has("id") || url.searchParams.has("user_id") || url.searchParams.has("userId")) {
      const paramName = url.searchParams.has("id") ? "id" : url.searchParams.has("user_id") ? "user_id" : "userId";
      const originalId = url.searchParams.get(paramName);
      const testIds = ["1", "2", "999"];
      let success = 0;

      for (const testId of testIds) {
        if (testId === originalId) continue;
        try {
          const testUrl = new URL(endpoint);
          testUrl.searchParams.set(paramName, testId);
          const res = await scanFetch(testUrl.href);
          if (res.ok) success++;
        } catch {
          // skip
        }
      }

      if (success >= 2) {
        findings.push({
          id: `idor-param-${findings.length}`,
          module: "IDOR",
          severity: "high",
          title: `IDOR via ${paramName} parameter on ${url.pathname}`,
          description: `Changing the ${paramName} parameter returns different users' data without access checks.`,
          remediation: "Validate that the authenticated user owns the requested resource.",
          cwe: "CWE-639",
          owasp: "A01:2021",
        });
      }
    }
  }

  return findings;
};
