import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml } from "../soft404";

const ID_PATH_PATTERNS = [
  /\/api\/\w+\/(\d+)$/,
  /\/api\/v\d\/\w+\/(\d+)$/,
  /\/\w+\/(\d+)$/,
  /\/api\/\w+\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i,
  /\/api\/v\d\/\w+\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i,
];

// Endpoints that naturally serve public content by ID — not IDOR
const PUBLIC_RESOURCE_PATTERNS = /\/(posts?|articles?|blogs?|products?|items?|pages?|categories|tags?|comments?|reviews?|docs?|help|faq|changelog)\b/i;

// Fields that indicate private/user-specific data
const PRIVATE_DATA_PATTERNS = /email|phone|address|ssn|password|billing|payment|credit|salary|dob|birth|social.?security/i;

const MAX_IDOR_FINDINGS = 3;

export const idorModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  let seqCount = 0;
  let paramCount = 0;

  // Find endpoints that look like they use sequential IDs
  const idEndpoints: { base: string; currentId: number }[] = [];
  const seenBases = new Set<string>();

  const stripId = (url: string) => url.replace(/\/(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i, "");

  for (const endpoint of target.apiEndpoints) {
    for (const pattern of ID_PATH_PATTERNS) {
      const match = endpoint.match(pattern);
      if (match) {
        const idStr = match[1];
        const id = parseInt(idStr);
        if (!isNaN(id)) {
          const base = stripId(endpoint);
          if (!seenBases.has(base)) {
            seenBases.add(base);
            idEndpoints.push({ base, currentId: id });
          }
        } else if (/^[0-9a-f]{8}-/.test(idStr)) {
          // UUID-based endpoint — still test for access control
          const base = stripId(endpoint);
          if (!seenBases.has(base)) {
            seenBases.add(base);
            idEndpoints.push({ base, currentId: 0 });
          }
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
            const base = url.origin + stripId(url.pathname);
            if (!seenBases.has(base)) {
              seenBases.add(base);
              idEndpoints.push({ base, currentId: id });
            }
          }
        }
      }
    } catch {
      // skip invalid URLs
    }
  }

  // Test sequential ID access
  for (const ep of idEndpoints.slice(0, 8)) {
    if (findings.length >= MAX_IDOR_FINDINGS) break;
    // Skip UUID-based endpoints — can't enumerate UUIDs sequentially
    if (ep.currentId === 0) continue;
    const testIds = [1, 2, 3, ep.currentId + 1, ep.currentId + 2];
    let accessibleCount = 0;
    const evidenceLines: string[] = [];
    const evidenceTexts: string[] = [];

    for (const id of testIds) {
      try {
        const url = `${ep.base}/${id}`;
        const res = await scanFetch(url);
        if (res.ok) {
          const ct = res.headers.get("content-type") || "";
          if (ct.includes("json")) {
            const text = await res.text();
            if (looksLikeHtml(text)) continue;
            accessibleCount++;
            evidenceLines.push(`GET ${url} → ${res.status}`);
            evidenceTexts.push(text.substring(0, 500));
          }
        }
      } catch {
        // skip
      }
    }

    if (accessibleCount >= 3) {
      // Skip endpoints that serve intentionally public content (blogs, products, etc.)
      if (PUBLIC_RESOURCE_PATTERNS.test(ep.base)) continue;

      // Check if responses contain private user data (stronger signal)
      const hasPrivateData = evidenceTexts.some((t) => PRIVATE_DATA_PATTERNS.test(t));
      const severity = hasPrivateData ? "high" : "medium";

      findings.push({
        id: `idor-sequential-${seqCount++}`,
        module: "IDOR",
        severity,
        title: `Sequential ID enumeration on ${ep.base}/[id]`,
        description: `${accessibleCount} different IDs returned data without any access control check. An attacker can enumerate all records by iterating through IDs.${hasPrivateData ? " Responses contain private user data fields." : ""}`,
        evidence: evidenceLines.join("\n"),
        remediation: "Use UUIDs instead of sequential IDs. Always verify the requesting user has permission to access the specific resource.",
        cwe: "CWE-639",
        owasp: "A01:2021",
      });
    }
  }

  // Test IDOR via query parameters
  for (const endpoint of target.apiEndpoints.slice(0, 10)) {
    if (findings.length >= MAX_IDOR_FINDINGS) break;
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
          id: `idor-param-${paramCount++}`,
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
