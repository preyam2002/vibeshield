import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml } from "../soft404";

const ID_PATH_PATTERNS = [
  /\/api\/\w+\/(\d+)$/,
  /\/api\/v\d\/\w+\/(\d+)$/,
  /\/\w+\/(\d+)$/,
  /\/api\/\w+\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i,
  /\/api\/v\d\/\w+\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i,
  // Composite: /api/org/123/user/456
  /\/api\/\w+\/\d+\/\w+\/(\d+)$/,
  // Short hash IDs: /api/user/abc123
  /\/api\/\w+\/([a-zA-Z0-9]{6,24})$/,
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

  const stripId = (url: string) => url.replace(/\/(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-zA-Z0-9]{6,24})$/i, "");

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

  // Test sequential ID access and query param IDOR in parallel
  const [seqResults, paramResults] = await Promise.all([
    // Sequential ID tests — each endpoint tests its IDs in parallel
    Promise.allSettled(
      idEndpoints.slice(0, 8).filter((ep) => ep.currentId > 0).map(async (ep) => {
        if (PUBLIC_RESOURCE_PATTERNS.test(ep.base)) return null;
        const testIds = [1, 2, 3, 5, 10, ep.currentId + 1, ep.currentId + 2, ep.currentId + 10];
        const idResults = await Promise.allSettled(
          testIds.map(async (id) => {
            const url = `${ep.base}/${id}`;
            const res = await scanFetch(url);
            if (!res.ok) return null;
            const ct = res.headers.get("content-type") || "";
            if (!ct.includes("json")) return null;
            const text = await res.text();
            if (looksLikeHtml(text)) return null;
            return { url, status: res.status, text: text.substring(0, 500) };
          }),
        );
        const accessible = idResults.filter((r) => r.status === "fulfilled" && r.value).map((r) => (r as PromiseFulfilledResult<{ url: string; status: number; text: string }>).value);
        if (accessible.length >= 3) {
          const hasPrivateData = accessible.some((a) => PRIVATE_DATA_PATTERNS.test(a.text));
          return { base: ep.base, count: accessible.length, evidence: accessible.map((a) => `GET ${a.url} → ${a.status}`), hasPrivateData };
        }
        return null;
      }),
    ),
    // Query param IDOR tests — each endpoint tests its IDs in parallel
    Promise.allSettled(
      target.apiEndpoints.slice(0, 10).map(async (endpoint) => {
        const url = new URL(endpoint);
        const ID_PARAM_NAMES = ["id", "user_id", "userId", "uid", "account_id", "accountId", "profile_id", "profileId", "org_id", "orgId", "team_id", "teamId", "order_id", "orderId"];
        const paramName = ID_PARAM_NAMES.find((p) => url.searchParams.has(p)) || null;
        if (!paramName) return null;
        const originalId = url.searchParams.get(paramName);
        const testIds = ["1", "2", "999"].filter((id) => id !== originalId);
        const results = await Promise.allSettled(
          testIds.map(async (testId) => {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(paramName, testId);
            const res = await scanFetch(testUrl.href);
            return res.ok;
          }),
        );
        const success = results.filter((r) => r.status === "fulfilled" && r.value).length;
        if (success >= 2) return { paramName, pathname: url.pathname };
        return null;
      }),
    ),
  ]);

  for (const r of seqResults) {
    if (findings.length >= MAX_IDOR_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `idor-sequential-${seqCount++}`, module: "IDOR", severity: v.hasPrivateData ? "high" : "medium",
      title: `Sequential ID enumeration on ${v.base}/[id]`,
      description: `${v.count} different IDs returned data without any access control check.${v.hasPrivateData ? " Responses contain private user data fields." : ""}`,
      evidence: v.evidence.join("\n"),
      remediation: "Use UUIDs instead of sequential IDs. Always verify the requesting user has permission to access the specific resource.",
      cwe: "CWE-639", owasp: "A01:2021",
      codeSnippet: `// Always check resource ownership\nexport async function GET(req: Request, { params }) {\n  const user = await getAuthUser(req);\n  const resource = await db.findById(params.id);\n  if (resource.userId !== user.id) {\n    return Response.json({ error: "Forbidden" }, { status: 403 });\n  }\n  return Response.json(resource);\n}`,
    });
  }

  for (const r of paramResults) {
    if (findings.length >= MAX_IDOR_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `idor-param-${paramCount++}`, module: "IDOR", severity: "high",
      title: `IDOR via ${v.paramName} parameter on ${v.pathname}`,
      description: `Changing the ${v.paramName} parameter returns different users' data without access checks.`,
      remediation: "Validate that the authenticated user owns the requested resource.",
      cwe: "CWE-639", owasp: "A01:2021",
      codeSnippet: `// Check ownership before returning data\nconst resource = await db.findOne({ id: params.id });\nif (resource.userId !== session.userId) {\n  return Response.json({ error: "Forbidden" }, { status: 403 });\n}`,
    });
  }

  return findings;
};
