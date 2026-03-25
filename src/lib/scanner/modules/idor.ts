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
  // ULID: 26 chars, starts with time component (Crockford base32)
  /\/api\/\w+\/([0-9A-HJKMNP-TV-Z]{26})$/,
  // Snowflake/Twitter-style IDs: large numeric strings (15-20 digits)
  /\/api\/\w+\/(\d{15,20})$/,
  // Base64-encoded IDs: alphanumeric + padding (common in GraphQL relay)
  /\/api\/\w+\/([A-Za-z0-9+/]{16,}={0,2})$/,
  // Nano ID: 21 chars, URL-safe alphabet
  /\/api\/\w+\/([A-Za-z0-9_-]{21})$/,
  // CUID/CUID2: starts with 'c', 24-25 chars
  /\/api\/\w+\/(c[a-z0-9]{23,24})$/,
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

  const stripId = (url: string) => url.replace(/\/(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9A-HJKMNP-TV-Z]{26}|[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{21}|c[a-z0-9]{23,24}|[a-zA-Z0-9]{6,24})$/i, "");

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

  // Phase 3: HTTP method-based IDOR — test if changing GET to PUT/DELETE works without auth
  const methodTestEndpoints = idEndpoints.slice(0, 5).filter((ep) => ep.currentId > 0 && !PUBLIC_RESOURCE_PATTERNS.test(ep.base));
  const methodResults = await Promise.allSettled(
    methodTestEndpoints.map(async (ep) => {
      const testUrl = `${ep.base}/${ep.currentId}`;
      const methods = ["PUT", "PATCH", "DELETE"] as const;
      const results = await Promise.allSettled(
        methods.map(async (method) => {
          const res = await scanFetch(testUrl, {
            method,
            headers: { "Content-Type": "application/json" },
            body: method !== "DELETE" ? JSON.stringify({ id: ep.currentId }) : undefined,
            timeoutMs: 5000,
          });
          // 2xx or 405 with allow header listing the method = method accepted
          if (res.ok) return { method, status: res.status };
          // Some servers return 200/204 for DELETE without checking auth
          if (method === "DELETE" && res.status === 204) return { method, status: res.status };
          return null;
        }),
      );
      const accepted = results.filter((r) => r.status === "fulfilled" && r.value).map((r) => (r as PromiseFulfilledResult<{ method: string; status: number }>).value);
      if (accepted.length > 0) return { base: ep.base, id: ep.currentId, methods: accepted };
      return null;
    }),
  );

  for (const r of methodResults) {
    if (findings.length >= MAX_IDOR_FINDINGS + 2) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const hasDangerous = v.methods.some((m) => m.method === "DELETE");
    findings.push({
      id: `idor-method-${findings.length}`, module: "IDOR",
      severity: hasDangerous ? "critical" : "high",
      title: `${v.methods.map((m) => m.method).join("/")} accepted without auth on ${v.base}/[id]`,
      description: `The endpoint accepts ${v.methods.map((m) => `${m.method} (→${m.status})`).join(", ")} requests on resource IDs without apparent authentication. ${hasDangerous ? "DELETE access enables arbitrary resource deletion." : "Write access enables unauthorized data modification."}`,
      evidence: v.methods.map((m) => `${m.method} ${v.base}/${v.id} → ${m.status}`).join("\n"),
      remediation: "Require authentication and ownership verification for all state-changing operations on resources.",
      cwe: "CWE-639", owasp: "A01:2021",
      codeSnippet: `// Verify auth + ownership for mutations\nexport async function DELETE(req: Request, { params }) {\n  const user = await getAuthUser(req);\n  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  const resource = await db.findById(params.id);\n  if (resource.userId !== user.id) return Response.json({ error: "Forbidden" }, { status: 403 });\n  await db.delete(params.id);\n  return new Response(null, { status: 204 });\n}`,
    });
  }

  // Phase 4: UUID predictability — check if UUIDs in API responses are v1 (time-based, predictable)
  const uuidEndpoints = target.apiEndpoints.slice(0, 10);
  const uuidResults = await Promise.allSettled(
    uuidEndpoints.map(async (endpoint) => {
      try {
        const res = await scanFetch(endpoint, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const ct = res.headers.get("content-type") || "";
        if (!ct.includes("json")) return null;
        const text = await res.text();
        // Extract all UUIDs from the response
        const uuidRegex = /[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
        const uuids: { full: string; version: string }[] = [];
        let m: RegExpExecArray | null;
        while ((m = uuidRegex.exec(text)) !== null) {
          uuids.push({ full: m[0], version: m[1] });
        }
        const v1Uuids = uuids.filter((u) => u.version === "1");
        if (v1Uuids.length > 0) {
          return { endpoint, v1Count: v1Uuids.length, totalCount: uuids.length, sample: v1Uuids[0].full, pathname: new URL(endpoint).pathname };
        }
        return null;
      } catch {
        return null;
      }
    }),
  );

  let uuidCount = 0;
  for (const r of uuidResults) {
    if (findings.length >= MAX_IDOR_FINDINGS + 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `idor-uuid-v1-${uuidCount++}`, module: "IDOR",
      severity: "medium",
      title: `Predictable UUIDv1 detected on ${v.pathname}`,
      description: `Found ${v.v1Count} UUIDv1 identifier(s) out of ${v.totalCount} total UUIDs in the response. UUIDv1 encodes the MAC address and timestamp, making IDs predictable and enumerable. An attacker can guess other resource IDs by extracting the time component.`,
      evidence: `Endpoint: ${v.endpoint}\nSample UUIDv1: ${v.sample}\nUUIDv1 count: ${v.v1Count}/${v.totalCount}`,
      remediation: "Use UUIDv4 (random) or UUIDv7 instead of UUIDv1. UUIDv1 leaks timestamp and MAC address, making identifiers guessable.",
      cwe: "CWE-330", owasp: "A01:2021",
      codeSnippet: `// Use UUIDv4 (random) instead of UUIDv1\nimport { randomUUID } from "crypto";\nconst id = randomUUID(); // UUIDv4 — cryptographically random\n\n// Or use a library:\n// import { v4 as uuidv4 } from "uuid";\n// const id = uuidv4();`,
    });
  }

  // Phase 5: Horizontal privilege escalation — test if changing user-related IDs returns different users' data
  const USER_ID_PARAMS = ["user_id", "userId", "uid", "account_id", "accountId", "profile_id", "profileId", "owner_id", "ownerId", "member_id", "memberId"];
  const hpeEndpoints: { endpoint: string; paramName: string; originalId: string }[] = [];
  for (const endpoint of target.apiEndpoints.slice(0, 15)) {
    try {
      const url = new URL(endpoint);
      for (const param of USER_ID_PARAMS) {
        const val = url.searchParams.get(param);
        if (val) {
          hpeEndpoints.push({ endpoint, paramName: param, originalId: val });
          break;
        }
      }
    } catch { /* skip */ }
  }
  // Also check path-based user endpoints like /api/users/123/profile
  const userPathPattern = /\/api\/(?:users?|accounts?|profiles?|members?)\/(\d+)/i;
  for (const endpoint of target.apiEndpoints.slice(0, 15)) {
    const match = endpoint.match(userPathPattern);
    if (match && !hpeEndpoints.some((e) => e.endpoint === endpoint)) {
      hpeEndpoints.push({ endpoint, paramName: "path_id", originalId: match[1] });
    }
  }

  const hpeResults = await Promise.allSettled(
    hpeEndpoints.slice(0, 6).map(async (ep) => {
      const originalRes = await scanFetch(ep.endpoint, { timeoutMs: 5000 });
      if (!originalRes.ok) return null;
      const originalText = await originalRes.text();
      const ct = originalRes.headers.get("content-type") || "";
      if (!ct.includes("json")) return null;

      // Generate test IDs different from original
      const origNum = parseInt(ep.originalId);
      const testIds = !isNaN(origNum)
        ? [String(origNum + 1), String(origNum + 2), String(origNum + 100)]
        : ["1", "2", "999"];

      const testResults = await Promise.allSettled(
        testIds.map(async (testId) => {
          let testUrl: string;
          if (ep.paramName === "path_id") {
            testUrl = ep.endpoint.replace(userPathPattern, (match, _id) => match.replace(_id, testId));
          } else {
            const url = new URL(ep.endpoint);
            url.searchParams.set(ep.paramName, testId);
            testUrl = url.href;
          }
          const res = await scanFetch(testUrl, { timeoutMs: 5000 });
          if (!res.ok) return null;
          const text = await res.text();
          // Different response body means different user's data
          if (text !== originalText && text.length > 10) {
            const hasPrivate = PRIVATE_DATA_PATTERNS.test(text);
            return { testId, testUrl, hasPrivate };
          }
          return null;
        }),
      );

      const different = testResults.filter((r) => r.status === "fulfilled" && r.value).map((r) => (r as PromiseFulfilledResult<{ testId: string; testUrl: string; hasPrivate: boolean }>).value);
      if (different.length >= 2) {
        return { endpoint: ep.endpoint, paramName: ep.paramName, count: different.length, hasPrivate: different.some((d) => d.hasPrivate), evidence: different.map((d) => `GET ${d.testUrl} → different data`), pathname: new URL(ep.endpoint).pathname };
      }
      return null;
    }),
  );

  let hpeCount = 0;
  for (const r of hpeResults) {
    if (findings.length >= MAX_IDOR_FINDINGS + 5) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `idor-horizontal-${hpeCount++}`, module: "IDOR",
      severity: v.hasPrivate ? "critical" : "high",
      title: `Horizontal privilege escalation via ${v.paramName} on ${v.pathname}`,
      description: `Changing the ${v.paramName} value returns different users' data (${v.count} different IDs returned unique responses).${v.hasPrivate ? " Responses contain private data fields (email, phone, etc.)." : ""} This allows any authenticated user to access other users' resources.`,
      evidence: v.evidence.join("\n"),
      remediation: "Always verify the authenticated user owns the requested resource. Never rely solely on client-supplied user IDs for authorization.",
      cwe: "CWE-639", owasp: "A01:2021",
      codeSnippet: `// Always derive the user from the session, not from the request\nexport async function GET(req: Request) {\n  const session = await getSession(req);\n  // WRONG: const userId = req.searchParams.get("user_id");\n  // RIGHT: use session.userId directly\n  const data = await db.findMany({ where: { userId: session.userId } });\n  return Response.json(data);\n}`,
    });
  }

  // Phase 6: Role/privilege escalation via body parameter injection
  const roleEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(users?|profile|account|settings|me)\b/i.test(ep) && !/\/(login|register|signup|reset)/i.test(ep),
  ).slice(0, 3);

  const roleResults = await Promise.allSettled(
    roleEndpoints.map(async (endpoint) => {
      const escalationPayloads = [
        { role: "admin" },
        { isAdmin: true },
        { admin: true },
        { permissions: ["admin", "write", "delete"] },
        { user_type: "admin" },
        { privilege: "superuser" },
      ];
      for (const payload of escalationPayloads) {
        const res = await scanFetch(endpoint, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          timeoutMs: 5000,
        });
        if (res.ok) {
          const text = await res.text();
          // Check if the response reflects the escalated role
          const payloadKey = Object.keys(payload)[0];
          if (text.includes('"admin"') || text.includes('"superuser"') || text.includes(`"${payloadKey}"`)) {
            return { endpoint, payload: payloadKey, pathname: new URL(endpoint).pathname };
          }
        }
      }
      return null;
    }),
  );

  for (const r of roleResults) {
    if (findings.length >= MAX_IDOR_FINDINGS + 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `idor-role-escalation-${findings.length}`, module: "IDOR",
      severity: "critical",
      title: `Privilege escalation via ${v.payload} parameter on ${v.pathname}`,
      description: `PATCH request with "${v.payload}" field was accepted and reflected in the response. Users may be able to escalate their own privileges by injecting role fields in profile update requests.`,
      evidence: `PATCH ${v.endpoint}\nBody: {"${v.payload}": ...}\nResponse reflects escalated privilege`,
      remediation: "Never trust client-supplied role/permission fields. Use an allowlist of updatable fields and derive roles from server-side logic only.",
      cwe: "CWE-269", owasp: "A01:2021",
      codeSnippet: `// Allowlist updatable fields — never allow role changes\nconst ALLOWED_FIELDS = ["name", "email", "avatar"];\nexport async function PATCH(req: Request) {\n  const body = await req.json();\n  const updates = Object.fromEntries(\n    Object.entries(body).filter(([k]) => ALLOWED_FIELDS.includes(k))\n  );\n  await db.user.update({ where: { id: session.userId }, data: updates });\n}`,
    });
  }

  return findings;
};
