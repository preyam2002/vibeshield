import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const PROTO_POLLUTION_PAYLOADS: { key: string; json: string }[] = [
  { key: "__proto__", json: '{"__proto__":{"polluted":true}}' },
  { key: "constructor.prototype", json: '{"constructor":{"prototype":{"polluted":true}}}' },
];

const MASS_ASSIGNMENT_FIELDS = [
  { role: "admin" },
  { isAdmin: true },
  { is_admin: true },
  { admin: true },
  { role: "superadmin" },
  { verified: true },
  { emailVerified: true },
  { email_verified: true },
  { premium: true },
  { is_premium: true },
  { tier: "enterprise" },
  { plan: "pro" },
  { permissions: ["admin", "write", "delete"] },
  { status: "active" },
  { active: true },
  { banned: false },
  { credits: 999999 },
  { balance: 999999 },
  { discount: 100 },
];

const LARGE_RESPONSE_THRESHOLD = 50_000; // 50KB — likely over-fetching
const LARGE_ARRAY_THRESHOLD = 50; // arrays with 50+ items suggest missing pagination

export const apiSecurityModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Run MIME check and per-endpoint tests in parallel
  const [mimeResults, endpointResults] = await Promise.all([
    // 1. Check MIME mismatches in parallel
    Promise.allSettled(
      target.apiEndpoints.slice(0, 20).map(async (endpoint) => {
        const res = await scanFetch(endpoint);
        if (!res.ok) return null;
        const ct = res.headers.get("content-type") || "";
        const text = await res.text();
        if (text.startsWith("{") || text.startsWith("[")) {
          try { JSON.parse(text); } catch { return null; }
          if (ct.includes("text/html") || ct.includes("text/plain")) {
            return `${new URL(endpoint).pathname} (returns JSON, served as ${ct.split(";")[0]})`;
          }
        }
        return null;
      }),
    ),
    // 2. Test each endpoint for proto pollution, over-fetching, and mass assignment in parallel
    Promise.allSettled(
      target.apiEndpoints.slice(0, 15).map(async (endpoint) => {
        const contentType = await getContentType(endpoint);
        if (!contentType?.includes("json")) return null;
        const pathname = new URL(endpoint).pathname;
        const result: { proto?: Finding; overfetch?: Finding; pagination?: Finding; massAssign?: Finding } = {};

        // Proto pollution — test payloads sequentially (stop on first hit)
        for (const { key, json } of PROTO_POLLUTION_PAYLOADS) {
          try {
            const res = await scanFetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: json });
            if (!res.ok) continue;
            const text = await res.text();
            let parsed: Record<string, unknown> | null = null;
            try { parsed = JSON.parse(text); } catch { /* skip */ }
            const isPolluted = parsed && "polluted" in parsed && parsed.polluted === true;
            const storedProto = parsed && key === "__proto__" && Object.prototype.hasOwnProperty.call(parsed, "__proto__");
            if (isPolluted || storedProto) {
              result.proto = {
                id: `api-proto-pollution-${pathname}`, module: "API Security", severity: "high",
                title: `Possible prototype pollution via ${key} on ${pathname}`,
                description: `The API accepted and processed a JSON body containing "${key}". This can lead to prototype pollution, which may allow an attacker to modify application behavior, bypass security checks, or achieve remote code execution.`,
                evidence: `POST ${endpoint}\nPayload: ${json}\nResponse: ${text.substring(0, 300)}`,
                remediation: "Sanitize incoming JSON to strip __proto__ and constructor keys. Use Object.create(null) for lookup objects. Consider a library like secure-json-parse.",
                codeSnippet: `// Use secure-json-parse to reject dangerous keys\nimport sjson from "secure-json-parse";\napp.use(express.json({ reviver: sjson.reviver }));\n\n// Or strip manually in middleware\nfunction stripProto(obj: unknown): unknown {\n  if (typeof obj !== "object" || obj === null) return obj;\n  const clean = Object.create(null);\n  for (const [k, v] of Object.entries(obj)) {\n    if (k === "__proto__" || k === "constructor") continue;\n    clean[k] = stripProto(v);\n  }\n  return clean;\n}`,
                cwe: "CWE-1321", owasp: "A03:2021",
              };
              break;
            }
          } catch { /* skip */ }
        }

        // Over-fetching / pagination check
        try {
          const res = await scanFetch(endpoint);
          if (res.ok) {
            const text = await res.text();
            if (text.length >= 10) {
              let data: unknown;
              try { data = JSON.parse(text); } catch { data = null; }
              if (data) {
                if (text.length > LARGE_RESPONSE_THRESHOLD) {
                  result.overfetch = {
                    id: `api-overfetch-${pathname}`, module: "API Security", severity: "medium",
                    title: `Possible over-fetching on ${pathname}`,
                    description: `This API endpoint returns ${(text.length / 1024).toFixed(1)}KB of data in a single response. This often means the server is returning full database records instead of selecting only needed fields, potentially exposing internal or sensitive fields.`,
                    evidence: `GET ${endpoint}\nResponse size: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
                    remediation: "Implement field selection — only return the fields the client needs. Use DTOs or serializers to control API output shape.",
                    codeSnippet: `// Select only needed fields instead of returning full records\n// Prisma\nconst users = await prisma.user.findMany({\n  select: { id: true, name: true, email: true },\n});\n\n// Or use a DTO to strip sensitive fields\nfunction toPublicUser(user: User) {\n  const { passwordHash, ssn, ...safe } = user;\n  return safe;\n}`,
                    cwe: "CWE-213", owasp: "A01:2021",
                  };
                }
                const arr = Array.isArray(data) ? data : null;
                if (arr && arr.length >= LARGE_ARRAY_THRESHOLD) {
                  result.pagination = {
                    id: `api-no-pagination-${pathname}`, module: "API Security", severity: "medium",
                    title: `No pagination on ${pathname} (${arr.length} items)`,
                    description: `This endpoint returns ${arr.length} items in a single response with no apparent pagination. As data grows, this becomes a denial-of-service risk and can leak data an attacker shouldn't see in bulk.`,
                    evidence: `GET ${endpoint}\nItems returned: ${arr.length}\nResponse size: ${text.length} bytes`,
                    remediation: "Implement cursor or offset-based pagination. Enforce a maximum page size (e.g., 50-100 items). Add rate limiting.",
                    codeSnippet: `// Offset-based pagination\napp.get("/api/items", async (req, res) => {\n  const page = Math.max(1, parseInt(req.query.page as string) || 1);\n  const limit = Math.min(100, parseInt(req.query.limit as string) || 20);\n  const items = await prisma.item.findMany({\n    skip: (page - 1) * limit,\n    take: limit,\n  });\n  res.json({ data: items, page, limit });\n});`,
                    cwe: "CWE-770", owasp: "A04:2021",
                  };
                }
              }
            }
          }
        } catch { /* skip */ }

        // Mass assignment — GET baseline then test fields sequentially
        try {
          const getRes = await scanFetch(endpoint);
          if (getRes.ok) {
            const getText = await getRes.text();
            for (const extraFields of MASS_ASSIGNMENT_FIELDS.slice(0, 3)) {
              try {
                const res = await scanFetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ test: "vibeshield-scan", ...extraFields }) });
                if (!res.ok) continue;
                const text = await res.text();
                const fieldName = Object.keys(extraFields)[0];
                const fieldVal = String(Object.values(extraFields)[0]);
                if (text.includes(fieldName) && text.includes(fieldVal)) {
                  let parsed: Record<string, unknown> | null = null;
                  try { parsed = JSON.parse(text); } catch { /* skip */ }
                  const fieldAlreadyInBaseline = getText.includes(`"${fieldName}"`) && getText.includes(fieldVal);
                  if (parsed && fieldName in parsed && !fieldAlreadyInBaseline) {
                    result.massAssign = {
                      id: `api-mass-assignment-${pathname}`, module: "API Security", severity: "high",
                      title: `Possible mass assignment on ${pathname}`,
                      description: `The API accepted and returned a privileged field "${fieldName}" set to "${fieldVal}". This suggests the endpoint blindly assigns all incoming fields to the data model, which could allow privilege escalation.`,
                      evidence: `POST ${endpoint}\nPayload included: ${JSON.stringify(extraFields)}\nResponse contains "${fieldName}": ${text.substring(0, 300)}`,
                      remediation: "Use an allowlist of accepted fields in your API handlers. Never pass raw request body directly to database create/update operations. Use DTOs or pick() to select only permitted fields.",
                      codeSnippet: `// Allowlist accepted fields — never spread raw body\nconst ALLOWED_FIELDS = ["name", "email", "bio"] as const;\n\napp.post("/api/users", async (req, res) => {\n  const data: Record<string, unknown> = {};\n  for (const key of ALLOWED_FIELDS) {\n    if (key in req.body) data[key] = req.body[key];\n  }\n  const user = await prisma.user.create({ data });\n  res.json(user);\n});`,
                      cwe: "CWE-915", owasp: "A08:2021",
                    };
                    break;
                  }
                }
              } catch { /* skip */ }
            }
          }
        } catch { /* skip */ }

        return result;
      }),
    ),
  ]);

  // Collect MIME mismatch findings
  const mismatchEndpoints: string[] = [];
  for (const r of mimeResults) {
    if (r.status === "fulfilled" && r.value) mismatchEndpoints.push(r.value);
  }
  if (mismatchEndpoints.length > 0) {
    findings.push({
      id: "api-mime-mismatch", module: "API Security", severity: "low",
      title: `${mismatchEndpoints.length} API endpoint${mismatchEndpoints.length > 1 ? "s" : ""} with Content-Type mismatch`,
      description: "API endpoints return JSON data but with an incorrect Content-Type header. Combined with missing X-Content-Type-Options, this enables MIME-sniffing attacks where browsers may interpret JSON as HTML.",
      evidence: mismatchEndpoints.slice(0, 5).join("\n"),
      remediation: "Set Content-Type: application/json for all JSON API responses. Ensure X-Content-Type-Options: nosniff is set.",
      codeSnippet: `// Express middleware to fix Content-Type for JSON responses\napp.use("/api", (req, res, next) => {\n  const originalJson = res.json.bind(res);\n  res.json = (body) => {\n    res.setHeader("Content-Type", "application/json");\n    res.setHeader("X-Content-Type-Options", "nosniff");\n    return originalJson(body);\n  };\n  next();\n});`,
      cwe: "CWE-436", owasp: "A05:2021",
    });
  }

  // Collect per-endpoint findings
  for (const r of endpointResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.proto) findings.push(v.proto);
    if (v.overfetch) findings.push(v.overfetch);
    if (v.pagination) findings.push(v.pagination);
    if (v.massAssign) findings.push(v.massAssign);
  }

  // Phase 5: GraphQL-style batching abuse on REST endpoints
  // Some APIs accept arrays, allowing N operations in one request (bypasses rate limiting)
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    try {
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify([{ id: 1 }, { id: 2 }, { id: 3 }]),
      });
      if (!res.ok) continue;
      const text = await res.text();
      let parsed: unknown;
      try { parsed = JSON.parse(text); } catch { continue; }
      if (Array.isArray(parsed) && parsed.length >= 2) {
        findings.push({
          id: `api-batch-abuse-${new URL(endpoint).pathname}`,
          module: "API Security",
          severity: "medium",
          title: `Batch processing on ${new URL(endpoint).pathname} — rate limit bypass risk`,
          description: "This endpoint accepts and processes arrays of requests in a single call. An attacker can bypass per-request rate limiting by batching thousands of operations into one HTTP request, enabling brute force, enumeration, or resource exhaustion.",
          evidence: `POST ${endpoint}\nPayload: [{id:1},{id:2},{id:3}]\nResponse: array with ${(parsed as unknown[]).length} items`,
          remediation: "Limit array size in batch endpoints (e.g., max 10 items). Count batch items against rate limits. Validate and authorize each item individually.",
          cwe: "CWE-770",
          owasp: "A04:2021",
          confidence: 70,
        });
        break;
      }
    } catch { /* skip */ }
  }

  // Phase 6: Verbose error detection on API endpoints
  const errorTriggers = [
    { body: "not-json", ct: "application/json", desc: "malformed JSON" },
    { body: JSON.stringify({ id: "'; DROP TABLE--" }), ct: "application/json", desc: "SQL-like string" },
    { body: JSON.stringify({ __proto__: null }), ct: "application/json", desc: "__proto__ null" },
  ];
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    for (const trigger of errorTriggers) {
      try {
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": trigger.ct },
          body: trigger.body,
        });
        const text = await res.text();
        if (res.status >= 400 && res.status < 600) {
          const leaks = [
            { re: /at\s+\S+\s+\([\w/\\.-]+:\d+:\d+\)/, type: "stack trace" },
            { re: /node_modules\//, type: "node_modules path" },
            { re: /ECONNREFUSED|ENOTFOUND|ETIMEOUT/, type: "internal network error" },
            { re: /password|secret|key|token/i, type: "credential keyword in error" },
          ];
          const detected = leaks.filter((l) => l.re.test(text));
          if (detected.length > 0) {
            findings.push({
              id: `api-verbose-error-${new URL(endpoint).pathname}`,
              module: "API Security",
              severity: "medium",
              title: `Verbose error on ${new URL(endpoint).pathname} leaks ${detected.map((d) => d.type).join(", ")}`,
              description: `Sending ${trigger.desc} to this endpoint produces a ${res.status} response that leaks internal details: ${detected.map((d) => d.type).join(", ")}. This information helps attackers understand the tech stack and find further vulnerabilities.`,
              evidence: `POST ${endpoint} (${trigger.desc})\nStatus: ${res.status}\nResponse excerpt: ${text.substring(0, 300)}`,
              remediation: "Return generic error messages to clients. Log detailed errors server-side only. In Next.js, customize error responses in route handlers.",
              cwe: "CWE-209",
              owasp: "A05:2021",
              confidence: 85,
              codeSnippet: `// Catch errors and return safe messages\nexport async function POST(req: Request) {\n  try {\n    const body = await req.json();\n    // ... handle request\n  } catch (err) {\n    console.error("API error:", err); // log server-side\n    return Response.json(\n      { error: "Invalid request" }, // generic client message\n      { status: 400 }\n    );\n  }\n}`,
            });
            break; // one finding per endpoint is enough
          }
        }
      } catch { /* skip */ }
    }
  }

  // Phase 7: CORS preflight bypass check on API endpoints
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    try {
      const res = await scanFetch(endpoint, {
        method: "OPTIONS",
        headers: {
          "Origin": "https://evil.com",
          "Access-Control-Request-Method": "DELETE",
          "Access-Control-Request-Headers": "Authorization",
        },
      });
      const acao = res.headers.get("access-control-allow-origin");
      const acam = res.headers.get("access-control-allow-methods");
      if (acao === "*" && acam && /DELETE|PUT|PATCH/i.test(acam)) {
        findings.push({
          id: `api-cors-wildcard-destructive-${new URL(endpoint).pathname}`,
          module: "API Security",
          severity: "high",
          title: `${new URL(endpoint).pathname} allows destructive methods from any origin`,
          description: "This API endpoint responds to CORS preflight with Access-Control-Allow-Origin: * and allows destructive HTTP methods (DELETE/PUT/PATCH). Any website can make authenticated requests to this endpoint.",
          evidence: `OPTIONS ${endpoint}\nOrigin: https://evil.com\nACAO: ${acao}\nACAM: ${acam}`,
          remediation: "Restrict CORS to your own domain. Never use * with credentials. Limit allowed methods to what's actually needed.",
          cwe: "CWE-942",
          owasp: "A05:2021",
          confidence: 90,
        });
        break;
      }
    } catch { /* skip */ }
  }

  return findings;
};

async function getContentType(url: string): Promise<string | null> {
  try {
    const res = await scanFetch(url, { method: "HEAD" });
    return res.headers.get("content-type");
  } catch {
    // Fall back to GET
    try {
      const res = await scanFetch(url);
      return res.headers.get("content-type");
    } catch {
      return null;
    }
  }
}
