import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

// NoSQL injection payloads for MongoDB-style backends
const NOSQL_PAYLOADS_GET = [
  // Operator injection via query params
  { param: "[$ne]", value: "", desc: "MongoDB $ne operator" },
  { param: "[$gt]", value: "", desc: "MongoDB $gt operator" },
  { param: "[$regex]", value: ".*", desc: "MongoDB $regex operator" },
  { param: "[$exists]", value: "true", desc: "MongoDB $exists operator" },
];

const NOSQL_JSON_PAYLOADS = [
  // JSON body injection
  { body: { "$gt": "" }, desc: "$gt operator in JSON" },
  { body: { "$ne": null }, desc: "$ne null in JSON" },
  { body: { "$regex": ".*" }, desc: "$regex wildcard in JSON" },
  { body: { "$where": "1==1" }, desc: "$where always-true" },
];

const NOSQL_AUTH_BYPASS = [
  // Auth bypass payloads
  { email: { "$ne": "" }, password: { "$ne": "" }, desc: "$ne empty string auth bypass" },
  { email: { "$gt": "" }, password: { "$gt": "" }, desc: "$gt empty string auth bypass" },
  { email: { "$regex": ".*" }, password: { "$ne": "" }, desc: "$regex wildcard auth bypass" },
];

const NOSQL_ERROR_PATTERNS = [
  /MongoError/i,
  /\bMongo\b.*\bfailed\b/i,
  /\bCastError\b/i,
  /\bBSONTypeError\b/i,
  /\bValidation.*failed\b/i,
  /\$where\b.*\bnot allowed\b/i,
  /\bunknown.*operator\b.*\$\w+/i,
  /\bbad.*query\b/i,
  /\bCannot.*\$\w+/i,
  /\billegal.*operator\b/i,
  /firestore.*error/i,
  /\bpermission.denied\b/i,
  /\binvalid.*filter\b/i,
];

export const nosqlInjectionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;

  // Identify likely NoSQL-backed endpoints
  const isNoSqlStack = target.technologies.some((t) =>
    /mongo|firebase|firestore|dynamo|convex/i.test(t),
  );

  const apiEndpoints = target.apiEndpoints.slice(0, 15);
  const postEndpoints = apiEndpoints.filter((ep) =>
    /auth|login|signin|signup|register|user|search|query|filter/i.test(ep),
  );

  // Run all 3 phases in parallel
  const [phase1Results, phase2Results, phase3Results] = await Promise.all([
    // Phase 1: Operator injection via query parameters — parallelize across endpoints
    Promise.allSettled(
      apiEndpoints.map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        let baselineText = "";
        let baselineStatus = 0;
        try {
          const res = await scanFetch(endpoint, { timeoutMs: 5000 });
          baselineStatus = res.status;
          baselineText = await res.text();
        } catch { return null; }

        if (NOSQL_ERROR_PATTERNS.some((p) => p.test(baselineText))) return null;

        for (const { param, value, desc } of NOSQL_PAYLOADS_GET) {
          const url = new URL(endpoint);
          const existingParams = [...url.searchParams.keys()];
          const testParams = existingParams.length > 0 ? existingParams : ["id", "email", "username"];

          for (const paramName of testParams.slice(0, 3)) {
            try {
              const testUrl = new URL(endpoint);
              testUrl.searchParams.delete(paramName);
              const injectedUrl = `${testUrl.href}${testUrl.search ? "&" : "?"}${paramName}${param}=${encodeURIComponent(value)}`;

              const res = await scanFetch(injectedUrl, { timeoutMs: 5000 });
              const text = await res.text();

              for (const pattern of NOSQL_ERROR_PATTERNS) {
                if (pattern.test(text) && !pattern.test(baselineText)) {
                  return { type: "error" as const, pathname, desc, injectedUrl, pattern: pattern.source, text };
                }
              }

              if (res.status === 200 && baselineStatus === 200) {
                const ct = res.headers.get("content-type") || "";
                if (ct.includes("application/json")) {
                  try {
                    const baseData = JSON.parse(baselineText);
                    const injData = JSON.parse(text);
                    const bCount = Array.isArray(baseData) ? baseData.length : (baseData.data ? (Array.isArray(baseData.data) ? baseData.data.length : 1) : 1);
                    const iCount = Array.isArray(injData) ? injData.length : (injData.data ? (Array.isArray(injData.data) ? injData.data.length : 1) : 1);
                    if (iCount > bCount * 2 && iCount > 3) {
                      return { type: "bypass" as const, pathname, desc, injectedUrl, baseCount: bCount, injCount: iCount };
                    }
                  } catch { /* skip */ }
                }
              }
            } catch { /* skip */ }
          }
        }
        return null;
      }),
    ),

    // Phase 2: JSON body injection — parallelize across endpoints
    Promise.allSettled(
      postEndpoints.slice(0, 5).map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        let baselineText = "";
        try {
          const res = await scanFetch(endpoint, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ test: "normal_value" }), timeoutMs: 5000,
          });
          baselineText = await res.text();
        } catch { return null; }

        if (NOSQL_ERROR_PATTERNS.some((p) => p.test(baselineText))) return null;

        for (const { body, desc } of NOSQL_JSON_PAYLOADS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ value: body }), timeoutMs: 5000,
            });
            const text = await res.text();
            for (const pattern of NOSQL_ERROR_PATTERNS) {
              if (pattern.test(text) && !pattern.test(baselineText)) {
                return { pathname, endpoint, body, desc, pattern: pattern.source, text };
              }
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Phase 3: Auth bypass — parallelize across endpoints
    (isNoSqlStack || postEndpoints.some((ep) => /auth|login|signin/i.test(ep)))
      ? Promise.allSettled(
          postEndpoints.filter((ep) => /auth|login|signin/i.test(ep)).slice(0, 3).map(async (endpoint) => {
            const pathname = new URL(endpoint).pathname;
            for (const payload of NOSQL_AUTH_BYPASS) {
              try {
                const res = await scanFetch(endpoint, {
                  method: "POST", headers: { "Content-Type": "application/json" },
                  body: JSON.stringify(payload), timeoutMs: 5000,
                });
                const text = await res.text();
                if (res.status === 200 || res.status === 302) {
                  const ct = res.headers.get("content-type") || "";
                  if (ct.includes("application/json")) {
                    try {
                      const data = JSON.parse(text);
                      if ("token" in data || "accessToken" in data || "access_token" in data || "session" in data || "jwt" in data) {
                        return { pathname, endpoint, payload };
                      }
                    } catch { /* skip */ }
                  }
                }
              } catch { /* skip */ }
            }
            return null;
          }),
        )
      : Promise.resolve([]),
  ]);

  const flagged = new Set<string>();

  // Collect Phase 1 findings
  for (const r of phase1Results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);

    if (v.type === "error") {
      findings.push({
        id: `nosql-error-${count++}`, module: "NoSQL Injection", severity: "high",
        title: `NoSQL error disclosure on ${v.pathname}`,
        description: `A NoSQL operator injection (${v.desc}) triggered a database error message. This reveals the database technology and suggests operator injection may be possible.`,
        evidence: `URL: ${v.injectedUrl}\nError pattern: ${v.pattern}\nResponse excerpt: ${v.text.substring(0, 300)}`,
        remediation: "Sanitize all query parameters before passing to database queries. Use an ORM/ODM with strict input typing. For MongoDB, reject objects in query parameters — only accept string/number values.",
        cwe: "CWE-943", owasp: "A03:2021",
      });
    } else {
      findings.push({
        id: `nosql-bypass-${count++}`, module: "NoSQL Injection", severity: "critical",
        title: `NoSQL injection bypasses filter on ${v.pathname}`,
        description: `A ${v.desc} injection returned ${v.injCount} records vs ${v.baseCount} normally. The operator bypassed the intended query filter, exposing additional data.`,
        evidence: `URL: ${v.injectedUrl}\nBaseline records: ${v.baseCount}\nInjected records: ${v.injCount}`,
        remediation: "Never pass raw query parameters to MongoDB queries. Use mongoose schema validation or explicitly cast/validate each parameter type before querying.",
        cwe: "CWE-943", owasp: "A03:2021",
      });
    }
  }

  // Collect Phase 2 findings
  for (const r of phase2Results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    findings.push({
      id: `nosql-json-${count++}`, module: "NoSQL Injection", severity: "high",
      title: `NoSQL injection via JSON body on ${v.pathname}`,
      description: `Sending a ${v.desc} payload in the JSON body triggered a database error. The server passes user-supplied objects directly to database queries.`,
      evidence: `Payload: ${JSON.stringify(v.body)}\nEndpoint: ${v.endpoint}\nError pattern: ${v.pattern}\nResponse excerpt: ${v.text.substring(0, 300)}`,
      remediation: "Validate that request body fields are the expected primitive types (string, number). Reject objects/arrays where primitives are expected. Use schema validation (Zod, Joi).",
      cwe: "CWE-943", owasp: "A03:2021",
    });
  }

  // Collect Phase 3 findings
  if (Array.isArray(phase3Results)) {
    for (const r of phase3Results) {
      if ((r as PromiseSettledResult<unknown>).status !== "fulfilled") continue;
      const v = (r as PromiseFulfilledResult<{ pathname: string; endpoint: string; payload: typeof NOSQL_AUTH_BYPASS[0] } | null>).value;
      if (!v || flagged.has(v.pathname)) continue;
      flagged.add(v.pathname);
      findings.push({
        id: `nosql-auth-bypass-${count++}`, module: "NoSQL Injection", severity: "critical",
        title: `Authentication bypass via NoSQL injection on ${v.pathname}`,
        description: `Sending ${v.payload.desc || "NoSQL operators"} as credentials returned an authentication token. Attackers can log in as any user without knowing their password.`,
        evidence: `Endpoint: ${v.endpoint}\nPayload: ${JSON.stringify(v.payload)}\nResponse contains authentication token`,
        remediation: "Validate that email/username/password fields are strings before querying. Use bcrypt/argon2 for password comparison — never query the database with user-supplied password objects.",
        cwe: "CWE-943", owasp: "A07:2021",
      });
    }
  }

  return findings;
};
