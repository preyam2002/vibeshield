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

const NOSQL_JSON_PAYLOADS: { body: Record<string, unknown>; desc: string }[] = [
  // JSON body injection
  { body: { "$gt": "" }, desc: "$gt operator in JSON" },
  { body: { "$ne": null }, desc: "$ne null in JSON" },
  { body: { "$regex": ".*" }, desc: "$regex wildcard in JSON" },
  { body: { "$where": "1==1" }, desc: "$where always-true" },
  { body: { "$in": [null, "", 0] }, desc: "$in array injection" },
  { body: { "$or": [{ "a": 1 }, { "b": 1 }] }, desc: "$or condition injection" },
  // JS execution via $where (RCE vector)
  { body: { "$where": "function(){return true}" }, desc: "$where JS function" },
  // Prototype pollution via __proto__
  { body: { "__proto__": { "isAdmin": true } }, desc: "__proto__ pollution" },
  { body: { "constructor": { "prototype": { "isAdmin": true } } }, desc: "constructor.prototype pollution" },
];

const NOSQL_AUTH_BYPASS = [
  // Auth bypass payloads
  { email: { "$ne": "" }, password: { "$ne": "" }, desc: "$ne empty string auth bypass" },
  { email: { "$gt": "" }, password: { "$gt": "" }, desc: "$gt empty string auth bypass" },
  { email: { "$regex": ".*" }, password: { "$ne": "" }, desc: "$regex wildcard auth bypass" },
  // Array injection — MongoDB treats arrays differently from strings, bypassing comparisons
  { email: { "$ne": "" }, password: ["anything"], desc: "array injection auth bypass" },
];

// MongoDB regex injection payloads — detect if server processes $regex operators (enables ReDoS / data extraction)
const NOSQL_REGEX_PAYLOADS: { body: Record<string, unknown>; desc: string }[] = [
  { body: { field: { "$regex": ".*" } }, desc: "$regex wildcard on field" },
  { body: { field: { "$regex": "^a", "$options": "si" } }, desc: "$regex with options" },
  { body: { username: { "$regex": ".*" } }, desc: "$regex on username" },
  { body: { email: { "$regex": "^." } }, desc: "$regex prefix on email" },
];

// $where JavaScript injection payloads — blind detection via response time
const NOSQL_WHERE_PAYLOADS: { body: Record<string, unknown>; desc: string; delayMs: number }[] = [
  { body: { "$where": "sleep(3000)" }, desc: "$where sleep(3000)", delayMs: 3000 },
  { body: { "$where": "function(){sleep(3000);return true}" }, desc: "$where function sleep", delayMs: 3000 },
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
        codeSnippet: `// Validate input types before MongoDB queries\nimport { z } from "zod";\nconst schema = z.object({ email: z.string(), id: z.string() });\nconst input = schema.parse(req.query); // Rejects {$ne:""}\nconst user = await db.collection("users").findOne(input);`,
      });
    } else {
      findings.push({
        id: `nosql-bypass-${count++}`, module: "NoSQL Injection", severity: "critical",
        title: `NoSQL injection bypasses filter on ${v.pathname}`,
        description: `A ${v.desc} injection returned ${v.injCount} records vs ${v.baseCount} normally. The operator bypassed the intended query filter, exposing additional data.`,
        evidence: `URL: ${v.injectedUrl}\nBaseline records: ${v.baseCount}\nInjected records: ${v.injCount}`,
        remediation: "Never pass raw query parameters to MongoDB queries. Use mongoose schema validation or explicitly cast/validate each parameter type before querying.",
        cwe: "CWE-943", owasp: "A03:2021",
        codeSnippet: `// Validate input types before MongoDB queries\nimport { z } from "zod";\nconst schema = z.object({ email: z.string(), id: z.string() });\nconst input = schema.parse(req.query); // Rejects {$ne:""}\nconst user = await db.collection("users").findOne(input);`,
      });
    }
  }

  // Collect Phase 2 findings
  for (const r of phase2Results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    const isProtoPollution = v.desc.includes("__proto__") || v.desc.includes("constructor.prototype");
    findings.push({
      id: `nosql-json-${count++}`, module: isProtoPollution ? "Prototype Pollution" : "NoSQL Injection", severity: isProtoPollution ? "critical" : "high",
      title: isProtoPollution ? `Prototype pollution via JSON body on ${v.pathname}` : `NoSQL injection via JSON body on ${v.pathname}`,
      description: isProtoPollution
        ? `Sending a ${v.desc} payload was processed by the server. If the application merges user input into objects without sanitization, attackers can modify Object.prototype and gain privilege escalation or RCE.`
        : `Sending a ${v.desc} payload in the JSON body triggered a database error. The server passes user-supplied objects directly to database queries.`,
      evidence: `Payload: ${JSON.stringify(v.body)}\nEndpoint: ${v.endpoint}\nError pattern: ${v.pattern}\nResponse excerpt: ${v.text.substring(0, 300)}`,
      remediation: "Validate that request body fields are the expected primitive types (string, number). Reject objects/arrays where primitives are expected. Use schema validation (Zod, Joi).",
      cwe: "CWE-943", owasp: "A03:2021",
      codeSnippet: `// Validate JSON body types with Zod\nimport { z } from "zod";\nconst LoginSchema = z.object({\n  email: z.string().email(),\n  password: z.string().min(1),\n});\n// Rejects {email: {$gt: ""}} automatically\nconst { email, password } = LoginSchema.parse(await req.json());`,
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
        codeSnippet: `// Validate credential types before querying\nimport { z } from "zod";\nconst LoginSchema = z.object({\n  email: z.string().email(),\n  password: z.string().min(8),\n});\nconst { email, password } = LoginSchema.parse(await req.json());\n// Then use bcrypt.compare(password, user.passwordHash)`,
      });
    }
  }

  // Phase 4: MongoDB regex injection — detect if server processes $regex operators
  const regexResults = await Promise.allSettled(
    postEndpoints.slice(0, 5).map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      if (flagged.has(pathname)) return null;

      let baselineText = "";
      let baselineStatus = 0;
      try {
        const res = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ field: "normal_value" }), timeoutMs: 5000,
        });
        baselineStatus = res.status;
        baselineText = await res.text();
      } catch { return null; }

      for (const { body, desc } of NOSQL_REGEX_PAYLOADS) {
        try {
          const res = await scanFetch(endpoint, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body), timeoutMs: 5000,
          });
          const text = await res.text();

          // Check for error patterns indicating $regex was processed
          for (const pattern of NOSQL_ERROR_PATTERNS) {
            if (pattern.test(text) && !pattern.test(baselineText)) {
              return { type: "error" as const, pathname, endpoint, desc, pattern: pattern.source, text };
            }
          }

          // Check if regex returned more data than baseline (data extraction)
          if (res.status === 200 && baselineStatus === 200) {
            const ct = res.headers.get("content-type") || "";
            if (ct.includes("application/json")) {
              try {
                const baseData = JSON.parse(baselineText);
                const injData = JSON.parse(text);
                const bCount = Array.isArray(baseData) ? baseData.length : 1;
                const iCount = Array.isArray(injData) ? injData.length : 1;
                if (iCount > bCount * 2 && iCount > 3) {
                  return { type: "extraction" as const, pathname, endpoint, desc, baseCount: bCount, injCount: iCount };
                }
              } catch { /* skip */ }
            }
          }
        } catch { /* skip */ }
      }
      return null;
    }),
  );

  for (const r of regexResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    if (v.type === "error") {
      findings.push({
        id: `nosql-regex-${count++}`, module: "NoSQL Injection", severity: "high",
        title: `MongoDB $regex injection on ${v.pathname}`,
        description: `Sending a ${v.desc} payload triggered a database error. The server processes $regex operators from user input, enabling ReDoS attacks and regex-based data extraction.`,
        evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nError pattern: ${v.pattern}\nResponse excerpt: ${v.text.substring(0, 300)}`,
        remediation: "Reject objects in fields that expect string values. Use schema validation to ensure fields are primitives before passing to MongoDB queries. Disable $regex in user-facing queries.",
        cwe: "CWE-943", owasp: "A03:2021",
        codeSnippet: `// Strip MongoDB operators from user input\nfunction sanitize(input: unknown): string {\n  if (typeof input !== "string") throw new Error("Expected string");\n  return input;\n}\nconst query = { field: sanitize(req.body.field) };`,
      });
    } else {
      findings.push({
        id: `nosql-regex-extract-${count++}`, module: "NoSQL Injection", severity: "critical",
        title: `Data extraction via $regex injection on ${v.pathname}`,
        description: `A ${v.desc} payload returned ${v.injCount} records vs ${v.baseCount} normally. Attackers can use regex patterns to enumerate and extract data character by character.`,
        evidence: `Endpoint: ${v.endpoint}\nBaseline records: ${v.baseCount}\nRegex injection records: ${v.injCount}`,
        remediation: "Never pass user input directly as MongoDB query operators. Validate that query fields are strings, not objects containing $regex.",
        cwe: "CWE-943", owasp: "A03:2021",
        codeSnippet: `// Validate input types before MongoDB queries\nimport { z } from "zod";\nconst schema = z.object({ field: z.string() });\nconst input = schema.parse(req.body); // Rejects {$regex: ".*"}`,
      });
    }
  }

  // Phase 5: Array injection bypass — MongoDB treats arrays differently, bypassing string comparisons
  const arrayResults = await Promise.allSettled(
    postEndpoints.filter((ep) => /auth|login|signin|signup|register/i.test(ep)).slice(0, 3).map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      if (flagged.has(pathname)) return null;

      const arrayPayloads = [
        { email: "test@test.com", password: ["anything"], desc: "password as array" },
        { username: "admin", password: [""], desc: "password as empty-string array" },
        { email: ["admin@test.com"], password: "test", desc: "email as array" },
      ];

      for (const payload of arrayPayloads) {
        try {
          const res = await scanFetch(endpoint, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload), timeoutMs: 5000,
          });
          const text = await res.text();

          // Check for error patterns
          for (const pattern of NOSQL_ERROR_PATTERNS) {
            if (pattern.test(text)) {
              return { type: "error" as const, pathname, endpoint, desc: payload.desc, pattern: pattern.source, text };
            }
          }

          // Check for auth success indicators
          if (res.status === 200 || res.status === 302) {
            const ct = res.headers.get("content-type") || "";
            if (ct.includes("application/json")) {
              try {
                const data = JSON.parse(text);
                if ("token" in data || "accessToken" in data || "access_token" in data || "session" in data || "jwt" in data) {
                  return { type: "bypass" as const, pathname, endpoint, desc: payload.desc };
                }
              } catch { /* skip */ }
            }
          }
        } catch { /* skip */ }
      }
      return null;
    }),
  );

  for (const r of arrayResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    findings.push({
      id: `nosql-array-${count++}`, module: "NoSQL Injection",
      severity: v.type === "bypass" ? "critical" : "high",
      title: v.type === "bypass"
        ? `Authentication bypass via array injection on ${v.pathname}`
        : `Array injection processed on ${v.pathname}`,
      description: v.type === "bypass"
        ? `Sending ${v.desc} returned an authentication token. MongoDB treats arrays differently from strings in comparisons, allowing attackers to bypass password checks.`
        : `Sending ${v.desc} triggered a database error. The server does not validate that credential fields are strings, allowing type confusion attacks.`,
      evidence: v.type === "bypass"
        ? `Endpoint: ${v.endpoint}\nPayload type: ${v.desc}\nResponse contains authentication token`
        : `Endpoint: ${v.endpoint}\nPayload type: ${v.desc}\nError pattern: ${v.pattern}\nResponse excerpt: ${v.text.substring(0, 300)}`,
      remediation: "Validate that all credential fields (email, password, username) are strings before processing. Use schema validation (Zod, Joi) to reject arrays and objects.",
      cwe: "CWE-943", owasp: "A07:2021",
      codeSnippet: `// Reject non-string credentials\nimport { z } from "zod";\nconst LoginSchema = z.object({\n  email: z.string().email(),\n  password: z.string().min(1), // Rejects ["anything"]\n});\nconst { email, password } = LoginSchema.parse(await req.json());`,
    });
  }

  // Phase 6: $where JavaScript injection — blind detection via response time
  const whereResults = await Promise.allSettled(
    postEndpoints.slice(0, 3).map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      if (flagged.has(pathname)) return null;

      // Get baseline response time
      let baselineMs = 0;
      try {
        const start = Date.now();
        await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ test: "normal_value" }), timeoutMs: 5000,
        });
        baselineMs = Date.now() - start;
      } catch { return null; }

      for (const { body, desc, delayMs } of NOSQL_WHERE_PAYLOADS) {
        try {
          const start = Date.now();
          const res = await scanFetch(endpoint, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body), timeoutMs: delayMs + 5000,
          });
          const elapsed = Date.now() - start;
          const text = await res.text();

          // Check for error patterns indicating $where was processed
          for (const pattern of NOSQL_ERROR_PATTERNS) {
            if (pattern.test(text)) {
              return { type: "error" as const, pathname, endpoint, desc, pattern: pattern.source, text };
            }
          }

          // Blind detection: if response took significantly longer than baseline, sleep() executed
          if (elapsed > baselineMs + delayMs * 0.8 && elapsed > 2500) {
            return { type: "blind" as const, pathname, endpoint, desc, baselineMs, elapsed };
          }
        } catch { /* skip */ }
      }
      return null;
    }),
  );

  for (const r of whereResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    if (v.type === "blind") {
      findings.push({
        id: `nosql-where-blind-${count++}`, module: "NoSQL Injection", severity: "critical",
        title: `Blind $where JavaScript injection on ${v.pathname}`,
        description: `Sending ${v.desc} caused a ${v.elapsed}ms response (baseline: ${v.baselineMs}ms). The server executes JavaScript in MongoDB $where clauses, enabling data exfiltration and potential server-side code execution.`,
        evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nBaseline response: ${v.baselineMs}ms\nInjected response: ${v.elapsed}ms`,
        remediation: "Disable $where in MongoDB queries. Never pass user input to $where clauses. Use standard query operators instead. Set mongod --noscripting to disable server-side JavaScript entirely.",
        cwe: "CWE-943", owasp: "A03:2021",
        codeSnippet: `// Disable $where by sanitizing input\nfunction rejectOperators(obj: Record<string, unknown>) {\n  for (const key of Object.keys(obj)) {\n    if (key.startsWith("$")) throw new Error("Operators not allowed");\n  }\n}\n// Or disable server-side JS: mongod --noscripting`,
      });
    } else {
      findings.push({
        id: `nosql-where-error-${count++}`, module: "NoSQL Injection", severity: "high",
        title: `$where clause injection detected on ${v.pathname}`,
        description: `Sending ${v.desc} triggered a database error. The server processes $where clauses from user input, which can execute arbitrary JavaScript on the MongoDB server.`,
        evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nError pattern: ${v.pattern}\nResponse excerpt: ${v.text.substring(0, 300)}`,
        remediation: "Never pass user input to MongoDB $where clauses. Use standard query operators. Set mongod --noscripting to disable server-side JavaScript.",
        cwe: "CWE-943", owasp: "A03:2021",
        codeSnippet: `// Reject $where and other dangerous operators\nfunction sanitizeQuery(input: Record<string, unknown>) {\n  const banned = ["$where", "$expr", "$accumulator", "$function"];\n  for (const key of Object.keys(input)) {\n    if (banned.includes(key)) throw new Error("Operator not allowed");\n  }\n}`,
      });
    }
  }

  return findings;
};
