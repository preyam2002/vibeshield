import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml, isSoft404 } from "../soft404";

const SUCCESS_RE = /("success"|"ok"|"token"|"data"|"user"|"id"|"created"|"updated"|"message"\s*:\s*"[^"]*success)/i;
const ERR_LEAK = [
  /stack.*trace/i, /at\s+\w+\.\w+\s*\(/i, /TypeError:/i, /ReferenceError:/i,
  /Cannot read propert/i, /is not a function/i, /SQL.*syntax/i, /ORA-\d+/i,
  /pg_.*error/i, /Internal Server Error/i, /Traceback \(most recent/i,
];

type Payload = { body: Record<string, unknown>; desc: string };
const TYPE_PAYLOADS: Payload[] = [
  { body: { email: true }, desc: "boolean instead of string email" },
  { body: { id: ["1", "2"] }, desc: "array instead of scalar id" },
  { body: { amount: "0.1e2" }, desc: "scientific notation amount" },
  { body: { admin: true, role: "admin" }, desc: "privilege escalation fields" },
];
const CT_TESTS: { ct: string; body: string; desc: string }[] = [
  { ct: "text/plain", body: '{"test":"value"}', desc: "JSON body with text/plain Content-Type" },
  { ct: "application/xml", body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', desc: "XXE via XML body to JSON endpoint" },
  { ct: "multipart/form-data; boundary=----test", body: '------test\r\nContent-Disposition: form-data; name="data"\r\n\r\n{"test":"value"}\r\n------test--', desc: "multipart wrapping JSON body" },
];
const PROTO_PAYLOADS: Payload[] = [
  { body: { __proto__: { isAdmin: true } }, desc: "__proto__ pollution" },
  { body: { constructor: { prototype: { isAdmin: true } } }, desc: "constructor.prototype pollution" },
];
const NUM_PAYLOADS: Payload[] = [
  { body: { id: "1 OR 1=1" }, desc: "SQL injection via string id" },
  { body: { id: "NaN" }, desc: "NaN coercion" },
  { body: { id: "Infinity" }, desc: "Infinity coercion" },
  { body: { id: "undefined" }, desc: "undefined string coercion" },
  { body: { id: "0" }, desc: "string zero" }, { body: { id: 0 }, desc: "numeric zero" },
];
const MASS_ASSIGN_FIELDS = ["isAdmin", "role", "verified", "is_superuser", "permissions", "email_verified"];
const MASS_ASSIGN_METHODS = ["POST", "PUT"] as const;

const CT_MISMATCH_TESTS: { ct: string; body: string; desc: string }[] = [
  { ct: "application/xml", body: '{"test":"value","secret":"leak"}', desc: "JSON body with XML Content-Type" },
  { ct: "application/json", body: '<?xml version="1.0"?><root><test>value</test></root>', desc: "XML body with JSON Content-Type" },
  { ct: "application/x-www-form-urlencoded", body: '{"test":"value"}', desc: "JSON body with form-urlencoded Content-Type" },
  { ct: "application/json", body: "test=value&secret=leak", desc: "form-urlencoded body with JSON Content-Type" },
];

const ARRAY_CONFUSION_PARAMS = ["id", "user", "role", "filter", "category", "type", "status"];

const INT_OVERFLOW_PAYLOADS: { value: unknown; desc: string }[] = [
  { value: 9999999999999999999999999999, desc: "extremely large integer" },
  { value: -9999999999999999999999999999, desc: "extremely large negative integer" },
  { value: 2147483648, desc: "int32 overflow (2^31)" },
  { value: -2147483649, desc: "int32 underflow (-(2^31)-1)" },
  { value: 9007199254740992, desc: "Number.MAX_SAFE_INTEGER+1" },
  { value: "NaN", desc: "NaN string" },
  { value: "Infinity", desc: "Infinity string" },
  { value: "-Infinity", desc: "-Infinity string" },
  { value: 1e308, desc: "near Number.MAX_VALUE" },
];

const PROTO_POLLUTION_PAYLOADS: { body: string; desc: string }[] = [
  { body: '{"__proto__":{"admin":true}}', desc: "__proto__.admin injection" },
  { body: '{"constructor":{"prototype":{"admin":true}}}', desc: "constructor.prototype.admin injection" },
  { body: '{"__proto__":{"isAdmin":true,"role":"admin"}}', desc: "__proto__ multi-field injection" },
  { body: '{"__proto__":{"toString":"polluted"}}', desc: "__proto__.toString pollution" },
];

const JS_PATTERNS: { re: RegExp; title: string }[] = [
  { re: /[^!=]={2}\s*(null|undefined)\b/g, title: "Loose equality with null/undefined" },
  { re: /JSON\.parse\s*\([^)]+\)(?!\s*(?:catch|\.catch|\}\s*catch))/g, title: "Unguarded JSON.parse" },
  { re: /parseInt\s*\([^,)]+\)/g, title: "parseInt without radix" },
  { re: /\beval\s*\(/g, title: "eval() usage" },
  { re: /\bFunction\s*\(/g, title: "Function() constructor" },
  { re: /document\.write\s*\(/g, title: "document.write usage" },
];

export const typeConfusionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;
  const MAX_FINDINGS = 12;
  const endpoints = target.apiEndpoints.slice(0, 10);

  const add = (f: Finding) => { if (findings.length < MAX_FINDINGS) findings.push(f); };

  const baselines = new Map<string, { status: number; text: string }>();
  await Promise.allSettled(endpoints.map(async (ep) => {
    try {
      const res = await scanFetch(ep, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ test: "baseline" }), timeoutMs: 5000 });
      const text = await res.text();
      if (!looksLikeHtml(text) || !isSoft404(text, target)) baselines.set(ep, { status: res.status, text });
    } catch { /* skip */ }
  }));
  const testable = endpoints.filter((ep) => baselines.has(ep));

  // Phase 1 + 2 + 3 + 4 in parallel
  const [phase1Results, phase2Results, phase3Results, phase4Results] = await Promise.all([
    // Phase 1: JSON type confusion
    Promise.allSettled(
      testable.slice(0, 6).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;

        for (const { body, desc } of TYPE_PAYLOADS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body),
              timeoutMs: 5000,
            });
            const text = await res.text();
            if (looksLikeHtml(text) && isSoft404(text, target)) continue;

            // Server accepted wrong type with success response
            if (res.status === 200 && SUCCESS_RE.test(text) && !SUCCESS_RE.test(baseline.text)) {
              return { pathname, endpoint, desc, evidence: text.substring(0, 300) };
            }
            // Privilege escalation fields accepted silently
            if (desc.includes("privilege") && res.status === 200) {
              try {
                const data = JSON.parse(text);
                if (data.admin === true || data.role === "admin" || data.isAdmin === true) {
                  return { pathname, endpoint, desc, evidence: text.substring(0, 300) };
                }
              } catch { /* skip */ }
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Phase 2: Content-Type confusion
    Promise.allSettled(
      testable.slice(0, 4).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;

        for (const { ct, body, desc } of CT_TESTS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": ct },
              body,
              timeoutMs: 5000,
            });
            const text = await res.text();
            if (looksLikeHtml(text) && isSoft404(text, target)) continue;

            // XXE: check for /etc/passwd content
            if (desc.includes("XXE") && /root:.*:0:0:/i.test(text)) {
              return { pathname, endpoint, desc, severity: "critical" as const, evidence: text.substring(0, 300) };
            }
            // Content-Type confusion: server processed the body despite wrong type
            if (res.status === 200 && baseline.status !== 200 && SUCCESS_RE.test(text)) {
              return { pathname, endpoint, desc, severity: "medium" as const, evidence: text.substring(0, 300) };
            }
            // Server accepted text/plain as JSON (no validation)
            if (desc.includes("text/plain") && res.status === 200 && SUCCESS_RE.test(text)) {
              if (baseline.status === 200 && SUCCESS_RE.test(baseline.text)) continue;
              return { pathname, endpoint, desc, severity: "medium" as const, evidence: text.substring(0, 300) };
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Phase 3: Prototype pollution
    Promise.allSettled(
      testable.slice(0, 4).map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;

        for (const { body, desc } of PROTO_PAYLOADS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body),
              timeoutMs: 5000,
            });
            const postText = await res.text();
            if (looksLikeHtml(postText) && isSoft404(postText, target)) continue;

            // Check if subsequent GET reflects the injected property
            const getRes = await scanFetch(endpoint, { timeoutMs: 5000, noCache: true });
            const getText = await getRes.text();
            if (/isAdmin.*true|"isAdmin"\s*:\s*true/i.test(getText)) {
              return { pathname, endpoint, desc, evidence: getText.substring(0, 300) };
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Phase 4: Numeric string confusion
    Promise.allSettled(
      testable.slice(0, 4).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;
        const leaks: string[] = [];

        for (const { body, desc } of NUM_PAYLOADS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body),
              timeoutMs: 5000,
            });
            const text = await res.text();
            if (looksLikeHtml(text) && isSoft404(text, target)) continue;

            // SQL injection indicator
            if (desc.includes("SQL") && res.status === 500 && ERR_LEAK.some((p) => p.test(text) && !p.test(baseline.text))) {
              return { pathname, endpoint, desc, type: "sqli" as const, evidence: text.substring(0, 300) };
            }
            // Error leak from coercion
            for (const pattern of ERR_LEAK) {
              if (pattern.test(text) && !pattern.test(baseline.text)) {
                leaks.push(`${desc}: ${text.substring(0, 150)}`);
                break;
              }
            }
          } catch { /* skip */ }
        }

        if (leaks.length > 0) {
          return { pathname, endpoint, desc: "numeric coercion errors", type: "leak" as const, evidence: leaks.join("\n") };
        }
        return null;
      }),
    ),
  ]);

  const flagged = new Set<string>();

  const collect = (results: PromiseSettledResult<unknown>[], makeFinding: (v: Record<string, unknown>) => Finding | null) => {
    for (const r of results) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value as Record<string, unknown>;
      if (flagged.has(v.pathname as string)) continue;
      flagged.add(v.pathname as string);
      const f = makeFinding(v);
      if (f) add(f);
    }
  };

  const ZOD_SNIPPET = `import { z } from "zod";\nconst Schema = z.object({\n  email: z.string().email(),\n  id: z.string().or(z.number()),\n  amount: z.number().positive(),\n});\nconst input = Schema.parse(await req.json());`;

  collect(phase1Results, (v) => ({
    id: `type-confusion-${count++}`, module: "Type Confusion", severity: "high",
    title: `Type confusion accepted on ${v.pathname}`,
    description: `The endpoint accepted ${v.desc} without validation. Vibe-coded apps often skip input type checks, allowing attackers to bypass business logic by sending unexpected JSON types.`,
    evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nResponse: ${v.evidence}`,
    endpoint: v.endpoint as string, confidence: 80, cwe: "CWE-843", owasp: "A03:2021",
    remediation: "Validate all input types at the API boundary with a schema validation library.",
    codeSnippet: ZOD_SNIPPET,
  }));

  collect(phase2Results, (v) => {
    const isCrit = v.severity === "critical";
    return {
      id: `content-type-confusion-${count++}`, module: "Type Confusion", severity: isCrit ? "critical" : "medium",
      title: isCrit ? `XXE injection on ${v.pathname}` : `Content-Type confusion on ${v.pathname}`,
      description: isCrit
        ? `The endpoint parsed XML with external entity resolution enabled, leaking server files.`
        : `The endpoint accepted a ${v.desc}, processing the body despite mismatched Content-Type.`,
      evidence: `Endpoint: ${v.endpoint}\nTest: ${v.desc}\nResponse: ${v.evidence}`,
      endpoint: v.endpoint as string, confidence: 85, cwe: isCrit ? "CWE-502" : "CWE-843", owasp: "A03:2021",
      remediation: "Strictly validate Content-Type headers. Reject unexpected types. Disable XML external entity processing.",
      codeSnippet: `if (req.headers.get("content-type") !== "application/json") {\n  return Response.json({ error: "Invalid Content-Type" }, { status: 415 });\n}`,
    };
  });

  collect(phase3Results, (v) => ({
    id: `proto-pollution-${count++}`, module: "Type Confusion", severity: "critical",
    title: `Server-side prototype pollution on ${v.pathname}`,
    description: `Sending ${v.desc} via POST caused isAdmin to appear in subsequent GET responses. The server merges untrusted JSON without sanitization.`,
    evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nGET response: ${v.evidence}`,
    endpoint: v.endpoint as string, confidence: 90, cwe: "CWE-843", owasp: "A03:2021",
    remediation: "Never use recursive object merge on untrusted input. Strip __proto__ and constructor keys.",
    codeSnippet: `const sanitize = (obj: unknown): unknown => {\n  if (typeof obj !== "object" || obj === null) return obj;\n  const clean: Record<string, unknown> = {};\n  for (const [k, v] of Object.entries(obj)) {\n    if (k === "__proto__" || k === "constructor") continue;\n    clean[k] = sanitize(v);\n  }\n  return clean;\n};`,
  }));

  collect(phase4Results, (v) => {
    const isSql = v.type === "sqli";
    return {
      id: `numeric-confusion-${count++}`, module: "Type Confusion", severity: isSql ? "critical" : "medium",
      title: isSql ? `SQL injection via type confusion on ${v.pathname}` : `Type coercion errors leak internals on ${v.pathname}`,
      description: isSql
        ? `Sending a SQL payload as a string ID triggered a server error with database details.`
        : `Sending JS-special values (NaN, Infinity, undefined) as IDs triggered error responses leaking internals.`,
      evidence: v.evidence as string, endpoint: v.endpoint as string,
      confidence: isSql ? 85 : 70, cwe: isSql ? "CWE-89" : "CWE-843", owasp: "A03:2021",
      remediation: isSql ? "Use parameterized queries. Never interpolate user input into SQL." : "Validate input types strictly. Reject NaN, Infinity, undefined at the API boundary.",
      codeSnippet: `import { z } from "zod";\nconst { id } = z.object({ id: z.string().regex(/^[a-zA-Z0-9-]+$/) }).parse(await req.json());\n// db.query("SELECT * FROM users WHERE id = $1", [id])`,
    };
  });

  // Phase 5–9: Additional detection phases in parallel
  const [phase5Results, phase6Results, phase7Results, phase8Results, phase9Results] = await Promise.all([
    // Phase 5: Mass assignment / parameter pollution
    Promise.allSettled(
      testable.slice(0, 6).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;

        for (const method of MASS_ASSIGN_METHODS) {
          const extraFields: Record<string, unknown> = {};
          for (const field of MASS_ASSIGN_FIELDS) extraFields[field] = true;
          try {
            const res = await scanFetch(endpoint, {
              method,
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ test: "baseline", ...extraFields }),
              timeoutMs: 5000,
            });
            const text = await res.text();
            if (looksLikeHtml(text) && isSoft404(text, target)) continue;

            if (res.status === 200) {
              try {
                const data = JSON.parse(text);
                const accepted = MASS_ASSIGN_FIELDS.filter(
                  (f) => data[f] === true || data[f] === "admin" || data[f] === "superuser",
                );
                if (accepted.length > 0) {
                  return { pathname, endpoint, method, accepted, evidence: text.substring(0, 300) };
                }
              } catch { /* skip */ }
              // Also flag if server accepted extra fields without error (different from baseline 4xx)
              if (baseline.status >= 400 && SUCCESS_RE.test(text)) {
                return { pathname, endpoint, method, accepted: MASS_ASSIGN_FIELDS, evidence: text.substring(0, 300) };
              }
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Phase 6: Content-type mismatch exploitation
    Promise.allSettled(
      testable.slice(0, 4).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;

        for (const { ct, body, desc } of CT_MISMATCH_TESTS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": ct },
              body,
              timeoutMs: 5000,
            });
            const text = await res.text();
            if (looksLikeHtml(text) && isSoft404(text, target)) continue;

            // Parser confusion: server processed body despite type mismatch
            if (res.status === 200 && SUCCESS_RE.test(text)) {
              if (baseline.status === 200 && SUCCESS_RE.test(baseline.text)) continue;
              return { pathname, endpoint, desc, evidence: text.substring(0, 300) };
            }
            // Error leak from parser confusion
            if (ERR_LEAK.some((p) => p.test(text) && !p.test(baseline.text))) {
              return { pathname, endpoint, desc, evidence: text.substring(0, 300), isLeak: true };
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Phase 7: Array/object confusion in parameters
    Promise.allSettled(
      testable.slice(0, 4).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;
        const url = new URL(endpoint);

        for (const param of ARRAY_CONFUSION_PARAMS) {
          try {
            // Test array notation in query string
            const arrayUrl = new URL(endpoint);
            arrayUrl.searchParams.delete(param);
            arrayUrl.search += `${arrayUrl.search ? "&" : "?"}${param}[]=value1&${param}[]=value2`;
            const arrRes = await scanFetch(arrayUrl.toString(), { timeoutMs: 5000 });
            const arrText = await arrRes.text();
            if (looksLikeHtml(arrText) && isSoft404(arrText, target)) continue;

            // Also test scalar vs array in JSON body
            const arrBodyRes = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ [param]: ["value1", "value2"] }),
              timeoutMs: 5000,
            });
            const arrBodyText = await arrBodyRes.text();

            const scalarBodyRes = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ [param]: "value1" }),
              timeoutMs: 5000,
            });
            const scalarBodyText = await scalarBodyRes.text();

            // Error leak when array given instead of scalar
            if (ERR_LEAK.some((p) => (p.test(arrText) || p.test(arrBodyText)) && !p.test(baseline.text))) {
              return { pathname, endpoint, param, evidence: (arrBodyText || arrText).substring(0, 300), isLeak: true };
            }
            // Different success behavior between array and scalar (type coercion)
            if (arrBodyRes.status === 200 && scalarBodyRes.status === 200 && SUCCESS_RE.test(arrBodyText) !== SUCCESS_RE.test(scalarBodyText)) {
              return { pathname, endpoint, param, evidence: `Array response: ${arrBodyText.substring(0, 150)}\nScalar response: ${scalarBodyText.substring(0, 150)}`, isLeak: false };
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // Phase 8: Integer overflow in parameters
    Promise.allSettled(
      testable.slice(0, 4).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;
        const leaks: string[] = [];

        for (const { value, desc } of INT_OVERFLOW_PAYLOADS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ id: value, amount: value, quantity: value }),
              timeoutMs: 5000,
            });
            const text = await res.text();
            if (looksLikeHtml(text) && isSoft404(text, target)) continue;

            // Server error from overflow
            if (res.status === 500 && ERR_LEAK.some((p) => p.test(text) && !p.test(baseline.text))) {
              leaks.push(`${desc}: ${text.substring(0, 150)}`);
              continue;
            }
            // Accepted extreme value without error (potential logic bypass)
            if (res.status === 200 && SUCCESS_RE.test(text) && !SUCCESS_RE.test(baseline.text)) {
              return { pathname, endpoint, desc, evidence: text.substring(0, 300), type: "accepted" as const };
            }
          } catch { /* skip */ }
        }
        if (leaks.length > 0) {
          return { pathname, endpoint, desc: "integer overflow errors", type: "leak" as const, evidence: leaks.join("\n") };
        }
        return null;
      }),
    ),

    // Phase 9: Prototype pollution via JSON
    Promise.allSettled(
      testable.slice(0, 4).map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;

        for (const { body, desc } of PROTO_POLLUTION_PAYLOADS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body,
              timeoutMs: 5000,
            });
            const postText = await res.text();
            if (looksLikeHtml(postText) && isSoft404(postText, target)) continue;

            // Server accepted the payload without stripping dangerous keys
            if (res.status === 200 && SUCCESS_RE.test(postText)) {
              // Verify: check if a subsequent GET reflects injected properties
              const getRes = await scanFetch(endpoint, { timeoutMs: 5000, noCache: true });
              const getText = await getRes.text();
              if (/admin.*true|"admin"\s*:\s*true|"isAdmin"\s*:\s*true|"role"\s*:\s*"admin"/i.test(getText)) {
                return { pathname, endpoint, desc, evidence: getText.substring(0, 300), confirmed: true };
              }
              // Even without GET confirmation, accepting __proto__ is a concern
              if (desc.includes("__proto__")) {
                return { pathname, endpoint, desc, evidence: postText.substring(0, 300), confirmed: false };
              }
            }
            // Error leak revealing prototype handling
            if (ERR_LEAK.some((p) => p.test(postText))) {
              return { pathname, endpoint, desc, evidence: postText.substring(0, 300), confirmed: false };
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),
  ]);

  // Collect Phase 5: Mass assignment
  collect(phase5Results, (v) => ({
    id: `mass-assignment-${count++}`, module: "type-confusion", severity: "high",
    title: `Mass assignment vulnerability on ${v.pathname}`,
    description: `The endpoint accepted privileged fields (${(v.accepted as string[]).join(", ")}) via ${v.method} without filtering. Attackers can escalate privileges by injecting extra fields into request bodies.`,
    evidence: `Endpoint: ${v.endpoint}\nMethod: ${v.method}\nAccepted fields: ${(v.accepted as string[]).join(", ")}\nResponse: ${v.evidence}`,
    endpoint: v.endpoint as string, confidence: 85, cwe: "CWE-915", owasp: "A01:2021",
    remediation: "Use an allowlist of permitted fields for each endpoint. Never blindly merge request body into database models.",
    codeSnippet: `const ALLOWED = ["name", "email", "bio"] as const;\nconst body = await req.json();\nconst safe = Object.fromEntries(\n  Object.entries(body).filter(([k]) => ALLOWED.includes(k as any))\n);`,
  }));

  // Collect Phase 6: Content-type mismatch
  collect(phase6Results, (v) => ({
    id: `ct-mismatch-${count++}`, module: "type-confusion", severity: (v.isLeak ? "medium" : "high") as "medium" | "high",
    title: `Content-Type mismatch exploitation on ${v.pathname}`,
    description: `The endpoint processed a request where the body format did not match the Content-Type header (${v.desc}). This indicates the server's parser is too permissive and may be confused into processing malicious payloads.`,
    evidence: `Endpoint: ${v.endpoint}\nTest: ${v.desc}\nResponse: ${v.evidence}`,
    endpoint: v.endpoint as string, confidence: 80, cwe: "CWE-436", owasp: "A03:2021",
    remediation: "Strictly validate that the request body format matches the Content-Type header. Reject requests with mismatched types with HTTP 415.",
    codeSnippet: `const ct = req.headers.get("content-type") ?? "";\nif (!ct.startsWith("application/json")) {\n  return Response.json({ error: "Unsupported Media Type" }, { status: 415 });\n}`,
  }));

  // Collect Phase 7: Array/object confusion
  collect(phase7Results, (v) => ({
    id: `array-confusion-${count++}`, module: "type-confusion", severity: (v.isLeak ? "medium" : "low") as "medium" | "low",
    title: `Array/object type confusion on parameter "${v.param}" at ${v.pathname}`,
    description: `The endpoint behaves differently when the parameter "${v.param}" is sent as an array vs a scalar value. This can lead to type coercion bugs, filter bypasses, or authorization issues.`,
    evidence: `Endpoint: ${v.endpoint}\nParameter: ${v.param}\n${v.evidence}`,
    endpoint: v.endpoint as string, confidence: 70, cwe: "CWE-843", owasp: "A03:2021",
    remediation: "Validate that each parameter has the expected type. Reject arrays when a scalar is expected. Use schema validation (Zod, Joi) at the API boundary.",
    codeSnippet: `import { z } from "zod";\nconst schema = z.object({\n  ${v.param}: z.string(), // rejects arrays\n});\nconst input = schema.parse(await req.json());`,
  }));

  // Collect Phase 8: Integer overflow
  collect(phase8Results, (v) => {
    const isAccepted = v.type === "accepted";
    return {
      id: `int-overflow-${count++}`, module: "type-confusion", severity: isAccepted ? "high" : "medium",
      title: isAccepted
        ? `Integer overflow accepted on ${v.pathname}`
        : `Integer overflow causes error leak on ${v.pathname}`,
      description: isAccepted
        ? `The endpoint accepted an extreme numeric value (${v.desc}) without validation, which may cause integer overflow, wraparound, or logic bypass in downstream processing.`
        : `Sending extreme numeric values (NaN, Infinity, very large numbers) triggered error responses leaking server internals.`,
      evidence: `Endpoint: ${v.endpoint}\n${v.evidence}`,
      endpoint: v.endpoint as string, confidence: isAccepted ? 80 : 70, cwe: "CWE-190", owasp: "A03:2021",
      remediation: "Validate numeric inputs with strict bounds. Reject NaN, Infinity, and values outside expected ranges. Use integer types with defined min/max.",
      codeSnippet: `import { z } from "zod";\nconst schema = z.object({\n  id: z.number().int().min(1).max(2147483647),\n  amount: z.number().finite().positive().max(1_000_000),\n});`,
    };
  });

  // Collect Phase 9: Prototype pollution via JSON
  collect(phase9Results, (v) => ({
    id: `proto-pollution-json-${count++}`, module: "type-confusion", severity: (v.confirmed ? "critical" : "high") as "critical" | "high",
    title: v.confirmed
      ? `Confirmed prototype pollution on ${v.pathname}`
      : `Potential prototype pollution on ${v.pathname}`,
    description: v.confirmed
      ? `Sending ${v.desc} via POST caused admin/privilege properties to appear in subsequent GET responses. The server unsafely merges untrusted JSON into objects, allowing prototype chain manipulation.`
      : `The endpoint accepted a JSON body containing ${v.desc} without stripping dangerous keys. This may enable prototype pollution if the server uses recursive object merge.`,
    evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nResponse: ${v.evidence}`,
    endpoint: v.endpoint as string, confidence: v.confirmed ? 95 : 70, cwe: "CWE-1321", owasp: "A03:2021",
    remediation: "Strip __proto__, constructor, and prototype keys from all incoming JSON. Use Object.create(null) for merge targets. Consider using a safe merge library like lodash.merge with key filtering.",
    codeSnippet: `const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);\nconst safeParse = (json: string) => {\n  return JSON.parse(json, (key, value) => {\n    if (DANGEROUS_KEYS.has(key)) return undefined;\n    return value;\n  });\n};`,
  }));

  // Phase 10: Client-side type confusion from JS bundles
  if (findings.length < MAX_FINDINGS && target.jsContents.size > 0) {
    const hits: { file: string; title: string; ctx: string }[] = [];
    for (const [file, content] of target.jsContents) {
      if (content.length > 500_000) continue;
      for (const { re, title } of JS_PATTERNS) {
        re.lastIndex = 0;
        const m = re.exec(content);
        if (m) {
          const s = Math.max(0, m.index - 30);
          hits.push({ file, title, ctx: content.substring(s, m.index + m[0].length + 30).replace(/\s+/g, " ").trim() });
        }
      }
    }
    if (hits.length > 0) {
      const top = hits.slice(0, 6);
      add({
        id: `client-type-confusion-${count++}`, module: "Type Confusion", severity: "low",
        title: "Client-side type safety issues in JavaScript bundles",
        description: `Found ${hits.length} pattern(s) indicating type confusion: ${top.map((h) => h.title).join(", ")}.`,
        evidence: top.map((h) => `${h.title} in ${h.file}: ${h.ctx}`).join("\n"),
        confidence: 60, cwe: "CWE-843",
        remediation: "Enable TypeScript strict mode. Use === instead of ==. Wrap JSON.parse in try/catch. Pass radix to parseInt.",
        codeSnippet: `- if (value == null)  // loose\n+ if (value === null || value === undefined)\n- parseInt(str)\n+ parseInt(str, 10)`,
      });
    }
  }

  return findings;
};
