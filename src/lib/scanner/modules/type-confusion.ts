import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml, isSoft404 } from "../soft404";

const SUCCESS_RE = /("success"|"ok"|"token"|"data"|"user"|"id"|"created"|"updated"|"message"\s*:\s*"[^"]*success)/i;
const ERR_LEAK = [
  /stack.*trace/i, /at\s+\w+\.\w+\s*\(/i, /TypeError:/i, /ReferenceError:/i,
  /Cannot read propert/i, /is not a function/i, /SQL.*syntax/i, /ORA-\d+/i,
  /pg_.*error/i, /Internal Server Error/i, /Traceback \(most recent/i,
];

const TYPE_CONFUSION_PAYLOADS: { body: Record<string, unknown>; desc: string; field: string }[] = [
  { body: { email: true }, desc: "boolean instead of string email", field: "email" },
  { body: { id: ["1", "2"] }, desc: "array instead of scalar id", field: "id" },
  { body: { amount: "0.1e2" }, desc: "scientific notation amount", field: "amount" },
  { body: { admin: true, role: "admin" }, desc: "privilege escalation fields", field: "admin" },
];

const CONTENT_TYPE_TESTS: { contentType: string; body: string; desc: string }[] = [
  { contentType: "text/plain", body: '{"test":"value"}', desc: "JSON body with text/plain Content-Type" },
  {
    contentType: "application/xml",
    body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    desc: "XXE via XML body to JSON endpoint",
  },
  { contentType: "multipart/form-data; boundary=----test", body: '------test\r\nContent-Disposition: form-data; name="data"\r\n\r\n{"test":"value"}\r\n------test--', desc: "multipart wrapping JSON body" },
];

const PROTO_PAYLOADS: { body: Record<string, unknown>; desc: string }[] = [
  { body: { __proto__: { isAdmin: true } }, desc: "__proto__ pollution" },
  { body: { constructor: { prototype: { isAdmin: true } } }, desc: "constructor.prototype pollution" },
];

const NUMERIC_PAYLOADS: { body: Record<string, unknown>; desc: string }[] = [
  { body: { id: "1 OR 1=1" }, desc: "SQL injection via string id" },
  { body: { id: "NaN" }, desc: "NaN coercion" },
  { body: { id: "Infinity" }, desc: "Infinity coercion" },
  { body: { id: "undefined" }, desc: "undefined string coercion" },
  { body: { id: "0" }, desc: "string zero (loose equality)" },
  { body: { id: 0 }, desc: "numeric zero (loose equality)" },
];

const JS_VULN_PATTERNS: { pattern: RegExp; desc: string; title: string }[] = [
  { pattern: /[^!=]={2}\s*(null|undefined)\b/g, desc: "Loose equality check with null/undefined allows type coercion bugs", title: "Loose equality with null/undefined" },
  { pattern: /JSON\.parse\s*\([^)]+\)(?!\s*(?:catch|\.catch|\}\s*catch))/g, desc: "JSON.parse without try/catch can crash on malformed input", title: "Unguarded JSON.parse" },
  { pattern: /parseInt\s*\([^,)]+\)/g, desc: "parseInt without radix parameter can misinterpret strings starting with 0", title: "parseInt without radix" },
  { pattern: /\beval\s*\(/g, desc: "eval() executes arbitrary code — critical if user input reaches it", title: "eval() usage detected" },
  { pattern: /\bFunction\s*\(/g, desc: "Function() constructor is equivalent to eval() for code execution", title: "Function() constructor usage" },
  { pattern: /document\.write\s*\(/g, desc: "document.write can enable XSS if user input is included", title: "document.write usage" },
];

export const typeConfusionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;
  const MAX_FINDINGS = 4;
  const endpoints = target.apiEndpoints.slice(0, 10);

  const addFinding = (f: Finding): boolean => {
    if (findings.length >= MAX_FINDINGS) return false;
    findings.push(f);
    return true;
  };

  // Gather baselines in parallel
  const baselines = new Map<string, { status: number; text: string }>();
  await Promise.allSettled(
    endpoints.map(async (ep) => {
      try {
        const res = await scanFetch(ep, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ test: "baseline" }),
          timeoutMs: 5000,
        });
        const text = await res.text();
        if (!looksLikeHtml(text) || !isSoft404(text, target)) {
          baselines.set(ep, { status: res.status, text });
        }
      } catch { /* skip */ }
    }),
  );

  const testableEndpoints = endpoints.filter((ep) => baselines.has(ep));

  // Phase 1 + 2 + 3 + 4 in parallel
  const [phase1Results, phase2Results, phase3Results, phase4Results] = await Promise.all([
    // Phase 1: JSON type confusion
    Promise.allSettled(
      testableEndpoints.slice(0, 6).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;

        for (const { body, desc } of TYPE_CONFUSION_PAYLOADS) {
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
      testableEndpoints.slice(0, 4).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;

        for (const { contentType, body, desc } of CONTENT_TYPE_TESTS) {
          try {
            const res = await scanFetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": contentType },
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
      testableEndpoints.slice(0, 4).map(async (endpoint) => {
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
      testableEndpoints.slice(0, 4).map(async (endpoint) => {
        const baseline = baselines.get(endpoint)!;
        const pathname = new URL(endpoint).pathname;
        const leaks: string[] = [];

        for (const { body, desc } of NUMERIC_PAYLOADS) {
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

  // Collect Phase 1
  for (const r of phase1Results) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    addFinding({
      id: `type-confusion-${count++}`, module: "Type Confusion", severity: "high",
      title: `Type confusion accepted on ${v.pathname}`,
      description: `The endpoint accepted ${v.desc} without validation. Vibe-coded apps often skip input type checks, allowing attackers to bypass business logic by sending unexpected JSON types.`,
      evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nResponse: ${v.evidence}`,
      endpoint: v.endpoint, confidence: 80, cwe: "CWE-843", owasp: "A03:2021",
      remediation: "Validate all input types at the API boundary with a schema validation library.",
      codeSnippet: `import { z } from "zod";\nconst Schema = z.object({\n  email: z.string().email(),\n  id: z.string().or(z.number()),\n  amount: z.number().positive(),\n});\nconst input = Schema.parse(await req.json());`,
    });
  }

  // Collect Phase 2
  for (const r of phase2Results) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    addFinding({
      id: `content-type-confusion-${count++}`, module: "Type Confusion", severity: v.severity === "critical" ? "critical" : "medium",
      title: v.severity === "critical" ? `XXE injection on ${v.pathname}` : `Content-Type confusion on ${v.pathname}`,
      description: v.severity === "critical"
        ? `The endpoint parsed XML with external entity resolution enabled, leaking server files. This is a critical deserialization vulnerability.`
        : `The endpoint accepted a ${v.desc}, processing the body despite the mismatched Content-Type. This indicates missing Content-Type validation, which can lead to parser differential attacks.`,
      evidence: `Endpoint: ${v.endpoint}\nTest: ${v.desc}\nResponse: ${v.evidence}`,
      endpoint: v.endpoint, confidence: 85,
      cwe: v.severity === "critical" ? "CWE-502" : "CWE-843", owasp: "A03:2021",
      remediation: "Strictly validate Content-Type headers and reject requests with unexpected types. Disable XML external entity processing.",
      codeSnippet: `// Middleware to enforce Content-Type\nif (req.headers.get("content-type") !== "application/json") {\n  return Response.json({ error: "Invalid Content-Type" }, { status: 415 });\n}\n// For XML parsers, disable external entities\n// libxmljs: { noent: false, dtdload: false }`,
    });
  }

  // Collect Phase 3
  for (const r of phase3Results) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    addFinding({
      id: `proto-pollution-${count++}`, module: "Type Confusion", severity: "critical",
      title: `Server-side prototype pollution on ${v.pathname}`,
      description: `Sending ${v.desc} via POST caused the injected property to appear in subsequent GET responses. The server merges untrusted JSON into objects without sanitization, enabling privilege escalation or RCE.`,
      evidence: `Endpoint: ${v.endpoint}\nPayload: ${v.desc}\nGET response shows isAdmin: ${v.evidence}`,
      endpoint: v.endpoint, confidence: 90, cwe: "CWE-843", owasp: "A03:2021",
      remediation: "Never use recursive object merge/spread on untrusted input. Strip __proto__ and constructor keys before processing.",
      codeSnippet: `// Sanitize incoming JSON\nconst sanitize = (obj: unknown): unknown => {\n  if (typeof obj !== "object" || obj === null) return obj;\n  const clean: Record<string, unknown> = {};\n  for (const [k, v] of Object.entries(obj)) {\n    if (k === "__proto__" || k === "constructor") continue;\n    clean[k] = sanitize(v);\n  }\n  return clean;\n};\n// Or use Object.create(null) for safe objects`,
    });
  }

  // Collect Phase 4
  for (const r of phase4Results) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (flagged.has(v.pathname)) continue;
    flagged.add(v.pathname);
    addFinding({
      id: `numeric-confusion-${count++}`, module: "Type Confusion",
      severity: v.type === "sqli" ? "critical" : "medium",
      title: v.type === "sqli" ? `SQL injection via type confusion on ${v.pathname}` : `Type coercion errors leak internals on ${v.pathname}`,
      description: v.type === "sqli"
        ? `Sending a SQL payload as a string ID triggered a server error with database details. The endpoint interpolates string IDs directly into SQL queries.`
        : `Sending JS-special values (NaN, Infinity, undefined) as IDs triggered error responses that leak internal details. This reveals type coercion bugs in the server logic.`,
      evidence: v.evidence,
      endpoint: v.endpoint, confidence: v.type === "sqli" ? 85 : 70,
      cwe: v.type === "sqli" ? "CWE-89" : "CWE-843", owasp: "A03:2021",
      remediation: v.type === "sqli"
        ? "Use parameterized queries. Never interpolate user input into SQL strings."
        : "Validate input types strictly. Reject NaN, Infinity, and undefined at the API boundary.",
      codeSnippet: `import { z } from "zod";\nconst IdSchema = z.object({\n  id: z.string().regex(/^[a-zA-Z0-9-]+$/), // or z.coerce.number().int().positive()\n});\nconst { id } = IdSchema.parse(await req.json());\n// Use parameterized query: db.query("SELECT * FROM users WHERE id = $1", [id])`,
    });
  }

  // Phase 5: Client-side type confusion from JS bundles
  if (findings.length < MAX_FINDINGS && target.jsContents.size > 0) {
    const allMatches: { file: string; title: string; desc: string; matches: string[] }[] = [];

    for (const [file, content] of target.jsContents) {
      if (content.length > 500_000) continue; // skip huge bundles
      for (const { pattern, desc, title } of JS_VULN_PATTERNS) {
        pattern.lastIndex = 0;
        const matches: string[] = [];
        let m: RegExpExecArray | null;
        while ((m = pattern.exec(content)) !== null && matches.length < 3) {
          const start = Math.max(0, m.index - 30);
          const end = Math.min(content.length, m.index + m[0].length + 30);
          matches.push(content.substring(start, end).replace(/\s+/g, " ").trim());
        }
        if (matches.length > 0) {
          allMatches.push({ file, title, desc, matches });
        }
      }
    }

    if (allMatches.length > 0) {
      const grouped = allMatches.slice(0, 6);
      const evidenceLines = grouped.map((m) => `${m.title} in ${m.file}: ${m.matches[0]}`).join("\n");
      addFinding({
        id: `client-type-confusion-${count++}`, module: "Type Confusion", severity: "low",
        title: `Client-side type safety issues in JavaScript bundles`,
        description: `Found ${allMatches.length} pattern(s) in JS bundles that indicate type confusion risks: ${grouped.map((m) => m.title).join(", ")}. These are common in vibe-coded apps where type safety is overlooked.`,
        evidence: evidenceLines,
        confidence: 60, cwe: "CWE-843",
        remediation: "Enable TypeScript strict mode. Replace loose equality (==) with strict (===). Wrap JSON.parse in try/catch. Always pass radix to parseInt.",
        codeSnippet: `// Replace loose checks\n- if (value == null)\n+ if (value === null || value === undefined)\n\n// Guard JSON.parse\n+ try {\n    const data = JSON.parse(raw);\n+ } catch { return defaultValue; }\n\n// Always pass radix\n- parseInt(str)\n+ parseInt(str, 10)`,
      });
    }
  }

  return findings;
};
