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
  const MAX_FINDINGS = 4;
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

  // Phase 5: Client-side type confusion from JS bundles
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
