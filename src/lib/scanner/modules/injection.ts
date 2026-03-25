import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml } from "../soft404";

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "\" OR \"1\"=\"1",
  "' OR 1=1--",
  "1' UNION SELECT NULL--",
  "1; DROP TABLE users--",
  "' WAITFOR DELAY '0:0:2'--",
  "1' AND SLEEP(2)--",
  "\\' OR 1=1#",
  "admin'--",
  "1)) OR ((1=1",
];

const SQLI_ERROR_PATTERNS = [
  /SQL syntax/i,
  /mysql_fetch/i,
  /pg_query/i,
  /sqlite3?\./i,
  /SQLSTATE/i,
  /unclosed quotation/i,
  /quoted string not properly terminated/i,
  /ORA-\d{5}/i,
  /Microsoft OLE DB/i,
  /ODBC SQL Server/i,
  /PostgreSQL.*ERROR/i,
  /syntax error at or near/i,
  /unterminated string/i,
];

const XSS_PAYLOADS: { payload: string; check: (text: string) => boolean }[] = [
  {
    payload: '<script>alert("XSS")</script>',
    check: (t) => t.includes('<script>alert("XSS")</script>'),
  },
  {
    payload: '"><img src=x onerror=alert(1)>',
    check: (t) => t.includes("<img src=x onerror=alert(1)>"),
  },
  {
    payload: "<svg onload=alert(1)>",
    check: (t) => t.includes("<svg onload=alert(1)>"),
  },
  {
    payload: '<img src="x" onerror="alert(1)">',
    check: (t) => t.includes('<img src="x" onerror="alert(1)">'),
  },
  {
    payload: '<iframe src="javascript:alert(1)">',
    check: (t) => t.includes('<iframe src="javascript:alert(1)">'),
  },
];

const SSTI_PAYLOADS = [
  "{{7*7}}",
  "${7*7}",
  "#{7*7}",
  "<%= 7*7 %>",
  "{7*7}",
  "{{constructor.constructor('return 1')()}}",
];

export const injectionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Collect testable endpoints (forms + API endpoints with params)
  const testTargets: { url: string; method: string; paramName: string }[] = [];

  // From forms
  for (const form of target.forms) {
    for (const input of form.inputs) {
      if (input.type === "hidden" || input.type === "submit" || !input.name) continue;
      testTargets.push({
        url: form.action.startsWith("http") ? form.action : target.baseUrl + form.action,
        method: form.method,
        paramName: input.name,
      });
    }
  }

  // From API endpoints with query params
  for (const endpoint of target.apiEndpoints) {
    try {
      const url = new URL(endpoint);
      for (const [key] of url.searchParams) {
        testTargets.push({ url: endpoint, method: "GET", paramName: key });
      }
    } catch {
      // skip
    }
  }

  // From discovered pages with query params
  for (const page of target.pages) {
    try {
      const url = new URL(page);
      for (const [key] of url.searchParams) {
        testTargets.push({ url: page, method: "GET", paramName: key });
      }
    } catch {
      // skip
    }
  }

  // Also probe API endpoints with common param names
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    for (const param of ["q", "search", "query", "id", "name", "email", "filter"]) {
      testTargets.push({ url: endpoint, method: "GET", paramName: param });
    }
  }

  // Use discovered POST body parameters from JS bundle analysis
  for (const [endpoint, params] of target.apiParams) {
    for (const param of params.slice(0, 5)) {
      testTargets.push({ url: endpoint, method: "GET", paramName: param });
    }
  }

  // Deduplicate test targets by pathname+param
  const seenTargets = new Set<string>();
  const dedupedTargets = testTargets.filter((t) => {
    const key = `${new URL(t.url).pathname}:${t.paramName}`;
    if (seenTargets.has(key)) return false;
    seenTargets.add(key);
    return true;
  });

  // Run SQLi, XSS, and SSTI tests in parallel across all targets
  const [sqliResults, xssResults, sstiResults] = await Promise.all([
    // SQLi: parallelize across endpoints (each endpoint tests payloads sequentially for time-based accuracy)
    Promise.allSettled(
      dedupedTargets.slice(0, 15).map(async (t) => {
        const sqliKey = `${new URL(t.url).pathname}:${t.paramName}`;
        for (const payload of SQLI_PAYLOADS.slice(0, 5)) {
          try {
            let res: Response;
            if (t.method === "GET") {
              const url = new URL(t.url);
              url.searchParams.set(t.paramName, payload);
              res = await scanFetch(url.href, { timeoutMs: 5000 });
            } else {
              res = await scanFetch(t.url, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: `${t.paramName}=${encodeURIComponent(payload)}`,
                timeoutMs: 5000,
              });
            }

            const text = await res.text();

            for (const pattern of SQLI_ERROR_PATTERNS) {
              if (pattern.test(text)) {
                return { type: "error" as const, key: sqliKey, pathname: new URL(t.url).pathname, paramName: t.paramName, payload, pattern: pattern.source, text };
              }
            }

            // Time-based detection
            if (payload.includes("SLEEP") || payload.includes("WAITFOR")) {
              const baseTimes: number[] = [];
              for (let i = 0; i < 3; i++) {
                const bs = Date.now();
                try {
                  const baseUrl = new URL(t.url);
                  baseUrl.searchParams.set(t.paramName, "baseline_test");
                  await scanFetch(baseUrl.href, { timeoutMs: 10000 });
                } catch { /* skip */ }
                baseTimes.push(Date.now() - bs);
              }
              const baseline = baseTimes.sort((a, b) => a - b)[1] || 500;

              const start = Date.now();
              try {
                if (t.method === "GET") {
                  const url = new URL(t.url);
                  url.searchParams.set(t.paramName, payload);
                  await scanFetch(url.href, { timeoutMs: 10000 });
                }
              } catch { /* skip */ }
              const elapsed = Date.now() - start;

              if (elapsed >= 1800 && elapsed >= baseline * 2) {
                return { type: "blind" as const, key: sqliKey, pathname: new URL(t.url).pathname, payload, elapsed, baseline };
              }
            }
          } catch { /* skip */ }
        }
        // Boolean-based SQLi detection: compare true vs false condition responses
        if (t.method === "GET") {
          try {
            const trueUrl = new URL(t.url);
            trueUrl.searchParams.set(t.paramName, "' OR '1'='1'--");
            const falseUrl = new URL(t.url);
            falseUrl.searchParams.set(t.paramName, "' AND '1'='2'--");
            const baseUrl = new URL(t.url);
            baseUrl.searchParams.set(t.paramName, "baseline_safe_value");
            const [trueRes, falseRes, baseRes] = await Promise.all([
              scanFetch(trueUrl.href, { timeoutMs: 5000 }),
              scanFetch(falseUrl.href, { timeoutMs: 5000 }),
              scanFetch(baseUrl.href, { timeoutMs: 5000 }),
            ]);
            const [trueText, falseText, baseText] = await Promise.all([
              trueRes.text(), falseRes.text(), baseRes.text(),
            ]);
            // If true condition response differs significantly from false/base,
            // but false matches base — classic boolean-based SQLi
            if (
              trueText.length > 50 && falseText.length > 50 &&
              Math.abs(trueText.length - falseText.length) > Math.min(trueText.length, falseText.length) * 0.3 &&
              Math.abs(falseText.length - baseText.length) < baseText.length * 0.1
            ) {
              return {
                type: "boolean" as const, key: sqliKey,
                pathname: new URL(t.url).pathname, paramName: t.paramName,
                payload: "' OR '1'='1'--",
                trueLen: trueText.length, falseLen: falseText.length, baseLen: baseText.length,
              };
            }
          } catch { /* skip */ }
        }
        return null;
      }),
    ),

    // XSS: parallelize across all endpoint+payload combos
    Promise.allSettled(
      dedupedTargets.slice(0, 10).flatMap((t) =>
        XSS_PAYLOADS.slice(0, 4).map(async ({ payload, check }) => {
          try {
            let res: Response;
            if (t.method === "GET") {
              const url = new URL(t.url);
              url.searchParams.set(t.paramName, payload);
              res = await scanFetch(url.href, { timeoutMs: 5000 });
            } else {
              res = await scanFetch(t.url, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: `${t.paramName}=${encodeURIComponent(payload)}`,
                timeoutMs: 5000,
              });
            }

            const text = await res.text();
            const ct = res.headers.get("content-type") || "";

            if (ct.includes("application/json") || ct.includes("text/x-component") || ct.includes("application/rsc")) return null;

            if (check(text)) {
              const escaped = text.includes("&lt;") && text.includes("&gt;");
              const inJsonStr = text.includes(JSON.stringify(payload));
              if (escaped || inJsonStr) return null;
              return { pathname: new URL(t.url).pathname, paramName: t.paramName, payload, ct, key: `${new URL(t.url).pathname}:${t.paramName}` };
            }
          } catch { /* skip */ }
          return null;
        }),
      ),
    ),

    // SSTI: parallelize across endpoints
    Promise.allSettled(
      dedupedTargets.slice(0, 5).map(async (t) => {
        const pathname = new URL(t.url).pathname;

        let baselineHas49 = false;
        try {
          const baseUrl = new URL(t.url);
          baseUrl.searchParams.set(t.paramName, "harmless_test_value");
          const baseRes = await scanFetch(baseUrl.href, { timeoutMs: 5000 });
          const baselineText = await baseRes.text();
          baselineHas49 = baselineText.includes("49");
        } catch { /* skip */ }

        if (baselineHas49) return null;

        const url1 = new URL(t.url);
        url1.searchParams.set(t.paramName, "{{7*7}}");
        const res1 = await scanFetch(url1.href, { timeoutMs: 5000 });
        const text1 = await res1.text();

        if (looksLikeHtml(text1) && target.isSpa) return null;

        if (text1.includes("49") && !text1.includes("{{7*7}}")) {
          const url2 = new URL(t.url);
          url2.searchParams.set(t.paramName, "{{8*8}}");
          const res2 = await scanFetch(url2.href, { timeoutMs: 5000 });
          const text2 = await res2.text();

          if (text2.includes("64") && !text2.includes("{{8*8}}")) {
            return { pathname };
          }
        }
        return null;
      }),
    ),
  ]);

  // Collect SQLi findings
  let sqliCount = 0;
  const sqliFound = new Set<string>();
  for (const r of sqliResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (sqliFound.has(v.key)) continue;
    sqliFound.add(v.key);

    if (v.type === "error") {
      findings.push({
        id: `injection-sqli-${sqliCount++}`,
        module: "SQL Injection",
        severity: "critical",
        title: `SQL injection on ${v.pathname} (param: ${v.paramName})`,
        description: "SQL error messages appeared in the response after injecting SQL syntax. This strongly indicates the input is used in SQL queries without proper parameterization.",
        evidence: `Payload: ${v.payload}\nParam: ${v.paramName}\nError pattern: ${v.pattern}\nResponse excerpt: ${v.text.substring(0, 300)}`,
        remediation: "Use parameterized queries (prepared statements) instead of string concatenation. With Prisma: use the built-in query methods. With raw SQL: use $1, $2 placeholders.",
        cwe: "CWE-89",
        owasp: "A03:2021",
        codeSnippet: `// Use parameterized queries\n// Prisma (safe by default)\nconst user = await prisma.user.findFirst({ where: { email } });\n\n// Raw SQL — use placeholders\nconst [rows] = await db.query("SELECT * FROM users WHERE id = $1", [id]);`,
      });
    } else if (v.type === "blind") {
      findings.push({
        id: `injection-sqli-blind-${sqliCount++}`,
        module: "SQL Injection",
        severity: "critical",
        title: `Blind SQL injection (time-based) on ${v.pathname}`,
        description: `The server delayed ${v.elapsed}ms when injecting a time-delay SQL payload (baseline: ${v.baseline}ms). This indicates the input is passed directly into SQL queries.`,
        evidence: `Payload: ${v.payload}\nResponse time: ${v.elapsed}ms\nBaseline: ${v.baseline}ms`,
        remediation: "Use parameterized queries. Never concatenate user input into SQL strings.",
        cwe: "CWE-89",
        owasp: "A03:2021",
        codeSnippet: `// Use parameterized queries\n// Prisma (safe by default)\nconst user = await prisma.user.findFirst({ where: { email } });\n\n// Raw SQL — use placeholders\nconst [rows] = await db.query("SELECT * FROM users WHERE id = $1", [id]);`,
      });
    } else if (v.type === "boolean") {
      findings.push({
        id: `injection-sqli-boolean-${sqliCount++}`,
        module: "SQL Injection",
        severity: "critical",
        title: `Boolean-based SQL injection on ${v.pathname} (param: ${v.paramName})`,
        description: `Injecting a true condition ('OR 1=1') returned ${v.trueLen} bytes vs ${v.falseLen} bytes for a false condition. This differential response confirms SQL injection.`,
        evidence: `True payload: ${v.payload} → ${v.trueLen} bytes\nFalse payload: ' AND '1'='2'-- → ${v.falseLen} bytes\nBaseline: ${v.baseLen} bytes`,
        remediation: "Use parameterized queries. Never concatenate user input into SQL strings.",
        cwe: "CWE-89",
        owasp: "A03:2021",
        codeSnippet: `// Use parameterized queries\n// Prisma (safe by default)\nconst user = await prisma.user.findFirst({ where: { email } });\n\n// Raw SQL — use placeholders\nconst [rows] = await db.query("SELECT * FROM users WHERE id = $1", [id]);`,
      });
    }
  }

  // Collect XSS findings (max 3, deduplicate by key)
  let xssCount = 0;
  const xssFound = new Set<string>();
  for (const r of xssResults) {
    if (xssFound.size >= 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (xssFound.has(v.key)) continue;
    xssFound.add(v.key);
    findings.push({
      id: `injection-xss-${xssCount++}`,
      module: "XSS",
      severity: "high",
      title: `Reflected XSS on ${v.pathname} (param: ${v.paramName})`,
      description: "An XSS payload was reflected unescaped in the HTML response. Attackers can inject scripts that steal cookies, redirect users, or perform actions as the victim.",
      evidence: `Payload: ${v.payload}\nParam: ${v.paramName}\nContent-Type: ${v.ct}\nPayload reflected unescaped in response body`,
      remediation: "Sanitize all user input before rendering. Use framework auto-escaping (React does this by default for JSX, but dangerouslySetInnerHTML bypasses it).",
      cwe: "CWE-79",
      owasp: "A03:2021",
      codeSnippet: `// Never use dangerouslySetInnerHTML with user input\n// Bad: <div dangerouslySetInnerHTML={{ __html: userInput }} />\n// Good: <div>{userInput}</div> (auto-escaped)\n\n// For API responses, escape HTML\nimport DOMPurify from "dompurify";\nconst safe = DOMPurify.sanitize(userInput);`,
    });
  }

  // Collect SSTI findings
  let sstiCount = 0;
  const sstiFound = new Set<string>();
  for (const r of sstiResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (sstiFound.has(v.pathname)) continue;
    sstiFound.add(v.pathname);
    findings.push({
      id: `injection-ssti-${sstiCount++}`,
      module: "SSTI",
      severity: "critical",
      title: `Server-Side Template Injection on ${v.pathname}`,
      description: "Template expressions are evaluated on the server. Attackers can execute arbitrary code on your server.",
      evidence: `Payload: {{7*7}} → response contains "49"\nPayload: {{8*8}} → response contains "64"\nBoth expressions evaluated — confirmed SSTI`,
      remediation: "Never pass user input into template engines. Use a logic-less template or sandbox the engine.",
      cwe: "CWE-1336",
      owasp: "A03:2021",
      codeSnippet: `// Never interpolate user input into templates\n// Bad: res.render("page", { title: userInput }) with {{title}} in template\n// Good: Use auto-escaping and avoid user data in template expressions\n\n// If using Nunjucks/Jinja: enable autoescaping\nconst env = nunjucks.configure({ autoescape: true });`,
    });
  }

  return findings;
};
