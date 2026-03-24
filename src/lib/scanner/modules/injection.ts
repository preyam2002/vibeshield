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

const XSS_PAYLOADS = [
  '<script>alert("XSS")</script>',
  '"><img src=x onerror=alert(1)>',
  "javascript:alert(1)",
  '<svg onload=alert(1)>',
  "'-alert(1)-'",
  '<img src="x" onerror="alert(1)">',
  '{{constructor.constructor("alert(1)")()}}',
  "${alert(1)}",
  '<iframe src="javascript:alert(1)">',
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

  // SQL Injection testing
  for (const t of testTargets.slice(0, 15)) {
    for (const payload of SQLI_PAYLOADS.slice(0, 5)) {
      try {
        let res: Response;
        if (t.method === "GET") {
          const url = new URL(t.url);
          url.searchParams.set(t.paramName, payload);
          res = await scanFetch(url.href);
        } else {
          res = await scanFetch(t.url, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `${t.paramName}=${encodeURIComponent(payload)}`,
          });
        }

        const text = await res.text();

        // Check for SQL error messages
        for (const pattern of SQLI_ERROR_PATTERNS) {
          if (pattern.test(text)) {
            findings.push({
              id: `injection-sqli-${findings.length}`,
              module: "SQL Injection",
              severity: "critical",
              title: `SQL injection on ${new URL(t.url).pathname} (param: ${t.paramName})`,
              description: "SQL error messages appeared in the response after injecting SQL syntax. This strongly indicates the input is used in SQL queries without proper parameterization.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nError pattern: ${pattern.source}\nResponse excerpt: ${text.substring(0, 300)}`,
              remediation: "Use parameterized queries (prepared statements) instead of string concatenation. With Prisma: use the built-in query methods. With raw SQL: use $1, $2 placeholders.",
              cwe: "CWE-89",
              owasp: "A03:2021",
            });
            break;
          }
        }

        // Time-based detection — compare against baseline to avoid false positives
        if (payload.includes("SLEEP") || payload.includes("WAITFOR")) {
          // Measure baseline (3 requests, take median)
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
          const baseline = baseTimes.sort((a, b) => a - b)[1] || 500; // median

          const start = Date.now();
          try {
            if (t.method === "GET") {
              const url = new URL(t.url);
              url.searchParams.set(t.paramName, payload);
              await scanFetch(url.href, { timeoutMs: 10000 });
            }
          } catch { /* skip */ }
          const elapsed = Date.now() - start;

          // Only flag if: absolute delay > 1800ms AND at least 2x baseline
          if (elapsed >= 1800 && elapsed >= baseline * 2) {
            findings.push({
              id: `injection-sqli-blind-${findings.length}`,
              module: "SQL Injection",
              severity: "critical",
              title: `Blind SQL injection (time-based) on ${new URL(t.url).pathname}`,
              description: `The server delayed ${elapsed}ms when injecting a time-delay SQL payload (baseline: ${baseline}ms). This indicates the input is passed directly into SQL queries.`,
              evidence: `Payload: ${payload}\nResponse time: ${elapsed}ms\nBaseline: ${baseline}ms`,
              remediation: "Use parameterized queries. Never concatenate user input into SQL strings.",
              cwe: "CWE-89",
              owasp: "A03:2021",
            });
          }
        }
      } catch {
        // skip
      }
    }
  }

  // XSS testing
  for (const t of testTargets.slice(0, 10)) {
    for (const payload of XSS_PAYLOADS.slice(0, 4)) {
      try {
        let res: Response;
        if (t.method === "GET") {
          const url = new URL(t.url);
          url.searchParams.set(t.paramName, payload);
          res = await scanFetch(url.href);
        } else {
          res = await scanFetch(t.url, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `${t.paramName}=${encodeURIComponent(payload)}`,
          });
        }

        const text = await res.text();
        // Check if payload is reflected unescaped
        if (text.includes(payload)) {
          findings.push({
            id: `injection-xss-${findings.length}`,
            module: "XSS",
            severity: "high",
            title: `Reflected XSS on ${new URL(t.url).pathname} (param: ${t.paramName})`,
            description: "An XSS payload was reflected in the response without sanitization. Attackers can inject scripts that steal cookies, redirect users, or perform actions as the victim.",
            evidence: `Payload: ${payload}\nParam: ${t.paramName}\nPayload reflected in response body`,
            remediation: "Sanitize all user input before rendering. Use framework auto-escaping (React does this by default for JSX, but dangerouslySetInnerHTML bypasses it).",
            cwe: "CWE-79",
            owasp: "A03:2021",
          });
          break; // one XSS finding per target is enough
        }
      } catch {
        // skip
      }
    }
  }

  // SSTI testing — fetch baseline first to avoid false positives
  const sstiFound = new Set<string>();
  for (const t of testTargets.slice(0, 5)) {
    const pathname = new URL(t.url).pathname;
    if (sstiFound.has(pathname)) continue;

    // Get baseline: fetch with a harmless value and check if "49" exists
    let baselineHas49 = false;
    let baselineText = "";
    try {
      const baseUrl = new URL(t.url);
      baseUrl.searchParams.set(t.paramName, "harmless_test_value");
      const baseRes = await scanFetch(baseUrl.href);
      baselineText = await baseRes.text();
      baselineHas49 = baselineText.includes("49");
    } catch { /* skip */ }

    if (baselineHas49) continue; // "49" exists naturally — can't distinguish injection

    for (const payload of SSTI_PAYLOADS.slice(0, 3)) {
      try {
        const url = new URL(t.url);
        url.searchParams.set(t.paramName, payload);
        const res = await scanFetch(url.href);
        const text = await res.text();

        // Skip HTML responses — real SSTI shows in rendered output, not SPA shells
        if (looksLikeHtml(text) && target.isSpa) continue;

        if (payload === "{{7*7}}" && text.includes("49") && !text.includes("{{7*7}}")) {
          sstiFound.add(pathname);
          findings.push({
            id: `injection-ssti-${findings.length}`,
            module: "SSTI",
            severity: "critical",
            title: `Server-Side Template Injection on ${pathname}`,
            description: "Template expressions are evaluated on the server. Attackers can execute arbitrary code on your server.",
            evidence: `Payload: ${payload}\nResult contains "49" (evaluated expression)`,
            remediation: "Never pass user input into template engines. Use a logic-less template or sandbox the engine.",
            cwe: "CWE-1336",
            owasp: "A03:2021",
          });
          break;
        }
      } catch {
        // skip
      }
    }
  }

  return findings;
};
