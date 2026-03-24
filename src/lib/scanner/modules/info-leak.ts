import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const ERROR_PATTERNS: { pattern: RegExp; tech: string }[] = [
  { pattern: /Traceback \(most recent call last\)/i, tech: "Python" },
  { pattern: /at [\w.]+\([\w/.]+:\d+:\d+\)/i, tech: "Node.js" },
  { pattern: /(?:Fatal error|Warning):.*on line \d+/i, tech: "PHP" },
  { pattern: /Exception in thread/i, tech: "Java" },
  { pattern: /panic:.*goroutine/i, tech: "Go" },
  { pattern: /ActionView::Template::Error/i, tech: "Ruby on Rails" },
  { pattern: /Microsoft\.AspNetCore/i, tech: ".NET" },
  { pattern: /SQLSTATE\[/i, tech: "Database" },
  { pattern: /pg_connect|pg_query/i, tech: "PostgreSQL" },
  { pattern: /mysql_connect|mysqli/i, tech: "MySQL" },
  { pattern: /at\s+.*\.java:\d+/i, tech: "Java" },
];

const SENSITIVE_INFO_PATTERNS: { pattern: RegExp; description: string }[] = [
  { pattern: /\/home\/\w+\/|\/var\/www\/|\/app\/|C:\\Users\\/i, description: "Server file paths" },
  { pattern: /internal server error.*stack/i, description: "Stack trace in error" },
  { pattern: /debug\s*=\s*True|DEBUG\s*=\s*true/i, description: "Debug mode enabled" },
  { pattern: /django\.core|django\.db/i, description: "Django framework details" },
  { pattern: /express-session/i, description: "Express session details" },
];

export const infoLeakModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Test error triggering on API endpoints
  const errorPayloads = [
    { suffix: "/undefined", desc: "non-existent resource" },
    { suffix: "?id=aaa", desc: "invalid parameter type" },
    { suffix: "?__proto__=test", desc: "prototype pollution probe" },
    { suffix: "/../../etc/passwd", desc: "path traversal" },
    { suffix: "/%00", desc: "null byte" },
  ];

  const seenEndpoints = new Set<string>();
  for (const endpoint of target.apiEndpoints.slice(0, 8)) {
    const pathname = new URL(endpoint).pathname;
    if (seenEndpoints.has(pathname)) continue;

    for (const payload of errorPayloads) {
      if (seenEndpoints.has(pathname)) break;
      try {
        const url = endpoint + payload.suffix;
        const res = await scanFetch(url);
        const text = await res.text();

        // Check for stack traces
        for (const ep of ERROR_PATTERNS) {
          if (ep.pattern.test(text)) {
            seenEndpoints.add(pathname);
            findings.push({
              id: `infoleak-stacktrace-${findings.length}`,
              module: "Information Leakage",
              severity: "medium",
              title: `Stack trace leaked (${ep.tech}) on ${pathname}`,
              description: `A ${ep.tech} stack trace was returned when sending ${payload.desc}. Stack traces reveal internal file paths, function names, and application structure.`,
              evidence: `URL: ${url}\nTech: ${ep.tech}\nResponse excerpt: ${text.substring(0, 400)}`,
              remediation: "Implement proper error handling that returns generic error messages in production. Never expose stack traces to users.",
              cwe: "CWE-209",
              owasp: "A05:2021",
            });
            break;
          }
        }

        // Check for sensitive info patterns (only if no stack trace found)
        if (!seenEndpoints.has(pathname)) {
          for (const si of SENSITIVE_INFO_PATTERNS) {
            if (si.pattern.test(text)) {
              seenEndpoints.add(pathname);
              findings.push({
                id: `infoleak-sensitive-${findings.length}`,
                module: "Information Leakage",
                severity: "low",
                title: `${si.description} leaked on ${pathname}`,
                description: `Sensitive information (${si.description}) was found in the response.`,
                evidence: `URL: ${url}\nPattern: ${si.description}`,
                remediation: "Sanitize error responses in production. Use a global error handler.",
                cwe: "CWE-200",
              });
              break;
            }
          }
        }
      } catch {
        // skip
      }
    }
  }

  // Check response headers for verbose error info
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    try {
      const res = await scanFetch(endpoint, { method: "POST", body: "{invalid json" });
      const text = await res.text();
      if (text.length > 100 && (res.status === 500 || res.status === 400)) {
        for (const ep of ERROR_PATTERNS) {
          if (ep.pattern.test(text)) {
            findings.push({
              id: `infoleak-malformed-${findings.length}`,
              module: "Information Leakage",
              severity: "medium",
              title: `Verbose error on malformed input to ${new URL(endpoint).pathname}`,
              description: `Sending malformed data triggers detailed error output revealing ${ep.tech} internals.`,
              evidence: `POST with malformed JSON\nStatus: ${res.status}\nResponse: ${text.substring(0, 300)}`,
              remediation: "Return generic 400/500 errors. Log details server-side only.",
              cwe: "CWE-209",
            });
            break;
          }
        }
      }
    } catch {
      // skip
    }
  }

  // Check for path traversal
  const traversalPaths = [
    "/../../../etc/passwd",
    "/..%2f..%2f..%2fetc/passwd",
    "/....//....//....//etc/passwd",
  ];

  for (const path of traversalPaths) {
    try {
      const res = await scanFetch(target.baseUrl + path);
      const text = await res.text();
      if (/root:.*:0:0:|daemon:|bin:\/bin/i.test(text)) {
        findings.push({
          id: `infoleak-traversal-${findings.length}`,
          module: "Information Leakage",
          severity: "critical",
          title: "Path traversal vulnerability — /etc/passwd readable",
          description: "The server is vulnerable to directory traversal. Attackers can read arbitrary files from the server filesystem.",
          evidence: `GET ${target.baseUrl + path}\nResponse contains /etc/passwd content`,
          remediation: "Sanitize file paths. Never use user input directly in file system operations. Use a whitelist of allowed paths.",
          cwe: "CWE-22",
          owasp: "A01:2021",
        });
        break;
      }
    } catch {
      // skip
    }
  }

  // Check for dangerouslySetInnerHTML usage in React bundles (common XSS vector)
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const dangerousMatches = allJs.match(/dangerouslySetInnerHTML/g);
  if (dangerousMatches && dangerousMatches.length > 0) {
    findings.push({
      id: "infoleak-dangerous-innerhtml",
      module: "Information Leakage",
      severity: "medium",
      title: `dangerouslySetInnerHTML used ${dangerousMatches.length} time${dangerousMatches.length > 1 ? "s" : ""}`,
      description: `Your React app uses dangerouslySetInnerHTML ${dangerousMatches.length} time(s). This bypasses React's XSS protection and renders raw HTML. If any of these render user-controlled content, it's a direct XSS vulnerability.`,
      evidence: `Found ${dangerousMatches.length} instances of dangerouslySetInnerHTML in JS bundles`,
      remediation: "Audit each dangerouslySetInnerHTML usage. If rendering user content, sanitize with DOMPurify first. Prefer React's built-in escaping.",
      cwe: "CWE-79",
      owasp: "A03:2021",
    });
  }

  return findings;
};
