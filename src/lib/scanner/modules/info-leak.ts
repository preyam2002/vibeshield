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
        // Cap at 2 findings per pattern type to avoid noise from similar endpoints
        if (!seenEndpoints.has(pathname)) {
          for (const si of SENSITIVE_INFO_PATTERNS) {
            if (si.pattern.test(text)) {
              const existingCount = findings.filter((f) => f.title.includes(si.description)).length;
              seenEndpoints.add(pathname);
              if (existingCount < 2) {
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
              }
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

  // Check for path traversal — base URL paths
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

  // Check for path traversal on file-serving API endpoints
  const fileParams = ["file", "path", "doc", "document", "template", "page", "name", "filename", "src"];
  const fileEndpoints = target.apiEndpoints.filter((ep) =>
    /file|document|download|export|template|asset|read|load|view|pdf|report/i.test(ep),
  );
  const traversalPayloads = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "....//....//....//....//etc/passwd",
  ];

  for (const ep of fileEndpoints.slice(0, 5)) {
    for (const param of fileParams) {
      for (const payload of traversalPayloads) {
        try {
          const url = new URL(ep);
          url.searchParams.set(param, payload);
          const res = await scanFetch(url.href, { timeoutMs: 5000 });
          const text = await res.text();
          if (/root:.*:0:0:|daemon:|bin:\/bin/i.test(text)) {
            findings.push({
              id: `infoleak-api-traversal-${findings.length}`,
              module: "Information Leakage",
              severity: "critical",
              title: `Path traversal on ${new URL(ep).pathname} via "${param}" parameter`,
              description: "An API endpoint accepts file path parameters and is vulnerable to directory traversal. Attackers can read arbitrary server files.",
              evidence: `GET ${url.href}\nResponse contains /etc/passwd content`,
              remediation: "Never use user input in file paths. Use a lookup table mapping IDs to allowed files. Resolve paths and verify they stay within the expected directory.",
              cwe: "CWE-22",
              owasp: "A01:2021",
            });
            break;
          }
        } catch {
          // skip
        }
      }
    }
  }

  // Check HTML for target="_blank" links without rel="noopener" (tabnabbing)
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Look in HTML and JS bundles for target="_blank" without noopener
  const blankTargetPattern = /target\s*=\s*["']_blank["']/gi;
  const noopenerPattern = /rel\s*=\s*["'][^"']*noopener[^"']*["']/gi;
  const blankCount = (allJs.match(blankTargetPattern) || []).length;
  const noopenerCount = (allJs.match(noopenerPattern) || []).length;
  const unsafe = blankCount - noopenerCount;
  if (unsafe >= 3) {
    findings.push({
      id: "infoleak-tabnabbing",
      module: "Information Leakage",
      severity: "low",
      title: `${unsafe} link${unsafe > 1 ? "s" : ""} open in new tab without rel="noopener"`,
      description: `Found ${blankCount} target="_blank" links but only ${noopenerCount} have rel="noopener". Without noopener, the opened page can access window.opener and redirect the original page (reverse tabnabbing).`,
      evidence: `target="_blank" occurrences: ${blankCount}\nrel="noopener" occurrences: ${noopenerCount}`,
      remediation: "Add rel=\"noopener noreferrer\" to all links with target=\"_blank\". Modern browsers handle this by default, but older browsers need it explicitly.",
      cwe: "CWE-1022",
    });
  }

  // Check for dangerouslySetInnerHTML — only flag if excessive and no CSP
  const dangerousMatches = allJs.match(/dangerouslySetInnerHTML/g);
  const hasCSP = !!target.headers["content-security-policy"];
  if (dangerousMatches && dangerousMatches.length > 10 && !hasCSP) {
    findings.push({
      id: "infoleak-dangerous-innerhtml",
      module: "Information Leakage",
      severity: "low",
      title: `dangerouslySetInnerHTML used ${dangerousMatches.length} times without CSP`,
      description: `Your React app uses dangerouslySetInnerHTML ${dangerousMatches.length} times and has no Content-Security-Policy header. If any render user-controlled content, it's a direct XSS vulnerability with no CSP mitigation.`,
      evidence: `Found ${dangerousMatches.length} instances of dangerouslySetInnerHTML in JS bundles`,
      remediation: "Audit each dangerouslySetInnerHTML usage. If rendering user content, sanitize with DOMPurify first. Add a CSP header to mitigate XSS risk.",
      cwe: "CWE-79",
      owasp: "A03:2021",
    });
  }

  return findings;
};
