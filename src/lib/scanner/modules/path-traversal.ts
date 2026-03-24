import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const TRAVERSAL_PAYLOADS = [
  "../../../etc/passwd",
  "..%2f..%2f..%2fetc%2fpasswd",
  "....//....//....//etc/passwd",
  "..\\..\\..\\etc\\passwd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "../../../etc/shadow",
  "..%252f..%252f..%252fetc%252fpasswd",
  "../../../windows/win.ini",
];

const TRAVERSAL_INDICATORS = [
  /root:.*:0:0/,                      // /etc/passwd
  /daemon:.*:\/usr/,                   // /etc/passwd
  /nobody:.*:\/nonexistent/,           // /etc/passwd
  /\[extensions\]/i,                   // win.ini
  /\[fonts\]/i,                        // win.ini
];

const NULL_BYTE_PAYLOADS = [
  "../../../etc/passwd%00.png",
  "../../../etc/passwd%00.jpg",
  "../../../etc/passwd\x00.html",
];

export const pathTraversalModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;

  // Collect endpoints that might serve files: pages with path params, API endpoints with file-like params
  const testEndpoints: { url: string; paramName: string }[] = [];

  for (const endpoint of target.apiEndpoints) {
    try {
      const url = new URL(endpoint);
      for (const [key] of url.searchParams) {
        if (/file|path|name|doc|page|template|include|dir|folder|src|img|image|download|load|read|view/i.test(key)) {
          testEndpoints.push({ url: endpoint, paramName: key });
        }
      }
    } catch { /* skip */ }
  }

  for (const page of target.pages) {
    try {
      const url = new URL(page);
      for (const [key] of url.searchParams) {
        if (/file|path|name|doc|page|template|include|dir|folder|src|img|image|download|load|read|view/i.test(key)) {
          testEndpoints.push({ url: page, paramName: key });
        }
      }
    } catch { /* skip */ }
  }

  // Also try common file-serving param names on API endpoints
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    for (const param of ["file", "path", "filename", "page", "template", "doc", "download"]) {
      testEndpoints.push({ url: endpoint, paramName: param });
    }
  }

  // Deduplicate
  const seen = new Set<string>();
  const deduped = testEndpoints.filter((t) => {
    const key = `${new URL(t.url).pathname}:${t.paramName}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Get baseline — fetch with a normal value to check for false positives
  const baselineTexts = new Map<string, string>();
  await Promise.allSettled(
    deduped.slice(0, 15).map(async (t) => {
      const url = new URL(t.url);
      url.searchParams.set(t.paramName, "normal_file.txt");
      const res = await scanFetch(url.href, { timeoutMs: 5000 });
      const text = await res.text();
      baselineTexts.set(`${new URL(t.url).pathname}:${t.paramName}`, text);
    }),
  );

  const flagged = new Set<string>();

  for (const t of deduped.slice(0, 15)) {
    const pathname = new URL(t.url).pathname;
    const key = `${pathname}:${t.paramName}`;
    if (flagged.has(key)) continue;

    const baseText = baselineTexts.get(key) || "";
    // If baseline already contains traversal indicators, skip (false positive)
    if (TRAVERSAL_INDICATORS.some((p) => p.test(baseText))) continue;

    for (const payload of TRAVERSAL_PAYLOADS) {
      try {
        const url = new URL(t.url);
        url.searchParams.set(t.paramName, payload);
        const res = await scanFetch(url.href, { timeoutMs: 5000 });
        const text = await res.text();

        if (TRAVERSAL_INDICATORS.some((p) => p.test(text))) {
          flagged.add(key);
          findings.push({
            id: `path-traversal-${count++}`,
            module: "Path Traversal",
            severity: "critical",
            title: `Path traversal on ${pathname} (param: ${t.paramName})`,
            description: "A directory traversal payload returned sensitive system file contents. Attackers can read any file on the server including configuration files, credentials, and source code.",
            evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
            remediation: "Never use user input directly in file paths. Use a whitelist of allowed files, or resolve the path and verify it stays within the intended directory using path.resolve() + startsWith() checks.",
            cwe: "CWE-22",
            owasp: "A01:2021",
          });
          break;
        }
      } catch { /* skip */ }
    }

    // Null byte injection (legacy PHP/older runtimes)
    if (!flagged.has(key)) {
      for (const payload of NULL_BYTE_PAYLOADS) {
        try {
          const url = new URL(t.url);
          url.searchParams.set(t.paramName, payload);
          const res = await scanFetch(url.href, { timeoutMs: 5000 });
          const text = await res.text();

          if (TRAVERSAL_INDICATORS.some((p) => p.test(text))) {
            flagged.add(key);
            findings.push({
              id: `path-traversal-null-${count++}`,
              module: "Path Traversal",
              severity: "critical",
              title: `Path traversal via null byte on ${pathname}`,
              description: "A null byte in the file path bypassed extension validation, allowing reading of arbitrary files. This is a classic bypass for file extension checks.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation: "Reject null bytes in all user input. Use path.resolve() and validate the resolved path is within the intended directory.",
              cwe: "CWE-22",
              owasp: "A01:2021",
            });
            break;
          }
        } catch { /* skip */ }
      }
    }
  }

  // Check for path traversal in URL path segments (e.g., /api/files/../../../etc/passwd)
  const fileEndpoints = target.apiEndpoints.filter((ep) =>
    /file|download|image|asset|static|upload|doc|media/i.test(ep),
  );
  for (const endpoint of fileEndpoints.slice(0, 5)) {
    try {
      const url = new URL(endpoint);
      const basePath = url.pathname;
      for (const traversal of ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]) {
        const testUrl = `${url.origin}${basePath}/${traversal}`;
        const res = await scanFetch(testUrl, { timeoutMs: 5000 });
        const text = await res.text();

        if (TRAVERSAL_INDICATORS.some((p) => p.test(text))) {
          findings.push({
            id: `path-traversal-url-${count++}`,
            module: "Path Traversal",
            severity: "critical",
            title: `Path traversal in URL path at ${basePath}`,
            description: "Directory traversal sequences in the URL path returned system file contents.",
            evidence: `URL: ${testUrl}\nResponse excerpt: ${text.substring(0, 200)}`,
            remediation: "Validate and sanitize URL path segments. Use a web application firewall or middleware that blocks traversal sequences.",
            cwe: "CWE-22",
            owasp: "A01:2021",
          });
          break;
        }
      }
    } catch { /* skip */ }
  }

  return findings;
};
