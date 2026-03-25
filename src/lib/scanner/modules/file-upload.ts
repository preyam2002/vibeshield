import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml, isSoft404 } from "../soft404";

const UPLOAD_PATHS = [
  "/api/upload", "/api/files", "/api/file", "/api/media",
  "/api/images", "/api/image", "/api/avatar", "/api/photo",
  "/api/attachment", "/api/attachments", "/api/documents",
  "/api/assets", "/upload", "/uploads", "/api/storage",
  "/api/import", "/api/csv", "/api/bulk",
];

export const fileUploadModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Discover upload endpoints from JS bundles
  const uploadEndpoints = new Set<string>();
  const jsPatterns = [
    /["'`](\/api\/[a-zA-Z0-9/_-]*(?:upload|file|media|image|avatar|photo|attachment|document|asset|import|csv|bulk)[a-zA-Z0-9/_-]*)["'`]/gi,
  ];
  for (const pat of jsPatterns) {
    for (const m of allJs.matchAll(pat)) {
      if (m[1]) uploadEndpoints.add(target.baseUrl + m[1]);
    }
  }

  // Check common paths
  for (const path of UPLOAD_PATHS) {
    uploadEndpoints.add(target.baseUrl + path);
  }

  // Also add any recon-discovered upload-related endpoints
  for (const ep of target.apiEndpoints) {
    if (/upload|file|media|image|avatar|attachment|document|import|csv/i.test(ep)) {
      uploadEndpoints.add(ep);
    }
  }

  const MAX_FINDINGS = 3;
  const endpointsToTest = [...uploadEndpoints].slice(0, 15);

  // Helper to build multipart body
  const buildMultipart = (filename: string, contentType: string, content: string) => {
    const boundary = "----VibeShieldBoundary" + Math.random().toString(36).slice(2);
    const body = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n${content}\r\n--${boundary}--`;
    return { boundary, body };
  };

  // Test all endpoints in parallel — each endpoint runs its 3 tests sequentially
  const [endpointResults, dirResults] = await Promise.all([
    Promise.allSettled(
      endpointsToTest.map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;

        // Test 1: HTML upload
        const { boundary: b1, body: body1 } = buildMultipart("test.html", "text/html", "<html><body><script>alert(1)</script></body></html>");
        const res1 = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${b1}` }, body: body1, timeoutMs: 5000,
        });
        if (res1.status === 404 || res1.status === 405) return null;
        const text1 = await res1.text();
        if (looksLikeHtml(text1) && (isSoft404(text1, target) || target.isSpa)) return null;
        if (text1.length < 5) return null;

        if (res1.ok) {
          const urlMatch = text1.match(/["']((?:https?:\/\/[^"']+|\/[^"']+)\.html?)["']/);
          if (urlMatch) {
            try {
              const fileUrl = urlMatch[1].startsWith("http") ? urlMatch[1] : target.baseUrl + urlMatch[1];
              const fileRes = await scanFetch(fileUrl, { timeoutMs: 5000 });
              const fileText = await fileRes.text();
              if (fileRes.ok && fileText.includes("alert(1)")) {
                return { type: "xss" as const, endpoint, pathname, fileUrl };
              }
            } catch { /* skip */ }
          }
          if (/url|path|key|location|filename/i.test(text1)) {
            return { type: "html" as const, endpoint, pathname, status: res1.status, text: text1 };
          }
        }

        // Test 2: SVG upload
        const { boundary: b2, body: body2 } = buildMultipart("test.svg", "image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`);
        const res2 = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${b2}` }, body: body2, timeoutMs: 5000,
        });
        if (res2.status !== 404 && res2.status !== 405) {
          const text2 = await res2.text();
          if (!(looksLikeHtml(text2) && (isSoft404(text2, target) || target.isSpa))) {
            if (res2.ok && text2.length > 10 && /url|path|key|location|filename/i.test(text2)) {
              return { type: "svg" as const, endpoint, pathname, status: res2.status, text: text2 };
            }
          }
        }

        // Test 3: Path traversal
        const { boundary: b3, body: body3 } = buildMultipart("../../../etc/passwd", "application/octet-stream", "test content");
        const res3 = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${b3}` }, body: body3, timeoutMs: 5000,
        });
        if (res3.ok) {
          const text3 = await res3.text();
          if (!(looksLikeHtml(text3) && (isSoft404(text3, target) || target.isSpa))) {
            if (text3.length > 10 && /url|path|key|location|filename/i.test(text3) && /etc|passwd|\.\.\//i.test(text3)) {
              return { type: "traversal" as const, endpoint, pathname, text: text3 };
            }
          }
        }

        // Test 4: MIME type confusion — upload .php disguised as image
        const { boundary: b4, body: body4 } = buildMultipart("shell.php.jpg", "image/jpeg", "<?php echo 'pwned'; ?>");
        const res4 = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${b4}` }, body: body4, timeoutMs: 5000,
        });
        if (res4.ok) {
          const text4 = await res4.text();
          if (!(looksLikeHtml(text4) && (isSoft404(text4, target) || target.isSpa))) {
            if (text4.length > 10 && /url|path|key|location|filename/i.test(text4)) {
              const hasDoubleExt = /\.php/i.test(text4);
              if (hasDoubleExt) {
                return { type: "mime-confusion" as const, endpoint, pathname, text: text4 };
              }
            }
          }
        }

        // Test 5: Null byte extension bypass
        const { boundary: b5, body: body5 } = buildMultipart("test.php%00.jpg", "image/jpeg", "<?php echo 'test'; ?>");
        const res5 = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${b5}` }, body: body5, timeoutMs: 5000,
        });
        if (res5.ok) {
          const text5 = await res5.text();
          if (!(looksLikeHtml(text5) && (isSoft404(text5, target) || target.isSpa))) {
            if (text5.length > 10 && /url|path|key|location|filename/i.test(text5) && /\.php/i.test(text5)) {
              return { type: "null-byte" as const, endpoint, pathname, text: text5 };
            }
          }
        }

        // Test 6: Polyglot JPEG/JS — JPEG magic bytes + JS payload
        const polyglotContent = "\xFF\xD8\xFF\xE0*/=alert(1)//";
        const { boundary: b6, body: body6 } = buildMultipart("polyglot.jpg", "image/jpeg", polyglotContent);
        const res6 = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${b6}` }, body: body6, timeoutMs: 5000,
        });
        if (res6.ok) {
          const text6 = await res6.text();
          if (!(looksLikeHtml(text6) && (isSoft404(text6, target) || target.isSpa))) {
            if (text6.length > 10 && /url|path|key|location|filename/i.test(text6)) {
              // Check if the uploaded file is served as text/html or application/javascript
              const urlMatch6 = text6.match(/["']((?:https?:\/\/[^"']+|\/[^"']+)\.jpg?)["']/);
              if (urlMatch6) {
                try {
                  const fileUrl = urlMatch6[1].startsWith("http") ? urlMatch6[1] : target.baseUrl + urlMatch6[1];
                  const fileRes = await scanFetch(fileUrl, { timeoutMs: 5000 });
                  const ct = fileRes.headers.get("content-type") || "";
                  if (ct.includes("text/html") || ct.includes("javascript")) {
                    return { type: "polyglot" as const, endpoint, pathname, fileUrl, contentType: ct };
                  }
                } catch { /* skip */ }
              }
            }
          }
        }

        // Test 7: Oversize filename (255+ chars) — may cause path truncation or errors
        const longName = "a".repeat(250) + ".jpg";
        const { boundary: b7, body: body7 } = buildMultipart(longName, "image/jpeg", "test");
        const res7 = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${b7}` }, body: body7, timeoutMs: 5000,
        });
        if (res7.status >= 500) {
          const text7 = await res7.text();
          if (/error|stack|trace|exception/i.test(text7)) {
            return { type: "oversize-error" as const, endpoint, pathname, text: text7 };
          }
        }

        return null;
      }),
    ),

    // Test 6: Exposed upload directories in parallel
    Promise.allSettled(
      ["/uploads", "/media", "/files", "/assets/uploads", "/public/uploads", "/static/uploads"].map(async (dir) => {
        const res = await scanFetch(target.baseUrl + dir, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        if (looksLikeHtml(text) && isSoft404(text, target)) return null;
        if (target.isSpa) return null;
        if (/Index of\s|directory listing|Parent Directory/i.test(text)) return { dir };
        return null;
      }),
    ),
  ]);

  for (const r of endpointResults) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;

    if (v.type === "xss") {
      findings.push({ id: `file-upload-xss-${findings.length}`, module: "File Upload", severity: "critical",
        title: `Stored XSS via HTML file upload on ${v.pathname}`,
        description: "The upload endpoint accepts HTML files and serves them with executable scripts.",
        evidence: `POST ${v.endpoint} with test.html\nUploaded to: ${v.fileUrl}\nHTML with script tag is served and executable`,
        remediation: "Restrict allowed file types. Never serve user-uploaded HTML files. Use Content-Disposition: attachment.", cwe: "CWE-434", owasp: "A04:2021",
        codeSnippet: `const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];\n\nexport async function POST(req: Request) {\n  const formData = await req.formData();\n  const file = formData.get('file') as File;\n  if (!file || !ALLOWED_TYPES.includes(file.type)) {\n    return Response.json({ error: 'Invalid file type' }, { status: 400 });\n  }\n  // Serve with Content-Disposition: attachment to prevent execution\n  // res.setHeader('Content-Disposition', 'attachment; filename=\"file.pdf\"');\n}` });
    } else if (v.type === "html") {
      findings.push({ id: `file-upload-html-${findings.length}`, module: "File Upload", severity: "high",
        title: `HTML file upload accepted on ${v.pathname}`,
        description: "The upload endpoint accepts HTML files without content-type validation.",
        evidence: `POST ${v.endpoint} with test.html → ${v.status}\nResponse: ${v.text.substring(0, 200)}`,
        remediation: "Validate file types on the server side. Restrict to expected types (images, PDFs, etc.).", cwe: "CWE-434", owasp: "A04:2021",
        codeSnippet: `import { fileTypeFromBuffer } from 'file-type';\n\nconst buffer = Buffer.from(await file.arrayBuffer());\nconst detected = await fileTypeFromBuffer(buffer);\nif (!detected || !ALLOWED_MIME.includes(detected.mime)) {\n  return Response.json({ error: 'File type not allowed' }, { status: 400 });\n}` });
    } else if (v.type === "svg") {
      findings.push({ id: `file-upload-svg-${findings.length}`, module: "File Upload", severity: "high",
        title: `SVG file upload accepted on ${v.pathname}`,
        description: "The upload endpoint accepts SVG files which can contain embedded JavaScript.",
        evidence: `POST ${v.endpoint} with test.svg (contains <script>) → ${v.status}\nResponse: ${v.text.substring(0, 200)}`,
        remediation: "Sanitize SVG uploads by stripping script tags. Or reject SVGs entirely.", cwe: "CWE-434", owasp: "A04:2021",
        codeSnippet: `import { JSDOM } from 'jsdom';\nimport DOMPurify from 'dompurify';\n\nconst window = new JSDOM('').window;\nconst purify = DOMPurify(window);\nconst cleanSvg = purify.sanitize(svgString, {\n  USE_PROFILES: { svg: true, svgFilters: true },\n  ADD_TAGS: ['svg'], FORBID_TAGS: ['script', 'foreignObject'],\n});` });
    } else if (v.type === "traversal") {
      findings.push({ id: `file-upload-traversal-${findings.length}`, module: "File Upload", severity: "critical",
        title: `Path traversal in file upload on ${v.pathname}`,
        description: "The upload endpoint accepted a filename containing path traversal sequences.",
        evidence: `POST ${v.endpoint} with filename="../../../etc/passwd"\nResponse: ${v.text.substring(0, 200)}`,
        remediation: "Sanitize filenames. Strip path separators and traversal sequences. Generate random filenames.", cwe: "CWE-22", owasp: "A01:2021",
        codeSnippet: `import path from 'path';\nimport crypto from 'crypto';\n\nconst safeName = crypto.randomUUID() + path.extname(file.name).toLowerCase();\nconst uploadDir = path.resolve('/app/uploads');\nconst dest = path.join(uploadDir, safeName);\nif (!dest.startsWith(uploadDir)) {\n  return Response.json({ error: 'Invalid path' }, { status: 400 });\n}` });
    } else if (v.type === "mime-confusion") {
      findings.push({ id: `file-upload-mime-${findings.length}`, module: "File Upload", severity: "high",
        title: `Double extension bypass accepted on ${v.pathname}`,
        description: "The upload endpoint accepted a file with a double extension (shell.php.jpg). On misconfigured servers, the .php extension may execute.",
        evidence: `POST ${v.endpoint} with filename "shell.php.jpg"\nResponse: ${v.text.substring(0, 200)}`,
        remediation: "Validate file type by reading magic bytes, not file extension. Strip all but the last extension.", cwe: "CWE-434", owasp: "A04:2021",
        codeSnippet: `import { fileTypeFromBuffer } from 'file-type';\n\n// Validate by content, not name\nconst buffer = Buffer.from(await file.arrayBuffer());\nconst type = await fileTypeFromBuffer(buffer);\nif (!type || !ALLOWED_TYPES.includes(type.mime)) {\n  return Response.json({ error: 'Invalid file type' }, { status: 400 });\n}\n// Generate safe filename\nconst safeName = crypto.randomUUID() + '.' + type.ext;` });
    } else if (v.type === "null-byte") {
      findings.push({ id: `file-upload-null-byte-${findings.length}`, module: "File Upload", severity: "critical",
        title: `Null byte injection in file upload on ${v.pathname}`,
        description: "The upload endpoint processed a filename containing a null byte (%00), which can truncate the filename and bypass extension checks.",
        evidence: `POST ${v.endpoint} with filename "test.php%00.jpg"\nResponse: ${v.text.substring(0, 200)}`,
        remediation: "Strip null bytes from filenames. Use content-based type detection, not extensions.", cwe: "CWE-158", owasp: "A03:2021",
        codeSnippet: `// Strip null bytes and validate\nconst safeName = filename.replace(/\\0/g, '').replace(/%00/g, '');\nif (safeName !== filename) {\n  return Response.json({ error: 'Invalid filename' }, { status: 400 });\n}` });
    } else if (v.type === "polyglot") {
      findings.push({ id: `file-upload-polyglot-${findings.length}`, module: "File Upload", severity: "high",
        title: `Polyglot file served with executable MIME type on ${v.pathname}`,
        description: `A polyglot JPEG/JavaScript file was uploaded and served with Content-Type: ${v.contentType}. This allows XSS attacks — the file is valid as both an image and executable script.`,
        evidence: `POST ${v.endpoint} with JPEG/JS polyglot → uploaded\nServed at: ${v.fileUrl}\nContent-Type: ${v.contentType}`,
        remediation: "Validate file content with magic byte detection. Always serve uploads with Content-Type matching the validated type. Set Content-Disposition: attachment.", cwe: "CWE-434", owasp: "A04:2021",
        codeSnippet: `// Validate content AND force correct Content-Type\nimport { fileTypeFromBuffer } from 'file-type';\n\nconst type = await fileTypeFromBuffer(buffer);\n// Serve with validated Content-Type, not whatever the file claims\nres.setHeader('Content-Type', type?.mime || 'application/octet-stream');\nres.setHeader('Content-Disposition', 'attachment');\nres.setHeader('X-Content-Type-Options', 'nosniff');` });
    } else if (v.type === "oversize-error") {
      findings.push({ id: `file-upload-error-${findings.length}`, module: "File Upload", severity: "low",
        title: `Upload endpoint error disclosure on ${v.pathname}`,
        description: "An oversized filename caused a server error with stack trace or debug information in the response.",
        evidence: `POST ${v.endpoint} with 250-char filename\nResponse: ${v.text.substring(0, 200)}`,
        remediation: "Handle upload errors gracefully. Don't expose stack traces or internal details in error responses.", cwe: "CWE-209", owasp: "A05:2021",
        confidence: 80 });
    }
  }

  for (const r of dirResults) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({ id: `file-upload-dir-listing-${findings.length}`, module: "File Upload", severity: "medium",
      title: `Upload directory listing exposed at ${r.value.dir}`,
      description: "The upload directory has directory listing enabled, exposing all uploaded files.",
      evidence: `GET ${target.baseUrl + r.value.dir} → 200\nDirectory listing detected`,
      remediation: "Disable directory listing on upload directories.", cwe: "CWE-548",
      codeSnippet: `// next.config.js — serve uploads via API route instead of static directory\n// Move uploads outside /public to prevent direct access\n// Use a signed URL or auth-gated API route:\nexport async function GET(req: Request) {\n  const session = await getServerSession();\n  if (!session) return new Response(null, { status: 401 });\n  const file = await fs.readFile(resolvedPath);\n  return new Response(file, {\n    headers: { 'Content-Disposition': 'attachment' },\n  });\n}` });
  }

  return findings;
};
