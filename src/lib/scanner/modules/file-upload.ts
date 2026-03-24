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

  for (const endpoint of endpointsToTest) {
    if (findings.length >= MAX_FINDINGS) break;

    // Test 1: Try uploading an HTML file (stored XSS vector)
    try {
      const htmlPayload = "<html><body><script>alert(1)</script></body></html>";
      const boundary = "----VibeShieldBoundary" + Date.now();
      const body = [
        `--${boundary}`,
        `Content-Disposition: form-data; name="file"; filename="test.html"`,
        `Content-Type: text/html`,
        ``,
        htmlPayload,
        `--${boundary}--`,
      ].join("\r\n");

      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
        body,
        timeoutMs: 5000,
      });

      if (res.status === 404 || res.status === 405) continue;
      const text = await res.text();
      if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) continue;
      if (text.length < 5) continue;

      if (res.ok) {
        // Check if response contains a URL/path to the uploaded file
        const urlMatch = text.match(/["']((?:https?:\/\/[^"']+|\/[^"']+)\.html?)["']/);
        if (urlMatch) {
          // Verify the uploaded file is actually accessible
          try {
            const fileUrl = urlMatch[1].startsWith("http") ? urlMatch[1] : target.baseUrl + urlMatch[1];
            const fileRes = await scanFetch(fileUrl, { timeoutMs: 5000 });
            const fileText = await fileRes.text();
            if (fileRes.ok && fileText.includes("alert(1)")) {
              findings.push({
                id: `file-upload-xss-${findings.length}`,
                module: "File Upload",
                severity: "critical",
                title: `Stored XSS via HTML file upload on ${new URL(endpoint).pathname}`,
                description: "The upload endpoint accepts HTML files and serves them with executable scripts. An attacker can upload malicious HTML that executes JavaScript in victims' browsers.",
                evidence: `POST ${endpoint} with test.html\nUploaded to: ${fileUrl}\nHTML with script tag is served and executable`,
                remediation: "Restrict allowed file types. Never serve user-uploaded HTML files. Use Content-Disposition: attachment for downloads. Store files on a separate domain.",
                cwe: "CWE-434",
                owasp: "A04:2021",
              });
              continue;
            }
          } catch { /* skip */ }
        }

        // Even without URL confirmation, accepting HTML uploads is risky
        if (/url|path|key|location|filename/i.test(text)) {
          findings.push({
            id: `file-upload-html-${findings.length}`,
            module: "File Upload",
            severity: "high",
            title: `HTML file upload accepted on ${new URL(endpoint).pathname}`,
            description: "The upload endpoint accepts HTML files without content-type validation. If these files are served to users, this enables stored XSS attacks.",
            evidence: `POST ${endpoint} with test.html → ${res.status}\nResponse: ${text.substring(0, 200)}`,
            remediation: "Validate file types on the server side (don't trust Content-Type headers). Restrict to expected types (images, PDFs, etc.).",
            cwe: "CWE-434",
            owasp: "A04:2021",
          });
          continue;
        }
      }
    } catch {
      // skip
    }

    // Test 2: Try uploading an SVG with embedded script (common bypass)
    if (findings.length >= MAX_FINDINGS) break;
    try {
      const svgPayload = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`;
      const boundary = "----VibeShieldBoundary" + Date.now();
      const body = [
        `--${boundary}`,
        `Content-Disposition: form-data; name="file"; filename="test.svg"`,
        `Content-Type: image/svg+xml`,
        ``,
        svgPayload,
        `--${boundary}--`,
      ].join("\r\n");

      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
        body,
        timeoutMs: 5000,
      });

      if (res.status === 404 || res.status === 405) continue;
      const text = await res.text();
      if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) continue;

      if (res.ok && text.length > 10 && /url|path|key|location|filename/i.test(text)) {
        findings.push({
          id: `file-upload-svg-${findings.length}`,
          module: "File Upload",
          severity: "high",
          title: `SVG file upload accepted on ${new URL(endpoint).pathname}`,
          description: "The upload endpoint accepts SVG files which can contain embedded JavaScript. If served inline, this enables stored XSS via SVG.",
          evidence: `POST ${endpoint} with test.svg (contains <script>) → ${res.status}\nResponse: ${text.substring(0, 200)}`,
          remediation: "Sanitize SVG uploads by stripping script tags. Or reject SVGs entirely and only accept rasterized image formats (PNG, JPG, WebP).",
          cwe: "CWE-434",
          owasp: "A04:2021",
        });
      }
    } catch {
      // skip
    }

    // Test 3: Path traversal in filename
    if (findings.length >= MAX_FINDINGS) break;
    try {
      const boundary = "----VibeShieldBoundary" + Date.now();
      const body = [
        `--${boundary}`,
        `Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"`,
        `Content-Type: application/octet-stream`,
        ``,
        `test content`,
        `--${boundary}--`,
      ].join("\r\n");

      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
        body,
        timeoutMs: 5000,
      });

      if (res.ok) {
        const text = await res.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) continue;
        // If it accepted the traversal filename without error, that's concerning
        if (text.length > 10 && /url|path|key|location|filename/i.test(text) && /etc|passwd|\.\.\//i.test(text)) {
          findings.push({
            id: `file-upload-traversal-${findings.length}`,
            module: "File Upload",
            severity: "critical",
            title: `Path traversal in file upload on ${new URL(endpoint).pathname}`,
            description: "The upload endpoint accepted a filename containing path traversal sequences (../). An attacker could write files to arbitrary locations on the server.",
            evidence: `POST ${endpoint} with filename="../../../etc/passwd"\nResponse: ${text.substring(0, 200)}`,
            remediation: "Sanitize filenames on the server. Strip path separators and traversal sequences. Generate random filenames for uploaded files.",
            cwe: "CWE-22",
            owasp: "A01:2021",
          });
        }
      }
    } catch {
      // skip
    }
  }

  // Test 4: Check for exposed upload directories
  const uploadDirs = ["/uploads", "/media", "/files", "/assets/uploads", "/public/uploads", "/static/uploads"];
  for (const dir of uploadDirs) {
    if (findings.length >= MAX_FINDINGS) break;
    try {
      const res = await scanFetch(target.baseUrl + dir, { timeoutMs: 5000 });
      if (res.ok) {
        const text = await res.text();
        if (looksLikeHtml(text) && isSoft404(text, target)) continue;
        // Check for directory listing indicators
        if (target.isSpa) continue;
        if (/Index of\s|directory listing|Parent Directory/i.test(text)) {
          findings.push({
            id: `file-upload-dir-listing-${findings.length}`,
            module: "File Upload",
            severity: "medium",
            title: `Upload directory listing exposed at ${dir}`,
            description: "The upload directory has directory listing enabled, exposing all uploaded files. Attackers can browse and download user-uploaded content.",
            evidence: `GET ${target.baseUrl + dir} → ${res.status}\nDirectory listing detected`,
            remediation: "Disable directory listing on upload directories. Serve files through an application endpoint with access controls.",
            cwe: "CWE-548",
          });
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};
