import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

/**
 * Response Security module — tests for MIME confusion, content disposition issues,
 * response splitting, and unsafe response handling patterns.
 */
export const responseSecurityModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;
  const testUrls = [target.url, ...target.apiEndpoints.slice(0, 5)];

  // Phase 1: MIME type confusion — check if API endpoints return wrong Content-Type
  const mimeResults = await Promise.allSettled(
    target.apiEndpoints.slice(0, 10).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      const ct = res.headers.get("content-type") || "";
      const text = await res.text();
      if (text.length < 10) return null;
      const xcto = res.headers.get("x-content-type-options") || "";
      const pathname = new URL(endpoint).pathname;

      // JSON body returned as text/html — browser will render it, enabling XSS via JSON injection
      if (ct.includes("text/html") && text.trimStart().startsWith("{") && text.includes('"')) {
        try {
          JSON.parse(text);
          return {
            pathname, type: "json-as-html" as const,
            ct, noSniff: xcto.toLowerCase() === "nosniff",
          };
        } catch { /* not valid JSON */ }
      }

      // HTML returned without X-Content-Type-Options — MIME sniffing may reinterpret it
      if (!xcto && ct && !ct.includes("text/html") && /<script|<img|<svg|<iframe/i.test(text)) {
        return {
          pathname, type: "html-in-non-html" as const,
          ct, noSniff: false,
        };
      }

      return null;
    }),
  );

  for (const r of mimeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;

    if (v.type === "json-as-html") {
      findings.push({
        id: `response-mime-${count++}`,
        module: "Response Security",
        severity: "high",
        title: `JSON response served as text/html on ${v.pathname}`,
        description: `This API endpoint returns JSON data with Content-Type: text/html. If any JSON value contains HTML/script tags, the browser will render them as HTML, enabling XSS. ${v.noSniff ? "X-Content-Type-Options: nosniff is set, which helps but doesn't fully mitigate." : "X-Content-Type-Options: nosniff is NOT set."}`,
        evidence: `GET ${v.pathname}\nContent-Type: ${v.ct}\nBody starts with "{" (JSON)\nX-Content-Type-Options: ${v.noSniff ? "nosniff" : "(not set)"}`,
        remediation: "Set Content-Type: application/json for JSON responses. Always set X-Content-Type-Options: nosniff.",
        cwe: "CWE-436",
        owasp: "A05:2021",
        codeSnippet: `// Always use Response.json() for JSON responses\nexport async function GET() {\n  return Response.json(data); // Sets application/json automatically\n}\n// Never: return new Response(JSON.stringify(data)); // Defaults to text/plain`,
      });
    } else if (v.type === "html-in-non-html") {
      findings.push({
        id: `response-sniff-${count++}`,
        module: "Response Security",
        severity: "medium",
        title: `HTML content in non-HTML response without nosniff on ${v.pathname}`,
        description: `Response contains HTML tags but is served as ${v.ct} without X-Content-Type-Options: nosniff. Browsers may MIME-sniff the response and render it as HTML, enabling XSS.`,
        evidence: `GET ${v.pathname}\nContent-Type: ${v.ct}\nResponse body contains HTML tags\nX-Content-Type-Options: not set`,
        remediation: "Set X-Content-Type-Options: nosniff on all responses. Ensure Content-Type matches actual content.",
        cwe: "CWE-436",
        owasp: "A05:2021",
        confidence: 70,
      });
    }
  }

  // Phase 2: Content-Disposition header on file-serving endpoints
  // Check if file downloads are served inline instead of as attachments
  const fileEndpoints = target.apiEndpoints.filter((ep) =>
    /download|file|export|attachment|document|upload/i.test(ep),
  );
  const filePageEndpoints = target.pages.filter((p) =>
    /download|file|export|attachment/i.test(p),
  );

  const dispResults = await Promise.allSettled(
    [...fileEndpoints, ...filePageEndpoints].slice(0, 5).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const ct = res.headers.get("content-type") || "";
      const disp = res.headers.get("content-disposition") || "";
      const pathname = new URL(endpoint).pathname;

      // Dangerous content types served without Content-Disposition: attachment
      const isDangerous = /text\/html|application\/xml|image\/svg/i.test(ct);
      if (isDangerous && !disp.includes("attachment")) {
        return { pathname, ct, disp };
      }
      return null;
    }),
  );

  for (const r of dispResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `response-disposition-${count++}`,
      module: "Response Security",
      severity: "medium",
      title: `File download served inline on ${v.pathname}`,
      description: `A file-serving endpoint returns ${v.ct} without Content-Disposition: attachment. Active content types (HTML, XML, SVG) served inline can execute scripts in the context of your domain.`,
      evidence: `GET ${v.pathname}\nContent-Type: ${v.ct}\nContent-Disposition: ${v.disp || "(not set)"}`,
      remediation: "Set Content-Disposition: attachment for user-uploaded files or file downloads. This prevents the browser from rendering the content inline.",
      cwe: "CWE-79",
      owasp: "A03:2021",
      codeSnippet: `// Force download for user-uploaded files\nexport async function GET(req: Request) {\n  const file = await getFile(id);\n  return new Response(file.data, {\n    headers: {\n      "Content-Type": file.type,\n      "Content-Disposition": \`attachment; filename="\${file.name}"\`,\n      "X-Content-Type-Options": "nosniff",\n    },\n  });\n}`,
    });
    if (count >= 2) break;
  }

  // Phase 3: Reflected content type — check if content type can be controlled via Accept header
  const reflectedCtResults = await Promise.allSettled(
    testUrls.slice(0, 4).map(async (url) => {
      const pathname = new URL(url).pathname;
      // Try requesting HTML from a JSON endpoint
      const res = await scanFetch(url, {
        headers: { Accept: "text/html, */*" },
        timeoutMs: 5000,
      });
      const ct = res.headers.get("content-type") || "";
      const text = await res.text();

      // Also test with explicit format parameter
      const formatUrl = new URL(url);
      formatUrl.searchParams.set("format", "html");
      const formatRes = await scanFetch(formatUrl.href, { timeoutMs: 5000 });
      const formatCt = formatRes.headers.get("content-type") || "";
      const formatText = await formatRes.text();

      if (formatCt.includes("text/html") && formatText.includes("<") && !ct.includes("text/html")) {
        return { pathname, param: "format=html", ct: formatCt };
      }

      return null;
    }),
  );

  for (const r of reflectedCtResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `response-reflected-ct-${count++}`,
      module: "Response Security",
      severity: "medium",
      title: `Content-Type controllable via ${v.param} on ${v.pathname}`,
      description: `Adding ?${v.param} changes the response Content-Type to text/html. If any response data is user-controlled, this enables XSS by forcing HTML rendering of API data.`,
      evidence: `GET ${v.pathname}?${v.param}\nContent-Type: ${v.ct}`,
      remediation: "Don't allow Content-Type to be controlled via query parameters. If format switching is needed, validate allowed formats strictly.",
      cwe: "CWE-79",
      owasp: "A03:2021",
      confidence: 75,
    });
    break;
  }

  // Phase 4: Information in error responses — check if error pages leak stack traces
  const errorPaths = [
    "/%00", "/..", "/undefined", "/null",
    "/api/undefined", "/api/null",
  ];

  const errorResults = await Promise.allSettled(
    errorPaths.map(async (path) => {
      const res = await scanFetch(target.baseUrl + path, { timeoutMs: 5000 });
      const text = await res.text();
      const ct = res.headers.get("content-type") || "";

      // Check for stack traces or framework errors in HTML error pages
      const patterns = [
        { name: "Node.js stack trace", pattern: /at\s+\w+\s+\(\/[^)]+\.[jt]s:\d+:\d+\)/ },
        { name: "Python traceback", pattern: /Traceback \(most recent call last\)/ },
        { name: "Java exception", pattern: /java\.\w+\.\w+Exception/ },
        { name: "PHP error", pattern: /Fatal error:.*in \/\w+/ },
        { name: "Next.js error", pattern: /Error: .*at .*(webpack|next)/ },
        { name: "Internal path", pattern: /\/(?:home|var|usr|app|src|opt)\/\w+\/.*\.\w+:\d+/ },
      ];

      for (const { name, pattern } of patterns) {
        if (pattern.test(text)) {
          return { path, name, status: res.status, ct };
        }
      }
      return null;
    }),
  );

  for (const r of errorResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `response-error-leak-${count++}`,
      module: "Response Security",
      severity: "low",
      title: `${v.name} in error response for ${v.path}`,
      description: `Requesting ${v.path} returns a ${v.status} response containing ${v.name}. This reveals internal server paths and framework details to attackers.`,
      evidence: `GET ${v.path} → ${v.status}\nContent-Type: ${v.ct}\nDetected: ${v.name}`,
      remediation: "Configure custom error pages for production. Never expose stack traces or internal paths in error responses.",
      cwe: "CWE-209",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts — custom error handling\n// Create src/app/not-found.tsx and src/app/error.tsx\n// In API routes:\nexport async function GET() {\n  try {\n    // ... handle request\n  } catch (err) {\n    console.error(err); // Log server-side only\n    return Response.json({ error: "Internal error" }, { status: 500 });\n  }\n}`,
    });
    if (count >= 5) break;
  }

  // Phase 5: Caching of sensitive responses
  const sensitiveEndpoints = target.apiEndpoints.filter((ep) =>
    /me|profile|user|account|session|token|auth/i.test(ep),
  );

  const cacheResults = await Promise.allSettled(
    sensitiveEndpoints.slice(0, 5).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const cc = res.headers.get("cache-control") || "";
      const pathname = new URL(endpoint).pathname;

      // Sensitive endpoint with cacheable response
      if (!cc || (!cc.includes("no-store") && !cc.includes("private"))) {
        return { pathname, cc: cc || "(not set)" };
      }
      return null;
    }),
  );

  for (const r of cacheResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `response-cache-sensitive-${count++}`,
      module: "Response Security",
      severity: "medium",
      title: `Sensitive endpoint cacheable: ${v.pathname}`,
      description: `The endpoint ${v.pathname} (likely returns user data) has Cache-Control: ${v.cc}. Without no-store or private, CDNs and browsers may cache this response, serving one user's data to another.`,
      evidence: `GET ${v.pathname}\nCache-Control: ${v.cc}`,
      remediation: "Set Cache-Control: no-store, private on all authenticated/sensitive API responses.",
      cwe: "CWE-524",
      owasp: "A05:2021",
      codeSnippet: `// Set no-store on sensitive endpoints\nexport async function GET(req: Request) {\n  const data = await getUserData(req);\n  return Response.json(data, {\n    headers: { "Cache-Control": "no-store, private" },\n  });\n}`,
    });
    if (count >= 7) break;
  }

  // Phase 6: Content-Disposition bypass — inline rendering of dangerous MIME types
  const dangerousMimeTypes = /text\/html|image\/svg\+xml|application\/xml|text\/xml|application\/xhtml\+xml/i;
  const allEndpoints = [...target.apiEndpoints.slice(0, 8), ...target.pages.slice(0, 4)];

  const dispBypassResults = await Promise.allSettled(
    allEndpoints.map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const ct = res.headers.get("content-type") || "";
      const disp = res.headers.get("content-disposition") || "";
      const pathname = new URL(endpoint).pathname;

      // Dangerous MIME type served with Content-Disposition: inline (or no disposition at all when
      // the endpoint looks like a file-serving route)
      if (dangerousMimeTypes.test(ct) && disp.toLowerCase().includes("inline")) {
        return { pathname, ct, disp };
      }
      return null;
    }),
  );

  for (const r of dispBypassResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `response-disp-bypass-${count++}`,
      module: "Response Security",
      severity: "high",
      title: `Content-Disposition inline for dangerous MIME type on ${v.pathname}`,
      description: `The endpoint returns ${v.ct} with Content-Disposition: inline. Dangerous content types (HTML, SVG, XML) served inline execute scripts in the origin's context. An attacker who can control uploaded file content achieves stored XSS.`,
      evidence: `GET ${v.pathname}\nContent-Type: ${v.ct}\nContent-Disposition: ${v.disp}`,
      remediation: "Set Content-Disposition: attachment for all user-controlled file downloads with active content types. Never use inline for HTML, SVG, or XML served from your domain.",
      cwe: "CWE-79",
      owasp: "A03:2021",
      codeSnippet: `// Force attachment for dangerous MIME types\nconst DANGEROUS = /html|svg|xml|xhtml/i;\nconst disp = DANGEROUS.test(contentType)\n  ? \`attachment; filename="\${filename}"\`\n  : \`inline; filename="\${filename}"\`;\nres.setHeader("Content-Disposition", disp);`,
    });
    if (count >= 9) break;
  }

  // Phase 7: Sensitive data caching — responses with Set-Cookie or auth-requiring endpoints missing no-store
  const sensitiveDataResults = await Promise.allSettled(
    testUrls.slice(0, 6).map(async (url) => {
      const res = await scanFetch(url, { timeoutMs: 5000 });
      const cc = res.headers.get("cache-control") || "";
      const setCookie = res.headers.get("set-cookie") || "";
      const pathname = new URL(url).pathname;

      // Response sets cookies but doesn't prevent caching — intermediate caches may store the Set-Cookie header
      if (setCookie && !cc.includes("no-store")) {
        return { pathname, reason: "Set-Cookie present", cc: cc || "(not set)", header: "Set-Cookie" };
      }
      return null;
    }),
  );

  for (const r of sensitiveDataResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `response-sensitive-cache-${count++}`,
      module: "Response Security",
      severity: "medium",
      title: `Response with ${v.header} missing Cache-Control: no-store on ${v.pathname}`,
      description: `The endpoint ${v.pathname} returns a ${v.header} header but Cache-Control is "${v.cc}". Without no-store, CDNs and shared caches may store the response including the Set-Cookie header, leaking session tokens to other users.`,
      evidence: `GET ${v.pathname}\n${v.header}: (present)\nCache-Control: ${v.cc}`,
      remediation: "Always set Cache-Control: no-store on responses that include Set-Cookie or contain sensitive authentication data. This prevents intermediate caches from storing credentials.",
      cwe: "CWE-524",
      owasp: "A05:2021",
      codeSnippet: `// Middleware to add no-store when setting cookies\nif (res.headers.has("Set-Cookie")) {\n  res.headers.set("Cache-Control", "no-store, private");\n}`,
    });
    if (count >= 11) break;
  }

  // Phase 8: CORS + cookie combo — permissive CORS on endpoints that set cookies
  const corsComboResults = await Promise.allSettled(
    [...target.apiEndpoints.slice(0, 8), target.url].map(async (endpoint) => {
      const res = await scanFetch(endpoint, {
        headers: { Origin: "https://evil.example.com" },
        timeoutMs: 5000,
      });
      const acao = res.headers.get("access-control-allow-origin") || "";
      const acac = res.headers.get("access-control-allow-credentials") || "";
      const setCookie = res.headers.get("set-cookie") || "";
      const pathname = new URL(endpoint).pathname;

      // Permissive CORS with credentials + cookie setting = cross-site cookie theft
      const permissiveCors = acao === "*" || acao === "https://evil.example.com" || acao === "null";
      const credentialsAllowed = acac.toLowerCase() === "true";
      const hasCookies = !!setCookie;

      if (permissiveCors && hasCookies) {
        return {
          pathname, acao, acac, setCookie: setCookie.split(";")[0],
          reflected: acao === "https://evil.example.com",
          credentials: credentialsAllowed,
        };
      }
      return null;
    }),
  );

  for (const r of corsComboResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const severity = v.reflected && v.credentials ? "critical" as const : "high" as const;
    findings.push({
      id: `response-cors-cookie-${count++}`,
      module: "Response Security",
      severity,
      title: `CORS + Set-Cookie combo on ${v.pathname}`,
      description: `The endpoint sets cookies while returning permissive CORS headers (Access-Control-Allow-Origin: ${v.acao}${v.credentials ? ", Access-Control-Allow-Credentials: true" : ""}). ${v.reflected ? "The origin is reflected from the request, meaning any site can make credentialed requests and read the response, including Set-Cookie values." : "A wildcard or null origin combined with cookie-setting allows cross-site interaction."} This enables cross-site cookie theft and session hijacking.`,
      evidence: `GET ${v.pathname} with Origin: https://evil.example.com\nAccess-Control-Allow-Origin: ${v.acao}\nAccess-Control-Allow-Credentials: ${v.acac || "(not set)"}\nSet-Cookie: ${v.setCookie}`,
      remediation: "Never reflect arbitrary origins when setting cookies. Use a strict allowlist of trusted origins. Remove Access-Control-Allow-Credentials: true unless absolutely required, and never combine it with a wildcard or reflected origin.",
      cwe: "CWE-346",
      owasp: "A01:2021",
      confidence: v.reflected && v.credentials ? 95 : 80,
      codeSnippet: `// Strict CORS origin allowlist\nconst ALLOWED_ORIGINS = new Set(["https://myapp.com", "https://admin.myapp.com"]);\nconst origin = req.headers.get("Origin") || "";\nif (ALLOWED_ORIGINS.has(origin)) {\n  res.headers.set("Access-Control-Allow-Origin", origin);\n  res.headers.set("Vary", "Origin");\n}`,
    });
    if (count >= 13) break;
  }

  return findings;
};
