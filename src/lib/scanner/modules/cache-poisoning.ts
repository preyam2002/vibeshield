import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

// Headers that can poison CDN/proxy caches
const POISONING_HEADERS = [
  { name: "X-Forwarded-Host", value: "evil.com", desc: "forwarded host" },
  { name: "X-Original-URL", value: "/admin", desc: "original URL override" },
  { name: "X-Rewrite-URL", value: "/admin", desc: "rewrite URL override" },
  { name: "X-Forwarded-Scheme", value: "nothttps", desc: "forwarded scheme" },
  { name: "X-Forwarded-Proto", value: "nothttps", desc: "forwarded protocol" },
];

export const cachePoisoningModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;

  const testUrls = [target.url, ...target.apiEndpoints.slice(0, 3)];

  // Phase 1: Get baseline response
  const baselines = new Map<string, { body: string; status: number; headers: Record<string, string> }>();
  await Promise.allSettled(
    testUrls.map(async (url) => {
      const res = await scanFetch(url, { timeoutMs: 5000 });
      const body = await res.text();
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      baselines.set(url, { body, status: res.status, headers });
    }),
  );

  // Phase 2: Test cache poisoning headers
  const tests = testUrls.flatMap((url) =>
    POISONING_HEADERS.map((h) => ({ url, header: h })),
  );

  const results = await Promise.allSettled(
    tests.map(async ({ url, header }) => {
      const res = await scanFetch(url, {
        headers: { [header.name]: header.value },
        timeoutMs: 5000,
      });
      const body = await res.text();
      return { url, header, body, status: res.status };
    }),
  );

  const flagged = new Set<string>();

  for (const r of results) {
    if (r.status !== "fulfilled") continue;
    const { url, header, body, status } = r.value;
    const baseline = baselines.get(url);
    if (!baseline) continue;
    const pathname = new URL(url).pathname;
    if (flagged.has(`${pathname}:${header.name}`)) continue;

    // Check if the poisoning header changed the response in a meaningful way
    if (header.name === "X-Forwarded-Host" || header.name === "X-Forwarded-Scheme" || header.name === "X-Forwarded-Proto") {
      // Check if evil.com or the injected value appears in the response
      if (body.includes("evil.com") && !baseline.body.includes("evil.com")) {
        flagged.add(`${pathname}:${header.name}`);
        findings.push({
          id: `cache-poison-${count++}`,
          module: "Cache Poisoning",
          severity: "high",
          title: `Cache poisoning via ${header.name} on ${pathname}`,
          description: `The ${header.desc} header value was reflected in the response body. If the response is cached by a CDN, attackers can serve malicious content to all users by poisoning the cache with a crafted ${header.name} header.`,
          evidence: `Header: ${header.name}: ${header.value}\nReflected "evil.com" in response body`,
          remediation: `Ensure your CDN/proxy includes ${header.name} in the cache key, or strip it before reaching your application. Add Vary: ${header.name} to the response.`,
          cwe: "CWE-444",
          owasp: "A05:2021",
          codeSnippet: `// next.config.ts — add Vary header to prevent cache poisoning\nexport default {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Vary", value: "Accept-Encoding, X-Forwarded-Host" },\n      { key: "Cache-Control", value: "public, max-age=3600, must-revalidate" }\n    ]}];\n  },\n};`,
        });
      }
    }

    if (header.name === "X-Original-URL" || header.name === "X-Rewrite-URL") {
      // Check if the response changed significantly (different page served)
      if (status === baseline.status && body !== baseline.body) {
        const similarity = body.length > 0 && baseline.body.length > 0
          ? Math.abs(body.length - baseline.body.length) / Math.max(body.length, baseline.body.length)
          : 1;
        // Only flag if content changed significantly (>30% difference in length)
        if (similarity > 0.3) {
          flagged.add(`${pathname}:${header.name}`);
          findings.push({
            id: `cache-poison-rewrite-${count++}`,
            module: "Cache Poisoning",
            severity: "high",
            title: `URL rewrite injection via ${header.name} on ${pathname}`,
            description: `The ${header.name} header caused the server to return different content. Attackers can use this to serve different pages under the same cached URL, potentially accessing admin panels or sensitive routes.`,
            evidence: `Header: ${header.name}: ${header.value}\nBaseline body length: ${baseline.body.length}\nPoisoned body length: ${body.length}`,
            remediation: `Block or strip ${header.name} headers at your reverse proxy/CDN layer. Most applications should not honor these headers.`,
            cwe: "CWE-444",
            owasp: "A05:2021",
            codeSnippet: `// middleware.ts — strip URL rewrite headers\nconst STRIPPED = ["x-original-url", "x-rewrite-url"];\nexport function middleware(req) {\n  const headers = new Headers(req.headers);\n  STRIPPED.forEach(h => headers.delete(h));\n  return NextResponse.next({ request: { headers } });\n}`,
          });
        }
      }
    }
  }

  // Phase 3: Check for cache-related header issues
  for (const [url, baseline] of baselines) {
    const pathname = new URL(url).pathname;
    const cacheControl = baseline.headers["cache-control"] || "";
    const vary = baseline.headers["vary"] || "";
    const age = baseline.headers["age"];
    const xCache = baseline.headers["x-cache"] || baseline.headers["cf-cache-status"] || "";

    // Check if response is being cached (has age or cache hit indicator)
    const isCached = age !== undefined || /hit/i.test(xCache);

    if (isCached) {
      // Cached response without Vary header — may serve same cached response for different origins/cookies
      if (!vary && !cacheControl.includes("private") && !cacheControl.includes("no-store")) {
        findings.push({
          id: `cache-no-vary-${count++}`,
          module: "Cache Poisoning",
          severity: "low",
          title: `Cached response without Vary header on ${pathname}`,
          description: "This response is being cached (CDN cache hit detected) but has no Vary header. The same cached response may be served regardless of cookies, origin, or other request-specific headers.",
          evidence: `Cache-Control: ${cacheControl || "(not set)"}\nVary: ${vary || "(not set)"}\n${age ? `Age: ${age}` : ""}${xCache ? `\nX-Cache: ${xCache}` : ""}`,
          remediation: "Add appropriate Vary headers (e.g., Vary: Cookie, Accept-Encoding) to prevent cache poisoning.",
          cwe: "CWE-444",
          codeSnippet: `// next.config.ts — add Vary header\nexport default {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Vary", value: "Cookie, Accept-Encoding" }\n    ]}];\n  },\n};`,
        });
      }

      // Cached response with Set-Cookie (CDN should not cache responses with Set-Cookie)
      if (baseline.headers["set-cookie"]) {
        findings.push({
          id: `cache-set-cookie-${count++}`,
          module: "Cache Poisoning",
          severity: "medium",
          title: `Cached response includes Set-Cookie on ${pathname}`,
          description: "A cached response includes Set-Cookie headers. This means one user's session cookie may be served to other users from the cache, leading to session fixation or information leakage.",
          evidence: `Cache indicators: ${age ? `Age: ${age}` : ""}${xCache ? ` X-Cache: ${xCache}` : ""}\nSet-Cookie present in cached response`,
          remediation: "Configure your CDN to never cache responses with Set-Cookie headers, or add Cache-Control: no-store to responses that set cookies.",
          cwe: "CWE-524",
          owasp: "A05:2021",
          codeSnippet: `// API route — prevent caching of authenticated responses\nexport async function GET(req) {\n  const res = NextResponse.json(data);\n  res.headers.set("Cache-Control", "private, no-store, no-cache");\n  return res;\n}`,
        });
      }
    }
  }

  // Phase 4: Fat GET / method override cache poisoning
  const fatGetResults = await Promise.allSettled(
    [...baselines.entries()].slice(0, 3).map(async ([url, baseline]) => {
      // Test if GET request with body or method override headers is cached differently
      const overrideHeaders: [string, string][] = [
        ["X-HTTP-Method-Override", "POST"],
        ["X-Method-Override", "POST"],
        ["X-HTTP-Method", "POST"],
      ];
      for (const [headerName, headerVal] of overrideHeaders) {
        const res = await scanFetch(url, {
          headers: { [headerName]: headerVal, "Content-Type": "application/x-www-form-urlencoded" },
          timeoutMs: 5000,
        });
        const resHeaders: Record<string, string> = {};
        res.headers.forEach((v, k) => { resHeaders[k] = v; });
        // If the response differs from baseline, the method override was processed
        const text = await res.text();
        if (res.status !== baseline.status || Math.abs(text.length - baseline.body.length) > text.length * 0.3) {
          return {
            url, pathname: new URL(url).pathname,
            header: headerName,
            baseStatus: baseline.status, overrideStatus: res.status,
          };
        }
      }
      return null;
    }),
  );

  for (const r of fatGetResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `cache-fat-get-${count++}`,
      module: "Cache Poisoning",
      severity: "medium",
      title: `Method override accepted on cached ${v.pathname}`,
      description: `The server processes ${v.header} header on GET requests, returning a different response (${v.baseStatus} vs ${v.overrideStatus}). If the CDN caches based on URL only, an attacker can poison the cache with a POST-like response served to all users.`,
      evidence: `GET ${v.url} → ${v.baseStatus}\nGET ${v.url} with ${v.header}: POST → ${v.overrideStatus}`,
      remediation: "Ignore HTTP method override headers in production. Configure your CDN to include the request method in the cache key.",
      cwe: "CWE-444", owasp: "A05:2021",
      codeSnippet: `// Reject method override headers in middleware\nexport function middleware(req: NextRequest) {\n  const override = req.headers.get("x-http-method-override");\n  if (override) {\n    return NextResponse.json({ error: "Method override not allowed" }, { status: 400 });\n  }\n}`,
    });
    break;
  }

  // Phase 5: Web cache deception — check if authenticated pages get cached
  // Try appending a static extension to an API/page URL to trick cache into storing dynamic content
  const deceptionExtensions = [".css", ".js", ".png", ".svg", ".ico", "/style.css", "/logo.png"];
  const deceptionResults = await Promise.allSettled(
    target.apiEndpoints
      .filter((ep) => /me|profile|user|account|dashboard|settings/i.test(ep))
      .slice(0, 2)
      .flatMap((endpoint) =>
        deceptionExtensions.slice(0, 3).map(async (ext) => {
          const testUrl = endpoint + ext;
          const res = await scanFetch(testUrl, { timeoutMs: 5000 });
          if (!res.ok) return null;
          const text = await res.text();
          const cacheHeader = res.headers.get("x-cache") || res.headers.get("cf-cache-status") || "";
          const age = res.headers.get("age");
          const isCachedResponse = /hit|miss/i.test(cacheHeader) || age !== null;
          // If dynamic content is returned AND it looks like it could be cached
          if (text.length > 50 && !text.includes("<!DOCTYPE") && (isCachedResponse || !res.headers.get("cache-control")?.includes("no-store"))) {
            return {
              endpoint: new URL(endpoint).pathname,
              ext,
              status: res.status,
              cacheHeader,
              bodyLen: text.length,
            };
          }
          return null;
        }),
      ),
  );

  for (const r of deceptionResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `cache-deception-${count++}`,
      module: "Cache Poisoning",
      severity: "high",
      title: `Web cache deception: ${v.endpoint}${v.ext} returns dynamic content`,
      description: `Appending "${v.ext}" to ${v.endpoint} still returns dynamic API content (${v.bodyLen} bytes). CDNs may cache this response because of the static file extension, exposing one user's private data to everyone.${v.cacheHeader ? ` Cache header: ${v.cacheHeader}` : ""}`,
      evidence: `GET ${v.endpoint}${v.ext} → ${v.status} (${v.bodyLen} bytes)${v.cacheHeader ? `\nX-Cache: ${v.cacheHeader}` : ""}\nResponse is dynamic content served with a static extension`,
      remediation: "Configure path-based cache rules strictly. Only cache explicit static file patterns. Return 404 for API routes with unexpected extensions.",
      cwe: "CWE-525",
      owasp: "A05:2021",
      confidence: 70,
      codeSnippet: `// middleware.ts — block cache deception attempts\nexport function middleware(req: NextRequest) {\n  const path = req.nextUrl.pathname;\n  // Block API requests with static file extensions\n  if (path.startsWith("/api/") && /\\.(css|js|png|jpg|svg|ico|woff2?)$/.test(path)) {\n    return NextResponse.json({ error: "Not found" }, { status: 404 });\n  }\n}\n\n// Also set Cache-Control: no-store on all authenticated API responses\nres.headers.set("Cache-Control", "no-store, private");`,
    });
    break;
  }

  // Phase 6: Unkeyed query parameter injection
  // Test if adding unknown query params changes the response (param might get reflected but not included in cache key)
  const unkeyedParamResults = await Promise.allSettled(
    [...baselines.entries()].slice(0, 3).map(async ([url, baseline]) => {
      const testUrl = new URL(url);
      testUrl.searchParams.set("vibeshield_cb", `"><script>x</script>`);
      const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });
      const body = await res.text();
      // Check if the injected value appears in the response body (reflected)
      if (body.includes(`"><script>x</script>`) && !baseline.body.includes(`"><script>x</script>`)) {
        const cacheHeader = res.headers.get("x-cache") || res.headers.get("cf-cache-status") || "";
        return {
          pathname: new URL(url).pathname,
          cacheHeader,
        };
      }
      return null;
    }),
  );

  for (const r of unkeyedParamResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `cache-unkeyed-param-${count++}`,
      module: "Cache Poisoning",
      severity: "high",
      title: `Unkeyed parameter reflected on ${v.pathname} (potential cache poisoning + XSS)`,
      description: `An unknown query parameter was injected and reflected in the response body. If this parameter is not part of the CDN's cache key, an attacker can poison the cache with XSS payloads that execute for all visitors.`,
      evidence: `GET ${v.pathname}?vibeshield_cb="><script>x</script>\nValue reflected in response body${v.cacheHeader ? `\nCache: ${v.cacheHeader}` : ""}`,
      remediation: "Don't reflect unknown query parameters in responses. Configure your CDN to include all query parameters in the cache key, or strip unknown params.",
      cwe: "CWE-79",
      owasp: "A03:2021",
      confidence: 80,
      codeSnippet: `// middleware.ts — strip unknown query params\nconst ALLOWED_PARAMS = new Set(["page", "sort", "q", "id"]);\nexport function middleware(req: NextRequest) {\n  const url = req.nextUrl.clone();\n  let stripped = false;\n  for (const key of url.searchParams.keys()) {\n    if (!ALLOWED_PARAMS.has(key)) {\n      url.searchParams.delete(key);\n      stripped = true;\n    }\n  }\n  if (stripped) return NextResponse.redirect(url, 301);\n}`,
    });
    break;
  }

  // Phase 7: Web cache deception via path suffix
  // Test if appending /.css or /.js to authenticated endpoints returns cached sensitive data
  const pathDeceptionSuffixes = ["/.css", "/.js", "/..%2f.css", "/..%2f.js"];
  const sensitiveEndpoints = target.apiEndpoints
    .filter((ep) => /me|profile|user|account|dashboard|settings|token|session/i.test(ep))
    .slice(0, 3);

  const pathDeceptionResults = await Promise.allSettled(
    sensitiveEndpoints.flatMap((endpoint) =>
      pathDeceptionSuffixes.map(async (suffix) => {
        const testUrl = endpoint + suffix;
        const res = await scanFetch(testUrl, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        const baseline = baselines.get(endpoint);
        const cacheControl = res.headers.get("cache-control") || "";
        const cacheStatus = res.headers.get("x-cache") || res.headers.get("cf-cache-status") || "";
        const age = res.headers.get("age");
        // If the suffixed URL returns similar content to the original authenticated endpoint
        // AND doesn't have no-store, it may be cacheable
        if (
          baseline &&
          text.length > 100 &&
          Math.abs(text.length - baseline.body.length) / Math.max(text.length, baseline.body.length) < 0.5 &&
          !cacheControl.includes("no-store") &&
          !cacheControl.includes("private")
        ) {
          return {
            endpoint: new URL(endpoint).pathname,
            suffix,
            status: res.status,
            bodyLen: text.length,
            cacheStatus,
            age,
          };
        }
        return null;
      }),
    ),
  );

  for (const r of pathDeceptionResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `cache-path-deception-${count++}`,
      module: "cache-poisoning",
      severity: "high",
      title: `Web cache deception via path suffix on ${v.endpoint}`,
      description: `Appending "${v.suffix}" to ${v.endpoint} returns similar dynamic content (${v.bodyLen} bytes, status ${v.status}) without cache-prevention headers. An attacker can trick a victim into visiting ${v.endpoint}${v.suffix}, causing the CDN to cache their authenticated response under a static-looking path.`,
      evidence: `GET ${v.endpoint}${v.suffix} → ${v.status} (${v.bodyLen} bytes)\nCache-Control does not include no-store or private${v.cacheStatus ? `\nX-Cache: ${v.cacheStatus}` : ""}${v.age ? `\nAge: ${v.age}` : ""}`,
      remediation: "Return 404 for requests with unexpected path suffixes on dynamic endpoints. Set Cache-Control: no-store on all authenticated responses. Configure CDN path-based caching rules to only match exact static asset paths.",
      cwe: "CWE-525",
      codeSnippet: `// middleware.ts — reject path suffix deception attempts\nexport function middleware(req: NextRequest) {\n  const path = req.nextUrl.pathname;\n  if (/\\/api\\/.*\\.(css|js|png|jpg|svg)$/i.test(path)) {\n    return NextResponse.json({ error: "Not found" }, { status: 404 });\n  }\n}`,
    });
  }

  // Phase 8: Cache key normalization — test if URL encoding differences lead to separate cache entries
  const normalizationPairs: [string, string][] = [
    ["/", "%2F"],
    [".", "%2E"],
    ["~", "%7E"],
  ];

  const normTestUrls = [...baselines.entries()].slice(0, 3);
  const normResults = await Promise.allSettled(
    normTestUrls.flatMap(([url, baseline]) => {
      const parsed = new URL(url);
      return normalizationPairs
        .filter(([char]) => parsed.pathname.includes(char))
        .map(async ([char, encoded]) => {
          const encodedPath = parsed.pathname.replace(char, encoded);
          const testUrl = `${parsed.origin}${encodedPath}${parsed.search}`;
          const res = await scanFetch(testUrl, { timeoutMs: 5000 });
          const body = await res.text();
          const cacheStatus = res.headers.get("x-cache") || res.headers.get("cf-cache-status") || "";
          const age = res.headers.get("age");
          // If same content is returned but with different cache indicators, keys diverge
          if (
            res.status === baseline.status &&
            Math.abs(body.length - baseline.body.length) / Math.max(body.length, baseline.body.length) < 0.1
          ) {
            const baselineAge = baseline.headers["age"];
            const baselineCacheStatus = baseline.headers["x-cache"] || baseline.headers["cf-cache-status"] || "";
            // Different age or different cache status = separate cache entries for same content
            if (
              (age !== null && baselineAge !== undefined && age !== baselineAge) ||
              (cacheStatus && baselineCacheStatus && cacheStatus !== baselineCacheStatus)
            ) {
              return {
                pathname: parsed.pathname,
                char,
                encoded,
                encodedPath,
                cacheStatus,
                baselineCacheStatus,
                age,
                baselineAge,
              };
            }
          }
          return null;
        });
    }),
  );

  for (const r of normResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `cache-key-norm-${count++}`,
      module: "cache-poisoning",
      severity: "medium",
      title: `Cache key normalization issue on ${v.pathname}`,
      description: `The CDN creates separate cache entries for "${v.char}" vs "${v.encoded}" in the URL path, even though the origin returns identical content. This allows cache poisoning by pre-populating the encoded variant with attacker-controlled content.`,
      evidence: `Original path: ${v.pathname} → Cache: ${v.baselineCacheStatus || "none"}, Age: ${v.baselineAge ?? "none"}\nEncoded path: ${v.encodedPath} → Cache: ${v.cacheStatus || "none"}, Age: ${v.age ?? "none"}\nSame content served under different cache keys`,
      remediation: "Configure your CDN to normalize URL encoding before computing cache keys. Most CDNs (Cloudflare, Fastly, Akamai) have URL normalization settings that should be enabled.",
      cwe: "CWE-436",
    });
  }

  // Phase 9: Fat GET poisoning — test if body content in GET requests affects cached responses
  const fatGetBodyResults = await Promise.allSettled(
    [...baselines.entries()].slice(0, 3).map(async ([url, baseline]) => {
      const res = await scanFetch(url, {
        method: "GET",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "admin=true&role=admin",
        timeoutMs: 5000,
      });
      const body = await res.text();
      // Check if the body parameter influenced the response
      if (
        res.status !== baseline.status ||
        (body !== baseline.body &&
          Math.abs(body.length - baseline.body.length) / Math.max(body.length, baseline.body.length) > 0.2)
      ) {
        return {
          url,
          pathname: new URL(url).pathname,
          baseStatus: baseline.status,
          bodyStatus: res.status,
          baseLen: baseline.body.length,
          bodyLen: body.length,
        };
      }
      return null;
    }),
  );

  for (const r of fatGetBodyResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `cache-fat-get-body-${count++}`,
      module: "cache-poisoning",
      severity: "medium",
      title: `Fat GET poisoning: body content affects response on ${v.pathname}`,
      description: `Sending a body with a GET request to ${v.pathname} changes the response (status ${v.baseStatus} → ${v.bodyStatus}, length ${v.baseLen} → ${v.bodyLen}). CDNs typically ignore the request body when computing cache keys for GET requests, allowing an attacker to poison the cache with a response influenced by arbitrary body parameters.`,
      evidence: `GET ${v.url} → ${v.baseStatus} (${v.baseLen} bytes)\nGET ${v.url} with body "admin=true&role=admin" → ${v.bodyStatus} (${v.bodyLen} bytes)`,
      remediation: "Ensure your application ignores request bodies on GET requests. Configure your framework to reject GET requests with bodies, or ensure the CDN includes the request body hash in the cache key.",
      cwe: "CWE-444",
      codeSnippet: `// middleware.ts — reject GET requests with bodies\nexport function middleware(req: NextRequest) {\n  if (req.method === "GET" && req.headers.get("content-length") !== "0" && req.headers.get("content-length") !== null) {\n    return NextResponse.json({ error: "GET requests must not have a body" }, { status: 400 });\n  }\n}`,
    });
  }

  // Phase 10: Cache poisoning via unkeyed scheme/protocol headers
  const schemeHeaders = [
    { name: "X-Forwarded-Scheme", value: "http", desc: "forwarded scheme" },
    { name: "X-Forwarded-Proto", value: "http", desc: "forwarded protocol" },
    { name: "X-Original-URL", value: "/admin/config", desc: "original URL override" },
  ];

  const schemePoisonResults = await Promise.allSettled(
    [...baselines.entries()].slice(0, 3).flatMap(([url, baseline]) =>
      schemeHeaders.map(async (header) => {
        const res = await scanFetch(url, {
          headers: { [header.name]: header.value },
          timeoutMs: 5000,
        });
        const body = await res.text();
        const resHeaders: Record<string, string> = {};
        res.headers.forEach((v, k) => { resHeaders[k] = v; });
        const pathname = new URL(url).pathname;

        // Check for redirect to HTTP (downgrade)
        if (
          (header.name === "X-Forwarded-Scheme" || header.name === "X-Forwarded-Proto") &&
          (res.status === 301 || res.status === 302)
        ) {
          const location = res.headers.get("location") || "";
          if (location.startsWith("http://")) {
            return {
              pathname,
              header: header.name,
              value: header.value,
              desc: header.desc,
              type: "redirect-downgrade" as const,
              location,
              status: res.status,
            };
          }
        }

        // Check for X-Original-URL serving different content
        if (header.name === "X-Original-URL" && res.status === 200 && body !== baseline.body) {
          const similarity = Math.abs(body.length - baseline.body.length) / Math.max(body.length, baseline.body.length);
          if (similarity > 0.3) {
            return {
              pathname,
              header: header.name,
              value: header.value,
              desc: header.desc,
              type: "content-override" as const,
              status: res.status,
              bodyLen: body.length,
              baselineLen: baseline.body.length,
            };
          }
        }
        return null;
      }),
    ),
  );

  const schemeFlagged = new Set<string>();
  for (const r of schemePoisonResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.header}`;
    if (schemeFlagged.has(key)) continue;
    schemeFlagged.add(key);

    if (v.type === "redirect-downgrade") {
      findings.push({
        id: `cache-scheme-poison-${count++}`,
        module: "cache-poisoning",
        severity: "high",
        title: `Cache poisoning via ${v.header}: HTTPS downgrade on ${v.pathname}`,
        description: `Setting ${v.header}: ${v.value} causes a ${v.status} redirect to ${v.location}. If the CDN does not include ${v.header} in the cache key, an attacker can poison the cache so all users are redirected from HTTPS to HTTP, enabling man-in-the-middle attacks.`,
        evidence: `GET ${v.pathname} with ${v.header}: ${v.value} → ${v.status} redirect to ${v.location}`,
        remediation: `Strip ${v.header} at the CDN/proxy edge. Never use it to determine the request scheme. Add Vary: ${v.header} if the header must be honored.`,
        cwe: "CWE-444",
        codeSnippet: `// next.config.ts — force HTTPS without relying on X-Forwarded-Scheme\nexport default {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n      { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }\n    ]}];\n  },\n};`,
      });
    } else if (v.type === "content-override") {
      findings.push({
        id: `cache-original-url-poison-${count++}`,
        module: "cache-poisoning",
        severity: "high",
        title: `Cache poisoning via ${v.header} on ${v.pathname}`,
        description: `The ${v.header}: ${v.value} header caused different content to be served (${v.baselineLen} → ${v.bodyLen} bytes). If this header is unkeyed by the CDN, an attacker can poison the cache to serve admin or internal pages under public URLs.`,
        evidence: `GET ${v.pathname} with ${v.header}: ${v.value} → ${v.status}\nBaseline: ${v.baselineLen} bytes, Poisoned: ${v.bodyLen} bytes`,
        remediation: `Block ${v.header} at your reverse proxy. This header should not be forwarded to the application.`,
        cwe: "CWE-444",
      });
    }
  }

  // Phase 11: Parameter cloaking — test if special characters in URL parameters hide them from cache keys
  const cloakingPayloads = [
    { param: "utm_content", separator: ";", desc: "semicolon separator" },
    { param: "utm_content", separator: "%26", desc: "encoded ampersand" },
    { param: "callback", separator: "%3B", desc: "encoded semicolon" },
  ];

  const cloakResults = await Promise.allSettled(
    [...baselines.entries()].slice(0, 3).flatMap(([url, baseline]) => {
      const parsed = new URL(url);
      return cloakingPayloads.map(async (payload) => {
        // Construct URL with parameter cloaking: append param using alternative separator
        const cloakedUrl = `${url}${parsed.search ? "&" : "?"}${payload.param}=${payload.separator}vibeshield_cloak=<script>alert(1)</script>`;
        const res = await scanFetch(cloakedUrl, { timeoutMs: 5000 });
        const body = await res.text();

        // Check if the cloaked parameter value appears in the response
        if (
          body.includes("vibeshield_cloak") ||
          body.includes("<script>alert(1)</script>")
        ) {
          if (
            !baseline.body.includes("vibeshield_cloak") &&
            !baseline.body.includes("<script>alert(1)</script>")
          ) {
            return {
              pathname: parsed.pathname,
              separator: payload.desc,
              reflected: body.includes("<script>alert(1)</script>") ? "script tag reflected" : "parameter name reflected",
              status: res.status,
            };
          }
        }
        return null;
      });
    }),
  );

  for (const r of cloakResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `cache-param-cloak-${count++}`,
      module: "cache-poisoning",
      severity: "high",
      title: `Parameter cloaking via ${v.separator} on ${v.pathname}`,
      description: `A cloaked parameter using ${v.separator} was reflected in the response (${v.reflected}). CDNs may parse URL parameters differently than the origin server — the CDN may ignore the cloaked parameter when computing the cache key, while the origin processes it. This enables cache poisoning with XSS payloads.`,
      evidence: `GET ${v.pathname} with cloaked parameter via ${v.separator} → ${v.status}\n${v.reflected}`,
      remediation: "Normalize URL parameter parsing at the CDN and origin to use the same separator. Strip or reject requests containing semicolons or encoded ampersands in query strings. Sanitize all reflected parameters.",
      cwe: "CWE-79",
      codeSnippet: `// middleware.ts — reject requests with parameter cloaking attempts\nexport function middleware(req: NextRequest) {\n  const url = req.nextUrl;\n  const raw = req.url;\n  // Block semicolons and encoded ampersands in query string\n  if (raw.includes(";") || raw.includes("%3B") || raw.includes("%26")) {\n    return NextResponse.json({ error: "Invalid query format" }, { status: 400 });\n  }\n}`,
    });
  }

  return findings;
};
