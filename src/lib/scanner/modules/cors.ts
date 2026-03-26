import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const makeEvilOrigins = (targetHost: string) => {
  const parts = targetHost.split(".");
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join(".") : targetHost;
  return [
    "https://evil.com",
    "https://attacker.com",
    "null",
    `https://${targetHost}.evil.com`,       // subdomain of attacker (endsWith bypass)
    `https://evil${targetHost}`,            // prefix bypass (includes bypass)
    `https://${targetHost.replace(".", "")}.com`, // dot-stripping bypass
    `https://not${baseDomain}`,             // domain suffix bypass
    `http://${targetHost}`,                 // protocol downgrade
  ];
};

export const corsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const endpoints = [target.url, ...target.apiEndpoints.filter((ep) => !ep.includes("/.well-known/")).slice(0, 5)];
  const targetHost = new URL(target.url).hostname;
  const evilOrigins = makeEvilOrigins(targetHost);
  let wildcardFound = false;
  let reflectFound = false;

  // Phase 1: Test all endpoints for wildcard/reflect in parallel
  const phase1 = await Promise.allSettled(
    endpoints.map(async (endpoint) => {
      const res = await scanFetch(endpoint, { headers: { Origin: "https://evil.com" } });
      return {
        endpoint,
        acao: res.headers.get("access-control-allow-origin"),
        acac: res.headers.get("access-control-allow-credentials"),
      };
    }),
  );

  for (const r of phase1) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, acao, acac } = r.value;

    if (acao === "*" && !wildcardFound) {
      wildcardFound = true;
      findings.push({
        id: `cors-wildcard-${findings.length}`,
        module: "CORS",
        severity: acac === "true" ? "critical" : "medium",
        title: `Wildcard CORS on ${new URL(endpoint).pathname}`,
        description: acac === "true"
          ? "This endpoint allows ANY origin with credentials. Any website can make authenticated requests to this endpoint and read the response — this is a full CORS bypass."
          : "This endpoint allows requests from any origin. While credentials aren't shared, data from this endpoint is readable by any website.",
        evidence: `Access-Control-Allow-Origin: *${acac ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        remediation: "Set Access-Control-Allow-Origin to your specific domain instead of *.",
        cwe: "CWE-942",
        owasp: "A05:2021",
        codeSnippet: `// middleware.ts or API route\nres.headers.set("Access-Control-Allow-Origin", "https://yourdomain.com");\nres.headers.set("Vary", "Origin");`,
      });
    }
  }

  // Phase 2: Test origin reflection with evil origins (only if no wildcard found)
  if (!wildcardFound) {
    // Test all endpoint+origin combos in parallel, take first match
    const reflectTests = await Promise.allSettled(
      endpoints.slice(0, 3).flatMap((endpoint) =>
        evilOrigins.map(async (origin) => {
          const res = await scanFetch(endpoint, { headers: { Origin: origin }, timeoutMs: 5000 });
          const acao = res.headers.get("access-control-allow-origin");
          if (acao !== origin) return null;
          return {
            endpoint,
            origin,
            acac: res.headers.get("access-control-allow-credentials"),
          };
        }),
      ),
    );
    for (const r of reflectTests) {
      if (r.status !== "fulfilled" || !r.value || reflectFound) continue;
      reflectFound = true;
      const { endpoint, origin, acac } = r.value;
      const withCreds = acac === "true";
      const isSubdomainBypass = origin.includes(targetHost) && origin !== `https://${targetHost}`;
      findings.push({
        id: `cors-reflect-${findings.length}`,
        module: "CORS",
        severity: withCreds ? "critical" : "high",
        title: `CORS reflects ${isSubdomainBypass ? "subdomain-spoofed " : ""}Origin${withCreds ? " with credentials" : ""} on ${new URL(endpoint).pathname}`,
        description: withCreds
          ? `This endpoint echoes back any Origin AND allows credentials. Any website can make fully authenticated requests and steal user data.`
          : isSubdomainBypass
            ? `This endpoint trusts origins containing "${targetHost}" (like ${origin}). An attacker can register a domain matching this pattern.`
            : `This endpoint echoes back whatever Origin is sent, including "${origin}". Any website can read responses.`,
        evidence: `Origin: ${origin}\nAccess-Control-Allow-Origin: ${origin}${withCreds ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        remediation: "Validate the Origin header against an exact whitelist of allowed domains.",
        cwe: "CWE-942",
        owasp: "A05:2021",
        codeSnippet: `// middleware.ts\nconst ALLOWED_ORIGINS = ["https://yourdomain.com"];\nconst origin = req.headers.get("origin") || "";\nif (ALLOWED_ORIGINS.includes(origin)) {\n  res.headers.set("Access-Control-Allow-Origin", origin);\n  res.headers.set("Vary", "Origin");\n}`,
      });
    }
  }

  // Phase 3: Vary: Origin check + preflight (parallel)
  const [varyResults, preflightResults] = await Promise.all([
    Promise.allSettled(
      endpoints.slice(0, 5).map(async (endpoint) => {
        const res = await scanFetch(endpoint, { headers: { Origin: `https://${targetHost}` } });
        return {
          endpoint,
          acao: res.headers.get("access-control-allow-origin"),
          vary: res.headers.get("vary") || "",
        };
      }),
    ),
    Promise.allSettled(
      target.apiEndpoints.slice(0, 5).map(async (endpoint) => {
        const res = await scanFetch(endpoint, {
          method: "OPTIONS",
          headers: {
            Origin: "https://evil.com",
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "Authorization",
          },
        });
        return {
          endpoint,
          methods: res.headers.get("access-control-allow-methods") || "",
          allowHeaders: res.headers.get("access-control-allow-headers") || "",
        };
      }),
    ),
  ]);

  let varyFlagged = false;
  for (const r of varyResults) {
    if (r.status !== "fulfilled" || varyFlagged) continue;
    const { endpoint, acao, vary } = r.value;
    if (acao && acao !== "*" && !/\borigin\b/i.test(vary)) {
      varyFlagged = true;
      findings.push({
        id: `cors-no-vary-${findings.length}`,
        module: "CORS",
        severity: "low",
        title: `CORS response missing Vary: Origin on ${new URL(endpoint).pathname}`,
        description: "The server returns a dynamic Access-Control-Allow-Origin but doesn't include Vary: Origin. This allows CDN/proxy cache poisoning.",
        evidence: `Access-Control-Allow-Origin: ${acao}\nVary: ${vary || "(not set)"}`,
        remediation: "Add Vary: Origin to responses with dynamic ACAO headers.",
        cwe: "CWE-942",
        codeSnippet: `// Always include Vary: Origin when ACAO is dynamic\nres.headers.set("Vary", "Origin");`,
      });
    }
  }

  for (const r of preflightResults) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, methods, allowHeaders } = r.value;
    if (/DELETE|PUT|PATCH/i.test(methods)) {
      findings.push({
        id: `cors-dangerous-methods-${findings.length}`,
        module: "CORS",
        severity: "medium",
        title: `CORS allows dangerous methods on ${new URL(endpoint).pathname}`,
        description: `Preflight response allows ${methods}. Cross-origin sites may be able to modify or delete data.`,
        evidence: `Access-Control-Allow-Methods: ${methods}`,
        remediation: "Only allow the HTTP methods that are actually needed.",
        cwe: "CWE-942",
        codeSnippet: `// Only allow needed methods\nres.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");`,
      });
    }
    if (allowHeaders === "*") {
      findings.push({
        id: `cors-wildcard-headers-${findings.length}`,
        module: "CORS",
        severity: "medium",
        title: `CORS allows any request header on ${new URL(endpoint).pathname}`,
        description: "Preflight response allows all request headers via wildcard, permitting cross-origin requests with arbitrary headers.",
        evidence: `Access-Control-Allow-Headers: *`,
        remediation: "Restrict to specific required headers.",
        cwe: "CWE-942",
        codeSnippet: `// Only allow specific headers\nres.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");`,
      });
    }
  }

  // Phase 4: Null origin and max-age checks
  const nullAndMaxAgeTests = await Promise.allSettled(
    endpoints.slice(0, 3).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { headers: { Origin: "null" }, timeoutMs: 5000 });
      return {
        endpoint,
        acao: res.headers.get("access-control-allow-origin"),
        acac: res.headers.get("access-control-allow-credentials"),
        maxAge: res.headers.get("access-control-max-age"),
      };
    }),
  );
  let nullFlagged = false;
  let maxAgeFlagged = false;
  for (const r of nullAndMaxAgeTests) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, acao, acac, maxAge } = r.value;
    if (acao === "null" && !nullFlagged && !reflectFound) {
      nullFlagged = true;
      findings.push({
        id: `cors-null-origin-${findings.length}`,
        module: "CORS",
        severity: acac === "true" ? "critical" : "high",
        title: `CORS accepts null Origin${acac === "true" ? " with credentials" : ""} on ${new URL(endpoint).pathname}`,
        description: `The server trusts the "null" Origin. Sandboxed iframes, data: URIs, and file:// pages send Origin: null — an attacker can use these to bypass CORS and ${acac === "true" ? "make authenticated requests stealing user data" : "read API responses"}.`,
        evidence: `Origin: null\nAccess-Control-Allow-Origin: null${acac === "true" ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        remediation: 'Never allow "null" as an origin. Use a strict allowlist of specific https:// origins.',
        cwe: "CWE-942", owasp: "A05:2021",
        codeSnippet: `// Reject null origin explicitly\nconst origin = req.headers.get("origin") || "";\nif (origin === "null" || !ALLOWED_ORIGINS.includes(origin)) {\n  // Do not set ACAO header — deny the cross-origin request\n  return res;\n}`,
      });
    }
    if (maxAge && parseInt(maxAge) > 86400 && !maxAgeFlagged) {
      maxAgeFlagged = true;
      findings.push({
        id: `cors-max-age-${findings.length}`,
        module: "CORS",
        severity: "low",
        title: `CORS preflight cached for ${Math.round(parseInt(maxAge) / 3600)}h on ${new URL(endpoint).pathname}`,
        description: `Access-Control-Max-Age is set to ${maxAge} seconds (${Math.round(parseInt(maxAge) / 3600)} hours). Overly long preflight caching means CORS policy changes won't take effect for browsers that cached the old preflight.`,
        evidence: `Access-Control-Max-Age: ${maxAge}`,
        remediation: "Set Access-Control-Max-Age to 3600 (1 hour) or less for reasonable cache freshness.",
        cwe: "CWE-942",
        codeSnippet: `// Reasonable preflight cache duration\nres.headers.set("Access-Control-Max-Age", "3600"); // 1 hour`,
      });
    }
  }

  // Phase 5: Check for overly permissive Access-Control-Expose-Headers
  const exposeTests = await Promise.allSettled(
    endpoints.slice(0, 3).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { headers: { Origin: `https://${targetHost}` } });
      return {
        endpoint,
        expose: res.headers.get("access-control-expose-headers") || "",
      };
    }),
  );
  let exposeFlagged = false;
  for (const r of exposeTests) {
    if (r.status !== "fulfilled" || exposeFlagged) continue;
    const { endpoint, expose } = r.value;
    if (expose === "*") {
      exposeFlagged = true;
      findings.push({
        id: `cors-expose-wildcard-${findings.length}`,
        module: "CORS",
        severity: "low",
        title: `CORS exposes all response headers on ${new URL(endpoint).pathname}`,
        description: "Access-Control-Expose-Headers: * allows cross-origin JavaScript to read any response header, potentially leaking internal headers like X-Request-Id, X-RateLimit-Remaining, or custom auth headers.",
        evidence: `Access-Control-Expose-Headers: *`,
        remediation: "Only expose the specific response headers that cross-origin clients need.",
        cwe: "CWE-942",
        codeSnippet: `// Only expose specific headers\nres.headers.set("Access-Control-Expose-Headers", "Content-Length, X-Request-Id");`,
      });
    }
  }

  // Phase 6: Null origin bypass testing (sandboxed iframes, data: URIs, file:// pages)
  const nullOriginResults = await Promise.allSettled(
    endpoints.slice(0, 3).map(async (endpoint) => {
      const res = await scanFetch(endpoint, { headers: { Origin: "null" } });
      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");
      return { endpoint, acao, acac };
    }),
  );
  for (const r of nullOriginResults) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, acao, acac } = r.value;
    if (acao === "null" && acac?.toLowerCase() === "true") {
      findings.push({
        id: `cors-null-origin-${findings.length}`,
        module: "CORS",
        severity: "high",
        title: `CORS accepts null origin with credentials on ${new URL(endpoint).pathname}`,
        description: "The endpoint accepts Origin: null and responds with Access-Control-Allow-Credentials: true. Attackers can use sandboxed iframes (which send Origin: null) to make authenticated cross-origin requests and steal data.",
        evidence: `Origin: null\nACAO: null\nACAC: true`,
        remediation: "Never reflect 'null' as an allowed origin. Maintain an explicit allowlist of trusted origins.",
        cwe: "CWE-942",
        owasp: "A01:2021",
        confidence: 95,
        codeSnippet: `// Reject null origin\nconst ALLOWED = new Set(["https://yourdomain.com"]);\nconst origin = req.headers.get("origin");\nif (origin && ALLOWED.has(origin)) {\n  res.headers.set("Access-Control-Allow-Origin", origin);\n}`,
      });
      break;
    }
  }

  // Phase 7: Subdomain wildcard CORS bypass
  // Test multiple subdomain patterns to detect overly permissive regex/endsWith checks
  const subdomainOrigins = [
    `https://evil.${targetHost}`,                    // arbitrary subdomain
    `https://test.staging.${targetHost}`,            // nested subdomain
    `https://${targetHost}.attacker.com`,            // target as subdomain of attacker
  ];
  const subdomainResults = await Promise.allSettled(
    subdomainOrigins.map(async (origin) => {
      const res = await scanFetch(endpoints[0] || target.url, { headers: { Origin: origin } });
      return {
        origin,
        acao: res.headers.get("access-control-allow-origin"),
        acac: res.headers.get("access-control-allow-credentials"),
      };
    }),
  );
  let subdomainFlagged = false;
  for (const r of subdomainResults) {
    if (r.status !== "fulfilled" || subdomainFlagged) continue;
    const { origin, acao, acac } = r.value;
    if (acao === origin) {
      subdomainFlagged = true;
      const withCreds = acac === "true";
      const isAttackerSubdomain = origin.includes(`${targetHost}.`);
      findings.push({
        id: `cors-subdomain-reflect-${findings.length}`,
        module: "CORS",
        severity: withCreds ? "high" : "medium",
        title: isAttackerSubdomain
          ? `CORS trusts target hostname as subdomain prefix (${origin})`
          : `CORS reflects arbitrary subdomain origins (*.${targetHost})`,
        description: isAttackerSubdomain
          ? `The server accepts "${origin}" as a valid origin, suggesting it uses a naive contains/endsWith check. An attacker can register this domain to bypass CORS.`
          : `The server accepts any subdomain as a valid origin (${origin}). If an attacker can control or compromise any subdomain (via XSS, subdomain takeover, or dangling DNS), they can bypass CORS restrictions and steal data.`,
        evidence: `Origin: ${origin}\nACAO: ${acao}${withCreds ? "\nACAC: true" : ""}`,
        remediation: "Don't blindly trust all subdomains. Maintain an explicit allowlist of trusted origins. Validate using exact string matching, not endsWith/includes.",
        cwe: "CWE-942",
        owasp: "A05:2021",
        confidence: isAttackerSubdomain ? 95 : 85,
      });
    }
  }

  // Phase 8: Pre-flight request manipulation — custom headers, non-standard methods
  const preflightManipTests = await Promise.allSettled(
    endpoints.slice(0, 3).map(async (endpoint) => {
      const [customHeaderRes, traceRes] = await Promise.all([
        scanFetch(endpoint, {
          method: "OPTIONS",
          headers: {
            Origin: "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Custom-Header, X-Debug, X-Forwarded-For, X-Original-URL",
          },
        }),
        scanFetch(endpoint, {
          method: "OPTIONS",
          headers: {
            Origin: "https://evil.com",
            "Access-Control-Request-Method": "TRACE",
          },
        }),
      ]);
      return {
        endpoint,
        customAllowHeaders: customHeaderRes.headers.get("access-control-allow-headers") || "",
        traceAllowMethods: traceRes.headers.get("access-control-allow-methods") || "",
      };
    }),
  );
  let customHeaderFlagged = false;
  let traceFlagged = false;
  for (const r of preflightManipTests) {
    if (r.status !== "fulfilled") continue;
    const { endpoint, customAllowHeaders, traceAllowMethods } = r.value;
    // Check if dangerous internal headers are allowed cross-origin
    const dangerousHeaders = ["x-forwarded-for", "x-original-url", "x-debug"];
    const allowedDangerous = dangerousHeaders.filter((h) =>
      customAllowHeaders.toLowerCase().includes(h) || customAllowHeaders === "*",
    );
    if (allowedDangerous.length > 0 && !customHeaderFlagged) {
      customHeaderFlagged = true;
      findings.push({
        id: `cors-dangerous-request-headers-${findings.length}`,
        module: "CORS",
        severity: "medium",
        title: `CORS allows dangerous request headers on ${new URL(endpoint).pathname}`,
        description: `Preflight response permits cross-origin requests with headers: ${allowedDangerous.join(", ")}. These headers can be used for IP spoofing (X-Forwarded-For), URL rewriting (X-Original-URL), or enabling debug modes.`,
        evidence: `Access-Control-Request-Headers: X-Custom-Header, X-Debug, X-Forwarded-For, X-Original-URL\nAccess-Control-Allow-Headers: ${customAllowHeaders}`,
        remediation: "Restrict Access-Control-Allow-Headers to only the headers your API actually uses. Never allow internal proxy headers like X-Forwarded-For cross-origin.",
        cwe: "CWE-942",
        owasp: "A05:2021",
        codeSnippet: `// Only allow specific safe headers\nres.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");`,
      });
    }
    // Check if TRACE method is allowed (enables XST attacks)
    if (/TRACE/i.test(traceAllowMethods) && !traceFlagged) {
      traceFlagged = true;
      findings.push({
        id: `cors-trace-method-${findings.length}`,
        module: "CORS",
        severity: "high",
        title: `CORS allows TRACE method on ${new URL(endpoint).pathname}`,
        description: "The server allows the TRACE HTTP method via CORS preflight. TRACE reflects the full request back in the response body, including cookies and auth headers. Combined with CORS, this enables Cross-Site Tracing (XST) attacks to steal credentials.",
        evidence: `Access-Control-Allow-Methods: ${traceAllowMethods}`,
        remediation: "Never allow TRACE in CORS preflight responses. Disable the TRACE method entirely on your server.",
        cwe: "CWE-693",
        owasp: "A05:2021",
        codeSnippet: `// Disable TRACE and only allow needed methods\nres.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");`,
      });
    }
  }

  // Phase 9: CORS credential leak — wildcard origin with credentials
  // This is a spec violation (browsers block it), but misconfigured servers may still send it
  if (wildcardFound) {
    const credLeakResults = await Promise.allSettled(
      endpoints.slice(0, 3).map(async (endpoint) => {
        const res = await scanFetch(endpoint, {
          headers: { Origin: "https://evil.com", Cookie: "test=1" },
        });
        return {
          endpoint,
          acao: res.headers.get("access-control-allow-origin"),
          acac: res.headers.get("access-control-allow-credentials"),
        };
      }),
    );
    let credLeakFlagged = false;
    for (const r of credLeakResults) {
      if (r.status !== "fulfilled" || credLeakFlagged) continue;
      const { endpoint, acao, acac } = r.value;
      if (acao === "*" && acac === "true") {
        credLeakFlagged = true;
        findings.push({
          id: `cors-wildcard-credentials-${findings.length}`,
          module: "CORS",
          severity: "critical",
          title: `CORS wildcard with credentials on ${new URL(endpoint).pathname}`,
          description: "The server sends Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true. While modern browsers reject this combination per spec, older browsers or non-browser HTTP clients can exploit it. This indicates a fundamental CORS misconfiguration that should be fixed regardless.",
          evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
          remediation: "Never combine wildcard origin with credentials. Use a specific origin allowlist when credentials are needed.",
          cwe: "CWE-942",
          owasp: "A05:2021",
          confidence: 100,
          codeSnippet: `// Use specific origin with credentials\nconst ALLOWED = new Set(["https://yourdomain.com"]);\nconst origin = req.headers.get("origin") || "";\nif (ALLOWED.has(origin)) {\n  res.headers.set("Access-Control-Allow-Origin", origin);\n  res.headers.set("Access-Control-Allow-Credentials", "true");\n  res.headers.set("Vary", "Origin");\n}`,
        });
      }
    }
  }

  // Phase 10: Internal network CORS probing
  // Test if the server reflects origins pointing to internal/private networks
  const internalOrigins = [
    "https://localhost",
    "https://127.0.0.1",
    "http://localhost:3000",
    "http://localhost:8080",
    "https://10.0.0.1",
    "https://192.168.1.1",
    "https://172.16.0.1",
    "https://intranet.local",
    "https://admin.internal",
  ];
  const internalResults = await Promise.allSettled(
    internalOrigins.map(async (origin) => {
      const res = await scanFetch(endpoints[0] || target.url, {
        headers: { Origin: origin },
        timeoutMs: 5000,
      });
      return {
        origin,
        acao: res.headers.get("access-control-allow-origin"),
        acac: res.headers.get("access-control-allow-credentials"),
      };
    }),
  );
  let internalFlagged = false;
  const reflectedInternalOrigins: string[] = [];
  for (const r of internalResults) {
    if (r.status !== "fulfilled") continue;
    const { origin, acao, acac } = r.value;
    if (acao === origin) {
      reflectedInternalOrigins.push(`${origin}${acac === "true" ? " (+credentials)" : ""}`);
    }
  }
  if (reflectedInternalOrigins.length > 0 && !internalFlagged) {
    internalFlagged = true;
    const hasCreds = reflectedInternalOrigins.some((o) => o.includes("+credentials"));
    findings.push({
      id: `cors-internal-network-${findings.length}`,
      module: "CORS",
      severity: hasCreds ? "high" : "medium",
      title: `CORS allows ${reflectedInternalOrigins.length} internal/private network origin${reflectedInternalOrigins.length > 1 ? "s" : ""}`,
      description: `The server reflects internal network origins in Access-Control-Allow-Origin. If this is a production server, it should not trust localhost, private IPs, or .local/.internal domains. An attacker on the local network or with SSRF access could exploit this to read responses.`,
      evidence: `Reflected internal origins:\n${reflectedInternalOrigins.join("\n")}`,
      remediation: "Remove localhost, private IP ranges (10.x, 172.16.x, 192.168.x), and internal domains from your CORS allowlist in production.",
      cwe: "CWE-942",
      owasp: "A05:2021",
      confidence: 80,
      codeSnippet: `// Only allow production origins\nconst ALLOWED_ORIGINS = [\n  "https://yourdomain.com",\n  "https://app.yourdomain.com",\n];\n// Never include localhost or internal IPs in production`,
    });
  }

  // Phase 11: CORS cache poisoning via Vary header absence
  // More thorough check: test multiple origins and see if Vary is consistently missing
  const cachePoisonResults = await Promise.allSettled(
    endpoints.slice(0, 3).map(async (endpoint) => {
      const [res1, res2] = await Promise.all([
        scanFetch(endpoint, { headers: { Origin: `https://${targetHost}` } }),
        scanFetch(endpoint, { headers: { Origin: "https://other-domain.com" } }),
      ]);
      return {
        endpoint,
        acao1: res1.headers.get("access-control-allow-origin"),
        acao2: res2.headers.get("access-control-allow-origin"),
        vary1: res1.headers.get("vary") || "",
        vary2: res2.headers.get("vary") || "",
        cacheControl: res1.headers.get("cache-control") || "",
      };
    }),
  );
  let cachePoisonFlagged = false;
  for (const r of cachePoisonResults) {
    if (r.status !== "fulfilled" || cachePoisonFlagged) continue;
    const { endpoint, acao1, acao2, vary1, cacheControl } = r.value;
    // Only flag if ACAO is dynamic (different for different origins) AND cacheable AND no Vary: Origin
    const isDynamic = acao1 && acao2 && acao1 !== acao2;
    const isCacheable = !cacheControl.includes("no-store") && !cacheControl.includes("private");
    const missingVary = !/\borigin\b/i.test(vary1);
    if (isDynamic && isCacheable && missingVary) {
      cachePoisonFlagged = true;
      findings.push({
        id: `cors-cache-poisoning-${findings.length}`,
        module: "CORS",
        severity: "medium",
        title: `CORS cache poisoning risk on ${new URL(endpoint).pathname}`,
        description: "The server returns different Access-Control-Allow-Origin values for different Origin requests, but does not include Vary: Origin and the response is cacheable. A CDN or proxy cache could serve a CORS response intended for one origin to a different origin, enabling cross-origin data theft.",
        evidence: `ACAO varies by Origin but Vary: Origin is missing\nCache-Control: ${cacheControl || "(not set)"}\nVary: ${vary1 || "(not set)"}`,
        remediation: "Add Vary: Origin to all responses with dynamic ACAO headers. Alternatively, set Cache-Control: private or no-store.",
        cwe: "CWE-525",
        owasp: "A05:2021",
        confidence: 85,
        codeSnippet: `// Prevent CORS cache poisoning\nres.headers.set("Vary", "Origin");\n// Or make response non-cacheable:\nres.headers.set("Cache-Control", "private, no-store");`,
      });
    }
  }

  return findings;
};
