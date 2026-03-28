import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

const ERROR_PATTERNS = [
  /stack.*trace/i,
  /at [\w.]+\([\w/.]+:\d+:\d+\)/,
  /Traceback/i,
  /ECONNREFUSED/i,
  /ECONNRESET/i,
  /ETIMEDOUT/i,
  /pool.*exhaust/i,
  /too many connections/i,
  /connection.*refused/i,
  /database.*unavailable/i,
  /internal server error/i,
  /out of memory/i,
  /heap.*limit/i,
  /ENOMEM/i,
  /MaxListenersExceeded/i,
  /socket hang up/i,
];

const SENSITIVE_PATTERNS = [
  { pattern: /postgres:\/\/[^\s"']+/i, type: "Database connection string" },
  { pattern: /mongodb(\+srv)?:\/\/[^\s"']+/i, type: "MongoDB connection string" },
  { pattern: /redis:\/\/[^\s"']+/i, type: "Redis connection string" },
  { pattern: /\/home\/\w+\//i, type: "Server file path" },
  { pattern: /\/var\/www\//i, type: "Server file path" },
  { pattern: /\/app\/node_modules/i, type: "Node.js module path" },
  { pattern: /process\.env\.\w+/i, type: "Environment variable reference" },
];

// Framework/version disclosure patterns in error bodies
const FRAMEWORK_PATTERNS = [
  { pattern: /Express\s*[\d.]+/i, type: "Express version" },
  { pattern: /Next\.js\s*[\d.]+/i, type: "Next.js version" },
  { pattern: /Django\s*[\d.]+/i, type: "Django version" },
  { pattern: /Rails\s*[\d.]+/i, type: "Rails version" },
  { pattern: /Laravel\s*[\d.]+/i, type: "Laravel version" },
  { pattern: /Flask\s*[\d.]+/i, type: "Flask version" },
  { pattern: /Spring\s*Boot\s*[\d.]+/i, type: "Spring Boot version" },
  { pattern: /ASP\.NET\s*[\d.]+/i, type: "ASP.NET version" },
  { pattern: /node[\s/]v?\d+\.\d+/i, type: "Node.js version" },
  { pattern: /Python\/\d+\.\d+/i, type: "Python version" },
  { pattern: /PHP\/\d+\.\d+/i, type: "PHP version" },
  { pattern: /Apache\/\d+\.\d+/i, type: "Apache version" },
  { pattern: /nginx\/\d+\.\d+/i, type: "Nginx version" },
];

// Debug mode indicators
const DEBUG_INDICATORS = [
  { param: "debug", value: "true" },
  { param: "debug", value: "1" },
  { param: "NODE_ENV", value: "development" },
  { param: "DJANGO_DEBUG", value: "true" },
  { param: "verbose", value: "true" },
  { param: "trace", value: "true" },
];

export const errorLeakModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Phase 1: Hammer endpoints to trigger error states
  const endpoints = [target.url, ...target.apiEndpoints.slice(0, 5)];

  for (const endpoint of endpoints) {
    const N = 30;
    const results = await Promise.allSettled(
      Array.from({ length: N }, async () => {
        const res = await scanFetch(endpoint, { timeoutMs: 10000 });
        return { status: res.status, body: await res.text() };
      }),
    );

    for (const r of results) {
      if (r.status !== "fulfilled") continue;
      const { status, body } = r.value;

      if (status >= 500 && body.length > 200) {
        for (const pattern of ERROR_PATTERNS) {
          if (pattern.test(body)) {
            findings.push({
              id: `errorleak-under-stress-${findings.length}`,
              module: "Error Leakage Under Stress",
              severity: "medium",
              title: `Verbose errors under load on ${new URL(endpoint).pathname}`,
              description: "When the server is under stress, error responses contain internal details like stack traces or connection errors. These reveal your infrastructure.",
              evidence: `Endpoint: ${endpoint}\nStatus: ${status}\nMatched: ${pattern.source}\nExcerpt: ${body.substring(0, 400)}`,
              remediation: "Implement a global error handler that catches all errors and returns generic 500 responses in production. Log details server-side only.",
              codeSnippet: `// app/api/[...route]/route.ts — wrap handlers with error boundary
function withErrorHandler(handler: Function) {
  return async (req: Request) => {
    try {
      return await handler(req);
    } catch (err) {
      console.error("Internal error:", err); // log server-side only
      return Response.json(
        { error: "Internal server error" },
        { status: 500 }
      );
    }
  };
}

export const POST = withErrorHandler(async (req: Request) => {
  // your handler logic
});`,
              cwe: "CWE-209",
            });
            break;
          }
        }

        for (const { pattern, type } of SENSITIVE_PATTERNS) {
          const match = body.match(pattern);
          if (match) {
            findings.push({
              id: `errorleak-sensitive-${findings.length}`,
              module: "Error Leakage Under Stress",
              severity: "high",
              title: `${type} leaked in error response on ${new URL(endpoint).pathname}`,
              description: `Under stress, the server leaked a ${type.toLowerCase()} in its error response. This only appears when the server is overloaded, making it hard to catch in testing.`,
              evidence: `Found: ${match[0].substring(0, 100)}...\nStatus: ${status}`,
              remediation: "Add a global error handler that sanitizes all error responses. Never include connection strings or file paths in responses.",
              codeSnippet: `// Sanitize all error output — strip connection strings and paths
function sanitizeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return msg
    .replace(/(postgres|mongodb|redis):\\/\\/[^\\s"']+/gi, "[REDACTED_URI]")
    .replace(/\\/home\\/\\w+\\//g, "[REDACTED_PATH]/")
    .replace(/\\/var\\/www\\//g, "[REDACTED_PATH]/")
    .replace(/process\\.env\\.\\w+/g, "[REDACTED_ENV]");
}`,
              cwe: "CWE-209",
              owasp: "A05:2021",
            });
          }
        }
      }
    }
  }

  // Phase 2: Test error responses with different Accept headers
  const acceptHeaders: { accept: string; label: string }[] = [
    { accept: "text/html", label: "HTML" },
    { accept: "application/json", label: "JSON" },
    { accept: "application/xml", label: "XML" },
    { accept: "text/plain", label: "Plain text" },
    { accept: "*/*", label: "Wildcard" },
  ];

  for (const endpoint of target.apiEndpoints.slice(0, 3)) {
    const badUrl = `${endpoint}/nonexistent-path-${Date.now()}`;
    const acceptChecks = acceptHeaders.map(async ({ accept, label }) => {
      try {
        const res = await scanFetch(badUrl, {
          headers: { "Accept": accept },
          timeoutMs: 8000,
          noCache: true,
        });
        const body = await res.text();
        return { accept, label, status: res.status, body, bodyLength: body.length };
      } catch {
        return null;
      }
    });

    const acceptResults = await Promise.allSettled(acceptChecks);
    const verboseAcceptTypes: string[] = [];

    for (const r of acceptResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const { label, status, body } = r.value;
      if (status >= 400 && body.length > 500) {
        // Check if error body contains stack traces or sensitive info depending on Accept header
        const hasStackTrace = /at [\w.]+\([\w/.]+:\d+:\d+\)/.test(body) || /Traceback/i.test(body);
        const hasSensitive = SENSITIVE_PATTERNS.some(({ pattern }) => pattern.test(body));
        if (hasStackTrace || hasSensitive) {
          verboseAcceptTypes.push(label);
        }
      }
    }

    if (verboseAcceptTypes.length > 0) {
      findings.push({
        id: `errorleak-accept-header-${findings.length}`,
        module: "Error Leakage Under Stress",
        severity: "medium",
        title: `Verbose error details leak via Accept header on ${new URL(endpoint).pathname}`,
        description: `Error responses contain stack traces or sensitive information when requested with certain Accept headers (${verboseAcceptTypes.join(", ")}). Different content types may expose different levels of detail in error responses.`,
        evidence: `Endpoint: ${badUrl}\nVerbose error for Accept types: ${verboseAcceptTypes.join(", ")}`,
        remediation: "Ensure error responses are sanitized regardless of the Accept header. Use content negotiation only for the response format, not the verbosity level.",
        cwe: "CWE-209",
        confidence: 75,
      });
    }
  }

  // Phase 3: Test stack trace exposure under concurrent load
  for (const endpoint of target.apiEndpoints.slice(0, 3)) {
    const concurrencyLevels = [10, 50];
    let stackTraceAtHighLoad = false;
    let stackTraceAtLowLoad = false;

    for (const concurrency of concurrencyLevels) {
      const results = await Promise.allSettled(
        Array.from({ length: concurrency }, async () => {
          try {
            const res = await scanFetch(endpoint, { timeoutMs: 10000, noCache: true });
            const body = await res.text();
            return { status: res.status, body };
          } catch {
            return null;
          }
        }),
      );

      for (const r of results) {
        if (r.status !== "fulfilled" || !r.value) continue;
        const { status, body } = r.value;
        if (status >= 500 && /at [\w.]+\([\w/.]+:\d+:\d+\)/.test(body)) {
          if (concurrency === 10) stackTraceAtLowLoad = true;
          if (concurrency === 50) stackTraceAtHighLoad = true;
        }
      }
    }

    if (stackTraceAtHighLoad && !stackTraceAtLowLoad) {
      findings.push({
        id: `errorleak-stack-under-load-${findings.length}`,
        module: "Error Leakage Under Stress",
        severity: "high",
        title: `Stack traces only exposed under high concurrency on ${new URL(endpoint).pathname}`,
        description: "Stack traces appear in error responses only under high concurrent load (50 requests), not at lower levels (10 requests). This indicates the error handler breaks down under pressure, possibly due to connection pool exhaustion or memory pressure.",
        evidence: `Endpoint: ${endpoint}\nStack trace at 10 concurrent: No\nStack trace at 50 concurrent: Yes`,
        remediation: "Wrap all error handling in a failsafe that returns generic errors even when the primary error handler fails. Test error handling under load.",
        cwe: "CWE-209",
        confidence: 80,
      });
    }
  }

  // Phase 4: Test database error message leakage (connection pool exhaustion)
  const dbEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(api|data|query|db|users|items|posts|orders)\b/i.test(ep),
  ).slice(0, 3);

  if (dbEndpoints.length > 0) {
    const dbErrorPatterns = [
      /pool.*exhaust/i,
      /too many connections/i,
      /connection.*timeout/i,
      /ECONNREFUSED.*5432/i,  // PostgreSQL default port
      /ECONNREFUSED.*3306/i,  // MySQL default port
      /ECONNREFUSED.*27017/i, // MongoDB default port
      /max_connections/i,
      /remaining connection slots/i,
      /SequelizeConnectionError/i,
      /PrismaClientKnownRequestError/i,
      /MongoServerError/i,
    ];

    for (const endpoint of dbEndpoints) {
      // Flood the endpoint to exhaust database connections
      const N = 50;
      const results = await Promise.allSettled(
        Array.from({ length: N }, async () => {
          try {
            const res = await scanFetch(endpoint, { timeoutMs: 12000, noCache: true });
            const body = await res.text();
            return { status: res.status, body };
          } catch {
            return null;
          }
        }),
      );

      for (const r of results) {
        if (r.status !== "fulfilled" || !r.value) continue;
        const { status, body } = r.value;
        if (status >= 500) {
          for (const pattern of dbErrorPatterns) {
            if (pattern.test(body)) {
              findings.push({
                id: `errorleak-db-${findings.length}`,
                module: "Error Leakage Under Stress",
                severity: "high",
                title: `Database error leaked under load on ${new URL(endpoint).pathname}`,
                description: `Under ${N} concurrent requests, the server exposed database connection details in error responses. This reveals database technology, connection configuration, and potentially connection string information.`,
                evidence: `Endpoint: ${endpoint}\nStatus: ${status}\nMatched: ${pattern.source}\nExcerpt: ${body.substring(0, 300)}`,
                remediation: "1. Catch all database errors and return generic responses\n2. Configure connection pool limits with proper timeouts\n3. Use a circuit breaker pattern for database access\n4. Monitor connection pool usage and alert before exhaustion",
                codeSnippet: `// Wrap database calls with a circuit breaker
import { CircuitBreaker } from "opossum";

const dbBreaker = new CircuitBreaker(queryDatabase, {
  timeout: 5000,
  errorThresholdPercentage: 50,
  resetTimeout: 10000,
});

dbBreaker.fallback(() => {
  return Response.json({ error: "Service temporarily unavailable" }, { status: 503 });
});`,
                cwe: "CWE-209",
                owasp: "A05:2021",
                confidence: 85,
              });
              break;
            }
          }
        }
      }
    }
  }

  // Phase 5: Test verbose error mode detection (debug=true, NODE_ENV=development)
  for (const endpoint of endpoints.slice(0, 4)) {
    const debugChecks = DEBUG_INDICATORS.map(async ({ param, value }) => {
      try {
        const testUrl = new URL(endpoint);
        testUrl.searchParams.set(param, value);
        const res = await scanFetch(testUrl.href, { timeoutMs: 8000, noCache: true });
        const body = await res.text();

        // Also try as a header
        const headerRes = await scanFetch(endpoint, {
          headers: { [`X-${param}`]: value },
          timeoutMs: 8000,
          noCache: true,
        });
        const headerBody = await headerRes.text();

        return { param, value, queryBody: body, queryStatus: res.status, headerBody, headerStatus: headerRes.status };
      } catch {
        return null;
      }
    });

    const debugResults = await Promise.allSettled(debugChecks);
    for (const r of debugResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const { param, value, queryBody, queryStatus, headerBody, headerStatus } = r.value;

      // Check if setting debug param reveals more info than normal
      const queryHasDebug = /stack.*trace|stackTrace|debug_info|debugInfo|Traceback|at [\w.]+\(/i.test(queryBody);
      const headerHasDebug = /stack.*trace|stackTrace|debug_info|debugInfo|Traceback|at [\w.]+\(/i.test(headerBody);

      if (queryHasDebug || headerHasDebug) {
        const via = queryHasDebug ? `?${param}=${value}` : `X-${param}: ${value} header`;
        findings.push({
          id: `errorleak-debug-mode-${findings.length}`,
          module: "Error Leakage Under Stress",
          severity: "high",
          title: `Debug/verbose mode activatable via ${via} on ${new URL(endpoint).pathname}`,
          description: `Setting ${via} causes the server to return verbose debug information including stack traces or internal details. An attacker can use this to map your application internals.`,
          evidence: `Endpoint: ${endpoint}\nTrigger: ${via}\nStatus: ${queryHasDebug ? queryStatus : headerStatus}\nBody excerpt: ${(queryHasDebug ? queryBody : headerBody).substring(0, 300)}`,
          remediation: "1. Never allow client-controlled parameters to toggle debug mode\n2. Ensure NODE_ENV=production in all deployments\n3. Use environment variables for debug flags, never query parameters\n4. Strip debug middleware in production builds",
          cwe: "CWE-209",
          owasp: "A05:2021",
          confidence: 90,
        });
        break;
      }
    }
  }

  // Phase 6: Test error response timing consistency
  for (const endpoint of target.apiEndpoints.slice(0, 3)) {
    const validPayloads = [
      JSON.stringify({ email: "valid@example.com", password: "password123" }),
      JSON.stringify({ email: "valid@example.com", password: "wrongpassword" }),
    ];
    const invalidPayloads = [
      JSON.stringify({ email: "nonexistent@nowhere.invalid", password: "password123" }),
      JSON.stringify({ email: "", password: "" }),
    ];

    const timingChecks = [...validPayloads, ...invalidPayloads].map(async (payload) => {
      const times: number[] = [];
      for (let i = 0; i < 5; i++) {
        const start = Date.now();
        try {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: payload,
            timeoutMs: 8000,
            noCache: true,
          });
          await res.text();
          times.push(Date.now() - start);
        } catch {
          times.push(Date.now() - start);
        }
      }
      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      return { payload: payload.substring(0, 60), avg };
    });

    const timingResults = await Promise.allSettled(timingChecks);
    const avgTimes = timingResults
      .filter((r) => r.status === "fulfilled")
      .map((r) => (r as PromiseFulfilledResult<{ payload: string; avg: number }>).value);

    if (avgTimes.length >= 3) {
      const allAvgs = avgTimes.map((t) => t.avg);
      const minAvg = Math.min(...allAvgs);
      const maxAvg = Math.max(...allAvgs);
      const timingDiff = maxAvg - minAvg;

      // If there's >500ms difference between fastest and slowest error responses
      if (timingDiff > 500 && minAvg > 0) {
        const ratio = maxAvg / minAvg;
        if (ratio > 2) {
          findings.push({
            id: `errorleak-timing-${findings.length}`,
            module: "Error Leakage Under Stress",
            severity: "medium",
            title: `Inconsistent error timing on ${new URL(endpoint).pathname} (${timingDiff.toFixed(0)}ms variance)`,
            description: `Error responses have inconsistent timing (${minAvg.toFixed(0)}ms to ${maxAvg.toFixed(0)}ms, ${ratio.toFixed(1)}x difference). This timing difference can be used for user enumeration — different response times for valid vs. invalid inputs reveal which accounts exist.`,
            evidence: avgTimes.map((t) => `${t.payload}: avg ${t.avg.toFixed(0)}ms`).join("\n"),
            remediation: "1. Add constant-time comparison for auth checks\n2. Use consistent code paths for valid and invalid inputs\n3. Add random delay jitter to normalize response times\n4. Use generic error messages that don't distinguish between 'user not found' and 'wrong password'",
            codeSnippet: `// Normalize response timing to prevent enumeration
const MIN_RESPONSE_MS = 200;

export async function POST(req: Request) {
  const start = Date.now();
  try {
    const result = await authenticate(req);
    return result;
  } catch (err) {
    // Always return the same error regardless of reason
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
  } finally {
    // Pad response time to a consistent minimum
    const elapsed = Date.now() - start;
    if (elapsed < MIN_RESPONSE_MS) {
      await new Promise((r) => setTimeout(r, MIN_RESPONSE_MS - elapsed));
    }
  }
}`,
            cwe: "CWE-208",
            owasp: "A07:2021",
            confidence: 65,
          });
        }
      }
    }
  }

  // Phase 7: Test 500 error body for framework/version disclosure
  for (const endpoint of endpoints.slice(0, 4)) {
    // Trigger 500 errors with malformed requests
    const errorTriggers: { method: string; body: string | undefined; headers: Record<string, string> }[] = [
      { method: "POST", body: "{{{{", headers: { "Content-Type": "application/json" } },
      { method: "POST", body: "\x00\x01\x02", headers: { "Content-Type": "application/json" } },
      { method: "GET", body: undefined, headers: { "Host": "localhost" } },
    ];

    for (const trigger of errorTriggers) {
      try {
        const res = await scanFetch(endpoint, {
          method: trigger.method,
          headers: trigger.headers,
          body: trigger.body,
          timeoutMs: 8000,
          noCache: true,
        });
        const body = await res.text();

        if (res.status >= 400) {
          for (const { pattern, type } of FRAMEWORK_PATTERNS) {
            const match = body.match(pattern);
            if (match) {
              findings.push({
                id: `errorleak-framework-${findings.length}`,
                module: "Error Leakage Under Stress",
                severity: "low",
                title: `${type} disclosed in error response on ${new URL(endpoint).pathname}`,
                description: `Error responses reveal ${type} (${match[0]}). Version information helps attackers identify known vulnerabilities for the specific framework version.`,
                evidence: `Endpoint: ${endpoint}\nStatus: ${res.status}\nDisclosed: ${match[0]}`,
                remediation: "1. Remove version numbers from error pages\n2. Set server header to a generic value\n3. Use custom error pages that don't include framework defaults\n4. Keep frameworks updated to latest versions",
                cwe: "CWE-200",
                confidence: 90,
              });
              break;
            }
          }

          // Check response headers too
          const serverHeader = res.headers.get("server") || "";
          const poweredBy = res.headers.get("x-powered-by") || "";
          const headerInfo = `${serverHeader} ${poweredBy}`;
          for (const { pattern, type } of FRAMEWORK_PATTERNS) {
            const match = headerInfo.match(pattern);
            if (match) {
              findings.push({
                id: `errorleak-header-disclosure-${findings.length}`,
                module: "Error Leakage Under Stress",
                severity: "low",
                title: `${type} disclosed via response headers on error`,
                description: `The Server or X-Powered-By header reveals ${type} (${match[0]}) on error responses. This helps attackers fingerprint your stack.`,
                evidence: `Server: ${serverHeader}\nX-Powered-By: ${poweredBy}`,
                remediation: "Remove or genericize the Server and X-Powered-By headers in your web server configuration.",
                cwe: "CWE-200",
                confidence: 95,
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

  // Phase 8: ReDoS detection
  const REDOS_PAYLOADS = [
    { input: "a".repeat(30) + "!", desc: "repeated 'a' + mismatch", param: "search" },
    { input: "0".repeat(30) + "x", desc: "repeated '0' + mismatch", param: "email" },
    { input: "@".repeat(20) + "a".repeat(20), desc: "repeated '@' + 'a'", param: "email" },
    { input: " ".repeat(50) + "x", desc: "spaces + mismatch", param: "query" },
    { input: "a]" + "[a".repeat(25), desc: "bracket nesting", param: "search" },
  ];

  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    const url = new URL(endpoint);
    for (const { input, desc, param } of REDOS_PAYLOADS) {
      try {
        const testUrl = new URL(endpoint);
        testUrl.searchParams.set(param, input);
        const start = Date.now();
        const res = await scanFetch(testUrl.href, { timeoutMs: 8000 });
        const elapsed = Date.now() - start;

        if (elapsed > 5000) {
          findings.push({
            id: `errorleak-redos-${findings.length}`,
            module: "Error Leakage Under Stress",
            severity: "high",
            title: `Potential ReDoS on ${url.pathname} via ${param} parameter`,
            description: `Sending a crafted input (${desc}) caused the server to respond in ${(elapsed / 1000).toFixed(1)}s instead of the normal <1s. This suggests a vulnerable regular expression that exhibits catastrophic backtracking.`,
            evidence: `GET ${testUrl.pathname}?${param}=${input.substring(0, 40)}...\nResponse time: ${elapsed}ms (normal: <1000ms)`,
            remediation: "Audit regex patterns for catastrophic backtracking. Use linear-time regex engines (RE2) or add input length limits before regex matching.",
            cwe: "CWE-1333",
            owasp: "A06:2021",
            codeSnippet: `// Use RE2 for user-controlled regex matching\nimport RE2 from "re2";\nconst pattern = new RE2("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$");\n\n// Or limit input length before regex\nif (input.length > 200) {\n  return Response.json({ error: "Input too long" }, { status: 400 });\n}\nif (pattern.test(input)) { /* ... */ }`,
          });
          break;
        }
      } catch { /* timeout = also potentially ReDoS */ }
    }
  }

  // Phase 9: Test with malformed payloads under concurrency
  for (const endpoint of target.apiEndpoints.slice(0, 3)) {
    const payloads = [
      "x".repeat(100000),
      '{"a":'.repeat(100) + "1" + "}".repeat(100),
      "\x00\x01\x02\x03",
    ];

    for (const payload of payloads) {
      try {
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: payload,
          timeoutMs: 10000,
        });

        if (res.status >= 500) {
          const body = await res.text();
          if (body.length > 200) {
            for (const { pattern, type } of SENSITIVE_PATTERNS) {
              if (pattern.test(body)) {
                findings.push({
                  id: `errorleak-malformed-${findings.length}`,
                  module: "Error Leakage Under Stress",
                  severity: "high",
                  title: `${type} leaked via malformed input on ${new URL(endpoint).pathname}`,
                  description: `Sending malformed data triggered a verbose error containing ${type.toLowerCase()}.`,
                  evidence: `Payload type: ${payload.length > 1000 ? "large payload" : "malformed data"}\nStatus: ${res.status}`,
                  remediation: "Validate input size and format. Return generic errors for malformed requests.",
                  codeSnippet: `// Validate request body size and shape early
export async function POST(req: Request) {
  const contentLength = Number(req.headers.get("content-length") || 0);
  if (contentLength > 1_000_000) {
    return Response.json({ error: "Payload too large" }, { status: 413 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }
}`,
                  cwe: "CWE-209",
                });
                break;
              }
            }
          }
        }
      } catch {
        // skip
      }
    }
  }

  return findings;
};
