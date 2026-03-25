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

export const errorLeakModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Hammer endpoints to trigger error states
  const endpoints = [target.url, ...target.apiEndpoints.slice(0, 5)];

  for (const endpoint of endpoints) {
    // Send concurrent requests to stress the server
    const N = 30;
    const results = await Promise.allSettled(
      Array.from({ length: N }, async () => {
        const res = await scanFetch(endpoint, { timeoutMs: 10000 });
        return { status: res.status, body: await res.text() };
      }),
    );

    // Check error responses for sensitive info
    for (const r of results) {
      if (r.status !== "fulfilled") continue;
      const { status, body } = r.value;

      if (status >= 500 && body.length > 200) {
        // Check for error pattern leaks
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

        // Check for leaked sensitive data
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

  // Test with malformed payloads under concurrency
  for (const endpoint of target.apiEndpoints.slice(0, 3)) {
    const payloads = [
      "x".repeat(100000),           // Large payload
      '{"a":'.repeat(100) + "1" + "}".repeat(100), // Deeply nested JSON
      "\x00\x01\x02\x03",           // Binary data
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
