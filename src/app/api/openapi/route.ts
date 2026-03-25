import { NextResponse } from "next/server";

/**
 * OpenAPI 3.1 spec for the VibeShield API.
 * GET /api/openapi
 */
export async function GET() {
  const spec = {
    openapi: "3.1.0",
    info: {
      title: "VibeShield API",
      description: "Black-box DAST scanner for vibe-coded web applications. Scans for 48+ security vulnerabilities across OWASP Top 10 categories.",
      version: "1.0.0",
      contact: { name: "VibeShield", url: "https://github.com/vibeshield/vibeshield" },
    },
    servers: [{ url: "/", description: "Current instance" }],
    security: [{ bearerAuth: [] }, { apiKeyAuth: [] }],
    paths: {
      "/api/scan": {
        post: {
          summary: "Start a new scan",
          tags: ["Scanning"],
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/ScanRequest" } } },
          },
          responses: {
            "200": { description: "Scan started", content: { "application/json": { schema: { $ref: "#/components/schemas/ScanStarted" } } } },
            "400": { description: "Invalid URL or configuration" },
            "401": { description: "Invalid API key" },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/api/scan/{id}": {
        get: {
          summary: "Get scan status and results",
          tags: ["Scanning"],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: {
            "200": { description: "Scan data", content: { "application/json": { schema: { $ref: "#/components/schemas/ScanResult" } } } },
            "404": { description: "Scan not found" },
          },
        },
        delete: {
          summary: "Cancel a running scan",
          tags: ["Scanning"],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Scan cancelled" } },
        },
      },
      "/api/scan/{id}/ci": {
        get: {
          summary: "CI-friendly results with quality gates",
          tags: ["CI/CD"],
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } },
            { name: "minScore", in: "query", schema: { type: "integer", default: 60 } },
            { name: "failOnCritical", in: "query", schema: { type: "boolean", default: true } },
            { name: "format", in: "query", schema: { type: "string", enum: ["json", "slack", "discord"] } },
          ],
          responses: { "200": { description: "Pass" }, "422": { description: "Fail" } },
        },
      },
      "/api/scan/bulk": {
        post: {
          summary: "Scan multiple URLs at once",
          tags: ["Scanning"],
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/BulkScanRequest" } } },
          },
          responses: { "200": { description: "Bulk scan results" }, "401": { description: "Invalid API key" } },
        },
      },
      "/api/scan/schedule": {
        post: {
          summary: "Create recurring scan schedule",
          tags: ["Scheduling"],
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/ScheduleRequest" } } },
          },
          responses: { "200": { description: "Schedule created" }, "401": { description: "Invalid API key" } },
        },
        get: { summary: "List all schedules", tags: ["Scheduling"], responses: { "200": { description: "Schedule list" } } },
        delete: {
          summary: "Delete a schedule",
          tags: ["Scheduling"],
          parameters: [{ name: "id", in: "query", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Schedule deleted" } },
        },
      },
      "/api/scan/timeline": {
        get: {
          summary: "Security timeline for a target",
          tags: ["Analytics"],
          parameters: [{ name: "target", in: "query", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Timeline data" } },
        },
      },
      "/api/scan/compare": {
        get: {
          summary: "Compare two scans side-by-side",
          tags: ["Analytics"],
          parameters: [
            { name: "a", in: "query", required: true, schema: { type: "string" }, description: "Baseline scan ID" },
            { name: "b", in: "query", required: true, schema: { type: "string" }, description: "Current scan ID" },
          ],
          responses: { "200": { description: "Comparison data" } },
        },
      },
      "/api/scan/{id}/sarif": { get: { summary: "Export as SARIF", tags: ["Export"], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "SARIF JSON" } } } },
      "/api/scan/{id}/csv": { get: { summary: "Export as CSV", tags: ["Export"], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "CSV file" } } } },
      "/api/scan/{id}/junit": { get: { summary: "Export as JUnit XML", tags: ["Export"], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "JUnit XML" } } } },
      "/api/scan/{id}/badge": { get: { summary: "Security grade badge (SVG)", tags: ["Export"], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "SVG badge" } } } },
      "/api/health": { get: { summary: "Health check", tags: ["System"], responses: { "200": { description: "Healthy" }, "503": { description: "Overloaded" } } } },
      "/api/stats": { get: { summary: "Aggregate statistics", tags: ["System"], responses: { "200": { description: "Stats" } } } },
      "/api/webhook-test": {
        post: {
          summary: "Test webhook integration",
          tags: ["Integrations"],
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", properties: { url: { type: "string" }, format: { type: "string", enum: ["slack", "discord", "json"] } }, required: ["url"] } } },
          },
          responses: { "200": { description: "Webhook sent" } },
        },
      },
    },
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", description: "Set VIBESHIELD_API_KEY to enable" },
        apiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
      },
      schemas: {
        ScanRequest: {
          type: "object",
          required: ["url"],
          properties: {
            url: { type: "string", description: "Target URL to scan" },
            mode: { type: "string", enum: ["quick", "security", "full"], default: "full" },
            callbackUrl: { type: "string", description: "HTTPS webhook for completion notification" },
            minScore: { type: "integer", description: "Minimum score for CI pass" },
            failOnCritical: { type: "boolean", description: "Fail CI if critical findings exist" },
          },
        },
        ScanStarted: {
          type: "object",
          properties: { id: { type: "string" }, target: { type: "string" }, status: { type: "string" }, mode: { type: "string" } },
        },
        ScanResult: {
          type: "object",
          properties: {
            id: { type: "string" }, target: { type: "string" }, status: { type: "string", enum: ["queued", "scanning", "completed", "failed"] },
            grade: { type: "string" }, score: { type: "integer" },
            findings: { type: "array", items: { $ref: "#/components/schemas/Finding" } },
            summary: { type: "object", properties: { critical: { type: "integer" }, high: { type: "integer" }, medium: { type: "integer" }, low: { type: "integer" }, info: { type: "integer" }, total: { type: "integer" } } },
          },
        },
        Finding: {
          type: "object",
          properties: {
            id: { type: "string" }, module: { type: "string" }, severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
            title: { type: "string" }, description: { type: "string" }, evidence: { type: "string" }, remediation: { type: "string" },
            cwe: { type: "string" }, confidence: { type: "integer", minimum: 0, maximum: 100 },
          },
        },
        BulkScanRequest: {
          type: "object",
          required: ["urls"],
          properties: { urls: { type: "array", items: { type: "string" }, maxItems: 10 }, mode: { type: "string" }, callbackUrl: { type: "string" } },
        },
        ScheduleRequest: {
          type: "object",
          required: ["url"],
          properties: { url: { type: "string" }, mode: { type: "string" }, intervalHours: { type: "integer", minimum: 1, maximum: 168 }, callbackUrl: { type: "string" } },
        },
      },
    },
    tags: [
      { name: "Scanning", description: "Start and manage security scans" },
      { name: "CI/CD", description: "CI pipeline integration" },
      { name: "Scheduling", description: "Recurring scan management" },
      { name: "Analytics", description: "Timeline, comparison, and trends" },
      { name: "Export", description: "Export results in various formats" },
      { name: "Integrations", description: "Slack, Discord, and webhook integrations" },
      { name: "System", description: "Health and statistics" },
    ],
  };

  return NextResponse.json(spec, {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}
