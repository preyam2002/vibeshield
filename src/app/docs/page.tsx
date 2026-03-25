"use client";

export default function DocsPage() {
  const baseUrl = typeof window !== "undefined" ? window.location.origin : "https://vibeshield.dev";

  return (
    <div className="min-h-screen">
      <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,0.015)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.015)_1px,transparent_1px)] bg-[size:64px_64px] pointer-events-none" />

      <nav className="relative z-10 border-b border-zinc-800/50 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
            VibeShield
          </a>
          <div className="flex items-center gap-4">
            <a href="/scans" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">All Scans</a>
            <a href="/dashboard" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Dashboard</a>
            <a href="/compare" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Compare</a>
            <span className="text-xs text-zinc-400 font-medium">API Docs</span>
          </div>
        </div>
      </nav>

      <main className="relative z-10 max-w-4xl mx-auto px-6 py-12">
        <h1 className="text-3xl font-black text-zinc-100 mb-2">API & CI/CD Integration</h1>
        <p className="text-zinc-500 mb-10">Integrate VibeShield into your deployment pipeline to catch security issues before they ship.</p>

        {/* Authentication */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">Authentication</h2>
          <div className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-400 space-y-2">
            <p>API key auth is <span className="text-zinc-200">optional</span>. Set <code className="text-orange-400">VIBESHIELD_API_KEY</code> env var to enable it. Multiple keys can be comma-separated.</p>
            <p className="text-zinc-500">When enabled, all write endpoints require one of:</p>
            <pre className="text-zinc-300 mt-2">{`Authorization: Bearer <your-key>
X-API-Key: <your-key>`}</pre>
            <p className="text-zinc-500">Read-only endpoints (scan status, stats, scans list) remain unauthenticated.</p>
          </div>
        </section>

        {/* Quick start */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">Quick Start</h2>
          <div className="space-y-4">
            <div>
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">1. Start a scan</h3>
              <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`curl -X POST ${baseUrl}/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://your-app.vercel.app"}'

# Scan modes:
#   "quick"    - 13 essential modules, ~15s (headers, SSL, CSP, secrets, cookies)
#   "security" - all 48 security modules, ~45s (default)
#   "full"     - security + 6 stress tests (load, race, rate limit), ~90s
# -d '{"url": "...", "mode": "quick"}'

# Response: {"id": "abc-123", "url": "https://your-app.vercel.app"}`}
              </pre>
            </div>
            <div>
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">2. Poll for results</h3>
              <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`curl ${baseUrl}/api/scan/abc-123

# Response includes: status, grade, score, findings[]`}
              </pre>
            </div>
            <div>
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">3. Export results</h3>
              <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`# JSON export
curl ${baseUrl}/api/scan/abc-123/export -o report.json

# Markdown report
curl ${baseUrl}/api/scan/abc-123/report -o report.md

# PDF report (open in browser to print/save as PDF)
open "${baseUrl}/api/scan/abc-123/pdf"

# SARIF (GitHub Code Scanning)
curl ${baseUrl}/api/scan/abc-123/sarif -o results.sarif

# CSV (spreadsheet/JIRA import)
curl ${baseUrl}/api/scan/abc-123/csv -o findings.csv`}
              </pre>
            </div>
          </div>
        </section>

        {/* Webhook callback */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">Webhook Callback</h2>
          <p className="text-sm text-zinc-500 mb-4">Pass a <code className="text-zinc-400 bg-zinc-800/50 px-1.5 py-0.5 rounded">callbackUrl</code> to get notified when the scan completes:</p>
          <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`curl -X POST ${baseUrl}/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://your-app.vercel.app",
    "callbackUrl": "https://your-server.com/webhook"
  }'

# When scan completes, we POST to your callbackUrl:
# {
#   "event": "scan.completed",
#   "scanId": "abc-123",
#   "target": "https://your-app.vercel.app",
#   "grade": "B+",
#   "score": 78,
#   "summary": {"critical": 0, "high": 1, "medium": 3, ...},
#   "gate": {"passed": true},  // if minScore/failOnCritical set
#   "moduleHealth": {"failed": 0, "skipped": 0, "total": 54}  // if any modules failed/skipped
# }
# Callbacks retry up to 3x with exponential backoff on server errors.
#
# Webhook signature verification (optional):
# Set VIBESHIELD_WEBHOOK_SECRET env var to enable HMAC-SHA256 signatures.
# Callbacks include X-VibeShield-Signature and X-VibeShield-Timestamp headers.
# Verify: HMAC-SHA256(secret, timestamp + "." + body) === signature`}
          </pre>
        </section>

        {/* CI/CD Gating */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">CI/CD Gating</h2>
          <p className="text-sm text-zinc-500 mb-4">Block deployments that fail security thresholds. Pass <code className="text-zinc-400 bg-zinc-800/50 px-1.5 py-0.5 rounded">minScore</code> and/or <code className="text-zinc-400 bg-zinc-800/50 px-1.5 py-0.5 rounded">failOnCritical</code> to the scan request:</p>
          <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`# Fail if score < 70 or any critical findings
curl -X POST ${baseUrl}/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://your-app.vercel.app",
    "callbackUrl": "https://your-server.com/webhook",
    "minScore": 70,
    "failOnCritical": true
  }'

# The webhook callback includes a "gate" field:
# {"gate": {"passed": false, "reason": "Score 45 < threshold 70; 2 critical findings found"}}`}
          </pre>
        </section>

        {/* GitHub Actions */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">GitHub Actions</h2>
          <p className="text-sm text-zinc-500 mb-4">Add to <code className="text-zinc-400 bg-zinc-800/50 px-1.5 py-0.5 rounded">.github/workflows/security.yml</code>:</p>
          <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`name: Security Scan
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  vibeshield:
    runs-on: ubuntu-latest
    steps:
      - name: Start scan
        id: scan
        run: |
          RESPONSE=$(curl -s -X POST ${baseUrl}/api/scan \\
            -H "Content-Type: application/json" \\
            -d '{"url": "\${{ vars.APP_URL }}"}')
          echo "scan_id=$(echo $RESPONSE | jq -r .id)" >> $GITHUB_OUTPUT

      - name: Wait for results
        id: results
        run: |
          for i in $(seq 1 60); do
            RESULT=$(curl -s ${baseUrl}/api/scan/\${{ steps.scan.outputs.scan_id }})
            STATUS=$(echo $RESULT | jq -r .status)
            if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
              echo "grade=$(echo $RESULT | jq -r .grade)" >> $GITHUB_OUTPUT
              echo "score=$(echo $RESULT | jq -r .score)" >> $GITHUB_OUTPUT
              break
            fi
            sleep 5
          done

      - name: Download SARIF
        run: |
          curl -s ${baseUrl}/api/scan/\${{ steps.scan.outputs.scan_id }}/sarif \\
            -o results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Check thresholds
        run: |
          # CI endpoint returns 422 if thresholds are violated
          curl -sf "${baseUrl}/api/scan/\${{ steps.scan.outputs.scan_id }}/ci?min-score=50&max-critical=0&format=annotations" || exit 1`}
          </pre>
        </section>

        {/* One-liner */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">One-Liner CLI</h2>
          <p className="text-sm text-zinc-500 mb-4">Scan and gate deployments from your terminal:</p>
          <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`# Scan and fail if score < 50
ID=$(curl -s -X POST ${baseUrl}/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://your-app.vercel.app"}' | jq -r .id) && \\
while true; do
  R=$(curl -s ${baseUrl}/api/scan/$ID)
  S=$(echo $R | jq -r .status)
  [ "$S" = "completed" ] || [ "$S" = "failed" ] && break
  sleep 5
done && \\
echo $R | jq '{grade, score, summary}' && \\
[ "$(echo $R | jq .score)" -ge 50 ] || (echo "FAIL: score below threshold" && exit 1)`}
          </pre>
        </section>

        {/* Vercel Deploy Hook */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">Vercel Deploy Hook</h2>
          <p className="text-sm text-zinc-500 mb-4">Auto-scan after every Vercel deployment by adding a webhook in your project settings:</p>
          <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`# vercel.json — add a post-deploy webhook
{
  "github": {
    "autoAlias": true
  }
}

# Or use Vercel CLI to trigger a scan after deploy:
vercel deploy --prod && \\
  curl -s -X POST ${baseUrl}/api/scan \\
    -H "Content-Type: application/json" \\
    -d "{\\"url\\": \\"$(vercel inspect --json | jq -r .url)\\", \\"mode\\": \\"quick\\"}"
`}
          </pre>
        </section>

        {/* Response Schema */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">Response Schema</h2>
          <p className="text-sm text-zinc-500 mb-4">The scan result object returned by <code className="text-zinc-400 bg-zinc-800/50 px-1.5 py-0.5 rounded">GET /api/scan/:id</code>:</p>
          <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`{
  "id": "abc-123",
  "target": "https://your-app.vercel.app",
  "status": "completed",         // "queued" | "scanning" | "completed" | "failed"
  "mode": "full",                // "quick" | "security" | "full"
  "grade": "B+",                 // A, A-, B+, B, C+, C, D+, D, F
  "score": 78,                   // 0-100
  "startedAt": "2025-03-25T...",
  "completedAt": "2025-03-25T...",
  "technologies": ["Next.js", "React", "Tailwind", "Supabase"],
  "summary": {
    "critical": 0, "high": 2, "medium": 5, "low": 3, "info": 1, "total": 11
  },
  "surface": {
    "pages": 12, "apiEndpoints": 8, "jsFiles": 5, "forms": 2, "cookies": 3
  },
  "findings": [{
    "id": "headers-content-security-policy",
    "module": "Security Headers",
    "severity": "medium",        // "critical" | "high" | "medium" | "low" | "info"
    "title": "Missing Content-Security-Policy header",
    "description": "...",
    "evidence": "...",           // optional
    "remediation": "...",
    "codeSnippet": "...",        // optional — copy-paste fix
    "cwe": "CWE-693",           // optional
    "owasp": "A05:2021",        // optional
    "confidence": 95,           // optional — 0-100, detection confidence
    "endpoint": "/api/users"    // optional — specific URL where issue was found
  }],
  "modules": [{
    "name": "Security Headers",
    "status": "completed",
    "findingsCount": 2,
    "durationMs": 340
  }]
}`}
          </pre>
        </section>

        {/* GitHub Actions */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">GitHub Actions</h2>
          <p className="text-sm text-zinc-500 mb-4">Drop-in workflow that scans preview deployments on every PR. Copy <code className="text-orange-400">.github/workflows/vibeshield-scan.yml</code> from this repo, then add these secrets:</p>
          <div className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-400 space-y-1 mb-4">
            <p><code className="text-zinc-200">VIBESHIELD_URL</code> — your VibeShield instance URL</p>
            <p><code className="text-zinc-200">VIBESHIELD_KEY</code> — API key (optional, only if auth enabled)</p>
          </div>
          <p className="text-sm text-zinc-500">The workflow waits for the Vercel preview deployment, runs a security scan, posts results as a PR comment, and fails the check if the score is below threshold.</p>
        </section>

        {/* Slack/Discord Integration */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">Slack & Discord Notifications</h2>
          <p className="text-sm text-zinc-500 mb-4">Post scan results directly to Slack or Discord channels using the CI endpoint format options:</p>
          <div className="space-y-4">
            <div>
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Slack (via incoming webhook)</h3>
              <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`# Get Slack-formatted results and post to channel
PAYLOAD=$(curl -s "${baseUrl}/api/scan/SCAN_ID/ci?format=slack&min-score=50")
curl -X POST "$SLACK_WEBHOOK_URL" \\
  -H "Content-Type: application/json" \\
  -d "$PAYLOAD"`}
              </pre>
            </div>
            <div>
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Discord (via webhook)</h3>
              <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`# Get Discord-formatted results and post to channel
PAYLOAD=$(curl -s "${baseUrl}/api/scan/SCAN_ID/ci?format=discord&min-score=50")
curl -X POST "$DISCORD_WEBHOOK_URL" \\
  -H "Content-Type: application/json" \\
  -d "$PAYLOAD"`}
              </pre>
            </div>
            <div>
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Bulk Scanning</h3>
              <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`# Scan multiple URLs at once (up to 10)
curl -X POST ${baseUrl}/api/scan/bulk \\
  -H "Content-Type: application/json" \\
  -d '{
    "urls": [
      "https://app1.vercel.app",
      "https://app2.vercel.app",
      "https://app3.vercel.app"
    ],
    "mode": "security"
  }'`}
              </pre>
            </div>
          </div>
        </section>

        {/* Badge */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">README Badge</h2>
          <p className="text-sm text-zinc-500 mb-4">After scanning, embed a badge in your README:</p>
          <pre className="bg-zinc-900/80 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 overflow-x-auto">
{`![VibeShield](${baseUrl}/api/scan/SCAN_ID/badge)`}
          </pre>
        </section>

        {/* API reference */}
        <section className="mb-12">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold text-zinc-200">API Reference</h2>
            <a href="/api/openapi" target="_blank" className="text-xs text-blue-500 hover:text-blue-400 transition-colors">
              OpenAPI Spec →
            </a>
          </div>
          <div className="space-y-4">
            {[
              { method: "POST", path: "/api/scan", desc: "Start a new scan", body: '{"url": "...", "mode?": "quick|security|full", "callbackUrl?": "..."}' },
              { method: "GET", path: "/api/scan/:id", desc: "Get scan status and results" },
              { method: "GET", path: "/api/scan/:id/export", desc: "Download JSON report" },
              { method: "GET", path: "/api/scan/:id/report", desc: "Download Markdown report" },
              { method: "GET", path: "/api/scan/:id/sarif", desc: "Download SARIF file" },
              { method: "GET", path: "/api/scan/:id/csv", desc: "Download CSV report" },
              { method: "GET", path: "/api/scan/:id/junit", desc: "Download JUnit XML (CI test results)" },
              { method: "GET", path: "/api/scan/:id/pdf", desc: "Printable HTML/PDF report" },
              { method: "GET", path: "/api/scan/:id/badge", desc: "SVG badge image" },
              { method: "GET", path: "/api/scan/:id/ci", desc: "CI-friendly results. Query: ?min-score=70&max-critical=0&format=annotations|slack|discord. Returns 422 on fail." },
              { method: "POST", path: "/api/scan/bulk", desc: "Bulk scan up to 10 URLs", body: '{"urls": ["..."], "mode?": "quick|security|full", "callbackUrl?": "..."}' },
              { method: "GET", path: "/api/scan/:id/diff?baseline=:prevId", desc: "Compare two scans. Returns new/fixed findings and score delta. 422 on regression." },
              { method: "GET", path: "/api/scan/:id/github-action", desc: "Download pre-configured GitHub Actions workflow with quality gates" },
              { method: "DELETE", path: "/api/scan/:id", desc: "Cancel a running scan" },
              { method: "GET", path: "/api/scans", desc: "List recent scans. Filter: ?target=domain&status=completed" },
              { method: "POST", path: "/api/scan/schedule", desc: "Create recurring scan schedule (1h-168h interval)", body: '{"url": "...", "mode?": "...", "intervalHours?": 24, "callbackUrl?": "..."}' },
              { method: "GET", path: "/api/scan/schedule", desc: "List all scheduled scans" },
              { method: "DELETE", path: "/api/scan/schedule?id=:id", desc: "Delete a scheduled scan" },
              { method: "GET", path: "/api/scan/timeline?target=example.com", desc: "Security score timeline for a target. Returns trend, best/worst, and per-scan deltas." },
              { method: "GET", path: "/api/scan/compare?a=:id&b=:id", desc: "Compare two scans side-by-side. Returns new/fixed findings, severity changes, module-level diffs." },
              { method: "POST", path: "/api/webhook-test", desc: "Test webhook integration", body: '{"url": "https://hooks.slack.com/...", "format": "slack|discord|json"}' },
              { method: "GET", path: "/api/stats", desc: "Aggregate scan statistics" },
            ].map((ep) => (
              <div key={ep.path + ep.method} className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${ep.method === "POST" ? "bg-green-500/10 text-green-400" : ep.method === "DELETE" ? "bg-red-500/10 text-red-400" : "bg-blue-500/10 text-blue-400"}`}>
                    {ep.method}
                  </span>
                  <code className="text-sm text-zinc-300 font-mono">{ep.path}</code>
                </div>
                <p className="text-xs text-zinc-500">{ep.desc}</p>
                {ep.body && <p className="text-xs text-zinc-600 mt-1 font-mono">Body: {ep.body}</p>}
              </div>
            ))}
          </div>
        </section>
        {/* Configuration */}
        <section className="mb-12">
          <h2 className="text-lg font-bold text-zinc-200 mb-4">Configuration</h2>
          <p className="text-sm text-zinc-500 mb-4">All scanner limits are configurable via environment variables:</p>
          <div className="space-y-2">
            {[
              { env: "VIBESHIELD_MODULE_TIMEOUT_MS", desc: "Max time per module", default: "120000" },
              { env: "VIBESHIELD_MAX_FINDINGS_PER_MODULE", desc: "Max findings from a single module", default: "8" },
              { env: "VIBESHIELD_BATCH_SIZE", desc: "Parallel module batch size", default: "21" },
              { env: "VIBESHIELD_CIRCUIT_BREAKER", desc: "Consecutive failures before abort", default: "4" },
              { env: "VIBESHIELD_MAX_CONCURRENT", desc: "Max concurrent scans", default: "10" },
              { env: "VIBESHIELD_RATE_TARGET", desc: "Max scans per target per window", default: "3" },
              { env: "VIBESHIELD_RATE_IP", desc: "Max scans per IP per window", default: "20" },
              { env: "VIBESHIELD_RATE_WINDOW_MS", desc: "Rate limit window", default: "300000" },
              { env: "VIBESHIELD_MAX_SCANS", desc: "Max scans in memory", default: "100" },
              { env: "VIBESHIELD_WEBHOOK_SECRET", desc: "HMAC-SHA256 key for webhook signatures", default: "(none)" },
            ].map((c) => (
              <div key={c.env} className="flex items-baseline gap-3 text-xs">
                <code className="text-zinc-300 bg-zinc-800/50 px-1.5 py-0.5 rounded font-mono shrink-0">{c.env}</code>
                <span className="text-zinc-600">{c.desc}</span>
                <span className="text-zinc-700 ml-auto shrink-0">default: {c.default}</span>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="relative z-10 border-t border-zinc-800/50 text-center py-6 text-zinc-700 text-xs">
        VibeShield — Ship with confidence, not with vulnerabilities.
      </footer>
    </div>
  );
}
