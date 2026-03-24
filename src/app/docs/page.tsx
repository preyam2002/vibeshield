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
            <span className="text-xs text-zinc-400 font-medium">API Docs</span>
          </div>
        </div>
      </nav>

      <main className="relative z-10 max-w-4xl mx-auto px-6 py-12">
        <h1 className="text-3xl font-black text-zinc-100 mb-2">API & CI/CD Integration</h1>
        <p className="text-zinc-500 mb-10">Integrate VibeShield into your deployment pipeline to catch security issues before they ship.</p>

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

# Options: mode "full" (default) or "security" (skip stress tests)
# -d '{"url": "...", "mode": "security"}'

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

# SARIF (GitHub Code Scanning)
curl ${baseUrl}/api/scan/abc-123/sarif -o results.sarif`}
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
#   "summary": {"critical": 0, "high": 1, "medium": 3, ...}
# }`}
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

      - name: Check grade
        run: |
          SCORE=\${{ steps.results.outputs.score }}
          if [ "$SCORE" -lt 50 ]; then
            echo "::error::Security score $SCORE/100 is below threshold (50)"
            exit 1
          fi`}
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
          <h2 className="text-lg font-bold text-zinc-200 mb-4">API Reference</h2>
          <div className="space-y-4">
            {[
              { method: "POST", path: "/api/scan", desc: "Start a new scan", body: '{"url": "...", "mode?": "full|security", "callbackUrl?": "..."}' },
              { method: "GET", path: "/api/scan/:id", desc: "Get scan status and results" },
              { method: "GET", path: "/api/scan/:id/export", desc: "Download JSON report" },
              { method: "GET", path: "/api/scan/:id/report", desc: "Download Markdown report" },
              { method: "GET", path: "/api/scan/:id/sarif", desc: "Download SARIF file" },
              { method: "GET", path: "/api/scan/:id/badge", desc: "SVG badge image" },
              { method: "GET", path: "/api/scans", desc: "List recent scans" },
            ].map((ep) => (
              <div key={ep.path + ep.method} className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${ep.method === "POST" ? "bg-green-500/10 text-green-400" : "bg-blue-500/10 text-blue-400"}`}>
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
      </main>

      <footer className="relative z-10 border-t border-zinc-800/50 text-center py-6 text-zinc-700 text-xs">
        VibeShield — Ship with confidence, not with vulnerabilities.
      </footer>
    </div>
  );
}
