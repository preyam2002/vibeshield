import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

/**
 * Generate a GitHub Actions workflow file for continuous security scanning.
 * Pre-configured with the scan's target URL and quality gate thresholds.
 */
export const GET = async (
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const hostname = new URL(scan.target).hostname;
  const minScore = Math.max(0, scan.score - 10); // Set gate slightly below current score

  const workflow = `# VibeShield Security Scan — ${hostname}
# Generated from scan ${id} on ${new Date().toISOString().split("T")[0]}
# Add this file to .github/workflows/security-scan.yml

name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1" # Weekly on Monday at 6am UTC

env:
  VIBESHIELD_URL: \${VIBESHIELD_URL:-http://localhost:3000}
  TARGET_URL: "${scan.target}"

jobs:
  security-scan:
    name: VibeShield Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Start scan
        id: scan
        run: |
          RESPONSE=$(curl -s -X POST "$VIBESHIELD_URL/api/scan" \\
            -H "Content-Type: application/json" \\
            -d '{"url": "'"$TARGET_URL"'", "mode": "security"}')
          SCAN_ID=$(echo "$RESPONSE" | jq -r '.id')
          echo "scan_id=$SCAN_ID" >> "$GITHUB_OUTPUT"
          echo "Started scan: $SCAN_ID"

      - name: Wait for scan completion
        id: wait
        run: |
          SCAN_ID="\${{ steps.scan.outputs.scan_id }}"
          for i in $(seq 1 60); do
            STATUS=$(curl -s "$VIBESHIELD_URL/api/scan/$SCAN_ID" | jq -r '.status')
            echo "Attempt $i: status=$STATUS"
            if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
              break
            fi
            sleep 5
          done

      - name: Check results
        id: results
        run: |
          SCAN_ID="\${{ steps.scan.outputs.scan_id }}"
          # Get CI-friendly results with quality gates
          RESULT=$(curl -s -w "\\n%{http_code}" \\
            "$VIBESHIELD_URL/api/scan/$SCAN_ID/ci?min-score=${minScore}&max-critical=0&max-high=3")
          HTTP_CODE=$(echo "$RESULT" | tail -1)
          BODY=$(echo "$RESULT" | head -n -1)

          GRADE=$(echo "$BODY" | jq -r '.grade')
          SCORE=$(echo "$BODY" | jq -r '.score')
          PASS=$(echo "$BODY" | jq -r '.pass')
          CRITICAL=$(echo "$BODY" | jq -r '.summary.critical')
          HIGH=$(echo "$BODY" | jq -r '.summary.high')
          TOTAL=$(echo "$BODY" | jq -r '.summary.total')

          echo "## Security Scan Results" >> "$GITHUB_STEP_SUMMARY"
          echo "| Metric | Value |" >> "$GITHUB_STEP_SUMMARY"
          echo "|--------|-------|" >> "$GITHUB_STEP_SUMMARY"
          echo "| Grade | $GRADE ($SCORE/100) |" >> "$GITHUB_STEP_SUMMARY"
          echo "| Findings | $TOTAL ($CRITICAL critical, $HIGH high) |" >> "$GITHUB_STEP_SUMMARY"
          echo "| Quality Gate | $([ "$PASS" = "true" ] && echo "PASS ✅" || echo "FAIL ❌") |" >> "$GITHUB_STEP_SUMMARY"
          echo "" >> "$GITHUB_STEP_SUMMARY"
          echo "[View full report]($VIBESHIELD_URL/scan/$SCAN_ID)" >> "$GITHUB_STEP_SUMMARY"

          if [ "$PASS" != "true" ]; then
            echo "::error::Security scan failed: grade=$GRADE score=$SCORE critical=$CRITICAL high=$HIGH"
            exit 1
          fi

      - name: Post annotations
        if: always()
        run: |
          SCAN_ID="\${{ steps.scan.outputs.scan_id }}"
          curl -s "$VIBESHIELD_URL/api/scan/$SCAN_ID/ci?format=annotations" | while IFS= read -r line; do
            echo "$line"
          done
`;

  return new NextResponse(workflow, {
    headers: {
      "Content-Type": "text/yaml",
      "Content-Disposition": `attachment; filename="vibeshield-scan.yml"`,
    },
  });
};
