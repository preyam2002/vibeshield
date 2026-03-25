import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

/**
 * CI-friendly scan results endpoint.
 *
 * Returns a compact JSON summary designed for CI/CD pipelines.
 * Includes a `pass` boolean based on configurable thresholds,
 * GitHub Actions annotation-compatible output, and exit-code guidance.
 *
 * Query params:
 *   ?min-score=70      Minimum score to pass (default: 0 = always pass)
 *   ?max-critical=0    Maximum critical findings allowed (default: unlimited)
 *   ?max-high=5        Maximum high findings allowed (default: unlimited)
 *   ?format=annotations  Return GitHub Actions annotation format
 */
export const GET = async (
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  if (scan.status !== "completed" && scan.status !== "failed") {
    return NextResponse.json({
      status: scan.status,
      message: "Scan is still running. Poll this endpoint until status is 'completed'.",
    }, { status: 202 });
  }

  const url = new URL(req.url);
  const minScore = parseInt(url.searchParams.get("min-score") || "0", 10);
  const maxCritical = parseInt(url.searchParams.get("max-critical") || "-1", 10);
  const maxHigh = parseInt(url.searchParams.get("max-high") || "-1", 10);
  const format = url.searchParams.get("format");

  // Determine pass/fail
  const checks: { name: string; pass: boolean; actual: number; threshold: number }[] = [];

  if (minScore > 0) {
    checks.push({ name: "min-score", pass: scan.score >= minScore, actual: scan.score, threshold: minScore });
  }
  if (maxCritical >= 0) {
    checks.push({ name: "max-critical", pass: scan.summary.critical <= maxCritical, actual: scan.summary.critical, threshold: maxCritical });
  }
  if (maxHigh >= 0) {
    checks.push({ name: "max-high", pass: scan.summary.high <= maxHigh, actual: scan.summary.high, threshold: maxHigh });
  }

  const pass = checks.length === 0 ? true : checks.every((c) => c.pass);

  // GitHub Actions annotation format
  if (format === "annotations") {
    const annotations = scan.findings
      .filter((f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium")
      .map((f) => {
        const level = f.severity === "critical" || f.severity === "high" ? "error" : "warning";
        return `::${level} title=${f.module}: ${f.title}::${f.description.replace(/\n/g, "%0A")}${f.remediation ? `%0A%0ARemediation: ${f.remediation.replace(/\n/g, "%0A")}` : ""}`;
      });

    const summary = [
      `::group::VibeShield Scan Results — Grade: ${scan.grade} (${scan.score}/100)`,
      `Target: ${scan.target}`,
      `Findings: ${scan.summary.critical} critical, ${scan.summary.high} high, ${scan.summary.medium} medium, ${scan.summary.low} low`,
      `Status: ${pass ? "PASS" : "FAIL"}${checks.length > 0 ? ` (${checks.filter((c) => !c.pass).map((c) => `${c.name}: ${c.actual} vs ${c.threshold}`).join(", ")})` : ""}`,
      `::endgroup::`,
      ...annotations,
    ];

    return new NextResponse(summary.join("\n"), {
      headers: { "Content-Type": "text/plain" },
      status: pass ? 200 : 422,
    });
  }

  // Default: compact JSON
  const result = {
    tool: "vibeshield",
    version: "1.0.0",
    target: scan.target,
    status: scan.status,
    pass,
    grade: scan.grade,
    score: scan.score,
    summary: scan.summary,
    checks,
    duration: scan.completedAt && scan.startedAt
      ? Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)
      : null,
    findings: scan.findings.map((f) => ({
      severity: f.severity,
      module: f.module,
      title: f.title,
      cwe: f.cwe,
      ...(f.confidence !== undefined ? { confidence: f.confidence } : {}),
    })),
    urls: {
      report: `/scan/${scan.id}`,
      sarif: `/api/scan/${scan.id}/sarif`,
      badge: `/api/scan/${scan.id}/badge`,
      full: `/api/scan/${scan.id}/export`,
    },
  };

  return NextResponse.json(result, { status: pass ? 200 : 422 });
};
