import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

/**
 * Scan diff endpoint — compare two scans to see what changed.
 *
 * Usage: GET /api/scan/{current}/diff?baseline={previous}
 *
 * Returns new findings, fixed findings, score delta, and severity changes.
 * Designed for CI pipelines to detect security regressions between deploys.
 */
export const GET = async (
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const { id } = await params;
  const current = getScan(id);
  if (!current) {
    return NextResponse.json({ error: "Current scan not found" }, { status: 404 });
  }

  const baselineId = req.nextUrl.searchParams.get("baseline");
  if (!baselineId) {
    return NextResponse.json({ error: "Missing ?baseline= parameter" }, { status: 400 });
  }

  const baseline = getScan(baselineId);
  if (!baseline) {
    return NextResponse.json({ error: "Baseline scan not found" }, { status: 404 });
  }

  if (current.status !== "completed" || baseline.status !== "completed") {
    return NextResponse.json({
      error: "Both scans must be completed",
      currentStatus: current.status,
      baselineStatus: baseline.status,
    }, { status: 422 });
  }

  // Compare findings by title+module (since IDs may differ between runs)
  const baselineFindings = new Map(
    baseline.findings.map((f) => [`${f.module}:${f.title}`, f]),
  );
  const currentFindings = new Map(
    current.findings.map((f) => [`${f.module}:${f.title}`, f]),
  );

  const newFindings = current.findings
    .filter((f) => !baselineFindings.has(`${f.module}:${f.title}`))
    .map((f) => ({
      severity: f.severity,
      module: f.module,
      title: f.title,
      cwe: f.cwe,
    }));

  const fixedFindings = baseline.findings
    .filter((f) => !currentFindings.has(`${f.module}:${f.title}`))
    .map((f) => ({
      severity: f.severity,
      module: f.module,
      title: f.title,
      cwe: f.cwe,
    }));

  // Severity changes (same finding but different severity)
  const severityChanges: { title: string; module: string; from: string; to: string }[] = [];
  for (const [key, curr] of currentFindings) {
    const prev = baselineFindings.get(key);
    if (prev && prev.severity !== curr.severity) {
      severityChanges.push({
        title: curr.title,
        module: curr.module,
        from: prev.severity,
        to: curr.severity,
      });
    }
  }

  const scoreDelta = current.score - baseline.score;
  const isRegression = scoreDelta < 0 || newFindings.some((f) => f.severity === "critical" || f.severity === "high");

  const diff = {
    tool: "vibeshield",
    current: { id: current.id, target: current.target, grade: current.grade, score: current.score, summary: current.summary },
    baseline: { id: baseline.id, target: baseline.target, grade: baseline.grade, score: baseline.score, summary: baseline.summary },
    delta: {
      score: scoreDelta,
      grade: current.grade !== baseline.grade ? `${baseline.grade} → ${current.grade}` : null,
      findings: current.summary.total - baseline.summary.total,
      critical: current.summary.critical - baseline.summary.critical,
      high: current.summary.high - baseline.summary.high,
      medium: current.summary.medium - baseline.summary.medium,
    },
    regression: isRegression,
    newFindings,
    fixedFindings,
    severityChanges,
    unchanged: current.findings.length - newFindings.length - severityChanges.length,
  };

  return NextResponse.json(diff, { status: isRegression ? 422 : 200 });
};
