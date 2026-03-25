import { NextResponse, type NextRequest } from "next/server";
import { getRecentScans } from "@/lib/scanner/store";

/**
 * Security timeline endpoint — returns scan history for a given target.
 *
 * GET /api/scan/timeline?target=example.com
 *
 * Returns a timeline of scans for the target with score trends,
 * finding evolution, and grade changes.
 */
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const target = url.searchParams.get("target");

  if (!target) {
    return NextResponse.json({ error: "target parameter is required" }, { status: 400 });
  }

  const allScans = getRecentScans();

  // Match by hostname
  const targetHost = target.replace(/^https?:\/\//, "").replace(/\/.*/, "").toLowerCase();
  const matching = allScans
    .filter((s) => {
      try {
        return new URL(s.target).hostname.toLowerCase() === targetHost;
      } catch {
        return s.target.toLowerCase().includes(targetHost);
      }
    })
    .filter((s) => s.status === "completed")
    .sort((a, b) => (a.completedAt || a.startedAt).localeCompare(b.completedAt || b.startedAt));

  if (matching.length === 0) {
    return NextResponse.json({ error: "No completed scans found for this target" }, { status: 404 });
  }

  const timeline = matching.map((s, i) => ({
    id: s.id,
    date: s.completedAt || s.startedAt,
    grade: s.grade,
    score: s.score,
    findings: s.findings,
    summary: s.summary,
    mode: s.mode,
    ...(i > 0 ? {
      delta: {
        score: s.score - matching[i - 1].score,
        findings: s.findings - matching[i - 1].findings,
        critical: s.summary.critical - matching[i - 1].summary.critical,
        high: s.summary.high - matching[i - 1].summary.high,
      },
    } : {}),
  }));

  // Calculate trend
  const scores = matching.map((s) => s.score);
  const firstScore = scores[0];
  const lastScore = scores[scores.length - 1];
  const trend = lastScore - firstScore;
  const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);

  // Best and worst scans
  const best = matching.reduce((a, b) => (a.score > b.score ? a : b));
  const worst = matching.reduce((a, b) => (a.score < b.score ? a : b));

  return NextResponse.json({
    target: targetHost,
    scans: timeline.length,
    trend: {
      direction: trend > 0 ? "improving" : trend < 0 ? "declining" : "stable",
      delta: trend,
      avgScore,
      bestScore: best.score,
      bestGrade: best.grade,
      worstScore: worst.score,
      worstGrade: worst.grade,
    },
    latest: {
      id: matching[matching.length - 1].id,
      grade: matching[matching.length - 1].grade,
      score: matching[matching.length - 1].score,
      date: matching[matching.length - 1].completedAt || matching[matching.length - 1].startedAt,
    },
    timeline,
  });
}
