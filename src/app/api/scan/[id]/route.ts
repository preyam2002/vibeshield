import { NextResponse } from "next/server";
import { getScan, findPreviousScan, getPercentile, cancelScan, getScanHistory } from "@/lib/scanner/store";
import { dbAvailable, dbGetScan } from "@/lib/db";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = getScan(id) ?? (dbAvailable ? dbGetScan(id) : undefined);

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Include comparison data if there's a previous scan of the same target
  const prev = findPreviousScan(scan.target, scan.id);
  let comparison;
  if (prev && scan.status === "completed") {
    // Finding-level diff: match by module+title for stability
    const prevKeys = new Set(prev.findings.map((f) => `${f.module}::${f.title}`));
    const currKeys = new Set(scan.findings.map((f) => `${f.module}::${f.title}`));
    const newFindings = scan.findings.filter((f) => !prevKeys.has(`${f.module}::${f.title}`)).map((f) => ({ title: f.title, severity: f.severity, module: f.module }));
    const fixedFindings = prev.findings.filter((f) => !currKeys.has(`${f.module}::${f.title}`)).map((f) => ({ title: f.title, severity: f.severity, module: f.module }));

    comparison = {
      previousId: prev.id,
      previousGrade: prev.grade,
      previousScore: prev.score,
      previousFindings: prev.summary.total,
      delta: {
        score: scan.score - prev.score,
        findings: scan.summary.total - prev.summary.total,
        critical: scan.summary.critical - prev.summary.critical,
        high: scan.summary.high - prev.summary.high,
      },
      newFindings,
      fixedFindings,
    };
  }

  const percentile = scan.status === "completed" ? getPercentile(scan.score) : undefined;
  const history = scan.status === "completed" ? getScanHistory(scan.target) : undefined;
  const res = NextResponse.json({
    ...scan,
    comparison,
    ...(percentile !== undefined && percentile >= 0 ? { percentile } : {}),
    ...(history && history.length > 1 ? { history } : {}),
  });

  // Completed/failed scans are immutable — cache aggressively
  if (scan.status === "completed" || scan.status === "failed") {
    res.headers.set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
  } else {
    res.headers.set("Cache-Control", "no-store");
  }

  return res;
}

export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (scan.status !== "scanning") {
    return NextResponse.json({ error: "Scan is not running" }, { status: 409 });
  }
  cancelScan(id);
  return NextResponse.json({ id, status: "cancelled", message: "Scan cancelled successfully." });
}
