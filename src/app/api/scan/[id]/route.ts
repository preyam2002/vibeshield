import { NextResponse } from "next/server";
import { getScan, findPreviousScan } from "@/lib/scanner/store";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = getScan(id);

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Include comparison data if there's a previous scan of the same target
  const prev = findPreviousScan(scan.target, scan.id);
  const comparison = prev ? {
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
  } : undefined;

  return NextResponse.json({ ...scan, comparison });
}
