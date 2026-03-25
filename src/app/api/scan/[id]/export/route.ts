import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

export const GET = (_req: NextRequest, { params }: { params: Promise<{ id: string }> }) => {
  return params.then(({ id }) => {
    const scan = getScan(id);
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const report = {
      tool: "VibeShield",
      version: "1.0.0",
      exportedAt: new Date().toISOString(),
      target: scan.target,
      grade: scan.grade,
      score: scan.score,
      status: scan.status,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      technologies: scan.technologies,
      isSpa: scan.isSpa,
      summary: scan.summary,
      findings: scan.findings.map((f) => ({
        severity: f.severity,
        module: f.module,
        title: f.title,
        description: f.description,
        evidence: f.evidence,
        remediation: f.remediation,
        cwe: f.cwe,
        owasp: f.owasp,
      })),
    };

    let hostname = "unknown";
    try { hostname = new URL(scan.target).hostname; } catch { /* skip */ }

    return new NextResponse(JSON.stringify(report, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="vibeshield-${hostname}-${scan.grade}.json"`,
      },
    });
  });
};
