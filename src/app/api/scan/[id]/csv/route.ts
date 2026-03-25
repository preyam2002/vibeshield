import { NextResponse } from "next/server";
import { getScan } from "@/lib/scanner/store";

const escCsv = (s: string) => {
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
};

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const meta = [
    `# VibeShield Scan Report`,
    `# Target: ${scan.target}`,
    `# Scan ID: ${scan.id}`,
    `# Grade: ${scan.grade} (${scan.score}/100)`,
    `# Mode: ${scan.mode}`,
    `# Scanned: ${scan.startedAt}`,
    ...(scan.completedAt ? [`# Duration: ${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)}s`] : []),
    `# Findings: ${scan.summary.total} (${scan.summary.critical} critical, ${scan.summary.high} high, ${scan.summary.medium} medium, ${scan.summary.low} low)`,
  ];
  const header = "Severity,Module,Title,Description,Remediation,CWE,OWASP,Confidence,Endpoint";
  const rows = scan.findings.map((f) =>
    [f.severity, f.module, f.title, f.description, f.remediation, f.cwe || "", f.owasp || "", f.confidence !== undefined ? String(f.confidence) : "", f.endpoint || ""]
      .map(escCsv)
      .join(","),
  );
  const csv = [...meta, header, ...rows].join("\n");

  return new Response(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="vibeshield-${id}.csv"`,
    },
  });
}
