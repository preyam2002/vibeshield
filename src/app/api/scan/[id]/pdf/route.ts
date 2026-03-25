import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";
import type { Finding } from "@/lib/scanner/types";

const severityColor = (s: string) => {
  switch (s) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#3b82f6";
    default: return "#6b7280";
  }
};

const gradeColor = (grade: string) => {
  if (grade.startsWith("A")) return "#22c55e";
  if (grade.startsWith("B")) return "#84cc16";
  if (grade.startsWith("C")) return "#eab308";
  if (grade.startsWith("D")) return "#f97316";
  return "#ef4444";
};

const escapeHtml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const findingHtml = (f: Finding) => `
<div class="finding">
  <div class="finding-header">
    <span class="severity-badge" style="background:${severityColor(f.severity)}">${f.severity.toUpperCase()}</span>
    <span class="finding-title">${escapeHtml(f.title)}</span>
  </div>
  <p class="finding-desc">${escapeHtml(f.description)}</p>
  ${f.evidence ? `<div class="evidence"><strong>Evidence</strong><pre>${escapeHtml(f.evidence)}</pre></div>` : ""}
  <div class="remediation"><strong>Fix:</strong> ${escapeHtml(f.remediation)}</div>
  ${f.cwe || f.owasp ? `<div class="refs">${[f.cwe, f.owasp ? `OWASP ${f.owasp}` : ""].filter(Boolean).join(" · ")}</div>` : ""}
</div>`;

export const GET = (_req: NextRequest, { params }: { params: Promise<{ id: string }> }) => {
  return params.then(({ id }) => {
    const scan = getScan(id);
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const hostname = new URL(scan.target).hostname;
    const s = scan.summary;
    const duration = scan.completedAt
      ? Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)
      : null;

    const grouped = new Map<string, Finding[]>();
    for (const f of scan.findings) {
      if (!grouped.has(f.module)) grouped.set(f.module, []);
      grouped.get(f.module)!.push(f);
    }

    const moduleSections = Array.from(grouped.entries())
      .map(([mod, findings]) => `
        <div class="module-section">
          <h3>${escapeHtml(mod)} <span class="module-count">${findings.length} finding${findings.length !== 1 ? "s" : ""}</span></h3>
          ${findings.map(findingHtml).join("")}
        </div>
      `).join("");

    const completed = scan.modules.filter((m) => m.status === "completed");
    const passed = completed.filter((m) => m.findingsCount === 0);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>VibeShield Report — ${escapeHtml(hostname)}</title>
<style>
  @page { margin: 1.5cm; size: A4; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a2e; line-height: 1.5; font-size: 11px; background: #fff; }
  .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e5e7eb; padding-bottom: 16px; margin-bottom: 20px; }
  .header-left h1 { font-size: 22px; font-weight: 800; color: #dc2626; }
  .header-left .subtitle { color: #6b7280; font-size: 12px; margin-top: 2px; }
  .grade-box { text-align: center; padding: 12px 20px; border-radius: 10px; border: 2px solid ${gradeColor(scan.grade)}; }
  .grade-letter { font-size: 36px; font-weight: 900; color: ${gradeColor(scan.grade)}; line-height: 1; }
  .grade-score { font-size: 11px; color: #6b7280; }
  .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }
  .meta-item { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px; }
  .meta-label { font-size: 9px; text-transform: uppercase; color: #9ca3af; font-weight: 600; letter-spacing: 0.5px; }
  .meta-value { font-size: 14px; font-weight: 700; margin-top: 2px; }
  .summary-bar { display: flex; gap: 8px; margin-bottom: 20px; }
  .summary-item { flex: 1; text-align: center; padding: 8px; border-radius: 6px; border: 1px solid #e5e7eb; }
  .summary-count { font-size: 20px; font-weight: 800; }
  .summary-label { font-size: 9px; text-transform: uppercase; color: #6b7280; }
  .module-section { margin-bottom: 16px; page-break-inside: avoid; }
  .module-section h3 { font-size: 14px; font-weight: 700; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; margin-bottom: 8px; }
  .module-count { font-weight: 400; color: #9ca3af; font-size: 11px; }
  .finding { background: #fafafa; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px; margin-bottom: 8px; page-break-inside: avoid; }
  .finding-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .severity-badge { color: #fff; font-size: 9px; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
  .finding-title { font-weight: 600; font-size: 12px; }
  .finding-desc { color: #374151; margin-bottom: 6px; }
  .evidence { margin: 6px 0; }
  .evidence pre { background: #1a1a2e; color: #e5e7eb; padding: 8px; border-radius: 4px; font-size: 9px; overflow-wrap: break-word; white-space: pre-wrap; max-height: 120px; overflow: hidden; }
  .remediation { color: #047857; font-size: 11px; margin-top: 4px; }
  .refs { font-size: 9px; color: #9ca3af; margin-top: 4px; }
  .modules-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 10px; }
  .modules-table th { text-align: left; background: #f3f4f6; padding: 4px 8px; border: 1px solid #e5e7eb; }
  .modules-table td { padding: 4px 8px; border: 1px solid #e5e7eb; }
  .status-pass { color: #22c55e; } .status-fail { color: #ef4444; } .status-warn { color: #f97316; }
  .footer { border-top: 1px solid #e5e7eb; padding-top: 10px; margin-top: 20px; text-align: center; color: #9ca3af; font-size: 9px; }
  .no-findings { text-align: center; padding: 40px; color: #22c55e; font-size: 16px; font-weight: 600; }
  @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>VibeShield</h1>
    <div class="subtitle">Security Report for <strong>${escapeHtml(hostname)}</strong></div>
  </div>
  <div class="grade-box">
    <div class="grade-letter">${escapeHtml(scan.grade)}</div>
    <div class="grade-score">${scan.score}/100</div>
  </div>
</div>

<div class="meta-grid">
  <div class="meta-item">
    <div class="meta-label">Target</div>
    <div class="meta-value" style="font-size:11px;word-break:break-all">${escapeHtml(scan.target)}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Scanned</div>
    <div class="meta-value" style="font-size:11px">${new Date(scan.startedAt).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Duration</div>
    <div class="meta-value">${duration ? `${duration}s` : "—"}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Mode</div>
    <div class="meta-value" style="text-transform:capitalize">${scan.mode}</div>
  </div>
</div>

<div class="summary-bar">
  <div class="summary-item"><div class="summary-count" style="color:${severityColor("critical")}">${s.critical}</div><div class="summary-label">Critical</div></div>
  <div class="summary-item"><div class="summary-count" style="color:${severityColor("high")}">${s.high}</div><div class="summary-label">High</div></div>
  <div class="summary-item"><div class="summary-count" style="color:${severityColor("medium")}">${s.medium}</div><div class="summary-label">Medium</div></div>
  <div class="summary-item"><div class="summary-count" style="color:${severityColor("low")}">${s.low}</div><div class="summary-label">Low</div></div>
  <div class="summary-item"><div class="summary-count" style="color:${severityColor("info")}">${s.info}</div><div class="summary-label">Info</div></div>
</div>

${scan.surface ? `
<div class="meta-grid">
  <div class="meta-item"><div class="meta-label">Pages</div><div class="meta-value">${scan.surface.pages}</div></div>
  <div class="meta-item"><div class="meta-label">API Endpoints</div><div class="meta-value">${scan.surface.apiEndpoints}</div></div>
  <div class="meta-item"><div class="meta-label">JS Bundles</div><div class="meta-value">${scan.surface.jsFiles}</div></div>
  <div class="meta-item"><div class="meta-label">Technologies</div><div class="meta-value" style="font-size:10px">${scan.technologies.slice(0, 6).join(", ") || "—"}</div></div>
</div>` : ""}

<h2 style="font-size:14px;margin-bottom:8px">Module Results</h2>
<table class="modules-table">
<thead><tr><th>Module</th><th>Status</th><th>Findings</th><th>Time</th></tr></thead>
<tbody>
${scan.modules.map((m) => `<tr>
  <td>${escapeHtml(m.name)}</td>
  <td class="${m.status === "completed" && m.findingsCount === 0 ? "status-pass" : m.status === "failed" ? "status-fail" : m.findingsCount > 0 ? "status-warn" : ""}">${m.status === "completed" && m.findingsCount === 0 ? "✓ Pass" : m.status === "completed" ? `⚠ ${m.findingsCount} found` : m.status === "failed" ? "✗ Error" : m.status}</td>
  <td>${m.findingsCount}</td>
  <td>${m.durationMs ? `${(m.durationMs / 1000).toFixed(1)}s` : "—"}</td>
</tr>`).join("")}
</tbody>
</table>

${scan.findings.length > 0 ? `<h2 style="font-size:14px;margin-bottom:12px">Findings (${s.total})</h2>${moduleSections}` : '<div class="no-findings">✅ No vulnerabilities found</div>'}

${scan.comparison ? `
<h2 style="font-size:14px;margin-bottom:8px">Comparison</h2>
<div class="meta-grid">
  <div class="meta-item"><div class="meta-label">Previous Grade</div><div class="meta-value">${escapeHtml(scan.comparison.previousGrade)}</div></div>
  <div class="meta-item"><div class="meta-label">Score Delta</div><div class="meta-value">${scan.comparison.delta.score > 0 ? "+" : ""}${scan.comparison.delta.score}</div></div>
  <div class="meta-item"><div class="meta-label">Finding Delta</div><div class="meta-value">${scan.comparison.delta.findings > 0 ? "+" : ""}${scan.comparison.delta.findings}</div></div>
  <div class="meta-item"><div class="meta-label">Previous Findings</div><div class="meta-value">${scan.comparison.previousFindings}</div></div>
</div>` : ""}

<div class="footer">
  Generated by VibeShield · Black-box pentesting for vibe-coded apps · ${new Date().toISOString().split("T")[0]}
</div>

</body>
</html>`;

    return new NextResponse(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": `inline; filename="vibeshield-${hostname}-report.html"`,
      },
    });
  });
};
