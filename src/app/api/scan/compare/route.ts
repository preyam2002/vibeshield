import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

/**
 * Scan comparison endpoint — diffs two completed scans.
 *
 * GET /api/scan/compare?a=<scanId>&b=<scanId>
 */
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const idA = url.searchParams.get("a");
  const idB = url.searchParams.get("b");

  if (!idA || !idB) {
    return NextResponse.json({ error: "Both 'a' and 'b' scan IDs are required" }, { status: 400 });
  }

  const scanA = getScan(idA);
  const scanB = getScan(idB);

  if (!scanA) return NextResponse.json({ error: `Scan ${idA} not found` }, { status: 404 });
  if (!scanB) return NextResponse.json({ error: `Scan ${idB} not found` }, { status: 404 });
  if (scanA.status !== "completed") return NextResponse.json({ error: `Scan ${idA} is not completed` }, { status: 422 });
  if (scanB.status !== "completed") return NextResponse.json({ error: `Scan ${idB} is not completed` }, { status: 422 });

  const findingKey = (f: { module: string; title: string }) => `${f.module}::${f.title}`;

  const keysA = new Set(scanA.findings.map(findingKey));
  const keysB = new Set(scanB.findings.map(findingKey));

  const newFindings = scanB.findings.filter((f) => !keysA.has(findingKey(f)));
  const fixedFindings = scanA.findings.filter((f) => !keysB.has(findingKey(f)));
  const persistentFindings = scanB.findings.filter((f) => keysA.has(findingKey(f)));

  // Severity changes (same finding, different severity)
  const severityChanges: { module: string; title: string; oldSeverity: string; newSeverity: string }[] = [];
  const findingMapA = new Map(scanA.findings.map((f) => [findingKey(f), f]));
  for (const f of persistentFindings) {
    const prev = findingMapA.get(findingKey(f));
    if (prev && prev.severity !== f.severity) {
      severityChanges.push({ module: f.module, title: f.title, oldSeverity: prev.severity, newSeverity: f.severity });
    }
  }

  // Module-level comparison
  const moduleMapA = new Map(scanA.modules.map((m) => [m.name, m]));
  const moduleMapB = new Map(scanB.modules.map((m) => [m.name, m]));
  const allModuleNames = new Set([...moduleMapA.keys(), ...moduleMapB.keys()]);
  const moduleComparison = Array.from(allModuleNames).map((name) => {
    const a = moduleMapA.get(name);
    const b = moduleMapB.get(name);
    return {
      name,
      statusA: a?.status || "absent",
      statusB: b?.status || "absent",
      findingsA: a?.findingsCount || 0,
      findingsB: b?.findingsCount || 0,
      delta: (b?.findingsCount || 0) - (a?.findingsCount || 0),
      durationA: a?.durationMs,
      durationB: b?.durationMs,
    };
  }).sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));

  return NextResponse.json({
    scanA: {
      id: scanA.id, target: scanA.target, grade: scanA.grade, score: scanA.score,
      date: scanA.completedAt || scanA.startedAt, mode: scanA.mode, summary: scanA.summary,
    },
    scanB: {
      id: scanB.id, target: scanB.target, grade: scanB.grade, score: scanB.score,
      date: scanB.completedAt || scanB.startedAt, mode: scanB.mode, summary: scanB.summary,
    },
    delta: {
      score: scanB.score - scanA.score,
      grade: { from: scanA.grade, to: scanB.grade },
      findings: scanB.summary.total - scanA.summary.total,
      critical: scanB.summary.critical - scanA.summary.critical,
      high: scanB.summary.high - scanA.summary.high,
      medium: scanB.summary.medium - scanA.summary.medium,
      low: scanB.summary.low - scanA.summary.low,
    },
    newFindings: newFindings.map((f) => ({ module: f.module, title: f.title, severity: f.severity, cwe: f.cwe })),
    fixedFindings: fixedFindings.map((f) => ({ module: f.module, title: f.title, severity: f.severity, cwe: f.cwe })),
    persistentFindings: persistentFindings.length,
    severityChanges,
    modules: moduleComparison,
  });
}
