import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

/**
 * Export scan results as JUnit XML.
 *
 * Most CI platforms (GitHub Actions, GitLab, Jenkins, CircleCI) natively
 * parse JUnit XML to display test results inline. Each finding becomes a
 * test case failure, grouped by module as test suites.
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
  if (scan.status !== "completed") {
    return NextResponse.json({ error: "Scan not yet completed" }, { status: 409 });
  }

  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");

  // Group findings by module
  const byModule = new Map<string, typeof scan.findings>();
  for (const f of scan.findings) {
    if (!byModule.has(f.module)) byModule.set(f.module, []);
    byModule.get(f.module)!.push(f);
  }

  // Also add passed modules (no findings) as successful test suites
  const passedModules = scan.modules
    .filter((m) => m.status === "completed" && !byModule.has(m.name))
    .map((m) => m.name);

  const duration = scan.completedAt && scan.startedAt
    ? ((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000).toFixed(1)
    : "0";

  const totalTests = scan.findings.length + passedModules.length;
  const failures = scan.findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
  const errors = 0;

  const suites: string[] = [];

  // Failed suites (modules with findings)
  for (const [module, findings] of byModule) {
    const modDuration = scan.modules.find((m) => m.name === module)?.durationMs;
    const suiteDur = modDuration ? (modDuration / 1000).toFixed(2) : "0";
    const suiteFailures = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;

    const testCases = findings.map((f) => {
      const isFail = f.severity === "critical" || f.severity === "high";
      const body = [
        f.description,
        f.evidence ? `\nEvidence:\n${f.evidence}` : "",
        `\nRemediation:\n${f.remediation}`,
        f.cwe ? `\nCWE: ${f.cwe}` : "",
        f.owasp ? `\nOWASP: ${f.owasp}` : "",
      ].join("");

      if (isFail) {
        return `      <testcase name="${esc(f.title)}" classname="${esc(module)}" time="0">
        <failure message="${esc(f.title)}" type="${f.severity}">${esc(body)}</failure>
      </testcase>`;
      }
      // Medium/low/info as non-failure test cases with system-out
      return `      <testcase name="${esc(f.title)}" classname="${esc(module)}" time="0">
        <system-out>${esc(body)}</system-out>
      </testcase>`;
    });

    suites.push(`  <testsuite name="${esc(module)}" tests="${findings.length}" failures="${suiteFailures}" errors="0" time="${suiteDur}">
${testCases.join("\n")}
  </testsuite>`);
  }

  // Passed suites
  for (const module of passedModules) {
    const modDuration = scan.modules.find((m) => m.name === module)?.durationMs;
    const suiteDur = modDuration ? (modDuration / 1000).toFixed(2) : "0";
    suites.push(`  <testsuite name="${esc(module)}" tests="1" failures="0" errors="0" time="${suiteDur}">
    <testcase name="No vulnerabilities found" classname="${esc(module)}" time="${suiteDur}" />
  </testsuite>`);
  }

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="VibeShield Security Scan" tests="${totalTests}" failures="${failures}" errors="${errors}" time="${duration}">
${suites.join("\n")}
</testsuites>`;

  return new NextResponse(xml, {
    headers: {
      "Content-Type": "application/xml",
      "Content-Disposition": `attachment; filename="vibeshield-${id}.xml"`,
    },
  });
};
