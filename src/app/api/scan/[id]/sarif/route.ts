import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

const SEVERITY_MAP: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SEVERITY_LEVEL: Record<string, string> = {
  critical: "9.0",
  high: "7.0",
  medium: "4.0",
  low: "2.0",
  info: "0.0",
};

export const GET = async (
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const rules = new Map<string, { id: string; name: string; description: string; cwe?: string }>();
  const results = [];

  for (const f of scan.findings) {
    const ruleId = f.id.replace(/-\d+$/, "");
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.title,
        description: f.description,
        cwe: f.cwe,
      });
    }

    results.push({
      ruleId,
      level: SEVERITY_MAP[f.severity] || "note",
      message: { text: `${f.title}\n\n${f.description}\n\nRemediation: ${f.remediation}` },
      properties: {
        severity: f.severity,
        module: f.module,
        "security-severity": SEVERITY_LEVEL[f.severity] || "0.0",
        ...(f.confidence !== undefined ? { confidence: f.confidence } : {}),
      },
      ...(f.evidence ? { fingerprints: { evidence: f.evidence.substring(0, 200) } } : {}),
      ...(f.endpoint ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.endpoint } } }] } : {}),
      rank: f.confidence ?? 80,
    });
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "VibeShield",
            version: "1.0.0",
            informationUri: "https://vibeshield.dev",
            rules: Array.from(rules.values()).map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.name },
              fullDescription: { text: r.description },
              properties: {
                ...(r.cwe ? { tags: [r.cwe] } : {}),
              },
            })),
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: scan.status === "completed",
            startTimeUtc: scan.startedAt,
            ...(scan.completedAt ? { endTimeUtc: scan.completedAt } : {}),
          },
        ],
      },
    ],
  };

  let hostname = "unknown";
  try { hostname = new URL(scan.target).hostname; } catch { /* skip */ }
  return new NextResponse(JSON.stringify(sarif, null, 2), {
    headers: {
      "Content-Type": "application/sarif+json",
      "Content-Disposition": `attachment; filename="vibeshield-${hostname}.sarif"`,
    },
  });
};
