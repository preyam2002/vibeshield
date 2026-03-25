import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";
import type { Finding } from "@/lib/scanner/types";

/**
 * Prioritized remediation plan for a completed scan.
 *
 * GET /api/scan/:id/remediation
 *
 * Groups findings by effort level and returns a prioritized action list
 * with estimated fix difficulty, impact score, and ROI ranking.
 */

const EFFORT_MAP: Record<string, "quick" | "moderate" | "significant"> = {
  "security-headers": "quick",
  headers: "quick",
  cookies: "quick",
  clickjacking: "quick",
  cors: "quick",
  ssl: "quick",
  csp: "quick",
  privacy: "quick",
  "source-maps": "quick",
  "env-leak": "moderate",
  directories: "moderate",
  "info-leak": "moderate",
  secrets: "moderate",
  session: "moderate",
  "jwt-check": "moderate",
  "rate-limit": "moderate",
  "open-redirect": "moderate",
  csrf: "moderate",
  "email-enum": "moderate",
  "api-security": "moderate",
  xss: "significant",
  sqli: "significant",
  ssti: "significant",
  "command-injection": "significant",
  ssrf: "significant",
  "path-traversal": "significant",
  idor: "significant",
  "auth-bypass": "significant",
  "business-logic": "significant",
  "request-smuggling": "significant",
  firebase: "significant",
  supabase: "significant",
};

const SEVERITY_IMPACT: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 2, info: 0 };
const EFFORT_COST: Record<string, number> = { quick: 1, moderate: 3, significant: 7 };

interface PrioritizedFinding {
  title: string;
  module: string;
  severity: string;
  cwe?: string;
  remediation: string;
  effort: "quick" | "moderate" | "significant";
  impact: number;
  roi: number;
}

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = getScan(id);

  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  if (scan.status !== "completed") return NextResponse.json({ error: "Scan not completed" }, { status: 422 });

  const actionable = scan.findings.filter((f) => f.severity !== "info");

  const prioritized: PrioritizedFinding[] = actionable.map((f) => {
    const moduleKey = f.module.toLowerCase().replace(/[^a-z-]/g, "");
    const effort = EFFORT_MAP[moduleKey] || "moderate";
    const impact = SEVERITY_IMPACT[f.severity] || 0;
    const confidence = (f.confidence ?? 75) / 100;
    const roi = (impact * confidence) / EFFORT_COST[effort];

    return {
      title: f.title,
      module: f.module,
      severity: f.severity,
      cwe: f.cwe,
      remediation: f.remediation,
      effort,
      impact,
      roi: Math.round(roi * 100) / 100,
    };
  }).sort((a, b) => b.roi - a.roi);

  const quick = prioritized.filter((f) => f.effort === "quick");
  const moderate = prioritized.filter((f) => f.effort === "moderate");
  const significant = prioritized.filter((f) => f.effort === "significant");

  // Score potential: if all findings were fixed, what would the grade be
  const potentialScore = 100;
  const currentScore = scan.score;

  return NextResponse.json({
    scanId: id,
    target: scan.target,
    currentGrade: scan.grade,
    currentScore,
    potentialScore,
    totalActions: prioritized.length,
    summary: {
      quickWins: quick.length,
      moderateEffort: moderate.length,
      significantEffort: significant.length,
    },
    phases: [
      {
        name: "Quick Wins",
        description: "Configuration changes, header additions, and simple fixes that can be deployed immediately.",
        effort: "minutes to hours",
        actions: quick,
      },
      {
        name: "Moderate Effort",
        description: "Code changes requiring testing, credential rotation, or moderate refactoring.",
        effort: "hours to days",
        actions: moderate,
      },
      {
        name: "Significant Effort",
        description: "Architectural changes, input validation overhauls, or security model redesigns.",
        effort: "days to weeks",
        actions: significant,
      },
    ],
  });
}
