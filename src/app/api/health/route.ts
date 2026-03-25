import { NextResponse } from "next/server";
import { getActiveScansCount, getStats } from "@/lib/scanner/store";
import { MAX_CONCURRENT_SCANS } from "@/lib/scanner/config";
import { isAuthEnabled } from "@/lib/auth";

/**
 * Health check endpoint for monitoring and load balancers.
 *
 * GET /api/health
 * Returns 200 if healthy, 503 if overloaded.
 */
export async function GET() {
  const stats = getStats();
  const activeScans = getActiveScansCount();
  const healthy = activeScans < MAX_CONCURRENT_SCANS;

  return NextResponse.json(
    {
      status: healthy ? "healthy" : "overloaded",
      version: "1.0.0",
      uptime: Math.floor(process.uptime()),
      auth: isAuthEnabled ? "enabled" : "disabled",
      scanner: {
        activeScans,
        maxConcurrent: MAX_CONCURRENT_SCANS,
        completedScans: stats.completedScans,
        totalFindings: stats.totalFindings,
        uniqueTargets: stats.uniqueTargets,
        avgScore: stats.avgScore,
      },
    },
    { status: healthy ? 200 : 503 },
  );
}
