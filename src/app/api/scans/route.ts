import { NextResponse, type NextRequest } from "next/server";
import { getRecentScans } from "@/lib/scanner/store";
import { dbAvailable, dbGetRecentScans } from "@/lib/db";

const LIMIT = 100;

export const GET = (req: NextRequest) => {
  const target = req.nextUrl.searchParams.get("target");
  const status = req.nextUrl.searchParams.get("status");
  let scans = getRecentScans();

  // Back-fill from SQLite when in-memory store has fewer than limit
  if (dbAvailable && scans.length < LIMIT) {
    const dbScans = dbGetRecentScans(LIMIT);
    const memIds = new Set(scans.map((s) => s.id));
    for (const s of dbScans) {
      if (memIds.has(s.id)) continue;
      scans.push({
        id: s.id, target: s.target, grade: s.grade, score: s.score,
        status: s.status, findings: s.summary.total, summary: s.summary,
        startedAt: s.startedAt, completedAt: s.completedAt, mode: s.mode,
      });
      if (scans.length >= LIMIT) break;
    }
  }

  if (target) {
    const lower = target.toLowerCase();
    scans = scans.filter((s) => {
      try { return new URL(s.target).hostname.toLowerCase().includes(lower); } catch { return s.target.toLowerCase().includes(lower); }
    });
  }
  if (status && ["completed", "scanning", "failed", "queued"].includes(status)) {
    scans = scans.filter((s) => s.status === status);
  }
  return NextResponse.json(scans);
};
