import { NextResponse, type NextRequest } from "next/server";
import { getRecentScans } from "@/lib/scanner/store";

export const GET = (req: NextRequest) => {
  const target = req.nextUrl.searchParams.get("target");
  const status = req.nextUrl.searchParams.get("status");
  let scans = getRecentScans();
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
