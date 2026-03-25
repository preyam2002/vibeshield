import { NextResponse } from "next/server";
import { getStats } from "@/lib/scanner/store";

export const GET = () => {
  const stats = getStats();
  return NextResponse.json({
    status: "ok",
    uptime: process.uptime(),
    scans: {
      total: stats.totalScans,
      completed: stats.completedScans,
      avgScore: stats.avgScore,
    },
  });
};
