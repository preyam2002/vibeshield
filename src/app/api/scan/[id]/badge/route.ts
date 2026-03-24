import { NextResponse, type NextRequest } from "next/server";
import { getScan } from "@/lib/scanner/store";

const GRADE_COLORS: Record<string, string> = {
  A: "4ade80", "A-": "4ade80",
  "B+": "a3e635", B: "a3e635",
  "C+": "facc15", C: "facc15",
  "D+": "fb923c", D: "fb923c",
  F: "f87171",
  "-": "71717a",
};

export const GET = async (_req: NextRequest, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const scan = getScan(id);
  const grade = scan?.grade || "-";
  const color = GRADE_COLORS[grade] || "71717a";
  const score = scan?.score ?? "?";

  // shields.io compatible SVG badge
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20" role="img">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="130" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="75" height="20" fill="#555"/>
    <rect x="75" width="55" height="20" fill="#${color}"/>
    <rect width="130" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="37.5" y="14">VibeShield</text>
    <text x="102.5" y="14">${grade} ${score}</text>
  </g>
</svg>`;

  return new NextResponse(svg, {
    headers: {
      "Content-Type": "image/svg+xml",
      "Cache-Control": "no-cache, no-store",
    },
  });
};
