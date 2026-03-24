import { ImageResponse } from "next/og";
import { getScan } from "@/lib/scanner/store";

export const runtime = "nodejs";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const GRADE_COLORS: Record<string, string> = {
  A: "#4ade80", "A-": "#4ade80",
  "B+": "#a3e635", B: "#a3e635",
  "C+": "#facc15", C: "#facc15",
  "D+": "#fb923c", D: "#fb923c",
  F: "#f87171",
  "-": "#71717a",
};

export default async function Image({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const scan = getScan(id);

  const grade = scan?.grade || "-";
  const target = scan?.target || "Unknown";
  const hostname = (() => { try { return new URL(target).hostname; } catch { return target; } })();
  const total = scan?.summary.total || 0;
  const critical = scan?.summary.critical || 0;
  const high = scan?.summary.high || 0;
  const gradeColor = GRADE_COLORS[grade] || "#71717a";

  return new ImageResponse(
    (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          width: "100%",
          height: "100%",
          backgroundColor: "#09090b",
          fontFamily: "system-ui",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 24, marginBottom: 32 }}>
          <div style={{ fontSize: 32, fontWeight: 800, background: "linear-gradient(to right, #ef4444, #f97316)", backgroundClip: "text", color: "transparent" }}>
            VibeShield
          </div>
        </div>
        <div style={{ display: "flex", fontSize: 160, fontWeight: 900, color: gradeColor, lineHeight: 1 }}>
          {grade}
        </div>
        <div style={{ display: "flex", fontSize: 28, color: "#a1a1aa", marginTop: 16 }}>
          {hostname}
        </div>
        <div style={{ display: "flex", gap: 32, marginTop: 24, fontSize: 20 }}>
          <span style={{ color: "#71717a" }}>{total} findings</span>
          {critical > 0 && <span style={{ color: "#f87171" }}>{critical} critical</span>}
          {high > 0 && <span style={{ color: "#fb923c" }}>{high} high</span>}
        </div>
      </div>
    ),
    { ...size },
  );
}
