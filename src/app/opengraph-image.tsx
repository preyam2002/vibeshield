import { ImageResponse } from "next/og";

export const runtime = "nodejs";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
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
        <div style={{ display: "flex", fontSize: 48, fontWeight: 900, background: "linear-gradient(to right, #ef4444, #f97316, #fbbf24)", backgroundClip: "text", color: "transparent", marginBottom: 24 }}>
          VibeShield
        </div>
        <div style={{ display: "flex", fontSize: 36, fontWeight: 700, color: "#e4e4e7", textAlign: "center", maxWidth: 800, lineHeight: 1.3 }}>
          Pentest your vibe-coded app
        </div>
        <div style={{ display: "flex", fontSize: 20, color: "#71717a", marginTop: 20, textAlign: "center", maxWidth: 700 }}>
          39 attack modules. No code access needed. Results in minutes.
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 40 }}>
          {["SQLi", "XSS", "SSRF", "IDOR", "CORS", "JWT", "RLS", "CSRF"].map((tag) => (
            <div key={tag} style={{ display: "flex", fontSize: 14, color: "#a1a1aa", backgroundColor: "#27272a", borderRadius: 8, padding: "6px 14px", border: "1px solid #3f3f46" }}>
              {tag}
            </div>
          ))}
        </div>
      </div>
    ),
    { ...size },
  );
}
