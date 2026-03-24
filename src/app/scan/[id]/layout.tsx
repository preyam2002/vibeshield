import type { Metadata } from "next";
import { getScan } from "@/lib/scanner/store";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  const scan = getScan(id);

  if (!scan) {
    return { title: "Scan Not Found — VibeShield" };
  }

  const hostname = (() => { try { return new URL(scan.target).hostname; } catch { return scan.target; } })();
  const title = `${hostname} — Grade ${scan.grade} | VibeShield`;
  const description = `Security scan: ${scan.summary.total} findings (${scan.summary.critical} critical, ${scan.summary.high} high, ${scan.summary.medium} medium). Scanned with 40 attack modules.`;

  return {
    title,
    description,
    openGraph: { title, description },
    twitter: { card: "summary_large_image", title, description },
  };
}

export default function ScanLayout({ children }: { children: React.ReactNode }) {
  return children;
}
