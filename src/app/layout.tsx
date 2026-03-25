import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VibeShield — Pentest Your Vibe-Coded App",
  description: "Black-box security scanner for vibe-coded apps. Paste a URL, run 47 attack modules, get a severity-ranked report with fix instructions. No code access needed.",
  metadataBase: new URL(process.env.NEXT_PUBLIC_URL || "https://vibeshield.dev"),
  icons: { icon: "/favicon.svg", apple: "/favicon.svg" },
  openGraph: {
    title: "VibeShield — Pentest Your Vibe-Coded App",
    description: "47 attack modules. No code access needed. Results in minutes.",
    type: "website",
    siteName: "VibeShield",
  },
  twitter: {
    card: "summary_large_image",
    title: "VibeShield — Pentest Your Vibe-Coded App",
    description: "47 attack modules. No code access needed. Results in minutes.",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-zinc-950 text-zinc-100 antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
