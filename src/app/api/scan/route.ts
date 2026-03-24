import { NextResponse } from "next/server";
import { startScan } from "@/lib/scanner";

// Simple in-memory rate limiter: max 3 scans per target per 5 minutes
const recentScans = new Map<string, number[]>();
const RATE_LIMIT_WINDOW = 5 * 60 * 1000;
const RATE_LIMIT_MAX = 3;

export async function POST(req: Request) {
  const body = await req.json() as { url?: string; callbackUrl?: string; mode?: "full" | "security" };
  const url = body.url?.trim();
  const callbackUrl = body.callbackUrl?.trim();
  const mode = body.mode === "security" ? "security" : "full";

  if (!url) {
    return NextResponse.json({ error: "URL is required" }, { status: 400 });
  }

  // Basic URL validation
  let parsed: URL;
  try {
    parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
  } catch {
    return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
  }

  // Block scanning localhost/private IPs
  const host = parsed.hostname;
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host.startsWith("192.168.") ||
    host.startsWith("10.") ||
    host.startsWith("172.") ||
    host === "::1"
  ) {
    return NextResponse.json(
      { error: "Cannot scan private/local addresses" },
      { status: 400 },
    );
  }

  // Rate limit per target hostname
  const targetHost = parsed.hostname;
  const now = Date.now();
  const timestamps = (recentScans.get(targetHost) || []).filter((t) => now - t < RATE_LIMIT_WINDOW);
  if (timestamps.length >= RATE_LIMIT_MAX) {
    return NextResponse.json(
      { error: `Rate limited: max ${RATE_LIMIT_MAX} scans per target every 5 minutes. Try again later.` },
      { status: 429 },
    );
  }
  timestamps.push(now);
  recentScans.set(targetHost, timestamps);

  const scanId = crypto.randomUUID();
  startScan(scanId, parsed.href, callbackUrl, mode);

  return NextResponse.json({ id: scanId, url: parsed.href });
}
