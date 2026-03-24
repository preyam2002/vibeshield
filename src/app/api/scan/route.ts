import { NextResponse } from "next/server";
import { startScan } from "@/lib/scanner";

export async function POST(req: Request) {
  const body = await req.json() as { url?: string; callbackUrl?: string };
  const url = body.url?.trim();
  const callbackUrl = body.callbackUrl?.trim();

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

  const scanId = crypto.randomUUID();
  startScan(scanId, parsed.href, callbackUrl);

  return NextResponse.json({ id: scanId, url: parsed.href });
}
