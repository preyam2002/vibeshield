import { NextResponse } from "next/server";
import { startScan } from "@/lib/scanner";
import { getActiveScansCount, findActiveScan } from "@/lib/scanner/store";
import { MAX_CONCURRENT_SCANS } from "@/lib/scanner/config";

const MAX_BULK_URLS = 10;

const BLOCKED_HOSTNAMES = new Set([
  "metadata.google.internal", "metadata.google.com",
  "kubernetes.default.svc", "kubernetes.default",
]);

const isPrivateHost = (host: string): boolean => {
  if (host === "localhost" || host === "0.0.0.0" || host === "::1") return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localhost")) return true;
  if (host.startsWith("::ffff:")) return isPrivateHost(host.slice(7));
  if (host.startsWith("fd") || host.startsWith("fe80:") || host.startsWith("fc")) return true;
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p))) return false;
  const [a, b] = parts;
  if (a === 127 || a === 10 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
};

/**
 * Bulk scan endpoint — submit multiple URLs in one request.
 *
 * POST /api/scan/bulk
 * Body: { urls: string[], mode?: "full" | "security" | "quick", callbackUrl?: string }
 *
 * Returns: { scans: Array<{ url, id, error? }> }
 */
export async function POST(req: Request) {
  const body = await req.json() as {
    urls?: string[];
    mode?: "full" | "security" | "quick";
    callbackUrl?: string;
  };

  const urls = Array.isArray(body.urls) ? body.urls : [];
  if (urls.length === 0) {
    return NextResponse.json({ error: "urls array is required" }, { status: 400 });
  }
  if (urls.length > MAX_BULK_URLS) {
    return NextResponse.json({ error: `Maximum ${MAX_BULK_URLS} URLs per bulk request` }, { status: 400 });
  }

  const mode = body.mode === "security" ? "security" : body.mode === "quick" ? "quick" : "full";

  // Validate callback URL
  let callbackUrl: string | undefined;
  if (typeof body.callbackUrl === "string" && body.callbackUrl.trim()) {
    try {
      const cbUrl = new URL(body.callbackUrl.trim());
      if (cbUrl.protocol !== "https:") {
        return NextResponse.json({ error: "Callback URL must use HTTPS" }, { status: 400 });
      }
      if (isPrivateHost(cbUrl.hostname)) {
        return NextResponse.json({ error: "Callback URL cannot point to private addresses" }, { status: 400 });
      }
      callbackUrl = cbUrl.href;
    } catch {
      return NextResponse.json({ error: "Invalid callback URL" }, { status: 400 });
    }
  }

  const activeCount = getActiveScansCount();
  const slotsAvailable = MAX_CONCURRENT_SCANS - activeCount;

  const results: { url: string; id?: string; deduplicated?: boolean; error?: string }[] = [];

  let started = 0;
  for (const rawUrl of urls) {
    const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
    if (!url) {
      results.push({ url: rawUrl, error: "Empty URL" });
      continue;
    }

    let parsed: URL;
    try {
      parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
    } catch {
      results.push({ url, error: "Invalid URL" });
      continue;
    }

    if (isPrivateHost(parsed.hostname)) {
      results.push({ url: parsed.href, error: "Cannot scan private/local addresses" });
      continue;
    }

    // Dedup: reuse active scan
    const existing = findActiveScan(parsed.href);
    if (existing) {
      results.push({ url: parsed.href, id: existing.id, deduplicated: true });
      continue;
    }

    if (started >= slotsAvailable) {
      results.push({ url: parsed.href, error: "Server busy — too many concurrent scans" });
      continue;
    }

    const scanId = crypto.randomUUID();
    startScan(scanId, parsed.href, callbackUrl, mode);
    results.push({ url: parsed.href, id: scanId });
    started++;
  }

  return NextResponse.json({
    scans: results,
    mode,
    total: results.length,
    started: results.filter((r) => r.id && !r.deduplicated).length,
    deduplicated: results.filter((r) => r.deduplicated).length,
    failed: results.filter((r) => r.error).length,
  });
}
