import { NextResponse } from "next/server";
import { startScan } from "@/lib/scanner";
import { getActiveScansCount, findActiveScan } from "@/lib/scanner/store";

const MAX_CONCURRENT_SCANS = 10;

// Rate limiting: per-target + global per-IP
const recentScans = new Map<string, number[]>();
const globalScans = new Map<string, number[]>();
const RATE_LIMIT_WINDOW = 5 * 60 * 1000;
const RATE_LIMIT_MAX = 3; // per target per 5 min
const GLOBAL_RATE_LIMIT_MAX = 20; // per IP per 5 min
let lastCleanup = Date.now();

// Hostnames that should never be scanned (cloud metadata, internal services)
const BLOCKED_HOSTNAMES = new Set([
  "metadata.google.internal",
  "metadata.google.com",
  "kubernetes.default.svc",
  "kubernetes.default",
]);

const isPrivateHost = (host: string): boolean => {
  if (host === "localhost" || host === "0.0.0.0" || host === "::1") return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  // Block any hostname ending in .internal or .local
  if (host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localhost")) return true;
  // IPv4-mapped IPv6
  if (host.startsWith("::ffff:")) return isPrivateHost(host.slice(7));
  // IPv6 loopback/private
  if (host.startsWith("fd") || host.startsWith("fe80:") || host.startsWith("fc")) return true;
  // IPv4 checks
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p))) return false;
  const [a, b] = parts;
  if (a === 127) return true; // 127.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (link-local + cloud metadata)
  if (a === 0) return true; // 0.0.0.0/8
  return false;
};

export async function POST(req: Request) {
  const body = await req.json() as { url?: string; callbackUrl?: string; mode?: "full" | "security" | "quick"; minScore?: number; failOnCritical?: boolean };
  const url = typeof body.url === "string" ? body.url.trim() : "";
  // Validate callback URL — only allow public HTTPS URLs
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
  const mode = body.mode === "security" ? "security" : body.mode === "quick" ? "quick" : "full";

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
  if (isPrivateHost(parsed.hostname)) {
    return NextResponse.json(
      { error: "Cannot scan private/local addresses" },
      { status: 400 },
    );
  }

  // Rate limiting + periodic cleanup
  const targetHost = parsed.hostname;
  const clientIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown";
  const now = Date.now();
  if (now - lastCleanup > RATE_LIMIT_WINDOW) {
    for (const map of [recentScans, globalScans]) {
      for (const [key, ts] of map) {
        const fresh = ts.filter((t) => now - t < RATE_LIMIT_WINDOW);
        if (fresh.length === 0) map.delete(key);
        else map.set(key, fresh);
      }
    }
    lastCleanup = now;
  }

  // Global per-IP rate limit
  const ipTimestamps = (globalScans.get(clientIp) || []).filter((t) => now - t < RATE_LIMIT_WINDOW);
  if (ipTimestamps.length >= GLOBAL_RATE_LIMIT_MAX) {
    return NextResponse.json(
      { error: `Rate limited: max ${GLOBAL_RATE_LIMIT_MAX} scans per 5 minutes. Try again later.` },
      { status: 429 },
    );
  }

  // Per-target rate limit
  const timestamps = (recentScans.get(targetHost) || []).filter((t) => now - t < RATE_LIMIT_WINDOW);
  if (timestamps.length >= RATE_LIMIT_MAX) {
    return NextResponse.json(
      { error: `Rate limited: max ${RATE_LIMIT_MAX} scans per target every 5 minutes. Try again later.` },
      { status: 429 },
    );
  }
  timestamps.push(now);
  recentScans.set(targetHost, timestamps);
  ipTimestamps.push(now);
  globalScans.set(clientIp, ipTimestamps);

  // Concurrency limit
  if (getActiveScansCount() >= MAX_CONCURRENT_SCANS) {
    return NextResponse.json(
      { error: `Server busy: ${MAX_CONCURRENT_SCANS} scans are already running. Try again in a minute.` },
      { status: 503 },
    );
  }

  // Deduplicate: if an identical scan is already running, return its ID
  const existingScan = findActiveScan(parsed.href);
  if (existingScan) {
    return NextResponse.json({
      id: existingScan.id,
      url: parsed.href,
      deduplicated: true,
      message: "A scan for this URL is already in progress.",
    });
  }

  // CI/CD gating parameters
  const minScore = typeof body.minScore === "number" && body.minScore >= 0 && body.minScore <= 100 ? Math.round(body.minScore) : undefined;
  const failOnCritical = body.failOnCritical === true;

  const scanId = crypto.randomUUID();
  const gateConfig = (minScore !== undefined || failOnCritical) ? { minScore, failOnCritical } : undefined;
  startScan(scanId, parsed.href, callbackUrl, mode, gateConfig);

  return NextResponse.json({
    id: scanId,
    url: parsed.href,
    ...(minScore !== undefined ? { minScore } : {}),
    ...(failOnCritical ? { failOnCritical } : {}),
  });
}
