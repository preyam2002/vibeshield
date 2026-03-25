import { NextResponse, type NextRequest } from "next/server";
import { startScan } from "@/lib/scanner";
import { findActiveScan } from "@/lib/scanner/store";
import { validateApiKey } from "@/lib/auth";

interface ScheduledScan {
  id: string;
  url: string;
  mode: "full" | "security" | "quick";
  callbackUrl?: string;
  cronHours: number;
  createdAt: string;
  lastRunAt?: string;
  lastScanId?: string;
  nextRunAt: string;
  runCount: number;
  enabled: boolean;
}

const globalForSchedule = globalThis as unknown as {
  __vibeshieldSchedules?: Map<string, ScheduledScan>;
  __vibeshieldScheduleTimer?: ReturnType<typeof setInterval>;
};
if (!globalForSchedule.__vibeshieldSchedules) globalForSchedule.__vibeshieldSchedules = new Map();
const schedules = globalForSchedule.__vibeshieldSchedules;

const BLOCKED_HOSTNAMES = new Set([
  "metadata.google.internal", "metadata.google.com",
  "kubernetes.default.svc", "kubernetes.default",
]);

const isPrivateHost = (host: string): boolean => {
  if (host === "localhost" || host === "0.0.0.0" || host === "::1") return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localhost")) return true;
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p))) return false;
  const [a, b] = parts;
  if (a === 127 || a === 10 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
};

// Run scheduled scans
const checkSchedules = () => {
  const now = new Date();
  for (const schedule of schedules.values()) {
    if (!schedule.enabled) continue;
    if (new Date(schedule.nextRunAt) > now) continue;

    // Don't start if one is already running for this URL
    if (findActiveScan(schedule.url)) continue;

    const scanId = crypto.randomUUID();
    startScan(scanId, schedule.url, schedule.callbackUrl, schedule.mode);
    schedule.lastRunAt = now.toISOString();
    schedule.lastScanId = scanId;
    schedule.runCount++;
    schedule.nextRunAt = new Date(now.getTime() + schedule.cronHours * 3600_000).toISOString();
  }
};

// Start the scheduler (check every 60 seconds)
if (!globalForSchedule.__vibeshieldScheduleTimer) {
  globalForSchedule.__vibeshieldScheduleTimer = setInterval(checkSchedules, 60_000);
}

/**
 * Create a scheduled recurring scan.
 *
 * POST /api/scan/schedule
 * Body: { url, mode?, callbackUrl?, intervalHours? }
 */
export async function POST(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid) return NextResponse.json({ error: auth.error }, { status: 401 });
  const body = await req.json() as {
    url?: string;
    mode?: "full" | "security" | "quick";
    callbackUrl?: string;
    intervalHours?: number;
  };

  const url = typeof body.url === "string" ? body.url.trim() : "";
  if (!url) {
    return NextResponse.json({ error: "URL is required" }, { status: 400 });
  }

  let parsed: URL;
  try {
    parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
  } catch {
    return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
  }

  if (isPrivateHost(parsed.hostname)) {
    return NextResponse.json({ error: "Cannot scan private/local addresses" }, { status: 400 });
  }

  const mode = body.mode === "security" ? "security" : body.mode === "quick" ? "quick" : "full";
  const intervalHours = Math.max(1, Math.min(168, Number(body.intervalHours) || 24)); // 1h to 7d, default 24h

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

  // Check for existing schedule for same URL
  for (const schedule of schedules.values()) {
    if (schedule.url === parsed.href && schedule.enabled) {
      return NextResponse.json({
        error: "Schedule already exists for this URL",
        scheduleId: schedule.id,
      }, { status: 409 });
    }
  }

  if (schedules.size >= 50) {
    return NextResponse.json({ error: "Maximum 50 scheduled scans" }, { status: 400 });
  }

  const id = crypto.randomUUID();
  const now = new Date();
  const schedule: ScheduledScan = {
    id,
    url: parsed.href,
    mode,
    callbackUrl,
    cronHours: intervalHours,
    createdAt: now.toISOString(),
    nextRunAt: now.toISOString(), // Run immediately on first trigger
    runCount: 0,
    enabled: true,
  };

  schedules.set(id, schedule);

  return NextResponse.json({
    id,
    url: parsed.href,
    mode,
    intervalHours,
    nextRunAt: schedule.nextRunAt,
  });
}

/**
 * List all scheduled scans.
 */
export async function GET() {
  return NextResponse.json(
    Array.from(schedules.values())
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((s) => ({
        id: s.id,
        url: s.url,
        mode: s.mode,
        intervalHours: s.cronHours,
        enabled: s.enabled,
        runCount: s.runCount,
        lastRunAt: s.lastRunAt,
        lastScanId: s.lastScanId,
        nextRunAt: s.nextRunAt,
        createdAt: s.createdAt,
      })),
  );
}

/**
 * DELETE a scheduled scan by ID (passed as query param).
 */
export async function DELETE(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid) return NextResponse.json({ error: auth.error }, { status: 401 });
  const url = new URL(req.url);
  const scheduleId = url.searchParams.get("id");
  if (!scheduleId) {
    return NextResponse.json({ error: "Schedule ID required (?id=...)" }, { status: 400 });
  }
  const deleted = schedules.delete(scheduleId);
  if (!deleted) {
    return NextResponse.json({ error: "Schedule not found" }, { status: 404 });
  }
  return NextResponse.json({ deleted: true });
}
