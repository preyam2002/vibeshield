"use client";

import { useEffect, useState } from "react";

interface ScheduledScan {
  id: string;
  url: string;
  mode: string;
  intervalHours: number;
  enabled: boolean;
  runCount: number;
  lastRunAt?: string;
  lastScanId?: string;
  nextRunAt: string;
  createdAt: string;
}

interface RecentScan {
  id: string;
  target: string;
  grade: string;
  score: number;
  status: string;
  findings: number;
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
  startedAt: string;
  completedAt?: string;
  mode: string;
  delta?: { score: number; findings: number };
}

interface Stats {
  totalScans: number;
  completedScans: number;
  totalFindings: number;
  totalCritical: number;
  uniqueTargets: number;
  avgScore: number;
  topModules: { name: string; count: number }[];
  gradeDistribution: Record<string, number>;
}

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-400", "A-": "text-green-400",
  "B+": "text-lime-400", B: "text-lime-400",
  "C+": "text-yellow-400", C: "text-yellow-400",
  "D+": "text-orange-400", D: "text-orange-400",
  F: "text-red-400",
};

export default function DashboardPage() {
  const [schedules, setSchedules] = useState<ScheduledScan[]>([]);
  const [scans, setScans] = useState<RecentScan[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [newUrl, setNewUrl] = useState("");
  const [newMode, setNewMode] = useState<"quick" | "security" | "full">("security");
  const [newInterval, setNewInterval] = useState(24);
  const [creating, setCreating] = useState(false);

  const loadData = async () => {
    const [schedRes, scansRes, statsRes] = await Promise.all([
      fetch("/api/scan/schedule").then((r) => r.json()).catch(() => []),
      fetch("/api/scans").then((r) => r.json()).catch(() => []),
      fetch("/api/stats").then((r) => r.json()).catch(() => null),
    ]);
    setSchedules(schedRes);
    setScans(scansRes);
    setStats(statsRes);
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const createSchedule = async () => {
    if (!newUrl.trim()) return;
    setCreating(true);
    try {
      const res = await fetch("/api/scan/schedule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: newUrl, mode: newMode, intervalHours: newInterval }),
      });
      if (res.ok) {
        setNewUrl("");
        loadData();
      }
    } catch { /* skip */ }
    setCreating(false);
  };

  const deleteSchedule = async (id: string) => {
    await fetch(`/api/scan/schedule?id=${id}`, { method: "DELETE" });
    loadData();
  };

  const runNow = async (schedule: ScheduledScan) => {
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: schedule.url, mode: schedule.mode }),
      });
      if (res.ok) loadData();
    } catch { /* skip */ }
  };

  const activeScans = scans.filter((s) => s.status === "scanning" || s.status === "queued");
  const completedScans = scans.filter((s) => s.status === "completed");

  // Group completed scans by domain
  const byDomain = new Map<string, RecentScan[]>();
  for (const s of completedScans) {
    const host = (() => { try { return new URL(s.target).hostname; } catch { return s.target; } })();
    if (!byDomain.has(host)) byDomain.set(host, []);
    byDomain.get(host)!.push(s);
  }

  return (
    <div className="min-h-screen">
      <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,0.015)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.015)_1px,transparent_1px)] bg-[size:64px_64px] pointer-events-none" />

      <nav className="relative z-10 border-b border-zinc-800/50 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
            VibeShield
          </a>
          <div className="flex items-center gap-4">
            <a href="/scans" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">All Scans</a>
            <a href="/compare" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Compare</a>
            <a href="/docs" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">API</a>
            <span className="text-xs text-zinc-400 font-medium">Dashboard</span>
          </div>
        </div>
      </nav>

      <main className="relative z-10 max-w-6xl mx-auto px-6 py-8">
        <h1 className="text-2xl font-black text-zinc-100 mb-6">Security Dashboard</h1>

        {/* Stats overview */}
        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8">
            {[
              { label: "Total Scans", value: stats.totalScans },
              { label: "Apps Tested", value: stats.uniqueTargets },
              { label: "Vulns Found", value: stats.totalFindings, warn: stats.totalCritical > 0 },
              { label: "Critical", value: stats.totalCritical, warn: stats.totalCritical > 0 },
              { label: "Avg Score", value: stats.avgScore },
            ].map((s) => (
              <div key={s.label} className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4 text-center">
                <div className={`text-2xl font-bold ${s.warn ? "text-red-400" : "text-zinc-200"}`}>{s.value}</div>
                <div className="text-[10px] text-zinc-600 uppercase tracking-wider mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Active scans */}
        {activeScans.length > 0 && (
          <div className="mb-8">
            <h2 className="text-sm font-semibold text-zinc-400 mb-3 flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
              </span>
              Active Scans ({activeScans.length})
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {activeScans.map((s) => (
                <a key={s.id} href={`/scan/${s.id}`} className="bg-zinc-900/50 border border-red-500/20 rounded-xl p-4 hover:border-red-500/40 transition-colors">
                  <div className="text-sm font-medium text-zinc-200 truncate">{(() => { try { return new URL(s.target).hostname; } catch { return s.target; } })()}</div>
                  <div className="text-xs text-red-400 mt-1">Scanning...</div>
                </a>
              ))}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scheduled scans */}
          <div className="lg:col-span-2">
            <h2 className="text-sm font-semibold text-zinc-400 mb-3">Scheduled Scans</h2>

            {/* Create new schedule */}
            <div className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4 mb-4">
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="https://your-app.vercel.app"
                  className="flex-1 bg-zinc-800/50 border border-zinc-700/50 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-red-500/40"
                />
                <select
                  value={newMode}
                  onChange={(e) => setNewMode(e.target.value as "quick" | "security" | "full")}
                  className="bg-zinc-800/50 border border-zinc-700/50 rounded-lg px-2 py-2 text-xs text-zinc-400 focus:outline-none"
                >
                  <option value="quick">Quick</option>
                  <option value="security">Security</option>
                  <option value="full">Full</option>
                </select>
                <select
                  value={newInterval}
                  onChange={(e) => setNewInterval(Number(e.target.value))}
                  className="bg-zinc-800/50 border border-zinc-700/50 rounded-lg px-2 py-2 text-xs text-zinc-400 focus:outline-none"
                >
                  <option value={1}>Every 1h</option>
                  <option value={6}>Every 6h</option>
                  <option value={12}>Every 12h</option>
                  <option value={24}>Daily</option>
                  <option value={168}>Weekly</option>
                </select>
                <button
                  onClick={createSchedule}
                  disabled={creating || !newUrl.trim()}
                  className="bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 disabled:from-zinc-800 disabled:to-zinc-800 disabled:text-zinc-600 text-white text-sm font-medium px-4 py-2 rounded-lg transition-all whitespace-nowrap"
                >
                  {creating ? "..." : "Schedule"}
                </button>
              </div>
            </div>

            {schedules.length === 0 ? (
              <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-8 text-center">
                <div className="text-zinc-600 text-sm">No scheduled scans yet. Add one above to monitor your apps automatically.</div>
              </div>
            ) : (
              <div className="space-y-2">
                {schedules.map((s) => {
                  const hostname = (() => { try { return new URL(s.url).hostname; } catch { return s.url; } })();
                  const nextRun = new Date(s.nextRunAt);
                  const isOverdue = nextRun < new Date();
                  return (
                    <div key={s.id} className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4 flex items-center gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-zinc-200 truncate">{hostname}</div>
                        <div className="text-xs text-zinc-600 mt-0.5 flex items-center gap-2 flex-wrap">
                          <span className="bg-zinc-800/80 px-1.5 py-0.5 rounded">{s.mode}</span>
                          <span>every {s.intervalHours}h</span>
                          <span>{s.runCount} runs</span>
                          {s.lastScanId && (
                            <a href={`/scan/${s.lastScanId}`} className="text-zinc-500 hover:text-zinc-300 transition-colors">
                              Last scan →
                            </a>
                          )}
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className={`text-[10px] ${isOverdue ? "text-orange-400" : "text-zinc-600"}`}>
                          Next: {nextRun.toLocaleString()}
                        </div>
                      </div>
                      <button
                        onClick={() => runNow(s)}
                        className="text-zinc-600 hover:text-zinc-300 transition-colors text-xs shrink-0"
                        title="Run scan now"
                      >
                        Run Now
                      </button>
                      <button
                        onClick={() => deleteSchedule(s.id)}
                        className="text-zinc-600 hover:text-red-400 transition-colors text-xs shrink-0"
                        title="Delete schedule"
                      >
                        Delete
                      </button>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Domain health grid */}
            {byDomain.size > 0 && (
              <div className="mt-8">
                <h2 className="text-sm font-semibold text-zinc-400 mb-3">Domain Health</h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {Array.from(byDomain.entries())
                    .sort((a, b) => b[1].length - a[1].length)
                    .slice(0, 10)
                    .map(([domain, domainScans]) => {
                      const latest = domainScans.sort((a, b) => (b.completedAt || "").localeCompare(a.completedAt || ""))[0];
                      const trend = domainScans.length >= 2
                        ? domainScans[0].score - domainScans[domainScans.length - 1].score
                        : 0;
                      return (
                        <a
                          key={domain}
                          href={`/scan/${latest.id}`}
                          className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4 hover:border-zinc-700/50 transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <div className="text-sm font-medium text-zinc-200 truncate">{domain}</div>
                            <div className={`text-lg font-black ${GRADE_COLORS[latest.grade] || "text-zinc-600"}`}>
                              {latest.grade}
                            </div>
                          </div>
                          <div className="flex items-center gap-3 mt-2 text-xs text-zinc-600">
                            <span>{latest.score}/100</span>
                            <span>{latest.findings} findings</span>
                            {latest.summary.critical > 0 && <span className="text-red-400">{latest.summary.critical}C</span>}
                            {latest.summary.high > 0 && <span className="text-orange-400">{latest.summary.high}H</span>}
                            {domainScans.length > 1 && (
                              <span className={trend > 0 ? "text-green-400" : trend < 0 ? "text-red-400" : ""}>
                                {trend > 0 ? "+" : ""}{trend} pts
                              </span>
                            )}
                            <span className="ml-auto">{domainScans.length} scans</span>
                          </div>
                        </a>
                      );
                    })}
                </div>
              </div>
            )}
          </div>

          {/* Sidebar: top modules + grade distribution */}
          <div className="space-y-4">
            {stats && stats.topModules.length > 0 && (
              <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                  Most Common Vulnerabilities
                </h3>
                <div className="space-y-2">
                  {stats.topModules.map((m, i) => (
                    <div key={m.name} className="flex items-center gap-2">
                      <span className="text-[10px] text-zinc-700 w-4 text-right">{i + 1}.</span>
                      <span className="text-xs text-zinc-400 flex-1 truncate">{m.name}</span>
                      <span className="text-xs text-zinc-600 tabular-nums">{m.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {stats && Object.keys(stats.gradeDistribution).length > 0 && (
              <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                  Grade Distribution
                </h3>
                <div className="space-y-1.5">
                  {["A", "A-", "B+", "B", "C+", "C", "D+", "D", "F"]
                    .filter((g) => stats.gradeDistribution[g] > 0)
                    .map((grade) => {
                      const count = stats.gradeDistribution[grade];
                      const pct = (count / stats.completedScans) * 100;
                      return (
                        <div key={grade} className="flex items-center gap-2">
                          <span className={`text-xs font-bold w-6 ${GRADE_COLORS[grade] || "text-zinc-600"}`}>{grade}</span>
                          <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                            <div className="h-full bg-zinc-600 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-[10px] text-zinc-600 tabular-nums w-6 text-right">{count}</span>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}

            <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
              <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">Quick Actions</h3>
              <div className="space-y-2">
                <a href="/" className="block text-xs text-zinc-400 hover:text-zinc-200 transition-colors">New Scan</a>
                <a href="/scans" className="block text-xs text-zinc-400 hover:text-zinc-200 transition-colors">All Scans</a>
                <a href="/docs" className="block text-xs text-zinc-400 hover:text-zinc-200 transition-colors">API Docs</a>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
