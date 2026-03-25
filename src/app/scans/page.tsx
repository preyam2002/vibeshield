"use client";

import { useEffect, useState } from "react";

interface ScanEntry {
  id: string;
  target: string;
  grade: string;
  score: number;
  status: string;
  findings: number;
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
  startedAt: string;
  completedAt?: string;
  mode?: string;
  delta?: { score: number; findings: number };
}

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-400", "A-": "text-green-400",
  "B+": "text-lime-400", B: "text-lime-400",
  "C+": "text-yellow-400", C: "text-yellow-400",
  "D+": "text-orange-400", D: "text-orange-400",
  F: "text-red-400",
};

type SortKey = "date" | "grade" | "findings";

const timeAgo = (dateStr: string) => {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
};

export default function ScansPage() {
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<SortKey>("date");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [localOnly, setLocalOnly] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch("/api/scans");
        const serverScans: ScanEntry[] = await res.json();
        const stored: ScanEntry[] = JSON.parse(localStorage.getItem("vibeshield-history") || "[]");
        const merged = new Map<string, ScanEntry>();
        for (const s of stored) merged.set(s.id, s);
        for (const s of serverScans) merged.set(s.id, s);
        setScans([...merged.values()]);
        setLocalOnly(serverScans.length === 0 && stored.length > 0);
      } catch {
        try {
          const stored: ScanEntry[] = JSON.parse(localStorage.getItem("vibeshield-history") || "[]");
          if (stored.length > 0) { setScans(stored); setLocalOnly(true); }
        } catch { /* skip */ }
      }
    };
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, []);

  const searchLower = search.toLowerCase();
  const filtered = scans.filter((s) => {
    if (search && !s.target.toLowerCase().includes(searchLower)) return false;
    if (statusFilter === "running" && s.status !== "scanning" && s.status !== "queued") return false;
    if (statusFilter === "completed" && s.status !== "completed") return false;
    if (statusFilter === "failed" && s.status !== "failed") return false;
    return true;
  });

  const sorted = [...filtered].sort((a, b) => {
    // Always put running scans first
    const aRunning = a.status === "scanning" || a.status === "queued";
    const bRunning = b.status === "scanning" || b.status === "queued";
    if (aRunning && !bRunning) return -1;
    if (bRunning && !aRunning) return 1;

    if (sortBy === "grade") return a.score - b.score;
    if (sortBy === "findings") return b.findings - a.findings;
    return (b.completedAt || b.startedAt).localeCompare(a.completedAt || a.startedAt);
  });

  const runningCount = scans.filter((s) => s.status === "scanning" || s.status === "queued").length;
  const completedCount = scans.filter((s) => s.status === "completed").length;
  const failedCount = scans.filter((s) => s.status === "failed").length;

  return (
    <div className="min-h-screen">
      <nav className="border-b border-zinc-800/50 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
            VibeShield
          </a>
          <div className="flex items-center gap-3">
            <a href="/docs" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">API</a>
            <a href="/" className="text-xs bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-4 py-1.5 rounded-lg transition-colors">
              New Scan
            </a>
          </div>
        </div>
      </nav>

      <main className="max-w-4xl mx-auto px-4 py-8">
        <div className="flex items-end justify-between mb-6 gap-4 flex-wrap">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100 mb-1">All Scans</h1>
            <p className="text-sm text-zinc-500">
              {scans.length} {scans.length === 1 ? "scan" : "scans"}
              {runningCount > 0 && <span className="text-red-400"> · {runningCount} running</span>}
              {localOnly && <span className="text-zinc-600"> · from browser cache</span>}
            </p>
          </div>
          <input
            type="text"
            placeholder="Search by URL..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="text-xs bg-zinc-900/50 border border-zinc-800/50 rounded-lg px-3 py-2 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-700 w-full max-w-[240px]"
          />
        </div>

        {/* Aggregate stats */}
        {completedCount > 0 && (() => {
          const completed = scans.filter((s) => s.status === "completed");
          const avgScore = Math.round(completed.reduce((sum, s) => sum + s.score, 0) / completed.length);
          const totalFindings = completed.reduce((sum, s) => sum + s.findings, 0);
          const totalCritical = completed.reduce((sum, s) => sum + s.summary.critical, 0);
          const totalHigh = completed.reduce((sum, s) => sum + s.summary.high, 0);
          const uniqueDomains = new Set(completed.map((s) => { try { return new URL(s.target).hostname; } catch { return s.target; } })).size;
          return (
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 mb-6">
              {[
                { label: "Avg Score", value: `${avgScore}/100`, color: avgScore >= 75 ? "text-green-400" : avgScore >= 50 ? "text-yellow-400" : "text-red-400" },
                { label: "Domains", value: String(uniqueDomains), color: "text-zinc-300" },
                { label: "Findings", value: String(totalFindings), color: "text-zinc-300" },
                { label: "Critical", value: String(totalCritical), color: totalCritical > 0 ? "text-red-400" : "text-emerald-400" },
                { label: "High", value: String(totalHigh), color: totalHigh > 0 ? "text-orange-400" : "text-emerald-400" },
              ].map((stat) => (
                <div key={stat.label} className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-3 text-center">
                  <div className={`text-lg font-bold ${stat.color}`}>{stat.value}</div>
                  <div className="text-[10px] text-zinc-600">{stat.label}</div>
                </div>
              ))}
            </div>
          );
        })()}

        {/* Filters */}
        <div className="flex items-center gap-2 mb-4 flex-wrap">
          <div className="flex items-center bg-zinc-900/50 border border-zinc-800/50 rounded-lg overflow-hidden">
            {[
              { key: "all", label: `All (${scans.length})` },
              ...(runningCount > 0 ? [{ key: "running", label: `Running (${runningCount})` }] : []),
              { key: "completed", label: `Completed (${completedCount})` },
              ...(failedCount > 0 ? [{ key: "failed", label: `Failed (${failedCount})` }] : []),
            ].map((f) => (
              <button
                key={f.key}
                onClick={() => setStatusFilter(f.key)}
                className={`text-[10px] px-2.5 py-1.5 transition-colors ${statusFilter === f.key ? "bg-zinc-800 text-zinc-300" : "text-zinc-600 hover:text-zinc-400"}`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <div className="flex items-center bg-zinc-900/50 border border-zinc-800/50 rounded-lg overflow-hidden ml-auto">
            {([
              { key: "date" as SortKey, label: "Recent" },
              { key: "grade" as SortKey, label: "Worst grade" },
              { key: "findings" as SortKey, label: "Most findings" },
            ]).map((s) => (
              <button
                key={s.key}
                onClick={() => setSortBy(s.key)}
                className={`text-[10px] px-2.5 py-1.5 transition-colors ${sortBy === s.key ? "bg-zinc-800 text-zinc-300" : "text-zinc-600 hover:text-zinc-400"}`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {sorted.length === 0 ? (
          <div className="text-center py-20 bg-zinc-900/20 border border-zinc-800/30 rounded-xl">
            {scans.length === 0 ? (
              <div className="space-y-3">
                <div className="text-4xl">&#x1f50d;</div>
                <p className="text-zinc-400 font-medium">No scans yet</p>
                <p className="text-xs text-zinc-600">Paste a URL on the home page to run your first security scan</p>
                <a href="/" className="inline-block mt-2 text-xs bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-5 py-2 rounded-lg transition-colors">
                  Start scanning
                </a>
              </div>
            ) : (
              <p className="text-zinc-600">No scans match your filters.</p>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {sorted.map((s) => {
              const hostname = (() => { try { return new URL(s.target).hostname; } catch { return s.target; } })();
              const isRunning = s.status === "scanning" || s.status === "queued";
              const isFailed = s.status === "failed";
              return (
                <a
                  key={s.id}
                  href={`/scan/${s.id}`}
                  className="flex items-center gap-4 bg-zinc-900/30 border border-zinc-800/30 rounded-xl px-5 py-4 hover:border-zinc-700/50 transition-colors group"
                >
                  {isRunning ? (
                    <svg className="animate-spin h-8 w-8 text-red-500 shrink-0" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : isFailed ? (
                    <div className="text-2xl w-10 text-center text-zinc-600">&#x2717;</div>
                  ) : (
                    <div className={`text-3xl font-black w-10 text-center ${GRADE_COLORS[s.grade] || "text-zinc-600"}`}>
                      {s.grade}
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-zinc-200 truncate">{hostname}</span>
                      {s.score > 0 && !isRunning && !isFailed && (
                        <span className="text-[10px] text-zinc-600">{s.score}/100</span>
                      )}
                      {s.delta && s.delta.score !== 0 && (
                        <span className={`text-[10px] font-medium ${s.delta.score > 0 ? "text-emerald-400" : "text-red-400"}`}>
                          {s.delta.score > 0 ? "+" : ""}{s.delta.score} pts
                        </span>
                      )}
                      {s.mode && s.mode !== "full" && !isRunning && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-800/50 text-zinc-600">{s.mode}</span>
                      )}
                    </div>
                    <div className="text-xs text-zinc-600 mt-0.5 flex items-center gap-2">
                      {isRunning ? (
                        <span className="text-red-400">Scanning...</span>
                      ) : isFailed ? (
                        <span className="text-zinc-500">Scan failed</span>
                      ) : (
                        <span>
                          {s.findings} {s.findings === 1 ? "finding" : "findings"}
                          {s.summary.critical > 0 && <span className="text-red-400"> · {s.summary.critical} critical</span>}
                          {s.summary.high > 0 && <span className="text-orange-400"> · {s.summary.high} high</span>}
                          {s.delta && s.delta.findings !== 0 && (
                            <span className={s.delta.findings < 0 ? "text-emerald-500" : "text-red-400"}>
                              {" · "}{s.delta.findings > 0 ? "+" : ""}{s.delta.findings} {Math.abs(s.delta.findings) === 1 ? "issue" : "issues"}
                            </span>
                          )}
                        </span>
                      )}
                      <span className="text-zinc-700">·</span>
                      <span className="text-zinc-700">{timeAgo(s.completedAt || s.startedAt)}</span>
                      {!isRunning && s.completedAt && s.startedAt && (() => {
                        const dur = new Date(s.completedAt).getTime() - new Date(s.startedAt).getTime();
                        if (dur <= 0) return null;
                        const secs = Math.round(dur / 1000);
                        return (
                          <>
                            <span className="text-zinc-700">·</span>
                            <span className="text-zinc-700">{secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`}</span>
                          </>
                        );
                      })()}
                    </div>
                  </div>
                  <div className="hidden sm:flex gap-1.5 shrink-0">
                    {(["critical", "high", "medium", "low"] as const).map((sev) => {
                      const count = s.summary[sev];
                      if (count === 0) return null;
                      const colors = { critical: "bg-red-500/20 text-red-400", high: "bg-orange-500/20 text-orange-400", medium: "bg-yellow-500/20 text-yellow-400", low: "bg-blue-500/20 text-blue-400" };
                      return (
                        <span key={sev} className={`text-[10px] px-2 py-0.5 rounded-full ${colors[sev]}`}>
                          {count} {sev}
                        </span>
                      );
                    })}
                  </div>
                  <svg className="w-4 h-4 text-zinc-700 group-hover:text-zinc-500 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </a>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}
