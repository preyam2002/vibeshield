"use client";

import { useEffect, useState } from "react";

interface ScanEntry {
  id: string;
  target: string;
  grade: string;
  status: string;
  findings: number;
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
}

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-400", "A-": "text-green-400",
  "B+": "text-lime-400", B: "text-lime-400",
  "C+": "text-yellow-400", C: "text-yellow-400",
  "D+": "text-orange-400", D: "text-orange-400",
  F: "text-red-400",
};

export default function ScansPage() {
  const [scans, setScans] = useState<ScanEntry[]>([]);

  useEffect(() => {
    const load = () => fetch("/api/scans").then((r) => r.json()).then(setScans).catch(() => {});
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, []);

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
        <h1 className="text-2xl font-bold text-zinc-100 mb-1">All Scans</h1>
        <p className="text-sm text-zinc-500 mb-8">{scans.length} scans in memory</p>

        {scans.length === 0 ? (
          <div className="text-center py-20 bg-zinc-900/20 border border-zinc-800/30 rounded-xl">
            <p className="text-zinc-600">No scans yet. Start one from the home page.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {scans.map((s) => {
              const hostname = (() => { try { return new URL(s.target).hostname; } catch { return s.target; } })();
              const isRunning = s.status === "scanning" || s.status === "queued";
              return (
                <a
                  key={s.id}
                  href={`/scan/${s.id}`}
                  className="flex items-center gap-4 bg-zinc-900/30 border border-zinc-800/30 rounded-xl px-5 py-4 hover:border-zinc-700/50 transition-colors"
                >
                  {isRunning ? (
                    <svg className="animate-spin h-8 w-8 text-red-500 shrink-0" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : (
                    <div className={`text-3xl font-black w-10 text-center ${GRADE_COLORS[s.grade] || "text-zinc-600"}`}>
                      {s.grade}
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-zinc-200 truncate">{hostname}</div>
                    <div className="text-xs text-zinc-600 mt-0.5">
                      {isRunning ? (
                        <span className="text-red-400">Scanning...</span>
                      ) : (
                        <>
                          {s.findings} findings
                          {s.summary.critical > 0 && <span className="text-red-400"> · {s.summary.critical} critical</span>}
                          {s.summary.high > 0 && <span className="text-orange-400"> · {s.summary.high} high</span>}
                          {s.summary.medium > 0 && <span className="text-yellow-400"> · {s.summary.medium} medium</span>}
                        </>
                      )}
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
                  <svg className="w-4 h-4 text-zinc-700 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
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
