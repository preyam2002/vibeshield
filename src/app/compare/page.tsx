"use client";

import { useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";

interface ScanSide {
  id: string; target: string; grade: string; score: number;
  date: string; mode: string; summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
}

interface FindingDiff { module: string; title: string; severity: string; cwe?: string }
interface SeverityChange { module: string; title: string; oldSeverity: string; newSeverity: string }
interface ModuleComp { name: string; statusA: string; statusB: string; findingsA: number; findingsB: number; delta: number }

interface ComparisonData {
  scanA: ScanSide; scanB: ScanSide;
  delta: { score: number; grade: { from: string; to: string }; findings: number; critical: number; high: number; medium: number; low: number };
  newFindings: FindingDiff[]; fixedFindings: FindingDiff[]; persistentFindings: number;
  severityChanges: SeverityChange[]; modules: ModuleComp[];
}

interface ScanListItem { id: string; target: string; grade: string; score: number; completedAt?: string; status: string }

const sevColor: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-blue-400", info: "text-zinc-400",
};

const gradeColor = (g: string) =>
  g.startsWith("A") ? "text-green-400" : g.startsWith("B") ? "text-lime-400" :
  g.startsWith("C") ? "text-yellow-400" : g.startsWith("D") ? "text-orange-400" : "text-red-400";

export default function ComparePage() {
  const params = useSearchParams();
  const router = useRouter();
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [idA, setIdA] = useState(params.get("a") || "");
  const [idB, setIdB] = useState(params.get("b") || "");
  const [data, setData] = useState<ComparisonData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/scans").then((r) => r.json()).then((d) => {
      setScans((d.scans || []).filter((s: ScanListItem) => s.status === "completed"));
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!idA || !idB || idA === idB) { setData(null); return; }
    setLoading(true); setError("");
    fetch(`/api/scan/compare?a=${idA}&b=${idB}`).then(async (r) => {
      if (!r.ok) { const e = await r.json(); throw new Error(e.error || "Compare failed"); }
      return r.json();
    }).then(setData).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, [idA, idB]);

  // Update URL params
  useEffect(() => {
    if (idA || idB) {
      const p = new URLSearchParams();
      if (idA) p.set("a", idA);
      if (idB) p.set("b", idB);
      router.replace(`/compare?${p.toString()}`);
    }
  }, [idA, idB, router]);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <nav className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 flex items-center h-14 gap-6">
          <Link href="/" className="font-bold text-lg tracking-tight">⚡ VibeShield</Link>
          <Link href="/scans" className="text-sm text-zinc-400 hover:text-zinc-200">Scans</Link>
          <Link href="/dashboard" className="text-sm text-zinc-400 hover:text-zinc-200">Dashboard</Link>
          <span className="text-sm text-zinc-200 font-medium">Compare</span>
          <Link href="/docs" className="text-sm text-zinc-400 hover:text-zinc-200">Docs</Link>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold mb-6">Scan Comparison</h1>

        {/* Scan selectors */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
          <div>
            <label className="text-sm text-zinc-400 mb-1 block">Baseline (A)</label>
            <select value={idA} onChange={(e) => setIdA(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent">
              <option value="">Select scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id} disabled={s.id === idB}>
                  {s.target} — {s.grade} ({s.score}) — {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : ""}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-sm text-zinc-400 mb-1 block">Current (B)</label>
            <select value={idB} onChange={(e) => setIdB(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent">
              <option value="">Select scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id} disabled={s.id === idA}>
                  {s.target} — {s.grade} ({s.score}) — {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : ""}
                </option>
              ))}
            </select>
          </div>
        </div>

        {loading && <div className="text-center py-12 text-zinc-500">Loading comparison...</div>}
        {error && <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400 mb-8">{error}</div>}

        {data && (
          <>
            {/* Score overview */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 text-center">
                <div className="text-sm text-zinc-500 mb-2">Baseline</div>
                <div className={`text-4xl font-bold ${gradeColor(data.scanA.grade)}`}>{data.scanA.grade}</div>
                <div className="text-lg text-zinc-300 mt-1">{data.scanA.score}/100</div>
                <div className="text-xs text-zinc-500 mt-2">{data.scanA.summary.total} findings</div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 text-center flex flex-col items-center justify-center">
                <div className="text-sm text-zinc-500 mb-2">Delta</div>
                <div className={`text-3xl font-bold ${data.delta.score > 0 ? "text-green-400" : data.delta.score < 0 ? "text-red-400" : "text-zinc-400"}`}>
                  {data.delta.score > 0 ? "+" : ""}{data.delta.score}
                </div>
                <div className="text-sm text-zinc-400 mt-1">{data.delta.grade.from} → {data.delta.grade.to}</div>
                <div className="flex gap-3 mt-3 text-xs">
                  {data.delta.findings !== 0 && (
                    <span className={data.delta.findings < 0 ? "text-green-400" : "text-red-400"}>
                      {data.delta.findings > 0 ? "+" : ""}{data.delta.findings} findings
                    </span>
                  )}
                </div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 text-center">
                <div className="text-sm text-zinc-500 mb-2">Current</div>
                <div className={`text-4xl font-bold ${gradeColor(data.scanB.grade)}`}>{data.scanB.grade}</div>
                <div className="text-lg text-zinc-300 mt-1">{data.scanB.score}/100</div>
                <div className="text-xs text-zinc-500 mt-2">{data.scanB.summary.total} findings</div>
              </div>
            </div>

            {/* Severity breakdown */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 mb-8">
              <h2 className="text-lg font-semibold mb-4">Severity Breakdown</h2>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                  const a = data.scanA.summary[sev];
                  const b = data.scanB.summary[sev];
                  const d = b - a;
                  return (
                    <div key={sev} className="text-center">
                      <div className={`text-xs uppercase tracking-wider mb-2 ${sevColor[sev]}`}>{sev}</div>
                      <div className="flex items-center justify-center gap-3">
                        <span className="text-zinc-400">{a}</span>
                        <span className="text-zinc-600">→</span>
                        <span className="text-zinc-200">{b}</span>
                      </div>
                      {d !== 0 && (
                        <div className={`text-xs mt-1 ${d < 0 ? "text-green-400" : "text-red-400"}`}>
                          {d > 0 ? "+" : ""}{d}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* New and fixed findings */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
              {data.fixedFindings.length > 0 && (
                <div className="bg-zinc-900 border border-green-500/20 rounded-xl p-6">
                  <h2 className="text-lg font-semibold text-green-400 mb-4">Fixed ({data.fixedFindings.length})</h2>
                  <div className="space-y-2">
                    {data.fixedFindings.map((f, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm">
                        <span className={`shrink-0 ${sevColor[f.severity]}`}>●</span>
                        <div>
                          <span className="text-zinc-200">{f.title}</span>
                          <span className="text-zinc-500 ml-2">{f.module}</span>
                          {f.cwe && <span className="text-zinc-600 ml-2 text-xs">{f.cwe}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {data.newFindings.length > 0 && (
                <div className="bg-zinc-900 border border-red-500/20 rounded-xl p-6">
                  <h2 className="text-lg font-semibold text-red-400 mb-4">New ({data.newFindings.length})</h2>
                  <div className="space-y-2">
                    {data.newFindings.map((f, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm">
                        <span className={`shrink-0 ${sevColor[f.severity]}`}>●</span>
                        <div>
                          <span className="text-zinc-200">{f.title}</span>
                          <span className="text-zinc-500 ml-2">{f.module}</span>
                          {f.cwe && <span className="text-zinc-600 ml-2 text-xs">{f.cwe}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {data.fixedFindings.length === 0 && data.newFindings.length === 0 && (
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 mb-8 text-center text-zinc-500">
                No finding changes between scans. {data.persistentFindings} findings remain.
              </div>
            )}

            {/* Severity changes */}
            {data.severityChanges.length > 0 && (
              <div className="bg-zinc-900 border border-yellow-500/20 rounded-xl p-6 mb-8">
                <h2 className="text-lg font-semibold text-yellow-400 mb-4">Severity Changes ({data.severityChanges.length})</h2>
                <div className="space-y-2">
                  {data.severityChanges.map((c, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm">
                      <span className="text-zinc-200">{c.title}</span>
                      <span className={sevColor[c.oldSeverity]}>{c.oldSeverity}</span>
                      <span className="text-zinc-600">→</span>
                      <span className={sevColor[c.newSeverity]}>{c.newSeverity}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Module comparison */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
              <h2 className="text-lg font-semibold mb-4">Module Comparison</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-zinc-500 border-b border-zinc-800">
                      <th className="text-left py-2 pr-4">Module</th>
                      <th className="text-center py-2 px-3">Baseline</th>
                      <th className="text-center py-2 px-3">Current</th>
                      <th className="text-center py-2 pl-3">Delta</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.modules.filter((m) => m.findingsA > 0 || m.findingsB > 0).map((m) => (
                      <tr key={m.name} className="border-b border-zinc-800/50">
                        <td className="py-2 pr-4 text-zinc-300">{m.name}</td>
                        <td className="py-2 px-3 text-center text-zinc-400">{m.findingsA}</td>
                        <td className="py-2 px-3 text-center text-zinc-200">{m.findingsB}</td>
                        <td className={`py-2 pl-3 text-center ${m.delta < 0 ? "text-green-400" : m.delta > 0 ? "text-red-400" : "text-zinc-600"}`}>
                          {m.delta !== 0 ? `${m.delta > 0 ? "+" : ""}${m.delta}` : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {!data && !loading && !error && (
          <div className="text-center py-16 text-zinc-500">
            <p className="text-lg mb-2">Select two completed scans to compare</p>
            <p className="text-sm">See what changed between scan runs — new findings, fixes, and score trends.</p>
          </div>
        )}
      </main>
    </div>
  );
}
