"use client";

import { useEffect, useState, use } from "react";
import { useSearchParams } from "next/navigation";

interface DiffFinding {
  severity: string;
  module: string;
  title: string;
  cwe?: string;
}

interface SeverityChange {
  title: string;
  module: string;
  from: string;
  to: string;
}

interface ScanSummary {
  id: string;
  target: string;
  grade: string;
  score: number;
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
}

interface DiffData {
  tool: string;
  current: ScanSummary;
  baseline: ScanSummary;
  delta: { score: number; grade: string; findings: number; critical: number; high: number; medium: number };
  regression: boolean;
  newFindings: DiffFinding[];
  fixedFindings: DiffFinding[];
  severityChanges: SeverityChange[];
  unchanged: number;
}

const SEVERITY_COLORS: Record<string, { text: string; bg: string }> = {
  critical: { text: "text-red-400", bg: "bg-red-500/10" },
  high: { text: "text-orange-400", bg: "bg-orange-500/10" },
  medium: { text: "text-yellow-400", bg: "bg-yellow-500/10" },
  low: { text: "text-blue-400", bg: "bg-blue-500/10" },
  info: { text: "text-zinc-400", bg: "bg-zinc-500/10" },
};

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-400", "A-": "text-green-400",
  "B+": "text-lime-400", B: "text-lime-400",
  "C+": "text-yellow-400", C: "text-yellow-400",
  "D+": "text-orange-400", D: "text-orange-400",
  F: "text-red-400",
};

const SeverityBadge = ({ severity }: { severity: string }) => {
  const s = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${s.bg} ${s.text} shrink-0 uppercase`}>
      {severity}
    </span>
  );
};

const Skeleton = () => (
  <div className="min-h-screen">
    <nav className="border-b border-zinc-800/50 px-6 py-4">
      <div className="max-w-5xl mx-auto flex items-center justify-between">
        <div className="h-6 w-24 bg-zinc-800/50 rounded animate-pulse" />
        <div className="h-6 w-16 bg-zinc-800/50 rounded animate-pulse" />
      </div>
    </nav>
    <main className="max-w-5xl mx-auto px-4 py-8 space-y-6">
      <div className="h-24 bg-zinc-800/20 rounded-xl animate-pulse" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="h-40 bg-zinc-800/20 rounded-xl animate-pulse" />
        <div className="h-40 bg-zinc-800/20 rounded-xl animate-pulse" style={{ animationDelay: "100ms" }} />
      </div>
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="h-32 bg-zinc-800/20 rounded-xl animate-pulse" style={{ animationDelay: `${(i + 2) * 100}ms` }} />
      ))}
    </main>
  </div>
);

export default function ComparePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const searchParams = useSearchParams();
  const baseline = searchParams.get("baseline");

  const [data, setData] = useState<DiffData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [baselineInput, setBaselineInput] = useState("");

  useEffect(() => {
    if (!baseline) return;
    setLoading(true);
    setError(null);
    fetch(`/api/scan/${id}/diff?baseline=${baseline}`)
      .then((r) => {
        if (!r.ok) throw new Error(r.status === 404 ? "One or both scans not found." : "Failed to fetch comparison data.");
        return r.json();
      })
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id, baseline]);

  if (!baseline) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4 px-4">
        <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
          VibeShield
        </a>
        <div className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-8 w-full max-w-md">
          <h2 className="text-lg font-semibold text-zinc-200 mb-1">Compare Scans</h2>
          <p className="text-sm text-zinc-500 mb-4">Enter a baseline scan ID to compare against scan <code className="text-zinc-400">{id.slice(0, 8)}</code>.</p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (baselineInput.trim()) {
                window.location.href = `/scan/${id}/compare?baseline=${baselineInput.trim()}`;
              }
            }}
            className="space-y-3"
          >
            <input
              type="text"
              value={baselineInput}
              onChange={(e) => setBaselineInput(e.target.value)}
              placeholder="Baseline scan ID"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700"
            />
            <button
              type="submit"
              disabled={!baselineInput.trim()}
              className="w-full text-sm bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 disabled:opacity-40 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg transition-colors"
            >
              Compare
            </button>
          </form>
          <a href={`/scan/${id}`} className="block text-center text-xs text-zinc-600 hover:text-zinc-400 mt-4 transition-colors">
            Back to scan
          </a>
        </div>
      </div>
    );
  }

  if (loading) return <Skeleton />;

  if (error) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
          VibeShield
        </a>
        <div className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-8 text-center max-w-sm">
          <div className="text-2xl mb-2">Comparison failed</div>
          <p className="text-sm text-zinc-500 mb-4">{error}</p>
          <div className="flex gap-3 justify-center">
            <a
              href={`/scan/${id}/compare`}
              className="text-xs bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-400 px-4 py-2 rounded-lg transition-colors"
            >
              Try different baseline
            </a>
            <a
              href={`/scan/${id}`}
              className="text-xs bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Back to scan
            </a>
          </div>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const { current, baseline: base, delta, regression, newFindings, fixedFindings, severityChanges, unchanged } = data;
  const scoreDelta = delta.score;
  const gradeColor = (g: string) => GRADE_COLORS[g] ?? "text-zinc-400";

  return (
    <div className="min-h-screen">
      <nav className="border-b border-zinc-800/50 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
            VibeShield
          </a>
          <a href={`/scan/${id}`} className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
            Back to scan
          </a>
        </div>
      </nav>

      <main className="max-w-5xl mx-auto px-4 py-8 space-y-6">
        {/* Regression / Improvement Banner */}
        <div
          className={`rounded-xl border px-5 py-3 flex items-center gap-3 ${
            regression
              ? "bg-red-500/5 border-red-500/20 text-red-400"
              : "bg-green-500/5 border-green-500/20 text-green-400"
          }`}
        >
          <span className="text-xl">{regression ? "\u2193" : "\u2191"}</span>
          <div>
            <div className="font-semibold text-sm">
              {regression ? "Security Regression Detected" : "Security Improved"}
            </div>
            <div className="text-xs opacity-70">
              Score changed by {scoreDelta > 0 ? "+" : ""}{scoreDelta} points ({delta.grade})
            </div>
          </div>
        </div>

        {/* Side-by-Side Grade/Score */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { label: "Baseline", scan: base },
            { label: "Current", scan: current },
          ].map(({ label, scan }) => (
            <div key={label} className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-5">
              <div className="text-xs text-zinc-500 mb-3 uppercase tracking-wider">{label}</div>
              <div className="flex items-center gap-4">
                <div className={`text-4xl font-bold ${gradeColor(scan.grade)}`}>{scan.grade}</div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-zinc-300 truncate">{scan.target}</div>
                  <div className="text-2xl font-semibold text-zinc-100">{scan.score}<span className="text-sm text-zinc-600">/100</span></div>
                </div>
              </div>
              <div className="flex gap-3 mt-3 text-xs text-zinc-500">
                <span className="text-red-400">{scan.summary.critical}C</span>
                <span className="text-orange-400">{scan.summary.high}H</span>
                <span className="text-yellow-400">{scan.summary.medium}M</span>
                <span className="text-blue-400">{scan.summary.low}L</span>
              </div>
              <a href={`/scan/${scan.id}`} className="text-[10px] text-zinc-600 hover:text-zinc-400 mt-2 inline-block transition-colors">
                {scan.id.slice(0, 12)}...
              </a>
            </div>
          ))}
        </div>

        {/* Delta Bar */}
        <div className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 text-sm">
          <div className="flex items-center gap-4">
            <span className="text-zinc-500">Delta:</span>
            <span className={scoreDelta >= 0 ? "text-green-400" : "text-red-400"}>
              {scoreDelta > 0 ? "+" : ""}{scoreDelta} score
            </span>
            <span className={delta.findings <= 0 ? "text-green-400" : "text-red-400"}>
              {delta.findings > 0 ? "+" : ""}{delta.findings} findings
            </span>
          </div>
          <div className="text-zinc-600 text-xs">{unchanged} unchanged finding{unchanged !== 1 ? "s" : ""}</div>
        </div>

        {/* New Findings */}
        <FindingSection
          title="New Findings"
          count={newFindings.length}
          borderColor="border-red-500/20"
          bgColor="bg-red-500/5"
          headerColor="text-red-400"
          emptyText="No new findings"
        >
          {newFindings.map((f, i) => (
            <div key={i} className="flex items-center gap-3 px-4 py-2.5 border-t border-zinc-800/30">
              <SeverityBadge severity={f.severity} />
              <span className="flex-1 text-sm text-zinc-300 min-w-0 truncate">{f.title}</span>
              <span className="text-[10px] text-zinc-600 shrink-0 hidden sm:block">{f.module}</span>
              {f.cwe && <span className="text-[10px] text-zinc-700 shrink-0">{f.cwe}</span>}
            </div>
          ))}
        </FindingSection>

        {/* Fixed Findings */}
        <FindingSection
          title="Fixed Findings"
          count={fixedFindings.length}
          borderColor="border-green-500/20"
          bgColor="bg-green-500/5"
          headerColor="text-green-400"
          emptyText="No fixed findings"
        >
          {fixedFindings.map((f, i) => (
            <div key={i} className="flex items-center gap-3 px-4 py-2.5 border-t border-zinc-800/30">
              <SeverityBadge severity={f.severity} />
              <span className="flex-1 text-sm text-zinc-300 min-w-0 truncate line-through opacity-60">{f.title}</span>
              <span className="text-[10px] text-zinc-600 shrink-0 hidden sm:block">{f.module}</span>
              {f.cwe && <span className="text-[10px] text-zinc-700 shrink-0">{f.cwe}</span>}
            </div>
          ))}
        </FindingSection>

        {/* Severity Changes */}
        <FindingSection
          title="Severity Changes"
          count={severityChanges.length}
          borderColor="border-yellow-500/20"
          bgColor="bg-yellow-500/5"
          headerColor="text-yellow-400"
          emptyText="No severity changes"
        >
          {severityChanges.map((c, i) => (
            <div key={i} className="flex items-center gap-3 px-4 py-2.5 border-t border-zinc-800/30">
              <SeverityBadge severity={c.from} />
              <svg className="w-3 h-3 text-zinc-600 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
              <SeverityBadge severity={c.to} />
              <span className="flex-1 text-sm text-zinc-300 min-w-0 truncate">{c.title}</span>
              <span className="text-[10px] text-zinc-600 shrink-0 hidden sm:block">{c.module}</span>
            </div>
          ))}
        </FindingSection>
      </main>
    </div>
  );
}

const FindingSection = ({
  title,
  count,
  borderColor,
  bgColor,
  headerColor,
  emptyText,
  children,
}: {
  title: string;
  count: number;
  borderColor: string;
  bgColor: string;
  headerColor: string;
  emptyText: string;
  children: React.ReactNode;
}) => (
  <div className={`border ${borderColor} rounded-xl overflow-hidden ${count > 0 ? bgColor : "bg-zinc-900/30"}`}>
    <div className="px-4 py-3 flex items-center justify-between">
      <span className={`text-sm font-medium ${count > 0 ? headerColor : "text-zinc-500"}`}>{title}</span>
      <span className={`text-xs font-mono ${count > 0 ? headerColor : "text-zinc-600"}`}>{count}</span>
    </div>
    {count > 0 ? children : <div className="px-4 pb-3 text-xs text-zinc-600">{emptyText}</div>}
  </div>
);
