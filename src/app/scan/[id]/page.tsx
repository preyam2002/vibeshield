"use client";

import { useEffect, useState, useCallback, useRef, use } from "react";
import { useRouter } from "next/navigation";

interface Finding {
  id: string;
  module: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence?: string;
  remediation: string;
  cwe?: string;
  owasp?: string;
  codeSnippet?: string;
}

interface ModuleStatus {
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  findingsCount: number;
  durationMs?: number;
  error?: string;
}

interface ScanResult {
  id: string;
  target: string;
  status: "queued" | "scanning" | "completed" | "failed";
  mode?: "full" | "security" | "quick";
  startedAt: string;
  completedAt?: string;
  error?: string;
  findings: Finding[];
  modules: ModuleStatus[];
  grade: string;
  score: number;
  technologies: string[];
  isSpa: boolean;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  surface?: {
    pages: number;
    apiEndpoints: number;
    jsFiles: number;
    forms: number;
    cookies: number;
  };
  comparison?: {
    previousId: string;
    previousGrade: string;
    previousScore: number;
    previousFindings: number;
    delta: { score: number; findings: number; critical: number; high: number };
    newFindings?: { title: string; severity: string; module: string }[];
    fixedFindings?: { title: string; severity: string; module: string }[];
  };
  percentile?: number;
  history?: { id: string; score: number; grade: string; findings: number; date: string }[];
}

const SEVERITY_CONFIG = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", label: "CRITICAL", dot: "bg-red-500" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", label: "HIGH", dot: "bg-orange-500" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", label: "MEDIUM", dot: "bg-yellow-500" },
  low: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", label: "LOW", dot: "bg-blue-500" },
  info: { color: "text-zinc-400", bg: "bg-zinc-500/10", border: "border-zinc-500/30", label: "INFO", dot: "bg-zinc-500" },
} as const;

const GRADE_CONFIG: Record<string, { color: string; bg: string; border: string; desc: string }> = {
  A: { color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/30", desc: "Excellent" },
  "A-": { color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/30", desc: "Great" },
  "B+": { color: "text-lime-400", bg: "bg-lime-500/10", border: "border-lime-500/30", desc: "Good" },
  B: { color: "text-lime-400", bg: "bg-lime-500/10", border: "border-lime-500/30", desc: "Good" },
  "C+": { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", desc: "Fair" },
  C: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", desc: "Fair" },
  "D+": { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", desc: "Poor" },
  D: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", desc: "Poor" },
  F: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", desc: "Critical" },
  "-": { color: "text-zinc-600", bg: "bg-zinc-500/10", border: "border-zinc-500/30", desc: "Scanning" },
};

const FindingCard = ({ finding, isOpen, onToggle }: { finding: Finding; isOpen: boolean; onToggle: () => void }) => {
  const sev = SEVERITY_CONFIG[finding.severity];
  return (
    <div id={`finding-${finding.id}`} className={`border ${sev.border} rounded-lg overflow-hidden bg-zinc-950/50`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-zinc-900/50 transition-colors"
      >
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${sev.bg} ${sev.color} shrink-0`}>
          {sev.label}
        </span>
        <span className="flex-1 text-sm font-medium text-zinc-200 min-w-0">{finding.title}</span>
        <span className="text-[10px] text-zinc-600 shrink-0 hidden sm:block">{finding.module}</span>
        <svg
          className={`w-4 h-4 text-zinc-600 transition-transform shrink-0 ${isOpen ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isOpen && (
        <div className="px-4 pb-4 space-y-3 border-t border-zinc-800/50">
          <div className="pt-3">
            <p className="text-sm text-zinc-400 leading-relaxed">{finding.description}</p>
          </div>
          {finding.evidence && (
            <div>
              <h4 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Evidence</h4>
              <div className="relative group/evidence">
                <pre className="text-xs bg-zinc-900/80 border border-zinc-800/50 rounded-lg p-3 pr-10 text-zinc-400 overflow-x-auto whitespace-pre-wrap break-all">
                  {finding.evidence}
                </pre>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(finding.evidence!);
                    const btn = e.currentTarget;
                    btn.textContent = "✓";
                    setTimeout(() => { btn.textContent = "⎘"; }, 1200);
                  }}
                  className="absolute top-2 right-2 text-zinc-600 hover:text-zinc-300 text-sm opacity-0 group-hover/evidence:opacity-100 transition-opacity bg-zinc-800/80 rounded px-1.5 py-0.5"
                  title="Copy evidence"
                >⎘</button>
              </div>
            </div>
          )}
          <div>
            <h4 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">How to Fix</h4>
            <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">{finding.remediation}</p>
          </div>
          {finding.codeSnippet && (
            <div>
              <h4 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Code Fix</h4>
              <div className="relative group/snippet">
                <pre className="text-xs bg-zinc-900/80 border border-emerald-500/20 rounded-lg p-3 pr-10 text-emerald-300/80 overflow-x-auto whitespace-pre-wrap">
                  {finding.codeSnippet}
                </pre>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(finding.codeSnippet!);
                    const btn = e.currentTarget;
                    btn.textContent = "Copied!";
                    setTimeout(() => { btn.textContent = "Copy"; }, 1200);
                  }}
                  className="absolute top-2 right-2 text-zinc-600 hover:text-emerald-400 text-[10px] opacity-0 group-hover/snippet:opacity-100 transition-opacity bg-zinc-800/80 rounded px-1.5 py-0.5"
                >Copy</button>
              </div>
            </div>
          )}
          <div className="flex items-center gap-2 pt-1 flex-wrap">
            {finding.cwe && (
              <span className="text-[10px] bg-zinc-900 border border-zinc-800 rounded px-2 py-0.5 text-zinc-500">{finding.cwe}</span>
            )}
            {finding.owasp && (
              <span className="text-[10px] bg-zinc-900 border border-zinc-800 rounded px-2 py-0.5 text-zinc-500">OWASP {finding.owasp}</span>
            )}
            <button
              onClick={(e) => {
                e.stopPropagation();
                const url = `${window.location.origin}${window.location.pathname}#finding-${finding.id}`;
                navigator.clipboard.writeText(url);
                const btn = e.currentTarget;
                btn.textContent = "Linked!";
                setTimeout(() => { btn.textContent = "Link"; }, 1500);
              }}
              className="text-[10px] bg-zinc-800/50 border border-zinc-700/30 hover:border-zinc-600/50 text-zinc-500 rounded px-2 py-0.5 transition-colors"
            >
              Link
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                const prompt = `Fix this security vulnerability in my app:\n\n**${finding.title}**\n\nSeverity: ${finding.severity.toUpperCase()}\n\n${finding.description}\n\n${finding.evidence ? `Evidence:\n${finding.evidence}\n\n` : ""}Recommended fix:\n${finding.remediation}${finding.codeSnippet ? `\n\nExample code fix:\n\`\`\`\n${finding.codeSnippet}\n\`\`\`` : ""}`;
                navigator.clipboard.writeText(prompt);
                const btn = e.currentTarget;
                btn.textContent = "Copied!";
                setTimeout(() => { btn.textContent = "Copy AI fix prompt"; }, 2000);
              }}
              className="text-[10px] bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 text-red-400 rounded px-2 py-0.5 transition-colors ml-auto"
            >
              Copy AI fix prompt
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const ElapsedTimer = ({ startedAt, completedAt }: { startedAt: string; completedAt?: string }) => {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (completedAt) {
      setElapsed(Math.round((new Date(completedAt).getTime() - new Date(startedAt).getTime()) / 1000));
      return;
    }
    const tick = () => setElapsed(Math.round((Date.now() - new Date(startedAt).getTime()) / 1000));
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [startedAt, completedAt]);

  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  return <span>{mins > 0 ? `${mins}m ${secs}s` : `${secs}s`}</span>;
};

export default function ScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [rescanning, setRescanning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [openFindings, setOpenFindings] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<string>("all");
  const [moduleFilter, setModuleFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [groupBy, setGroupBy] = useState<"severity" | "module">("severity");
  const [expandAll, setExpandAll] = useState(false);
  const [copied, setCopied] = useState(false);
  const [mdCopied, setMdCopied] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval>>(undefined);

  const fetchScan = useCallback(async () => {
    try {
      const res = await fetch(`/api/scan/${id}`);
      if (!res.ok) {
        // Try loading from localStorage cache
        try {
          const cached = localStorage.getItem(`vibeshield-scan-${id}`);
          if (cached) {
            setScan(JSON.parse(cached));
            if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = undefined; }
            return;
          }
        } catch { /* skip */ }
        setError("Scan not found");
        return;
      }
      const data = await res.json() as ScanResult;
      setScan(data);

      if (data.status === "completed" || data.status === "failed") {
        // Cache completed scans in localStorage
        try { localStorage.setItem(`vibeshield-scan-${id}`, JSON.stringify(data)); } catch { /* skip */ }
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = undefined;
        }
      }
    } catch {
      // Try localStorage before giving up
      try {
        const cached = localStorage.getItem(`vibeshield-scan-${id}`);
        if (cached) {
          setScan(JSON.parse(cached));
          if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = undefined; }
          return;
        }
      } catch { /* skip */ }
      setError("Failed to fetch scan results");
    }
  }, [id]);

  useEffect(() => {
    fetchScan();
    intervalRef.current = setInterval(fetchScan, 2000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchScan]);

  // Keyboard shortcuts: / to focus search, Escape to clear, j/k to navigate findings
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        if (e.key === "Escape") { setSearch(""); setFilter("all"); (e.target as HTMLElement).blur(); }
        return;
      }
      if (e.key === "/" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        const input = document.querySelector<HTMLInputElement>('input[placeholder="Search findings..."]');
        input?.focus();
      }
      // j/k vim-style navigation between findings
      if ((e.key === "j" || e.key === "k") && !e.metaKey && !e.ctrlKey) {
        const cards = Array.from(document.querySelectorAll<HTMLElement>('[id^="finding-"]'));
        if (cards.length === 0) return;
        const currentIdx = cards.findIndex((c) => c.getBoundingClientRect().top >= 0);
        const nextIdx = e.key === "j"
          ? Math.min((currentIdx === -1 ? 0 : currentIdx) + 1, cards.length - 1)
          : Math.max((currentIdx === -1 ? 0 : currentIdx) - 1, 0);
        cards[nextIdx]?.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Auto-expand first critical/high finding when scan completes, or deep-link to hash target
  useEffect(() => {
    if (scan?.status === "completed" && openFindings.size === 0) {
      const hash = window.location.hash.replace("#", "");
      if (hash) {
        const target = scan.findings.find((f) => `finding-${f.id}` === hash);
        if (target) {
          setOpenFindings(new Set([target.id]));
          setTimeout(() => document.getElementById(hash)?.scrollIntoView({ behavior: "smooth", block: "center" }), 100);
          return;
        }
      }
      const first = scan.findings.find((f) => f.severity === "critical" || f.severity === "high");
      if (first) setOpenFindings(new Set([first.id]));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.status]);

  const toggleFinding = (findingId: string) => {
    setOpenFindings((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  const copyAsMarkdown = () => {
    if (!scan) return;
    const lines = [
      `# VibeShield Scan: ${scan.target}`,
      `**Grade:** ${scan.grade} (${scan.score}/100) | **Findings:** ${scan.summary.total}`,
      `**Critical:** ${scan.summary.critical} | **High:** ${scan.summary.high} | **Medium:** ${scan.summary.medium} | **Low:** ${scan.summary.low}`,
      "",
    ];
    const bySev = ["critical", "high", "medium", "low", "info"] as const;
    for (const sev of bySev) {
      const items = scan.findings.filter((f) => f.severity === sev);
      if (items.length === 0) continue;
      lines.push(`## ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${items.length})`);
      for (const f of items) {
        lines.push(`- **${f.title}** — ${f.description.split(".")[0]}.`);
      }
      lines.push("");
    }
    navigator.clipboard.writeText(lines.join("\n"));
    setMdCopied(true);
    setTimeout(() => setMdCopied(false), 2000);
  };

  const handleCancel = async () => {
    setCancelling(true);
    try {
      await fetch(`/api/scan/${id}`, { method: "DELETE" });
      fetchScan();
    } catch { /* skip */ }
    setCancelling(false);
  };

  const handleRescan = async () => {
    if (!scan) return;
    setRescanning(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scan.target, mode: scan.mode || "full" }),
      });
      const data = await res.json();
      router.push(`/scan/${data.id}`);
    } catch {
      setRescanning(false);
    }
  };

  const toggleExpandAll = () => {
    if (expandAll) {
      setOpenFindings(new Set());
    } else {
      setOpenFindings(new Set(sortedFindings.map((f) => f.id)));
    }
    setExpandAll(!expandAll);
  };

  if (error) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">VibeShield</a>
        <div className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-8 text-center max-w-sm">
          <div className="text-red-400 text-4xl mb-3">404</div>
          <p className="text-zinc-400 text-sm mb-4">{error}</p>
          <a href="/" className="text-sm bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-5 py-2 rounded-lg transition-colors inline-block">
            Start a new scan
          </a>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex items-center gap-3 text-zinc-500">
          <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading scan...
        </div>
      </div>
    );
  }

  const isRunning = scan.status === "scanning" || scan.status === "queued";
  const completedModules = scan.modules.filter((m) => m.status === "completed" || m.status === "failed" || m.status === "skipped").length;
  const totalModules = scan.modules.length;
  const progress = totalModules > 0 ? Math.round((completedModules / totalModules) * 100) : 0;
  const currentModule = scan.modules.find((m) => m.status === "running");

  const severityOrder = ["critical", "high", "medium", "low", "info"] as const;
  const searchLower = search.toLowerCase();
  const filteredFindings = scan.findings.filter((f) => {
    if (filter !== "all" && f.severity !== filter) return false;
    if (moduleFilter && f.module !== moduleFilter) return false;
    if (search && !f.title.toLowerCase().includes(searchLower) && !f.module.toLowerCase().includes(searchLower) && !f.remediation.toLowerCase().includes(searchLower)) return false;
    return true;
  });
  const sortedFindings = [...filteredFindings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
  );

  const gradeConf = GRADE_CONFIG[scan.grade] || GRADE_CONFIG["-"];

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="border-b border-zinc-800/50 px-4 sm:px-6 py-3">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400 shrink-0">
            VibeShield
          </a>
          <div className="flex items-center gap-3 min-w-0">
            <span className="text-sm text-zinc-500 truncate">{scan.target}</span>
            {scan.mode && (
              <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-zinc-800/80 text-zinc-500 shrink-0">
                {scan.mode === "quick" ? "Quick" : scan.mode === "full" ? "Full" : "Security"}
              </span>
            )}
            {!isRunning && (
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(window.location.href);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="text-xs bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-400 px-3 py-1.5 rounded-lg transition-colors"
                >
                  {copied ? "Copied!" : "Share"}
                </button>
                <div className="relative group/export">
                  <button className="text-xs bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-400 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1">
                    Export
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
                  </button>
                  <div className="absolute right-0 top-full mt-1 bg-zinc-900 border border-zinc-800 rounded-lg py-1 min-w-[140px] opacity-0 invisible group-hover/export:opacity-100 group-hover/export:visible transition-all z-50 shadow-xl">
                    <button onClick={copyAsMarkdown} className="w-full text-left text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 px-3 py-1.5 transition-colors">
                      {mdCopied ? "Copied!" : "Copy Markdown"}
                    </button>
                    <a href={`/api/scan/${id}/pdf`} target="_blank" rel="noopener" className="block text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 px-3 py-1.5 transition-colors">PDF Report</a>
                    <a href={`/api/scan/${id}/report`} download className="block text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 px-3 py-1.5 transition-colors">Markdown</a>
                    <a href={`/api/scan/${id}/export`} download className="block text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 px-3 py-1.5 transition-colors">JSON</a>
                    <a href={`/api/scan/${id}/sarif`} download className="block text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 px-3 py-1.5 transition-colors">SARIF</a>
                    <a href={`/api/scan/${id}/csv`} download className="block text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 px-3 py-1.5 transition-colors">CSV</a>
                  </div>
                </div>
                <button
                  onClick={handleRescan}
                  disabled={rescanning}
                  className="text-xs bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-400 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
                >
                  {rescanning ? "Starting..." : "Rescan"}
                </button>
                <a
                  href="/"
                  className="text-xs bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-3 py-1.5 rounded-lg transition-colors"
                >
                  New Scan
                </a>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6">
        {/* Failed banner */}
        {scan.status === "failed" && (
          <div className="mb-6 bg-red-500/5 border border-red-500/20 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="text-2xl">⚠</div>
              <div>
                <div className="text-sm font-medium text-red-400">Scan failed</div>
                <div className="text-xs text-zinc-500 mt-0.5">
                  {scan.error || (scan.modules.find((m) => m.error)?.error) || "The target may be unreachable, blocking our requests, or behind a firewall."}
                </div>
              </div>
              <button
                onClick={handleRescan}
                disabled={rescanning}
                className="ml-auto text-xs bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-400 px-3 py-1.5 rounded-lg transition-colors"
              >
                Retry
              </button>
            </div>
          </div>
        )}

        {/* Completion banner */}
        {!isRunning && scan.status === "completed" && (
          <div className={`mb-6 ${gradeConf.bg} border ${gradeConf.border} rounded-xl p-4`}>
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center gap-4">
                <div className={`text-3xl font-black ${gradeConf.color}`}>{scan.grade}</div>
                <div>
                  <div className="text-sm font-medium text-zinc-200">
                    Scan complete — {scan.summary.total} {scan.summary.total === 1 ? "finding" : "findings"} across {totalModules} modules
                  </div>
                  <div className="text-xs text-zinc-500 mt-0.5">
                    {scan.summary.critical > 0 && `${scan.summary.critical} critical, `}
                    {scan.summary.high > 0 && `${scan.summary.high} high, `}
                    {scan.summary.medium > 0 && `${scan.summary.medium} medium`}
                    {scan.summary.critical === 0 && scan.summary.high === 0 && scan.summary.medium === 0 && "No significant issues found"}
                    {" — "}
                    <ElapsedTimer startedAt={scan.startedAt} completedAt={scan.completedAt} /> scan time
                    {scan.mode && scan.mode !== "full" && ` (${scan.mode} mode)`}
                    {scan.percentile !== undefined && scan.percentile >= 0 && (
                      <span className="ml-1">— better than {scan.percentile}% of scanned apps</span>
                    )}
                  </div>
                  {scan.comparison && (
                    <div className="mt-2 bg-zinc-900/40 border border-zinc-800/40 rounded-lg p-3 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-medium">vs previous scan</div>
                        <a href={`/scan/${scan.comparison.previousId}`} className="text-[10px] text-zinc-600 hover:text-zinc-400 transition-colors">
                          View previous →
                        </a>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className={`text-sm font-bold ${scan.comparison.delta.score > 0 ? "text-green-400" : scan.comparison.delta.score < 0 ? "text-red-400" : "text-zinc-400"}`}>
                          {scan.comparison.delta.score > 0 ? "↑" : scan.comparison.delta.score < 0 ? "↓" : "="}{" "}
                          {Math.abs(scan.comparison.delta.score)} pts
                        </div>
                        <div className="text-[10px] text-zinc-600">
                          {scan.comparison.previousGrade} → {scan.grade}
                        </div>
                        <div className={`text-xs ${scan.comparison.delta.findings < 0 ? "text-green-400" : scan.comparison.delta.findings > 0 ? "text-red-400" : "text-zinc-500"}`}>
                          {scan.comparison.delta.findings > 0 ? "+" : ""}{scan.comparison.delta.findings} findings
                        </div>
                        {scan.comparison.delta.critical !== 0 && (
                          <div className={`text-xs ${scan.comparison.delta.critical < 0 ? "text-green-400" : "text-red-400"}`}>
                            {scan.comparison.delta.critical > 0 ? "+" : ""}{scan.comparison.delta.critical} critical
                          </div>
                        )}
                      </div>
                      {(scan.comparison.fixedFindings?.length ?? 0) > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] text-green-500/70 font-medium">FIXED</span>
                          {scan.comparison.fixedFindings!.map((f, i) => (
                            <span key={i} className="text-[10px] text-green-400/80 bg-green-500/10 border border-green-500/20 rounded px-1.5 py-0.5">{f.title.length > 35 ? f.title.slice(0, 35) + "…" : f.title}</span>
                          ))}
                        </div>
                      )}
                      {(scan.comparison.newFindings?.length ?? 0) > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] text-red-500/70 font-medium">NEW</span>
                          {scan.comparison.newFindings!.map((f, i) => (
                            <span key={i} className="text-[10px] text-red-400/80 bg-red-500/10 border border-red-500/20 rounded px-1.5 py-0.5">{f.title.length > 35 ? f.title.slice(0, 35) + "…" : f.title}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
              {scan.summary.total > 0 && (
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => {
                      const criticalAndHigh = scan.findings.filter((f) => f.severity === "critical" || f.severity === "high");
                      const medium = scan.findings.filter((f) => f.severity === "medium");
                      const items = [...criticalAndHigh, ...medium.slice(0, 5)];
                      const prompt = `Fix these security vulnerabilities found in ${scan.target}:\n\n${items.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n   ${f.remediation}${f.codeSnippet ? `\n   Example fix:\n   ${f.codeSnippet.split("\n").join("\n   ")}` : ""}`).join("\n\n")}${medium.length > 5 ? `\n\n...and ${medium.length - 5} more medium findings (download full report for details)` : ""}`;
                      navigator.clipboard.writeText(prompt);
                      const btn = document.getElementById("fix-all-btn");
                      if (btn) { btn.textContent = "Copied!"; setTimeout(() => { btn.textContent = "Copy Fix-All Prompt"; }, 2000); }
                    }}
                    id="fix-all-btn"
                    className="text-xs bg-zinc-950/50 border border-zinc-700/50 hover:border-zinc-600 text-zinc-300 px-4 py-2 rounded-lg transition-colors"
                  >
                    Copy Fix-All Prompt
                  </button>
                  <button
                    onClick={() => {
                      const hostname = (() => { try { return new URL(scan.target).hostname; } catch { return scan.target; } })();
                      const emoji = scan.score >= 75 ? "🟢" : scan.score >= 50 ? "🟡" : "🔴";
                      const lines = [
                        `${emoji} VibeShield Scan: ${hostname}`,
                        `Grade: ${scan.grade} (${scan.score}/100)`,
                        `Findings: ${scan.summary.total} total`,
                        scan.summary.critical > 0 ? `  🔴 ${scan.summary.critical} critical` : "",
                        scan.summary.high > 0 ? `  🟠 ${scan.summary.high} high` : "",
                        scan.summary.medium > 0 ? `  🟡 ${scan.summary.medium} medium` : "",
                        scan.summary.low > 0 ? `  🔵 ${scan.summary.low} low` : "",
                        "",
                        `Full report: ${window.location.href}`,
                      ].filter(Boolean).join("\n");
                      navigator.clipboard.writeText(lines);
                      const btn = document.getElementById("share-summary-btn");
                      if (btn) { btn.textContent = "Copied!"; setTimeout(() => { btn.textContent = "Copy Summary"; }, 2000); }
                    }}
                    id="share-summary-btn"
                    className="text-xs bg-zinc-950/50 border border-zinc-700/50 hover:border-zinc-600 text-zinc-300 px-4 py-2 rounded-lg transition-colors"
                  >
                    Copy Summary
                  </button>
                  <button
                    onClick={() => {
                      const hostname = (() => { try { return new URL(scan.target).hostname; } catch { return scan.target; } })();
                      const sevEmoji = (s: string) => s === "critical" ? "🔴" : s === "high" ? "🟠" : s === "medium" ? "🟡" : "🔵";
                      const critical = scan.findings.filter((f) => f.severity === "critical" || f.severity === "high");
                      const medium = scan.findings.filter((f) => f.severity === "medium");
                      const items = [...critical, ...medium];
                      const body = [
                        `## VibeShield Security Scan — ${hostname}`,
                        "",
                        `**Grade:** ${scan.grade} (${scan.score}/100) | **Findings:** ${scan.summary.total}`,
                        "",
                        "### Findings to Fix",
                        "",
                        ...items.slice(0, 10).map((f) => [
                          `#### ${sevEmoji(f.severity)} [${f.severity.toUpperCase()}] ${f.title}`,
                          "",
                          f.description,
                          "",
                          `**Fix:** ${f.remediation}`,
                          f.cwe ? `\n*${f.cwe}${f.owasp ? ` | OWASP ${f.owasp}` : ""}*` : "",
                          "",
                        ]).flat(),
                        items.length > 10 ? `...and ${items.length - 10} more findings` : "",
                        "",
                        `---`,
                        `*Scanned by [VibeShield](${window.location.href})*`,
                      ].filter(Boolean).join("\n");
                      const title = `[Security] VibeShield scan: ${scan.grade} (${scan.summary.total} findings) — ${hostname}`;
                      const issueUrl = `https://github.com/new?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}&labels=security`;
                      window.open(issueUrl, "_blank");
                    }}
                    className="text-xs bg-zinc-950/50 border border-zinc-700/50 hover:border-zinc-600 text-zinc-300 px-4 py-2 rounded-lg transition-colors"
                  >
                    Create GitHub Issue
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Quick scan upsell */}
        {!isRunning && scan.status === "completed" && scan.mode === "quick" && scan.summary.total > 0 && (
          <div className="mb-4 bg-orange-500/5 border border-orange-500/20 rounded-xl p-3 flex items-center justify-between gap-3">
            <div className="text-xs text-orange-300/80">
              Quick scan found {scan.summary.total} issue{scan.summary.total !== 1 ? "s" : ""}. Run a full scan to check {48 - 13} more security modules including injection, SSRF, and stress testing.
            </div>
            <button
              onClick={async () => {
                setRescanning(true);
                try {
                  const res = await fetch("/api/scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: scan.target, mode: "full" }),
                  });
                  const data = await res.json();
                  router.push(`/scan/${data.id}`);
                } catch { setRescanning(false); }
              }}
              disabled={rescanning}
              className="text-[10px] bg-orange-600/20 border border-orange-500/30 hover:bg-orange-600/30 text-orange-300 px-3 py-1.5 rounded-lg transition-colors shrink-0 disabled:opacity-50"
            >
              {rescanning ? "Starting..." : "Run Full Scan"}
            </button>
          </div>
        )}

        {/* Badge embed */}
        {!isRunning && scan.status === "completed" && (
          <div className="mb-6 flex items-center gap-3 text-xs">
            <span className="text-zinc-600">Embed badge:</span>
            <code className="bg-zinc-900/80 border border-zinc-800/50 rounded px-2 py-1 text-zinc-500 font-mono text-[11px] truncate max-w-md">
              {`![VibeShield](${typeof window !== "undefined" ? window.location.origin : ""}/api/scan/${scan.id}/badge)`}
            </code>
            <button
              onClick={() => {
                const badgeUrl = `${window.location.origin}/api/scan/${scan.id}/badge`;
                navigator.clipboard.writeText(`![VibeShield](${badgeUrl})`);
                const el = document.getElementById("badge-copy-btn");
                if (el) { el.textContent = "Copied!"; setTimeout(() => { el.textContent = "Copy"; }, 2000); }
              }}
              id="badge-copy-btn"
              className="text-zinc-500 hover:text-zinc-300 transition-colors shrink-0"
            >
              Copy
            </button>
          </div>
        )}

        {/* Score history sparkline */}
        {!isRunning && scan.history && scan.history.length > 1 && (() => {
          const h = scan.history;
          const minScore = Math.min(...h.map((s) => s.score));
          const maxScore = Math.max(...h.map((s) => s.score));
          const range = Math.max(maxScore - minScore, 10);
          const height = 40;
          const width = h.length * 32;
          const points = h.map((s, i) => ({
            x: (i / (h.length - 1)) * (width - 8) + 4,
            y: height - ((s.score - minScore) / range) * (height - 8) - 4,
            ...s,
          }));
          const pathD = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
          const trend = h[h.length - 1].score - h[0].score;
          return (
            <div className="mb-6 bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-3 flex items-center gap-4">
              <div className="text-[10px] text-zinc-600 shrink-0">
                <div className="font-medium text-zinc-500">Score History</div>
                <div>{h.length} scans</div>
                <div className={trend > 0 ? "text-green-500" : trend < 0 ? "text-red-400" : "text-zinc-500"}>
                  {trend > 0 ? "+" : ""}{trend} pts overall
                </div>
              </div>
              <svg viewBox={`0 0 ${width} ${height}`} className="flex-1 max-w-xs h-10" preserveAspectRatio="none">
                <path d={pathD} fill="none" stroke={trend >= 0 ? "#22c55e" : "#ef4444"} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                {points.map((p, i) => (
                  <circle key={i} cx={p.x} cy={p.y} r={p.id === scan.id ? 4 : 2.5} fill={p.id === scan.id ? "#fff" : trend >= 0 ? "#22c55e" : "#ef4444"} stroke={p.id === scan.id ? (trend >= 0 ? "#22c55e" : "#ef4444") : "none"} strokeWidth="2" />
                ))}
              </svg>
              <div className="flex gap-1.5 shrink-0">
                {h.map((s) => (
                  <a
                    key={s.id}
                    href={`/scan/${s.id}`}
                    className={`text-[9px] px-1 py-0.5 rounded transition-colors ${s.id === scan.id ? "bg-zinc-700 text-zinc-200 font-bold" : "text-zinc-600 hover:text-zinc-400"}`}
                    title={`${s.grade} (${s.score}) — ${new Date(s.date).toLocaleDateString()}`}
                  >
                    {s.grade}
                  </a>
                ))}
              </div>
            </div>
          );
        })()}

        {/* Progress bar */}
        {isRunning && (
          <div className="mb-6 bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-4">
            <div className="flex items-center justify-between text-sm mb-3">
              <span className="text-zinc-300 flex items-center gap-2">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
                </span>
                {currentModule ? (
                  <>Running: <span className="font-medium text-zinc-100">{currentModule.name}</span></>
                ) : (
                  "Starting scan..."
                )}
              </span>
              <div className="flex items-center gap-3 text-zinc-500 text-xs">
                <span><ElapsedTimer startedAt={scan.startedAt} /></span>
                <span>{completedModules}/{totalModules} modules</span>
                {completedModules >= 3 && (() => {
                  const elapsed = (Date.now() - new Date(scan.startedAt).getTime()) / 1000;
                  const rate = completedModules / elapsed;
                  const remaining = Math.round((totalModules - completedModules) / rate);
                  const mins = Math.floor(remaining / 60);
                  const secs = remaining % 60;
                  return <span className="text-zinc-600">~{mins > 0 ? `${mins}m ${secs}s` : `${secs}s`} left</span>;
                })()}
                {scan.summary.total > 0 && (
                  <span className="text-orange-500/70">
                    {scan.summary.total} found
                    {scan.summary.critical > 0 && <span className="text-red-400 ml-1">({scan.summary.critical}C</span>}
                    {scan.summary.critical > 0 && scan.summary.high > 0 && <span className="text-orange-400"> {scan.summary.high}H</span>}
                    {scan.summary.critical > 0 && <span className="text-red-400">)</span>}
                    {scan.summary.critical === 0 && scan.summary.high > 0 && <span className="text-orange-400 ml-1">({scan.summary.high}H)</span>}
                  </span>
                )}
                <button
                  onClick={handleCancel}
                  disabled={cancelling}
                  className="text-zinc-600 hover:text-red-400 transition-colors disabled:opacity-50"
                  title="Cancel scan"
                >
                  {cancelling ? "..." : "Cancel"}
                </button>
              </div>
            </div>
            <div className="w-full bg-zinc-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-linear-to-r from-red-500 to-orange-500 h-1.5 rounded-full transition-all duration-700 ease-out"
                style={{ width: `${Math.max(progress, 2)}%` }}
              />
            </div>
          </div>
        )}

        {/* Top stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 sm:gap-3 mb-6">
          {/* Grade card */}
          <div className={`${gradeConf.bg} border ${gradeConf.border} rounded-xl p-4 text-center col-span-2`}>
            <div className={`text-5xl font-black ${scan.status === "failed" ? "text-red-500" : gradeConf.color}`}>
              {isRunning ? "..." : scan.status === "failed" ? "ERR" : scan.grade}
            </div>
            <div className="text-xs text-zinc-500 mt-1">
              {isRunning ? "Scanning" : scan.status === "failed" ? "Scan failed" : `${scan.score}/100 · ${gradeConf.desc}`}
            </div>
            {!isRunning && scan.status === "completed" && scan.summary.total > 0 && (
              <div className="mt-2 text-[10px] text-zinc-600 space-y-0.5">
                {scan.summary.critical > 0 && <div className="text-red-400/70">-{Math.round(30 * (1 - Math.pow(0.6, scan.summary.critical)) / (1 - 0.6))} critical</div>}
                {scan.summary.high > 0 && <div className="text-orange-400/70">-{Math.round(12 * (1 - Math.pow(0.7, scan.summary.high)) / (1 - 0.7))} high</div>}
                {scan.summary.medium > 0 && <div className="text-yellow-400/70">-{Math.round(4 * (1 - Math.pow(0.8, scan.summary.medium)) / (1 - 0.8))} medium</div>}
                {scan.summary.low > 0 && <div className="text-blue-400/70">-{Math.round(1 * (1 - Math.pow(0.85, scan.summary.low)) / (1 - 0.85))} low</div>}
                {scan.summary.critical >= 1 && scan.summary.high >= 2 && <div className="text-red-400/70">-10 combo</div>}
              </div>
            )}
          </div>

          {/* Severity breakdown */}
          {severityOrder.map((sev) => {
            const conf = SEVERITY_CONFIG[sev];
            const count = scan.summary[sev];
            const isActive = filter === sev;
            return (
              <button
                key={sev}
                onClick={() => setFilter(filter === sev ? "all" : sev)}
                className={`rounded-xl p-3 text-center transition-all ${
                  isActive
                    ? `${conf.bg} border ${conf.border} scale-[1.02]`
                    : "bg-zinc-900/50 border border-zinc-800/50 hover:border-zinc-700/50"
                }`}
              >
                <div className={`text-xl sm:text-2xl font-bold ${count > 0 ? conf.color : "text-zinc-700"}`}>
                  {count}
                </div>
                <div className="text-[10px] text-zinc-600 mt-0.5 capitalize">{sev}</div>
              </button>
            );
          })}

          <div className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-3 text-center">
            <div className="text-xl sm:text-2xl font-bold text-zinc-300">{scan.summary.total}</div>
            <div className="text-[10px] text-zinc-600 mt-0.5">Total</div>
          </div>
        </div>

        {/* Severity distribution bar */}
        {!isRunning && scan.summary.total > 0 && (
          <div className="mb-6 flex h-2 rounded-full overflow-hidden bg-zinc-800/50">
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
              const count = scan.summary[sev];
              if (count === 0) return null;
              const pct = (count / scan.summary.total) * 100;
              const colors = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500", info: "bg-zinc-500" };
              return (
                <div
                  key={sev}
                  className={`${colors[sev]} transition-all duration-500 cursor-pointer hover:opacity-80`}
                  style={{ width: `${pct}%` }}
                  title={`${count} ${sev}`}
                  onClick={() => setFilter(filter === sev ? "all" : sev)}
                />
              );
            })}
          </div>
        )}

        {/* Module filter pills */}
        {!isRunning && scan.findings.length > 0 && (() => {
          const modules = [...new Set(scan.findings.map((f) => f.module))].sort();
          if (modules.length <= 1) return null;
          return (
            <div className="mb-4 flex items-center gap-1.5 flex-wrap">
              <button
                onClick={() => setModuleFilter(null)}
                className={`text-[10px] px-2.5 py-1 rounded-full transition-colors ${!moduleFilter ? "bg-zinc-700 text-zinc-200" : "bg-zinc-900/50 text-zinc-600 hover:text-zinc-400 border border-zinc-800/50"}`}
              >
                All modules
              </button>
              {modules.map((mod) => {
                const count = scan.findings.filter((f) => f.module === mod).length;
                const worst = (["critical", "high", "medium", "low", "info"] as const).find((s) => scan.findings.some((f) => f.module === mod && f.severity === s));
                const dotColor = worst ? SEVERITY_CONFIG[worst].dot : "bg-zinc-600";
                return (
                  <button
                    key={mod}
                    onClick={() => setModuleFilter(moduleFilter === mod ? null : mod)}
                    className={`text-[10px] px-2.5 py-1 rounded-full transition-colors flex items-center gap-1.5 ${moduleFilter === mod ? "bg-zinc-700 text-zinc-200" : "bg-zinc-900/50 text-zinc-600 hover:text-zinc-400 border border-zinc-800/50"}`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
                    {mod} ({count})
                  </button>
                );
              })}
            </div>
          );
        })()}

        {/* Security summary */}
        {!isRunning && scan.status === "completed" && scan.findings.length > 0 && (
          <div className="mb-6 bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
            <p className="text-sm text-zinc-400 leading-relaxed">
              {(() => {
                const { critical, high, medium } = scan.summary;
                const hostname = (() => { try { return new URL(scan.target).hostname; } catch { return scan.target; } })();
                const parts: string[] = [];
                if (critical > 0) parts.push(`${critical} critical ${critical === 1 ? "vulnerability" : "vulnerabilities"} that need immediate attention`);
                if (high > 0) parts.push(`${high} high-severity ${high === 1 ? "issue" : "issues"}`);
                if (medium > 0) parts.push(`${medium} medium-severity ${medium === 1 ? "finding" : "findings"}`);

                const modules = [...new Set(scan.findings.filter((f) => f.severity === "critical" || f.severity === "high").map((f) => f.module))];
                const moduleStr = modules.length > 0 ? ` Key areas: ${modules.slice(0, 3).join(", ")}.` : "";

                if (critical > 0) return `${hostname} has ${parts.join(", ")}. Your app is at significant risk.${moduleStr} Fix critical issues first — they represent the highest risk to your users.`;
                if (high > 0) return `${hostname} has ${parts.join(" and ")}. While no critical vulnerabilities were found, the high-severity issues should be addressed soon.${moduleStr}`;
                return `${hostname} has ${parts.join(" and ")}. No critical or high-severity issues — good foundation. Address the medium findings to further harden your app.`;
              })()}
            </p>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 sm:gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-4">
            {/* Module progress */}
            <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
              <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                Modules ({completedModules}/{totalModules})
              </h3>
              <div className="space-y-0.5">
                {scan.modules.map((mod) => (
                  <button
                    key={mod.name}
                    onClick={() => {
                      if (mod.findingsCount > 0) {
                        setModuleFilter(moduleFilter === mod.name ? null : mod.name);
                        setGroupBy("module");
                      }
                    }}
                    className={`flex items-center gap-2 text-xs py-1.5 px-2 rounded-md transition-colors w-full text-left ${
                      moduleFilter === mod.name ? "bg-zinc-800/80" :
                      mod.status === "running" ? "bg-zinc-800/50" :
                      mod.findingsCount > 0 ? "hover:bg-zinc-800/40" : ""
                    }`}
                  >
                    {mod.status === "running" && (
                      <svg className="animate-spin h-3 w-3 text-red-500 shrink-0" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                    )}
                    {mod.status === "completed" && (
                      <svg className="h-3 w-3 text-emerald-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                    {mod.status === "failed" && (
                      <span title={mod.error || "Module failed"}>
                        <svg className="h-3 w-3 text-red-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </span>
                    )}
                    {mod.status === "skipped" && (
                      <svg className="h-3 w-3 text-zinc-600 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M5 5l7 7-7 7" />
                      </svg>
                    )}
                    {mod.status === "pending" && (
                      <div className="h-3 w-3 rounded-full border border-zinc-700/50 shrink-0" />
                    )}
                    <span className={`truncate ${
                      mod.status === "running" ? "text-zinc-200 font-medium" :
                      mod.status === "completed" ? "text-zinc-500" :
                      mod.status === "skipped" ? "text-zinc-700 line-through" : "text-zinc-700"
                    }`}>
                      {mod.name}
                    </span>
                    <span className="ml-auto flex items-center gap-1.5">
                      {mod.findingsCount > 0 && (
                        <span className="text-[10px] text-zinc-600 tabular-nums">{mod.findingsCount}</span>
                      )}
                      {mod.durationMs != null && (mod.status === "completed" || mod.status === "failed") && (
                        <span className="text-[10px] text-zinc-700 tabular-nums">{mod.durationMs < 1000 ? `${mod.durationMs}ms` : `${(mod.durationMs / 1000).toFixed(1)}s`}</span>
                      )}
                    </span>
                    {mod.status === "failed" && mod.error && (
                      <span className="text-[9px] text-red-500/60 truncate max-w-[120px]" title={mod.error}>
                        {mod.error.length > 30 ? `${mod.error.slice(0, 30)}…` : mod.error}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Tech stack */}
            {scan.technologies && scan.technologies.length > 0 && (
              <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                  Detected Stack
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {scan.technologies.map((tech) => (
                    <span
                      key={tech}
                      className="text-[10px] bg-zinc-800/80 border border-zinc-700/50 text-zinc-400 px-2 py-1 rounded-md"
                    >
                      {tech}
                    </span>
                  ))}
                  {scan.isSpa && (
                    <span className="text-[10px] bg-blue-500/10 border border-blue-500/20 text-blue-400 px-2 py-1 rounded-md">
                      SPA
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Tech-specific tips */}
            {!isRunning && scan.technologies.length > 0 && (() => {
              const tips: { tech: string; tip: string }[] = [];
              const techs = scan.technologies.map((t) => t.toLowerCase());
              if (techs.some((t) => t.includes("next"))) tips.push({ tech: "Next.js", tip: "Set NEXTAUTH_SECRET, enable CSP in next.config, use middleware for auth" });
              if (techs.some((t) => t.includes("react"))) tips.push({ tech: "React", tip: "Avoid dangerouslySetInnerHTML, sanitize props from URL params" });
              if (techs.some((t) => t.includes("supabase"))) tips.push({ tech: "Supabase", tip: "Enable RLS on all tables, never expose service_role key client-side" });
              if (techs.some((t) => t.includes("firebase"))) tips.push({ tech: "Firebase", tip: "Set Firestore security rules, restrict API key to your domain" });
              if (techs.some((t) => t.includes("stripe"))) tips.push({ tech: "Stripe", tip: "Verify webhook signatures, validate prices server-side" });
              if (techs.some((t) => t.includes("vercel"))) tips.push({ tech: "Vercel", tip: "Enable Vercel Firewall, set security headers in vercel.json" });
              if (techs.some((t) => t.includes("tailwind"))) tips.push({ tech: "Tailwind", tip: "CSP may need unsafe-inline for styles — use nonce-based CSP" });
              if (techs.some((t) => t.includes("graphql"))) tips.push({ tech: "GraphQL", tip: "Disable introspection in production, set query depth limits" });
              if (techs.some((t) => t.includes("socket"))) tips.push({ tech: "WebSocket", tip: "Use wss://, authenticate connections, validate message schemas" });
              if (techs.some((t) => t.includes("openai") || t.includes("anthropic"))) tips.push({ tech: "AI/LLM", tip: "Proxy API calls through backend, rate-limit per user, validate/sanitize prompts" });
              if (techs.some((t) => t.includes("remix"))) tips.push({ tech: "Remix", tip: "Validate loader/action data, use CSRF tokens on forms, sanitize user content" });
              if (techs.some((t) => t.includes("vite"))) tips.push({ tech: "Vite", tip: "Ensure .env files are not bundled, use VITE_ prefix only for public vars" });
              if (techs.some((t) => t.includes("convex"))) tips.push({ tech: "Convex", tip: "Use argument validation in mutations, never expose deploy keys client-side" });
              if (techs.some((t) => t.includes("clerk") || t.includes("auth0"))) tips.push({ tech: "Auth Provider", tip: "Verify JWT signatures server-side, restrict redirect URIs, enable MFA" });
              if (techs.some((t) => t.includes("mongodb") || t.includes("prisma"))) tips.push({ tech: "Database", tip: "Use parameterized queries, validate input types, never expose connection strings" });
              if (techs.some((t) => t.includes("sentry"))) tips.push({ tech: "Sentry", tip: "Configure allowed origins for DSN, strip PII from error reports" });
              if (techs.some((t) => t.includes("deepseek") || t.includes("groq") || t.includes("replicate") || t.includes("google ai"))) tips.push({ tech: "AI Provider", tip: "Proxy all API calls through backend, add per-user rate limits, set billing alerts" });
              if (techs.some((t) => t.includes("lemon"))) tips.push({ tech: "Lemon Squeezy", tip: "Verify webhook signatures, validate prices server-side, protect API keys" });
              if (techs.some((t) => t.includes("drizzle"))) tips.push({ tech: "Drizzle", tip: "Use parameterized queries, validate input with Zod, never expose Drizzle Studio in prod" });
              if (techs.some((t) => t.includes("trpc"))) tips.push({ tech: "tRPC", tip: "Add auth middleware to protected procedures, disable tRPC panel in production" });
              if (techs.some((t) => t.includes("inngest"))) tips.push({ tech: "Inngest", tip: "Set signing key in production, validate event payloads, use background functions for sensitive ops" });
              if (techs.some((t) => t.includes("uploadthing") || t.includes("upload"))) tips.push({ tech: "File Uploads", tip: "Validate file types server-side, limit file size, scan for malware, store outside web root" });
              if (techs.some((t) => t.includes("resend") || t.includes("sendgrid") || t.includes("postmark"))) tips.push({ tech: "Email Service", tip: "Protect API key, rate-limit email sends, validate recipient addresses to prevent abuse" });
              if (tips.length === 0) return null;
              return (
                <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                  <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                    Security Tips
                  </h3>
                  <div className="space-y-2">
                    {tips.slice(0, 4).map((t) => (
                      <div key={t.tech} className="text-xs">
                        <span className="text-zinc-400 font-medium">{t.tech}:</span>{" "}
                        <span className="text-zinc-600">{t.tip}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* Attack surface */}
            {scan.surface && (
              <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                  Attack Surface
                </h3>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: "Pages", value: scan.surface.pages },
                    { label: "API endpoints", value: scan.surface.apiEndpoints },
                    { label: "JS bundles", value: scan.surface.jsFiles },
                    { label: "Forms", value: scan.surface.forms },
                    { label: "Cookies", value: scan.surface.cookies },
                  ].filter((s) => s.value > 0).map((s) => (
                    <div key={s.label} className="text-xs">
                      <span className="text-zinc-300 font-medium tabular-nums">{s.value}</span>
                      <span className="text-zinc-600 ml-1">{s.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Security checklist */}
            {!isRunning && scan.status === "completed" && (() => {
              const modules = scan.modules.filter((m) => m.status === "completed");
              const failedModules = new Set(scan.findings.map((f) => f.module));
              const passedChecks: { name: string; label: string }[] = [];
              const failedChecks: { name: string; label: string; count: number }[] = [];

              const checkLabels: Record<string, string> = {
                "Security Headers": "Security headers configured",
                "SSL/TLS": "HTTPS/TLS properly set up",
                "Cookies": "Cookie security flags set",
                "CORS": "CORS policy is restrictive",
                "CSP Analysis": "Content Security Policy enforced",
                "Secret Detection": "No exposed API keys",
                "Source Maps": "Source maps not public",
                "CSRF": "CSRF protection in place",
                "Clickjacking": "Clickjacking protection",
                "Authentication": "Auth endpoints protected",
                "SQL Injection & XSS": "No injection vulnerabilities",
                "Open Redirect": "No open redirects",
                "IDOR": "No IDOR vulnerabilities",
                "Environment Leak": "No env variable leaks",
                "Dependencies": "Dependencies up to date",
                "JWT Security": "JWT implementation secure",
                "Directory & File Exposure": "No sensitive files exposed",
                "Exposed Dev Tools": "No dev tools in production",
                "API Security": "API endpoints hardened",
                "Information Leakage": "No info leaks in errors",
                "GraphQL": "GraphQL security configured",
              };

              for (const mod of modules) {
                const label = checkLabels[mod.name];
                if (!label) continue;
                if (failedModules.has(mod.name)) {
                  const count = scan.findings.filter((f) => f.module === mod.name).length;
                  failedChecks.push({ name: mod.name, label, count });
                } else {
                  passedChecks.push({ name: mod.name, label });
                }
              }

              if (passedChecks.length === 0 && failedChecks.length === 0) return null;
              return (
                <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                  <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                    Security Checklist
                  </h3>
                  <div className="space-y-1.5">
                    {passedChecks.slice(0, 8).map((c) => (
                      <div key={c.name} className="flex items-center gap-2 text-xs">
                        <span className="text-emerald-500 shrink-0">✓</span>
                        <span className="text-zinc-500">{c.label}</span>
                      </div>
                    ))}
                    {failedChecks.slice(0, 6).map((c) => (
                      <div key={c.name} className="flex items-center gap-2 text-xs">
                        <span className="text-red-400 shrink-0">✗</span>
                        <span className="text-zinc-400">{c.label}</span>
                        <span className="text-zinc-700 text-[10px]">({c.count})</span>
                      </div>
                    ))}
                  </div>
                  {passedChecks.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-zinc-800/30 text-[10px] text-zinc-600">
                      {passedChecks.length}/{passedChecks.length + failedChecks.length} checks passed
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Grade roadmap */}
            {!isRunning && scan.status === "completed" && scan.findings.length > 0 && scan.score < 95 && (() => {
              const penalty = (count: number, weight: number, decay: number) =>
                Array.from({ length: count }, (_, i) => weight * Math.pow(decay, i)).reduce((a, b) => a + b, 0);
              const weights = { critical: { w: 30, d: 0.6 }, high: { w: 12, d: 0.7 }, medium: { w: 4, d: 0.8 }, low: { w: 1, d: 0.85 } } as const;
              type Sev = keyof typeof weights;
              const effortForModule = (mod: string): "quick" | "medium" | "complex" => {
                const quickModules = /headers|cookies|clickjacking|ssl|cors|source.maps|dependencies|http.methods|environment/i;
                const complexModules = /injection|ssrf|auth|idor|business|command|nosql|supabase|firebase/i;
                if (quickModules.test(mod)) return "quick";
                if (complexModules.test(mod)) return "complex";
                return "medium";
              };
              const effortLabel = { quick: "5 min fix", medium: "~30 min", complex: "1+ hour" };
              const effortColor = { quick: "text-emerald-500/60", medium: "text-yellow-500/50", complex: "text-orange-500/50" };
              const steps: { fix: string; severity: Sev; points: number; findingId: string; effort: "quick" | "medium" | "complex" }[] = [];
              const remaining = { critical: scan.summary.critical, high: scan.summary.high, medium: scan.summary.medium, low: scan.summary.low };

              for (const sev of ["critical", "high", "medium", "low"] as Sev[]) {
                const sevFindings = scan.findings.filter((f) => f.severity === sev);
                for (const f of sevFindings) {
                  const { w, d } = weights[sev];
                  const before = penalty(remaining[sev], w, d);
                  remaining[sev]--;
                  const after = penalty(Math.max(0, remaining[sev]), w, d);
                  const pts = Math.round(before - after);
                  if (pts > 0) steps.push({ fix: f.title, severity: sev, points: pts, findingId: f.id, effort: effortForModule(f.module) });
                }
              }

              // Sort by points/effort ratio (quick wins first), then by points
              const effortRank = { quick: 0, medium: 1, complex: 2 };
              steps.sort((a, b) => {
                // Primary: quick efforts with high points first
                const ratioA = a.points / (effortRank[a.effort] + 1);
                const ratioB = b.points / (effortRank[b.effort] + 1);
                if (ratioA !== ratioB) return ratioB - ratioA;
                return b.points - a.points;
              });

              let runningScore = scan.score;
              const gradeAt = (s: number) => s >= 95 ? "A" : s >= 85 ? "A-" : s >= 75 ? "B+" : s >= 65 ? "B" : s >= 55 ? "C+" : s >= 45 ? "C" : s >= 35 ? "D+" : s >= 25 ? "D" : "F";
              const milestones: { step: number; grade: string; score: number }[] = [];
              for (let i = 0; i < steps.length; i++) {
                const newScore = Math.min(100, runningScore + steps[i].points);
                if (gradeAt(newScore) !== gradeAt(runningScore)) {
                  milestones.push({ step: i + 1, grade: gradeAt(newScore), score: newScore });
                }
                runningScore = newScore;
              }

              return (
                <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                  <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1">
                    Improve Your Grade
                  </h3>
                  <div className="text-[9px] text-zinc-600 mb-3">Sorted by quick wins first</div>
                  <div className="space-y-2">
                    {steps.slice(0, 7).map((s, i) => {
                      const sConf = SEVERITY_CONFIG[s.severity];
                      return (
                        <button
                          key={s.findingId}
                          className="text-xs text-left w-full hover:bg-zinc-800/30 rounded-md p-1 -m-1 transition-colors"
                          onClick={() => {
                            setOpenFindings((prev) => new Set([...prev, s.findingId]));
                            document.getElementById(`finding-${s.findingId}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
                          }}
                        >
                          <div className="flex items-start gap-2">
                            <span className={`font-bold ${sConf.color} shrink-0`}>{i + 1}.</span>
                            <div className="flex-1 min-w-0">
                              <div className="text-zinc-300 font-medium leading-snug truncate">{s.fix}</div>
                            </div>
                            <span className={`text-[9px] shrink-0 ${effortColor[s.effort]}`}>{effortLabel[s.effort]}</span>
                            <span className="text-green-400/70 text-[10px] shrink-0">+{s.points}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                  {milestones.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-zinc-800/30 space-y-1">
                      {milestones.map((m) => {
                        const gc = GRADE_CONFIG[m.grade] || GRADE_CONFIG["-"];
                        return (
                          <div key={m.grade} className="flex items-center gap-2 text-[10px]">
                            <span className={`font-bold ${gc.color}`}>{m.grade}</span>
                            <span className="text-zinc-600">after fixing top {m.step} {m.step === 1 ? "issue" : "issues"}</span>
                            <span className="text-zinc-700 ml-auto">{m.score}/100</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Module breakdown */}
            {!isRunning && (
              <div className="bg-zinc-900/30 border border-zinc-800/30 rounded-xl p-4">
                <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-3">
                  Module Results
                </h3>
                <div className="space-y-1">
                  {scan.modules.filter((m) => m.name !== "Recon").map((m) => {
                    const hasFindings = m.findingsCount > 0;
                    const isActive = moduleFilter === m.name;
                    return (
                      <button
                        key={m.name}
                        onClick={() => {
                          if (hasFindings) {
                            setModuleFilter(isActive ? null : m.name);
                            setGroupBy("module");
                          }
                        }}
                        className={`flex items-center gap-2 text-[11px] w-full text-left rounded-md px-1 py-0.5 transition-colors ${
                          isActive ? "bg-zinc-800/80" : hasFindings ? "hover:bg-zinc-800/40 cursor-pointer" : "cursor-default"
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                          m.status === "failed" ? "bg-zinc-600" :
                          hasFindings ? "bg-orange-500" : "bg-emerald-500"
                        }`} />
                        <span className={`truncate ${
                          isActive ? "text-zinc-100 font-medium" :
                          hasFindings ? "text-zinc-300" : "text-zinc-600"
                        }`}>
                          {m.name}
                        </span>
                        {hasFindings && (
                          <span className={`ml-auto shrink-0 ${isActive ? "text-orange-300" : "text-orange-400"}`}>{m.findingsCount}</span>
                        )}
                        {!hasFindings && m.status === "completed" && (
                          <span className="text-emerald-600 ml-auto shrink-0 text-[10px]">pass</span>
                        )}
                      </button>
                    );
                  })}
                </div>
                <div className="mt-3 pt-3 border-t border-zinc-800/30 text-xs text-zinc-500 flex justify-between">
                  <span>Duration</span>
                  <span className="text-zinc-400"><ElapsedTimer startedAt={scan.startedAt} completedAt={scan.completedAt} /></span>
                </div>
              </div>
            )}
          </div>

          {/* Findings */}
          <div className="lg:col-span-3">
            <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider shrink-0">
                  Findings{filter !== "all" ? ` — ${filter}` : ""}{moduleFilter ? ` — ${moduleFilter}` : ""}
                  {filteredFindings.length > 0 && ` (${filteredFindings.length})`}
                </h3>
                {scan.findings.length > 3 && (
                  <div className="relative w-full max-w-[200px]">
                    <input
                      type="text"
                      placeholder="Search findings..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="text-xs bg-zinc-900/50 border border-zinc-800/50 rounded-lg px-3 py-1.5 pr-8 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-700 w-full"
                    />
                    {!search && (
                      <kbd className="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] text-zinc-700 bg-zinc-800/80 border border-zinc-700/50 rounded px-1 py-0.5">/</kbd>
                    )}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-3">
                {(filter !== "all" || search || moduleFilter) && (
                  <button
                    onClick={() => { setFilter("all"); setSearch(""); setModuleFilter(null); }}
                    className="text-[10px] text-zinc-600 hover:text-zinc-400 transition-colors"
                  >
                    Clear filters
                  </button>
                )}
                <div className="flex items-center bg-zinc-900/50 border border-zinc-800/50 rounded-lg overflow-hidden">
                  <button
                    onClick={() => setGroupBy("severity")}
                    className={`text-[10px] px-2.5 py-1 transition-colors ${groupBy === "severity" ? "bg-zinc-800 text-zinc-300" : "text-zinc-600 hover:text-zinc-400"}`}
                  >
                    By severity
                  </button>
                  <button
                    onClick={() => setGroupBy("module")}
                    className={`text-[10px] px-2.5 py-1 transition-colors ${groupBy === "module" ? "bg-zinc-800 text-zinc-300" : "text-zinc-600 hover:text-zinc-400"}`}
                  >
                    By module
                  </button>
                </div>
                {sortedFindings.length > 0 && (
                  <button
                    onClick={toggleExpandAll}
                    className="text-[10px] text-zinc-600 hover:text-zinc-400 transition-colors"
                  >
                    {expandAll ? "Collapse all" : "Expand all"}
                  </button>
                )}
              </div>
            </div>

            {sortedFindings.length === 0 && !isRunning && (
              <div className="text-center py-20 bg-zinc-900/20 border border-zinc-800/30 rounded-xl">
                {scan.summary.total === 0 ? (
                  <div className="space-y-3">
                    <div className="text-5xl">&#x1f389;</div>
                    <p className="text-lg text-zinc-300 font-semibold">Clean bill of health</p>
                    <p className="text-sm text-zinc-500">Your app passed all {totalModules} security modules with zero findings</p>
                    <p className="text-xs text-zinc-600 max-w-md mx-auto">This is a point-in-time assessment. Keep scanning regularly as you add features and update dependencies.</p>
                  </div>
                ) : (
                  <p className="text-zinc-600">No findings match this filter.</p>
                )}
              </div>
            )}

            {sortedFindings.length === 0 && isRunning && (
              <div className="text-center py-20 bg-zinc-900/20 border border-zinc-800/30 rounded-xl">
                <div className="space-y-2">
                  <svg className="animate-spin h-6 w-6 mx-auto text-zinc-600" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  <p className="text-zinc-600 text-sm">Scanning... findings will appear here as they&apos;re discovered</p>
                </div>
              </div>
            )}

            {groupBy === "severity" ? (
              <div className="space-y-2">
                {sortedFindings.map((finding) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    isOpen={openFindings.has(finding.id)}
                    onToggle={() => toggleFinding(finding.id)}
                  />
                ))}
              </div>
            ) : (
              <div className="space-y-4">
                {Array.from(new Set(sortedFindings.map((f) => f.module))).map((moduleName) => {
                  const moduleFindings = sortedFindings.filter((f) => f.module === moduleName);
                  const worstSev = moduleFindings.reduce((worst, f) => {
                    const order = severityOrder as readonly string[];
                    return order.indexOf(f.severity) < order.indexOf(worst) ? f.severity : worst;
                  }, "info" as string);
                  const sevConf = SEVERITY_CONFIG[worstSev as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
                  return (
                    <div key={moduleName} className="bg-zinc-900/20 border border-zinc-800/30 rounded-xl overflow-hidden">
                      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-zinc-800/30">
                        <span className={`w-2 h-2 rounded-full ${sevConf.dot}`} />
                        <span className="text-sm font-medium text-zinc-300">{moduleName}</span>
                        <span className="text-[10px] text-zinc-600">{moduleFindings.length} {moduleFindings.length === 1 ? "finding" : "findings"}</span>
                      </div>
                      <div className="p-2 space-y-2">
                        {moduleFindings.map((finding) => (
                          <FindingCard
                            key={finding.id}
                            finding={finding}
                            isOpen={openFindings.has(finding.id)}
                            onToggle={() => toggleFinding(finding.id)}
                          />
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
