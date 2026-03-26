import type { ScanResult, Finding, ModuleStatus } from "./types";
import { MAX_STORED_SCANS, STALE_SCAN_TIMEOUT_MS } from "./config";
import { dbSaveScan, dbGetRecentScans, dbAvailable } from "../db";

const globalForStore = globalThis as unknown as {
  __vibeshieldScans?: Map<string, ScanResult>;
  __vibeshieldAbort?: Map<string, AbortController>;
};
if (!globalForStore.__vibeshieldScans) globalForStore.__vibeshieldScans = new Map();
if (!globalForStore.__vibeshieldAbort) globalForStore.__vibeshieldAbort = new Map();
const scans = globalForStore.__vibeshieldScans;
const abortControllers = globalForStore.__vibeshieldAbort;

const evictOldScans = () => {
  if (scans.size <= MAX_STORED_SCANS) return;
  // Evict completed/failed scans, but prioritize keeping scans with critical/high findings
  const evictable = Array.from(scans.entries())
    .filter(([, s]) => s.status === "completed" || s.status === "failed")
    .sort((a, b) => {
      // Failed scans evict first
      if (a[1].status === "failed" && b[1].status !== "failed") return -1;
      if (b[1].status === "failed" && a[1].status !== "failed") return 1;
      // Scans with no critical/high findings evict before those with them
      const aHasSevere = a[1].summary.critical > 0 || a[1].summary.high > 0;
      const bHasSevere = b[1].summary.critical > 0 || b[1].summary.high > 0;
      if (!aHasSevere && bHasSevere) return -1;
      if (aHasSevere && !bHasSevere) return 1;
      // Within same tier, evict oldest first
      return (a[1].completedAt || a[1].startedAt).localeCompare(b[1].completedAt || b[1].startedAt);
    });
  while (scans.size > MAX_STORED_SCANS && evictable.length > 0) {
    const [id] = evictable.shift()!;
    scans.delete(id);
  }
};

export const createScan = (id: string, target: string, mode: "full" | "security" | "quick" = "full"): ScanResult => {
  evictOldScans();
  const result: ScanResult = {
    id,
    target,
    status: "queued",
    mode,
    startedAt: new Date().toISOString(),
    findings: [],
    modules: [],
    grade: "-",
    score: 100,
    technologies: [],
    isSpa: false,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
  };
  scans.set(id, result);
  return result;
};

export const getScan = (id: string): ScanResult | undefined => scans.get(id);

export const getActiveScansCount = (): number =>
  Array.from(scans.values()).filter((s) => s.status === "scanning" || s.status === "queued").length;

export const findActiveScan = (target: string): ScanResult | undefined =>
  Array.from(scans.values()).find((s) => s.target === target && (s.status === "scanning" || s.status === "queued"));

export const findPreviousScan = (target: string, excludeId: string): ScanResult | undefined => {
  return Array.from(scans.values())
    .filter((s) => s.target === target && s.id !== excludeId && s.status === "completed")
    .sort((a, b) => (b.completedAt || "").localeCompare(a.completedAt || ""))
    [0];
};

export const getScanHistory = (target: string): { id: string; score: number; grade: string; findings: number; date: string }[] => {
  return Array.from(scans.values())
    .filter((s) => s.target === target && s.status === "completed")
    .sort((a, b) => (a.completedAt || a.startedAt).localeCompare(b.completedAt || b.startedAt))
    .slice(-10)
    .map((s) => ({ id: s.id, score: s.score, grade: s.grade, findings: s.summary.total, date: s.completedAt || s.startedAt }));
};

// Use configured stale timeout

const cleanupStaleScans = () => {
  const now = Date.now();
  for (const scan of scans.values()) {
    if (
      (scan.status === "scanning" || scan.status === "queued") &&
      now - new Date(scan.startedAt).getTime() > STALE_SCAN_TIMEOUT_MS
    ) {
      scan.status = "failed";
      scan.completedAt = new Date().toISOString();
    }
  }
};

export const getRecentScans = (): { id: string; target: string; grade: string; score: number; status: string; findings: number; summary: ScanResult["summary"]; startedAt: string; completedAt?: string; mode: string; delta?: { score: number; findings: number } }[] => {
  cleanupStaleScans();
  return Array.from(scans.values())
    .sort((a, b) => {
      if (a.status === "scanning" && b.status !== "scanning") return -1;
      if (b.status === "scanning" && a.status !== "scanning") return 1;
      return (b.completedAt || b.startedAt).localeCompare(a.completedAt || a.startedAt);
    })
    .slice(0, 100)
    .map((s) => ({
      id: s.id, target: s.target, grade: s.grade, score: s.score, status: s.status,
      findings: s.summary.total, summary: s.summary, startedAt: s.startedAt,
      completedAt: s.completedAt, mode: s.mode,
      ...(s.comparison ? { delta: { score: s.comparison.delta.score, findings: s.comparison.delta.findings } } : {}),
      ...(s.error ? { error: s.error } : {}),
    }));
};

export const updateScanStatus = (id: string, status: ScanResult["status"], error?: string) => {
  const scan = scans.get(id);
  if (scan) {
    scan.status = status;
    if (error) scan.error = error;
    if (status === "completed" || status === "failed") {
      scan.completedAt = new Date().toISOString();
    }
    if (status === "completed") {
      buildComparison(scan);
    }
    // Persist completed/failed scans to SQLite
    if ((status === "completed" || status === "failed") && dbAvailable) {
      try { dbSaveScan(scan); } catch { /* silently fail — in-memory is primary */ }
    }
  }
};

const findingKey = (f: { module: string; title: string }) => `${f.module}::${f.title}`;

const buildComparison = (scan: ScanResult) => {
  const prev = findPreviousScan(scan.target, scan.id);
  if (!prev) return;

  const prevKeys = new Set(prev.findings.map(findingKey));
  const currKeys = new Set(scan.findings.map(findingKey));

  const newFindings = scan.findings
    .filter((f) => !prevKeys.has(findingKey(f)))
    .map((f) => ({ title: f.title, severity: f.severity, module: f.module }));
  const fixedFindings = prev.findings
    .filter((f) => !currKeys.has(findingKey(f)))
    .map((f) => ({ title: f.title, severity: f.severity, module: f.module }));

  scan.comparison = {
    previousId: prev.id,
    previousGrade: prev.grade,
    previousScore: prev.score,
    previousFindings: prev.summary.total,
    delta: {
      score: scan.score - prev.score,
      findings: scan.summary.total - prev.summary.total,
      critical: scan.summary.critical - prev.summary.critical,
      high: scan.summary.high - prev.summary.high,
    },
    ...(newFindings.length > 0 ? { newFindings } : {}),
    ...(fixedFindings.length > 0 ? { fixedFindings } : {}),
  };
};

export const addFindings = (id: string, findings: Finding[]) => {
  const scan = scans.get(id);
  if (scan) {
    // Cross-module dedup: skip findings with identical module+title already present
    const existingKeys = new Set(scan.findings.map((f) => `${f.module}::${f.title}`));
    const unique = findings.filter((f) => {
      const key = `${f.module}::${f.title}`;
      if (existingKeys.has(key)) return false;
      existingKeys.add(key);
      return true;
    });
    scan.findings.push(...unique);
    recalcSummary(scan);
  }
};

export const setModules = (id: string, modules: ModuleStatus[]) => {
  const scan = scans.get(id);
  if (scan) scan.modules = modules;
};

export const updateModule = (
  id: string,
  moduleName: string,
  update: Partial<ModuleStatus>,
) => {
  const scan = scans.get(id);
  if (!scan) return;
  const mod = scan.modules.find((m) => m.name === moduleName);
  if (mod) Object.assign(mod, update);
};

export const setTechInfo = (id: string, technologies: string[], isSpa: boolean) => {
  const scan = scans.get(id);
  if (scan) {
    scan.technologies = technologies;
    scan.isSpa = isSpa;
  }
};

export const setSurface = (id: string, surface: NonNullable<ScanResult["surface"]>) => {
  const scan = scans.get(id);
  if (scan) scan.surface = surface;
};

export const registerAbort = (id: string, controller: AbortController) => {
  abortControllers.set(id, controller);
};

export const cancelScan = (id: string): boolean => {
  const scan = scans.get(id);
  if (!scan || scan.status !== "scanning") return false;
  const controller = abortControllers.get(id);
  if (controller) {
    controller.abort();
    abortControllers.delete(id);
  }
  scan.status = "failed";
  scan.completedAt = new Date().toISOString();
  scan.error = "Scan cancelled by user.";
  // Mark pending modules as skipped
  for (const mod of scan.modules) {
    if (mod.status === "pending" || mod.status === "running") {
      mod.status = "skipped";
    }
  }
  return true;
};

export const cleanupAbort = (id: string) => {
  abortControllers.delete(id);
};

export const getStats = () => {
  const all = Array.from(scans.values());
  const completed = all.filter((s) => s.status === "completed");
  const totalFindings = completed.reduce((sum, s) => sum + s.summary.total, 0);
  const totalCritical = completed.reduce((sum, s) => sum + s.summary.critical, 0);

  // Top vulnerability modules across all scans
  const moduleCounts = new Map<string, number>();
  for (const s of completed) {
    for (const f of s.findings) {
      if (f.severity === "info") continue;
      moduleCounts.set(f.module, (moduleCounts.get(f.module) || 0) + 1);
    }
  }
  const topModules = [...moduleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  // Grade distribution
  const gradeDistribution: Record<string, number> = {};
  for (const s of completed) {
    gradeDistribution[s.grade] = (gradeDistribution[s.grade] || 0) + 1;
  }

  // Average score
  const avgScore = completed.length > 0
    ? Math.round(completed.reduce((sum, s) => sum + s.score, 0) / completed.length)
    : 0;

  return {
    totalScans: all.length,
    completedScans: completed.length,
    totalFindings,
    totalCritical,
    uniqueTargets: new Set(all.map((s) => { try { return new URL(s.target).hostname; } catch { return s.target; } })).size,
    avgScore,
    topModules,
    gradeDistribution,
  };
};

export const getPercentile = (score: number): number => {
  const scores = Array.from(scans.values())
    .filter((s) => s.status === "completed")
    .map((s) => s.score);
  if (scores.length < 3) return -1;
  const below = scores.filter((s) => s <= score).length;
  return Math.round((below / scores.length) * 100);
};

const recalcSummary = (scan: ScanResult) => {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of scan.findings) {
    s[f.severity]++;
    s.total++;
  }
  scan.summary = s;
  const { grade, score } = calcGrade(s, scan.findings);
  scan.grade = grade;
  scan.score = score;
};

const calcGrade = (s: ScanResult["summary"], findings?: Finding[]): { grade: string; score: number } => {
  // Confidence-weighted penalty: findings with higher confidence count more
  // If individual findings are provided, use their confidence; otherwise fall back to count-based
  let score = 100;

  if (findings && findings.length > 0) {
    const SEVERITY_BASE: Record<string, number> = { critical: 30, high: 12, medium: 4, low: 1, info: 0 };
    const SEVERITY_DECAY: Record<string, number> = { critical: 0.6, high: 0.7, medium: 0.8, low: 0.85, info: 1 };

    // Group by severity, sort by confidence desc within each group
    const bySeverity: Record<string, Finding[]> = { critical: [], high: [], medium: [], low: [], info: [] };
    for (const f of findings) bySeverity[f.severity]?.push(f);

    for (const [sev, group] of Object.entries(bySeverity)) {
      const base = SEVERITY_BASE[sev] || 0;
      const decay = SEVERITY_DECAY[sev] || 1;
      // Sort by confidence descending — high-confidence findings penalize more
      const sorted = [...group].sort((a, b) => (b.confidence ?? 75) - (a.confidence ?? 75));
      for (let i = 0; i < sorted.length; i++) {
        const conf = (sorted[i].confidence ?? 75) / 100;
        score -= base * Math.pow(decay, i) * conf;
      }
    }

    if (s.critical >= 1 && s.high >= 2) score -= 10;
  } else {
    // Fallback: count-based scoring (used when findings aren't available)
    const penalty = (count: number, weight: number, decay: number) =>
      Array.from({ length: count }, (_, i) => weight * Math.pow(decay, i)).reduce((a, b) => a + b, 0);

    score -= penalty(s.critical, 30, 0.6);
    score -= penalty(s.high, 12, 0.7);
    score -= penalty(s.medium, 4, 0.8);
    score -= penalty(s.low, 1, 0.85);
    if (s.critical >= 1 && s.high >= 2) score -= 10;
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let grade: string;
  if (score >= 95) grade = "A";
  else if (score >= 85) grade = "A-";
  else if (score >= 75) grade = "B+";
  else if (score >= 65) grade = "B";
  else if (score >= 55) grade = "C+";
  else if (score >= 45) grade = "C";
  else if (score >= 35) grade = "D+";
  else if (score >= 25) grade = "D";
  else grade = "F";

  return { grade, score };
};
