import type { ScanResult, Finding, ModuleStatus } from "./types";

const globalForStore = globalThis as unknown as {
  __vibeshieldScans?: Map<string, ScanResult>;
  __vibeshieldAbort?: Map<string, AbortController>;
};
if (!globalForStore.__vibeshieldScans) globalForStore.__vibeshieldScans = new Map();
if (!globalForStore.__vibeshieldAbort) globalForStore.__vibeshieldAbort = new Map();
const scans = globalForStore.__vibeshieldScans;
const abortControllers = globalForStore.__vibeshieldAbort;
const MAX_SCANS = 100;

const evictOldScans = () => {
  if (scans.size <= MAX_SCANS) return;
  const completed = Array.from(scans.entries())
    .filter(([, s]) => s.status === "completed" || s.status === "failed")
    .sort((a, b) => (a[1].completedAt || a[1].startedAt).localeCompare(b[1].completedAt || b[1].startedAt));
  while (scans.size > MAX_SCANS && completed.length > 0) {
    const [id] = completed.shift()!;
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

export const findPreviousScan = (target: string, excludeId: string): ScanResult | undefined => {
  return Array.from(scans.values())
    .filter((s) => s.target === target && s.id !== excludeId && s.status === "completed")
    .sort((a, b) => (b.completedAt || "").localeCompare(a.completedAt || ""))
    [0];
};

const STALE_SCAN_TIMEOUT = 5 * 60 * 1000; // 5 minutes

const cleanupStaleScans = () => {
  const now = Date.now();
  for (const scan of scans.values()) {
    if (
      (scan.status === "scanning" || scan.status === "queued") &&
      now - new Date(scan.startedAt).getTime() > STALE_SCAN_TIMEOUT
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
    .slice(0, 50)
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
  return {
    totalScans: all.length,
    completedScans: completed.length,
    totalFindings,
    totalCritical,
    uniqueTargets: new Set(all.map((s) => { try { return new URL(s.target).hostname; } catch { return s.target; } })).size,
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
  const { grade, score } = calcGrade(s);
  scan.grade = grade;
  scan.score = score;
};

const calcGrade = (s: ScanResult["summary"]): { grade: string; score: number } => {
  // Weighted penalty with diminishing returns per severity
  // First findings of each severity hit harder; subsequent ones have less impact
  const penalty = (count: number, weight: number, decay: number) =>
    Array.from({ length: count }, (_, i) => weight * Math.pow(decay, i)).reduce((a, b) => a + b, 0);

  let score = 100;
  score -= penalty(s.critical, 30, 0.6);  // 30, 18, 10.8, ...
  score -= penalty(s.high, 12, 0.7);      // 12, 8.4, 5.9, ...
  score -= penalty(s.medium, 4, 0.8);     // 4, 3.2, 2.56, ...
  score -= penalty(s.low, 1, 0.85);       // 1, 0.85, 0.72, ...
  if (s.critical >= 1 && s.high >= 2) score -= 10;
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
