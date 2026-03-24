import type { ScanResult, Finding, ModuleStatus } from "./types";

const scans = new Map<string, ScanResult>();

export const createScan = (id: string, target: string): ScanResult => {
  const result: ScanResult = {
    id,
    target,
    status: "queued",
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

export const getRecentScans = (): { id: string; target: string; grade: string; status: string; findings: number; summary: ScanResult["summary"] }[] => {
  return Array.from(scans.values())
    .sort((a, b) => {
      // Running scans first, then by completion time
      if (a.status === "scanning" && b.status !== "scanning") return -1;
      if (b.status === "scanning" && a.status !== "scanning") return 1;
      return (b.completedAt || b.startedAt).localeCompare(a.completedAt || a.startedAt);
    })
    .slice(0, 20)
    .map((s) => ({ id: s.id, target: s.target, grade: s.grade, status: s.status, findings: s.summary.total, summary: s.summary }));
};

export const updateScanStatus = (id: string, status: ScanResult["status"]) => {
  const scan = scans.get(id);
  if (scan) {
    scan.status = status;
    if (status === "completed" || status === "failed") {
      scan.completedAt = new Date().toISOString();
    }
  }
};

export const addFindings = (id: string, findings: Finding[]) => {
  const scan = scans.get(id);
  if (scan) {
    scan.findings.push(...findings);
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
  let score = 100;
  score -= s.critical * 25;
  score -= s.high * 10;
  score -= s.medium * 4;
  score -= s.low * 1;
  score = Math.max(0, Math.min(100, score));

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
