import type { ScanResult, Finding } from "./scanner/types";
import path from "path";

export interface ScanPolicy {
  id: string;
  name: string;
  description: string;
  enabledModules: string[];
  createdAt: string;
}

// ---------- globalThis caching for Next.js hot reloads ----------

type BetterSqlite3Database = {
  prepare(sql: string): {
    run(...params: unknown[]): { changes: number };
    get(...params: unknown[]): Record<string, unknown> | undefined;
    all(...params: unknown[]): Record<string, unknown>[];
  };
  exec(sql: string): void;
  pragma(pragma: string): unknown;
  close(): void;
};

const globalForDb = globalThis as unknown as {
  __vibeshieldDb?: BetterSqlite3Database | null;
  __vibeshieldDbAvailable?: boolean;
};

let db: BetterSqlite3Database | null = null;
export let dbAvailable = false;

function initDb(): void {
  if (globalForDb.__vibeshieldDb !== undefined) {
    db = globalForDb.__vibeshieldDb;
    dbAvailable = globalForDb.__vibeshieldDbAvailable ?? false;
    return;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const Database = require("better-sqlite3");
    const dataDir = process.env.VIBESHIELD_DATA_DIR || ".vibeshield-data";
    const dbPath = path.join(dataDir, "vibeshield.db");

    const fs = require("fs");
    fs.mkdirSync(dataDir, { recursive: true });

    db = new Database(dbPath) as BetterSqlite3Database;
    db!.pragma("journal_mode = WAL");
    db!.pragma("foreign_keys = ON");

    createTables();
    createIndexes();

    globalForDb.__vibeshieldDb = db;
    globalForDb.__vibeshieldDbAvailable = true;
    dbAvailable = true;
  } catch {
    db = null;
    globalForDb.__vibeshieldDb = null;
    globalForDb.__vibeshieldDbAvailable = false;
    dbAvailable = false;
  }
}

function createTables(): void {
  db!.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      status TEXT NOT NULL,
      mode TEXT NOT NULL,
      started_at TEXT NOT NULL,
      completed_at TEXT,
      error TEXT,
      grade TEXT,
      score INTEGER,
      technologies TEXT,
      is_spa INTEGER,
      summary TEXT,
      surface TEXT,
      comparison TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT REFERENCES scans(id),
      module TEXT,
      severity TEXT,
      title TEXT,
      description TEXT,
      evidence TEXT,
      remediation TEXT,
      cwe TEXT,
      owasp TEXT,
      code_snippet TEXT,
      endpoint TEXT,
      confidence INTEGER,
      suppressed INTEGER DEFAULT 0,
      suppressed_reason TEXT
    );

    CREATE TABLE IF NOT EXISTS modules (
      scan_id TEXT,
      name TEXT,
      status TEXT,
      findings_count INTEGER,
      duration_ms INTEGER,
      error TEXT,
      PRIMARY KEY (scan_id, name)
    );

    CREATE TABLE IF NOT EXISTS scan_policies (
      id TEXT PRIMARY KEY,
      name TEXT,
      description TEXT,
      enabled_modules TEXT,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS false_positives (
      id TEXT PRIMARY KEY,
      finding_key TEXT UNIQUE,
      reason TEXT,
      created_at TEXT
    );
  `);
}

function createIndexes(): void {
  db!.exec(`
    CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_scans_target_status ON scans(target, status);
  `);
}

// Initialize on module load
initDb();

// ---------- Helpers ----------

function jsonOrNull(val: unknown): string | null {
  if (val === undefined || val === null) return null;
  return JSON.stringify(val);
}

function parseJsonOr<T>(val: unknown, fallback: T): T {
  if (val === null || val === undefined) return fallback;
  try {
    return JSON.parse(val as string) as T;
  } catch {
    return fallback;
  }
}

// ---------- Row -> Domain mapping ----------

function rowToScanResult(row: Record<string, unknown>, findings: Finding[], modules: ScanResult["modules"]): ScanResult {
  const result: ScanResult = {
    id: row.id as string,
    target: row.target as string,
    status: row.status as ScanResult["status"],
    mode: row.mode as ScanResult["mode"],
    startedAt: row.started_at as string,
    findings,
    modules,
    grade: (row.grade as string) || "-",
    score: (row.score as number) ?? 100,
    technologies: parseJsonOr<string[]>(row.technologies, []),
    isSpa: !!(row.is_spa as number),
    summary: parseJsonOr(row.summary, { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }),
  };
  if (row.completed_at) result.completedAt = row.completed_at as string;
  if (row.error) result.error = row.error as string;
  const surface = parseJsonOr<ScanResult["surface"]>(row.surface, undefined);
  if (surface) result.surface = surface;
  const comparison = parseJsonOr<ScanResult["comparison"]>(row.comparison, undefined);
  if (comparison) result.comparison = comparison;
  return result;
}

function rowToFinding(row: Record<string, unknown>): Finding {
  const f: Finding = {
    id: row.id as string,
    module: row.module as string,
    severity: row.severity as Finding["severity"],
    title: row.title as string,
    description: row.description as string,
    remediation: row.remediation as string,
  };
  if (row.evidence) f.evidence = row.evidence as string;
  if (row.cwe) f.cwe = row.cwe as string;
  if (row.owasp) f.owasp = row.owasp as string;
  if (row.code_snippet) f.codeSnippet = row.code_snippet as string;
  if (row.endpoint) f.endpoint = row.endpoint as string;
  if (row.confidence !== null && row.confidence !== undefined) f.confidence = row.confidence as number;
  return f;
}

function loadFindings(scanId: string): Finding[] {
  const rows = db!.prepare("SELECT * FROM findings WHERE scan_id = ?").all(scanId);
  return rows.map(rowToFinding);
}

function loadModules(scanId: string): ScanResult["modules"] {
  const rows = db!.prepare("SELECT * FROM modules WHERE scan_id = ?").all(scanId);
  return rows.map((r) => ({
    name: r.name as string,
    status: r.status as ScanResult["modules"][number]["status"],
    findingsCount: (r.findings_count as number) || 0,
    ...(r.duration_ms !== null ? { durationMs: r.duration_ms as number } : {}),
    ...(r.error ? { error: r.error as string } : {}),
  }));
}

function loadFullScan(row: Record<string, unknown>): ScanResult {
  const scanId = row.id as string;
  return rowToScanResult(row, loadFindings(scanId), loadModules(scanId));
}

// ---------- Public API ----------

export function dbSaveScan(scan: ScanResult): void {
  if (!db) return;

  db!.prepare(`
    INSERT OR REPLACE INTO scans (id, target, status, mode, started_at, completed_at, error, grade, score, technologies, is_spa, summary, surface, comparison)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    scan.id,
    scan.target,
    scan.status,
    scan.mode,
    scan.startedAt,
    scan.completedAt ?? null,
    scan.error ?? null,
    scan.grade,
    scan.score,
    jsonOrNull(scan.technologies),
    scan.isSpa ? 1 : 0,
    jsonOrNull(scan.summary),
    jsonOrNull(scan.surface),
    jsonOrNull(scan.comparison),
  );

  // Replace findings and modules for this scan
  db!.prepare("DELETE FROM findings WHERE scan_id = ?").run(scan.id);
  db!.prepare("DELETE FROM modules WHERE scan_id = ?").run(scan.id);

  const insertFinding = db!.prepare(`
    INSERT INTO findings (id, scan_id, module, severity, title, description, evidence, remediation, cwe, owasp, code_snippet, endpoint, confidence, suppressed, suppressed_reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
  `);

  for (const f of scan.findings) {
    insertFinding.run(
      f.id,
      scan.id,
      f.module,
      f.severity,
      f.title,
      f.description,
      f.evidence ?? null,
      f.remediation,
      f.cwe ?? null,
      f.owasp ?? null,
      f.codeSnippet ?? null,
      f.endpoint ?? null,
      f.confidence ?? null,
    );
  }

  const insertModule = db!.prepare(`
    INSERT INTO modules (scan_id, name, status, findings_count, duration_ms, error)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const m of scan.modules) {
    insertModule.run(
      scan.id,
      m.name,
      m.status,
      m.findingsCount,
      m.durationMs ?? null,
      m.error ?? null,
    );
  }
}

export function dbGetScan(id: string): ScanResult | undefined {
  if (!db) return undefined;
  const row = db!.prepare("SELECT * FROM scans WHERE id = ?").get(id);
  if (!row) return undefined;
  return loadFullScan(row);
}

export function dbGetRecentScans(limit = 100): ScanResult[] {
  if (!db) return [];
  const rows = db!.prepare(`
    SELECT * FROM scans
    ORDER BY
      CASE WHEN status = 'scanning' THEN 0 WHEN status = 'queued' THEN 1 ELSE 2 END,
      COALESCE(completed_at, started_at) DESC
    LIMIT ?
  `).all(limit);
  return rows.map(loadFullScan);
}

export function dbGetScanHistory(target: string): ScanResult[] {
  if (!db) return [];
  const rows = db!.prepare(`
    SELECT * FROM scans WHERE target = ? AND status = 'completed'
    ORDER BY COALESCE(completed_at, started_at) ASC
  `).all(target);
  return rows.map(loadFullScan);
}

export function dbFindPreviousScan(target: string, excludeId: string): ScanResult | undefined {
  if (!db) return undefined;
  const row = db!.prepare(`
    SELECT * FROM scans
    WHERE target = ? AND id != ? AND status = 'completed'
    ORDER BY completed_at DESC
    LIMIT 1
  `).get(target, excludeId);
  if (!row) return undefined;
  return loadFullScan(row);
}

export function dbGetStats(): {
  totalScans: number;
  completedScans: number;
  totalFindings: number;
  totalCritical: number;
  uniqueTargets: number;
  avgScore: number;
  topModules: { name: string; count: number }[];
  gradeDistribution: Record<string, number>;
} {
  const empty = {
    totalScans: 0, completedScans: 0, totalFindings: 0, totalCritical: 0,
    uniqueTargets: 0, avgScore: 0, topModules: [], gradeDistribution: {},
  };
  if (!db) return empty;

  const totalRow = db!.prepare("SELECT COUNT(*) as cnt FROM scans").get() as { cnt: number };
  const completedRow = db!.prepare("SELECT COUNT(*) as cnt FROM scans WHERE status = 'completed'").get() as { cnt: number };

  const completedScans = db!.prepare("SELECT * FROM scans WHERE status = 'completed'").all();
  let totalFindings = 0;
  let totalCritical = 0;
  let scoreSum = 0;
  const gradeDistribution: Record<string, number> = {};
  const moduleCounts = new Map<string, number>();

  for (const s of completedScans) {
    const summary = parseJsonOr<ScanResult["summary"]>(s.summary, { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 });
    totalFindings += summary.total;
    totalCritical += summary.critical;
    scoreSum += (s.score as number) ?? 0;
    const grade = (s.grade as string) || "-";
    gradeDistribution[grade] = (gradeDistribution[grade] || 0) + 1;

    const findings = loadFindings(s.id as string);
    for (const f of findings) {
      if (f.severity === "info") continue;
      moduleCounts.set(f.module, (moduleCounts.get(f.module) || 0) + 1);
    }
  }

  const topModules = [...moduleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  const uniqueTargetsRow = db!.prepare("SELECT COUNT(DISTINCT target) as cnt FROM scans").get() as { cnt: number };

  return {
    totalScans: totalRow.cnt,
    completedScans: completedRow.cnt,
    totalFindings,
    totalCritical,
    uniqueTargets: uniqueTargetsRow.cnt,
    avgScore: completedScans.length > 0 ? Math.round(scoreSum / completedScans.length) : 0,
    topModules,
    gradeDistribution,
  };
}

export function dbDeleteScan(id: string): void {
  if (!db) return;
  db!.prepare("DELETE FROM findings WHERE scan_id = ?").run(id);
  db!.prepare("DELETE FROM modules WHERE scan_id = ?").run(id);
  db!.prepare("DELETE FROM scans WHERE id = ?").run(id);
}

// ---------- False Positives ----------

export function dbSaveFalsePositive(findingKey: string, reason: string): void {
  if (!db) return;
  const id = crypto.randomUUID();
  db!.prepare(`
    INSERT OR REPLACE INTO false_positives (id, finding_key, reason, created_at)
    VALUES (?, ?, ?, ?)
  `).run(id, findingKey, reason, new Date().toISOString());
}

export function dbGetFalsePositives(): Map<string, string> {
  if (!db) return new Map();
  const rows = db!.prepare("SELECT finding_key, reason FROM false_positives").all();
  const map = new Map<string, string>();
  for (const r of rows) {
    map.set(r.finding_key as string, r.reason as string);
  }
  return map;
}

export function dbRemoveFalsePositive(findingKey: string): void {
  if (!db) return;
  db!.prepare("DELETE FROM false_positives WHERE finding_key = ?").run(findingKey);
}

// ---------- Scan Policies ----------

export function dbSaveScanPolicy(policy: ScanPolicy): void {
  if (!db) return;
  db!.prepare(`
    INSERT OR REPLACE INTO scan_policies (id, name, description, enabled_modules, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    policy.id,
    policy.name,
    policy.description,
    JSON.stringify(policy.enabledModules),
    policy.createdAt,
  );
}

export function dbGetScanPolicies(): ScanPolicy[] {
  if (!db) return [];
  const rows = db!.prepare("SELECT * FROM scan_policies").all();
  return rows.map((r) => ({
    id: r.id as string,
    name: r.name as string,
    description: r.description as string,
    enabledModules: parseJsonOr<string[]>(r.enabled_modules, []),
    createdAt: r.created_at as string,
  }));
}

export function dbGetScanPolicy(id: string): ScanPolicy | undefined {
  if (!db) return undefined;
  const r = db!.prepare("SELECT * FROM scan_policies WHERE id = ?").get(id);
  if (!r) return undefined;
  return {
    id: r.id as string,
    name: r.name as string,
    description: r.description as string,
    enabledModules: parseJsonOr<string[]>(r.enabled_modules, []),
    createdAt: r.created_at as string,
  };
}

export function dbDeleteScanPolicy(id: string): void {
  if (!db) return;
  db!.prepare("DELETE FROM scan_policies WHERE id = ?").run(id);
}
