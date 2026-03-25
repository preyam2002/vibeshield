export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  remediation: string;
  cwe?: string;
  owasp?: string;
  codeSnippet?: string;
  /** The specific URL/endpoint where the issue was found */
  endpoint?: string;
  /** Confidence in the finding (0-100). Header checks = 100, heuristic = 60-80 */
  confidence?: number;
}

export interface FormField {
  action: string;
  method: string;
  inputs: { name: string; type: string }[];
}

export interface CookieInfo {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  domain: string;
  path: string;
}

export interface ScanTarget {
  url: string;
  baseUrl: string;
  pages: string[];
  scripts: string[];
  apiEndpoints: string[];
  forms: FormField[];
  cookies: CookieInfo[];
  headers: Record<string, string>;
  technologies: string[];
  jsContents: Map<string, string>;
  linkUrls: string[];
  redirectUrls: string[];
  /** Discovered parameter names for API endpoints (from JS bundle analysis) */
  apiParams: Map<string, string[]>;
  /** Body returned for a URL that definitely doesn't exist — used to detect soft 404s (SPAs returning 200 for all routes) */
  soft404Body: string;
  /** Whether this site appears to be a SPA that returns 200 for all routes */
  isSpa: boolean;
}

export interface ModuleStatus {
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  findingsCount: number;
  durationMs?: number;
  error?: string;
}

export interface ScanResult {
  id: string;
  target: string;
  status: "queued" | "scanning" | "completed" | "failed";
  mode: "full" | "security" | "quick";
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
}

export type ScanModule = (
  target: ScanTarget,
) => Promise<Finding[]>;

export interface ScanModuleDefinition {
  name: string;
  description: string;
  category: "recon" | "security" | "stress";
  run: ScanModule;
}
