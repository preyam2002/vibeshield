import type { Severity } from "./types";

interface CvssResult {
  score: number;
  vector: string;
  rating: string;
}

interface CvssVector {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  PR: "N" | "L" | "H";
  UI: "N" | "R";
  S: "U" | "C";
  C: "N" | "L" | "H";
  I: "N" | "L" | "H";
  A: "N" | "L" | "H";
}

interface CweMapping {
  vector: CvssVector;
  score: number;
}

// Metric weights per CVSS v3.1 specification
const AV_WEIGHTS: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_WEIGHTS: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_WEIGHTS_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_WEIGHTS_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI_WEIGHTS: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA_WEIGHTS: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

function calculateBaseScore(v: CvssVector): number {
  const prWeights = v.S === "C" ? PR_WEIGHTS_CHANGED : PR_WEIGHTS_UNCHANGED;

  const exploitability =
    8.22 * AV_WEIGHTS[v.AV] * AC_WEIGHTS[v.AC] * prWeights[v.PR] * UI_WEIGHTS[v.UI];

  const iscBase = 1 - (1 - CIA_WEIGHTS[v.C]) * (1 - CIA_WEIGHTS[v.I]) * (1 - CIA_WEIGHTS[v.A]);

  let impact: number;
  if (v.S === "U") {
    impact = 6.42 * iscBase;
  } else {
    impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  if (impact <= 0) return 0;

  let score: number;
  if (v.S === "U") {
    score = Math.min(impact + exploitability, 10);
  } else {
    score = Math.min(1.08 * (impact + exploitability), 10);
  }

  return Math.ceil(score * 10) / 10;
}

function vectorString(v: CvssVector): string {
  return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`;
}

// CWE to CVSS v3.1 base vector mappings
const CWE_MAP: Record<string, CweMapping> = {};

function addCwe(cwe: string, v: CvssVector): void {
  CWE_MAP[cwe] = { vector: v, score: calculateBaseScore(v) };
}

// --- Injection ---
addCwe("CWE-79", { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" }); // XSS
addCwe("CWE-89", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // SQLi
addCwe("CWE-78", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // OS Command Injection
addCwe("CWE-943", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // NoSQL Injection
addCwe("CWE-90", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // LDAP Injection
addCwe("CWE-91", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // XML Injection
addCwe("CWE-94", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Code Injection
addCwe("CWE-77", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Command Injection
addCwe("CWE-917", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Expression Language Injection
addCwe("CWE-611", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // XXE

// --- Path Traversal / File Inclusion ---
addCwe("CWE-22", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // Path Traversal
addCwe("CWE-98", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Remote File Inclusion
addCwe("CWE-434", { AV: "N", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Unrestricted File Upload

// --- Authentication / Session ---
addCwe("CWE-352", { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "N", I: "H", A: "N" }); // CSRF
addCwe("CWE-384", { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "H", A: "N" }); // Session Fixation
addCwe("CWE-287", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Improper Authentication
addCwe("CWE-306", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Missing Authentication
addCwe("CWE-798", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Hardcoded Credentials
addCwe("CWE-307", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // Brute Force
addCwe("CWE-613", { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "N", A: "N" }); // Insufficient Session Expiration

// --- Access Control ---
addCwe("CWE-284", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" }); // Improper Access Control
addCwe("CWE-639", { AV: "N", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "H", A: "N" }); // IDOR
addCwe("CWE-862", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N" }); // Missing Authorization
addCwe("CWE-863", { AV: "N", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "H", A: "N" }); // Incorrect Authorization

// --- SSRF / Redirect ---
addCwe("CWE-918", { AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "N", A: "N" }); // SSRF
addCwe("CWE-601", { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" }); // Open Redirect

// --- Information Disclosure ---
addCwe("CWE-200", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" }); // Info Exposure
addCwe("CWE-209", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" }); // Error Message Info Leak
addCwe("CWE-532", { AV: "L", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // Info in Logs
addCwe("CWE-548", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" }); // Directory Listing

// --- Cryptography / Transport ---
addCwe("CWE-311", { AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // Missing Encryption
addCwe("CWE-319", { AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // Cleartext Transmission
addCwe("CWE-326", { AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // Inadequate Encryption Strength
addCwe("CWE-327", { AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" }); // Broken Crypto Algorithm
addCwe("CWE-614", { AV: "N", AC: "H", PR: "N", UI: "R", S: "U", C: "L", I: "N", A: "N" }); // Insecure Cookie (no Secure flag)

// --- Deserialization ---
addCwe("CWE-502", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }); // Deserialization

// --- Configuration / Headers ---
addCwe("CWE-16", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" }); // Configuration
addCwe("CWE-693", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "L", A: "N" }); // Protection Mechanism Failure
addCwe("CWE-942", { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "N", A: "N" }); // Permissive CORS
addCwe("CWE-1021", { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "N", I: "L", A: "N" }); // Clickjacking
addCwe("CWE-1004", { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "L", I: "N", A: "N" }); // Missing HttpOnly on Cookie
addCwe("CWE-525", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" }); // Browser Cache Weakness

// --- Denial of Service ---
addCwe("CWE-400", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "H" }); // Uncontrolled Resource Consumption
addCwe("CWE-770", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "H" }); // Allocation without Limits

// --- SSRF-adjacent ---
addCwe("CWE-441", { AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "L", I: "L", A: "N" }); // Unintended Proxy

// --- Miscellaneous ---
addCwe("CWE-829", { AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N" }); // Untrusted Resource Inclusion (SRI)
addCwe("CWE-1275", { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "H", I: "N", A: "N" }); // Sensitive Cookie without SameSite
addCwe("CWE-116", { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "L", A: "N" }); // Improper Encoding/Escaping

// Severity-based fallback scores
const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 2.5,
  info: 0.0,
};

const SEVERITY_VECTORS: Record<Severity, string> = {
  critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  medium: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  low: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
  info: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
};

export function cvssRating(score: number): string {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >= 0.1) return "Low";
  return "None";
}

export function getCvssScore(
  cwe?: string,
  severity?: string,
): CvssResult | undefined {
  // Try CWE-based lookup first
  if (cwe) {
    const normalized = cwe.startsWith("CWE-") ? cwe : `CWE-${cwe}`;
    const mapping = CWE_MAP[normalized];
    if (mapping) {
      return {
        score: mapping.score,
        vector: vectorString(mapping.vector),
        rating: cvssRating(mapping.score),
      };
    }
  }

  // Fall back to severity-based estimation
  if (severity) {
    const sev = severity.toLowerCase() as Severity;
    if (sev in SEVERITY_SCORES) {
      const score = SEVERITY_SCORES[sev];
      return {
        score,
        vector: SEVERITY_VECTORS[sev],
        rating: cvssRating(score),
      };
    }
  }

  return undefined;
}
