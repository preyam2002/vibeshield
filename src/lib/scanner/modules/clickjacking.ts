import type { ScanModule, Finding } from "../types";

export const clickjackingModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  const xfo = target.headers["x-frame-options"];
  const csp = target.headers["content-security-policy"];
  const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);

  if (!xfo && !hasFrameAncestors) {
    findings.push({
      id: "clickjacking-no-protection",
      module: "Clickjacking",
      severity: "medium",
      title: "No clickjacking protection",
      description: "Neither X-Frame-Options nor CSP frame-ancestors is set. Your site can be embedded in iframes on malicious sites, tricking users into clicking hidden buttons.",
      remediation: "Add X-Frame-Options: DENY header AND Content-Security-Policy: frame-ancestors 'none' (or 'self' if you need same-origin framing).",
      cwe: "CWE-1021",
      owasp: "A05:2021",
    });
  }

  if (xfo && xfo.toUpperCase() === "ALLOWALL") {
    findings.push({
      id: "clickjacking-allowall",
      module: "Clickjacking",
      severity: "medium",
      title: "X-Frame-Options set to ALLOWALL",
      description: "X-Frame-Options is set to ALLOWALL which provides no protection. Any site can iframe your app.",
      evidence: `X-Frame-Options: ${xfo}`,
      remediation: "Change to DENY or SAMEORIGIN.",
      cwe: "CWE-1021",
    });
  }

  return findings;
};
