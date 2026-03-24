import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

// Services that, when pointed to by a dangling CNAME, allow subdomain takeover
const TAKEOVER_FINGERPRINTS: { service: string; cname: string; fingerprint: string }[] = [
  { service: "GitHub Pages", cname: "github.io", fingerprint: "There isn't a GitHub Pages site here" },
  { service: "Heroku", cname: "herokuapp.com", fingerprint: "no-such-app" },
  { service: "AWS S3", cname: "s3.amazonaws.com", fingerprint: "NoSuchBucket" },
  { service: "Surge.sh", cname: "surge.sh", fingerprint: "project not found" },
  { service: "Netlify", cname: "netlify.app", fingerprint: "Not Found - Request ID:" },
  { service: "Fly.io", cname: "fly.dev", fingerprint: "Fly.io 404" },
  { service: "Vercel", cname: "vercel.app", fingerprint: "DEPLOYMENT_NOT_FOUND" },
  { service: "Render", cname: "onrender.com", fingerprint: "render.com/docs/custom-domains" },
];

export const subdomainModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const hostname = new URL(target.url).hostname;
  const parts = hostname.split(".");
  if (parts.length < 2) return findings;
  const baseDomain = parts.slice(-2).join(".");

  // Discover subdomains via crt.sh certificate transparency
  let subdomains: string[] = [];
  try {
    const res = await scanFetch(
      `https://crt.sh/?q=%.${baseDomain}&output=json`,
      { timeoutMs: 10000, noCache: true },
    );
    if (res.ok) {
      const certs: { name_value: string }[] = await res.json();
      const seen = new Set<string>();
      for (const cert of certs) {
        for (const name of cert.name_value.split("\n")) {
          const clean = name.replace(/^\*\./, "").trim().toLowerCase();
          if (clean.endsWith(baseDomain) && clean !== baseDomain && !seen.has(clean)) {
            seen.add(clean);
            subdomains.push(clean);
          }
        }
      }
    }
  } catch {
    // crt.sh may be slow or down — not a scan failure
    return findings;
  }

  // Limit to reasonable number
  subdomains = subdomains.slice(0, 30);

  if (subdomains.length === 0) return findings;

  // Check each subdomain for takeover indicators
  const MAX_FINDINGS = 3;
  for (const sub of subdomains) {
    if (findings.length >= MAX_FINDINGS) break;

    try {
      const res = await scanFetch(`https://${sub}`, { timeoutMs: 5000, noCache: true });
      const text = await res.text();

      // Skip if it's a live site returning real content (200 with >10KB of HTML)
      if (res.status === 200 && text.length > 10000) continue;

      for (const fp of TAKEOVER_FINGERPRINTS) {
        if (text.includes(fp.fingerprint)) {
          findings.push({
            id: `subdomain-takeover-${findings.length}`,
            module: "Subdomain Takeover",
            severity: "high",
            title: `Potential subdomain takeover: ${sub} (${fp.service})`,
            description: `The subdomain ${sub} appears to point to ${fp.service} but the resource doesn't exist. An attacker could claim this resource and serve malicious content under your domain.`,
            evidence: `Subdomain: ${sub}\nService: ${fp.service}\nFingerprint: "${fp.fingerprint}" found in response`,
            remediation: `Remove the DNS record for ${sub} or claim the resource on ${fp.service}. Dangling DNS records are a common source of subdomain takeover attacks.`,
            cwe: "CWE-404",
            owasp: "A05:2021",
          });
          break;
        }
      }
    } catch {
      // Connection failures on subdomains might indicate dangling records
      // but we don't flag them without positive evidence
    }
  }

  // Report discovered subdomains as info
  if (subdomains.length > 5 && findings.length === 0) {
    findings.push({
      id: "subdomain-surface",
      module: "Subdomain Takeover",
      severity: "info",
      title: `${subdomains.length} subdomains discovered via certificate transparency`,
      description: `Found ${subdomains.length} subdomains for ${baseDomain}. A larger subdomain surface increases the risk of forgotten or misconfigured services.`,
      evidence: `Subdomains: ${subdomains.slice(0, 10).join(", ")}${subdomains.length > 10 ? `, ...and ${subdomains.length - 10} more` : ""}`,
      remediation: "Regularly audit your subdomains and remove DNS records for decommissioned services.",
      cwe: "CWE-404",
    });
  }

  return findings;
};
