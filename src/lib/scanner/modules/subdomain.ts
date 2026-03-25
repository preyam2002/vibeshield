import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

// Services that, when pointed to by a dangling CNAME, allow subdomain takeover
const TAKEOVER_FINGERPRINTS: { service: string; cname: string; fingerprint: string; httpBody?: boolean }[] = [
  { service: "GitHub Pages", cname: "github.io", fingerprint: "There isn't a GitHub Pages site here" },
  { service: "Heroku", cname: "herokuapp.com", fingerprint: "no-such-app" },
  { service: "AWS S3", cname: "s3.amazonaws.com", fingerprint: "NoSuchBucket" },
  { service: "Surge.sh", cname: "surge.sh", fingerprint: "project not found" },
  { service: "Netlify", cname: "netlify.app", fingerprint: "Not Found - Request ID:" },
  { service: "Fly.io", cname: "fly.dev", fingerprint: "Fly.io 404" },
  { service: "Vercel", cname: "vercel.app", fingerprint: "DEPLOYMENT_NOT_FOUND" },
  { service: "Render", cname: "onrender.com", fingerprint: "render.com/docs/custom-domains" },
  { service: "Railway", cname: "up.railway.app", fingerprint: "Application Not Found" },
  { service: "Hugging Face Spaces", cname: "hf.space", fingerprint: "This space is sleeping" },
  { service: "Ngrok", cname: "ngrok.io", fingerprint: "Tunnel .* not found" },
  { service: "Cloudinary", cname: "cloudinary.com", fingerprint: "no such resource" },
];

// Some services return HTTP 200 but put "not found" messaging in the body
const SOFT_404_PATTERNS = [
  /there isn['']t a github pages site here/i,
  /this page isn['']t available/i,
  /application not found/i,
  /domain is not configured/i,
  /site not found/i,
  /project not found/i,
  /no such app/i,
  /this space is sleeping/i,
  /deployment not found/i,
];

function dnsCleanupSnippet(subdomain: string, recordType: string): string {
  return [
    `; Remove the dangling DNS record for ${subdomain}`,
    `; Option 1: Delete the record entirely`,
    `$ dig ${subdomain} ${recordType} +short   # verify current target`,
    `; Then remove the ${recordType} record from your DNS provider`,
    ``,
    `; Option 2: Re-point to a controlled resource`,
    `${subdomain}.  IN  ${recordType}  your-active-service.example.com.`,
  ].join("\n");
}

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

  // Check subdomains for takeover indicators — in parallel for speed
  const MAX_FINDINGS = 3;
  const checkResults = await Promise.allSettled(
    subdomains.map(async (sub) => {
      try {
        const res = await scanFetch(`https://${sub}`, { timeoutMs: 5000, noCache: true });
        const text = await res.text();

        if (res.status === 200 && text.length > 10000) return null;

        for (const fp of TAKEOVER_FINGERPRINTS) {
          const isMatch = fp.fingerprint.includes(".*")
            ? new RegExp(fp.fingerprint, "i").test(text)
            : text.includes(fp.fingerprint);
          if (isMatch) return { sub, type: "takeover" as const, service: fp.service, status: res.status, fingerprint: fp.fingerprint };
        }

        if (res.status === 200 && text.length < 10000) {
          for (const pattern of SOFT_404_PATTERNS) {
            if (pattern.test(text)) return { sub, type: "soft404" as const, textLen: text.length, pattern: pattern.source };
          }
        }
        return null;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        if (/ENOTFOUND|NXDOMAIN|ECONNREFUSED|ECONNRESET|CERT_HAS_EXPIRED/.test(message)) {
          return { sub, type: "dangling" as const, error: message };
        }
        return null;
      }
    }),
  );

  for (const r of checkResults) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;

    if (v.type === "takeover") {
      findings.push({
        id: `subdomain-takeover-${findings.length}`,
        module: "Subdomain Takeover",
        severity: "high",
        title: `Potential subdomain takeover: ${v.sub} (${v.service})`,
        description: `The subdomain ${v.sub} appears to point to ${v.service} but the resource doesn't exist. An attacker could claim this resource and serve malicious content under your domain.`,
        evidence: `Subdomain: ${v.sub}\nService: ${v.service}\nHTTP status: ${v.status}\nFingerprint: "${v.fingerprint}" found in response`,
        remediation: `Remove the DNS record for ${v.sub} or claim the resource on ${v.service}. Dangling DNS records are a common source of subdomain takeover attacks.`,
        codeSnippet: dnsCleanupSnippet(v.sub, "CNAME"),
        cwe: "CWE-404",
        owasp: "A05:2021",
      });
    } else if (v.type === "soft404") {
      findings.push({
        id: `subdomain-takeover-${findings.length}`,
        module: "Subdomain Takeover",
        severity: "medium",
        title: `Suspicious soft-404 on ${v.sub}`,
        description: `The subdomain ${v.sub} returns HTTP 200 but the response body contains error messaging ("${v.pattern}"). This may indicate a dangling DNS record pointing to a decommissioned service.`,
        evidence: `Subdomain: ${v.sub}\nHTTP status: 200\nBody length: ${v.textLen}\nMatched pattern: ${v.pattern}`,
        remediation: `Verify the subdomain ${v.sub} is intentionally configured. If the service is decommissioned, remove the DNS record to prevent subdomain takeover.`,
        codeSnippet: dnsCleanupSnippet(v.sub, "CNAME"),
        cwe: "CWE-404",
        owasp: "A05:2021",
      });
    } else if (v.type === "dangling") {
      findings.push({
        id: `subdomain-takeover-${findings.length}`,
        module: "Subdomain Takeover",
        severity: "medium",
        title: `Dangling DNS record: ${v.sub}`,
        description: `The subdomain ${v.sub} has a DNS record but the target is unreachable (${v.error.split(":")[0]}). This is a strong indicator of a decommissioned service and may be vulnerable to takeover if the target hostname can be reclaimed.`,
        evidence: `Subdomain: ${v.sub}\nError: ${v.error}`,
        remediation: `Remove the DNS record for ${v.sub}. Unreachable subdomains with active DNS records are prime targets for takeover.`,
        codeSnippet: dnsCleanupSnippet(v.sub, "CNAME"),
        cwe: "CWE-404",
        owasp: "A05:2021",
      });
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
      codeSnippet: [
        `; Audit all subdomains for ${baseDomain}`,
        `$ dig ${baseDomain} ANY +short`,
        `$ for sub in $(cat subdomains.txt); do dig $sub CNAME +short; done`,
        ``,
        `; Remove any records pointing to services you no longer use`,
      ].join("\n"),
      cwe: "CWE-404",
    });
  }

  return findings;
};
