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
  { service: "Azure", cname: "azurewebsites.net", fingerprint: "404 Web Site not found" },
  { service: "Azure TrafficManager", cname: "trafficmanager.net", fingerprint: "page not found" },
  { service: "Shopify", cname: "myshopify.com", fingerprint: "Sorry, this shop is currently unavailable" },
  { service: "Fastly", cname: "fastly.net", fingerprint: "Fastly error: unknown domain" },
  { service: "Pantheon", cname: "pantheonsite.io", fingerprint: "404 error unknown site" },
  { service: "Tumblr", cname: "domains.tumblr.com", fingerprint: "There's nothing here" },
  { service: "WordPress.com", cname: "wordpress.com", fingerprint: "Do you want to register" },
  { service: "Zendesk", cname: "zendesk.com", fingerprint: "Help Center Closed" },
  { service: "Unbounce", cname: "unbouncepages.com", fingerprint: "The requested URL was not found" },
  { service: "Cargo", cname: "cargocollective.com", fingerprint: "If you're moving your domain away" },
  { service: "Bitbucket", cname: "bitbucket.io", fingerprint: "Repository not found" },
  { service: "Ghost", cname: "ghost.io", fingerprint: "404 Ghost" },
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

  // Check for wildcard DNS (responds to any subdomain)
  try {
    const randomSub = `vibeshield-${Math.random().toString(36).slice(2, 10)}.${baseDomain}`;
    const wcRes = await scanFetch(`https://${randomSub}`, { timeoutMs: 5000, noCache: true });
    if (wcRes.ok) {
      findings.push({
        id: "subdomain-wildcard-dns",
        module: "Subdomain Takeover",
        severity: "low",
        title: `Wildcard DNS detected on ${baseDomain}`,
        description: `A random subdomain (${randomSub}) resolves and returns HTTP ${wcRes.status}. Wildcard DNS records can mask subdomain takeover vulnerabilities since all subdomains appear "active".`,
        evidence: `Random subdomain: ${randomSub}\nStatus: ${wcRes.status}`,
        remediation: "Remove wildcard DNS records unless intentionally needed. They make it impossible to detect dangling records and increase the attack surface.",
        cwe: "CWE-404",
        confidence: 90,
      });
    }
  } catch {
    // Random subdomain doesn't resolve — no wildcard DNS (good)
  }

  // Probe common sensitive subdomains not found in CT logs
  const commonSubs = [
    "admin", "dev", "staging", "test", "api-old", "internal",
    "beta", "demo", "sandbox", "debug", "old", "backup",
    "mail", "vpn", "jenkins", "ci", "grafana", "prometheus",
    "qa", "uat", "api-dev", "api-staging", "api-test", "preprod",
    "stage", "development", "testing", "docker", "k8s", "kibana",
    "elasticsearch", "redis", "mongo", "db", "phpmyadmin", "adminer",
  ].map((s) => `${s}.${baseDomain}`);

  const unprobed = commonSubs.filter((s) => !subdomains.includes(s));
  const commonResults = await Promise.allSettled(
    unprobed.slice(0, 10).map(async (sub) => {
      try {
        const res = await scanFetch(`https://${sub}`, { timeoutMs: 5000, noCache: true });
        if (!res.ok) return null;
        const text = await res.text();
        // Only flag if it's a real response, not a wildcard/parking page
        if (text.length < 100 || SOFT_404_PATTERNS.some((p) => p.test(text))) return null;
        // Check if it looks like an admin/internal tool
        const isInternal = /dashboard|admin|login|sign.in|jenkins|grafana|prometheus|debug|internal/i.test(text);
        if (isInternal) return { sub, status: res.status };
        return null;
      } catch {
        return null;
      }
    }),
  );

  for (const r of commonResults) {
    if (findings.length >= MAX_FINDINGS + 2) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `subdomain-internal-${findings.length}`,
      module: "Subdomain Takeover",
      severity: "medium",
      title: `Internal-looking subdomain accessible: ${v.sub}`,
      description: `The subdomain ${v.sub} appears to host an internal tool or admin interface that is publicly accessible. This was not discovered via certificate transparency, suggesting it may not be intended for public access.`,
      evidence: `Subdomain: ${v.sub}\nStatus: ${v.status}\nNot found in CT logs — discovered via common name enumeration`,
      remediation: `Restrict access to ${v.sub} using IP allowlists, VPN, or authentication. Internal tools should not be publicly accessible.`,
      cwe: "CWE-668", owasp: "A01:2021",
      confidence: 70,
    });
  }

  // ── Phase: SPF/DMARC/DKIM email security checks ──────────────────────
  // Check DNS TXT records for email authentication via DNS-over-HTTPS
  const emailDnsChecks = await Promise.allSettled([
    scanFetch(`https://dns.google/resolve?name=${baseDomain}&type=TXT`, { timeoutMs: 5000, noCache: true }),
    scanFetch(`https://dns.google/resolve?name=_dmarc.${baseDomain}&type=TXT`, { timeoutMs: 5000, noCache: true }),
    scanFetch(`https://dns.google/resolve?name=default._domainkey.${baseDomain}&type=TXT`, { timeoutMs: 5000, noCache: true }),
  ]);

  const missingRecords: string[] = [];
  let spfFound = false;
  let dmarcFound = false;
  let dkimFound = false;

  // Check SPF
  if (emailDnsChecks[0].status === "fulfilled" && emailDnsChecks[0].value.ok) {
    try {
      const data = await emailDnsChecks[0].value.json();
      const answers: { data: string }[] = data.Answer ?? [];
      spfFound = answers.some((a: { data: string }) => /v=spf1/i.test(a.data));
    } catch { /* parse failure */ }
  }
  if (!spfFound) missingRecords.push("SPF");

  // Check DMARC
  if (emailDnsChecks[1].status === "fulfilled" && emailDnsChecks[1].value.ok) {
    try {
      const data = await emailDnsChecks[1].value.json();
      const answers: { data: string }[] = data.Answer ?? [];
      dmarcFound = answers.some((a: { data: string }) => /v=DMARC1/i.test(a.data));
    } catch { /* parse failure */ }
  }
  if (!dmarcFound) missingRecords.push("DMARC");

  // Check DKIM (default selector)
  if (emailDnsChecks[2].status === "fulfilled" && emailDnsChecks[2].value.ok) {
    try {
      const data = await emailDnsChecks[2].value.json();
      const answers: { data: string }[] = data.Answer ?? [];
      dkimFound = answers.some((a: { data: string }) => /v=DKIM1/i.test(a.data));
    } catch { /* parse failure */ }
  }
  if (!dkimFound) missingRecords.push("DKIM");

  if (missingRecords.length > 0) {
    const severity = missingRecords.includes("SPF") && missingRecords.includes("DMARC") ? "high" as const : "medium" as const;
    findings.push({
      id: `subdomain-email-auth-${findings.length}`,
      module: "subdomain",
      severity,
      title: `Missing email security records: ${missingRecords.join(", ")}`,
      description: `The domain ${baseDomain} is missing ${missingRecords.join(", ")} DNS records. Without these records, attackers can spoof emails from your domain, increasing the risk of phishing attacks against your users and partners.`,
      evidence: `Domain: ${baseDomain}\nSPF: ${spfFound ? "present" : "MISSING"}\nDMARC: ${dmarcFound ? "present" : "MISSING"}\nDKIM (default selector): ${dkimFound ? "present" : "MISSING"}`,
      remediation: [
        missingRecords.includes("SPF") ? `Add an SPF record: ${baseDomain}. IN TXT "v=spf1 include:_spf.google.com ~all" (adjust include for your email provider)` : "",
        missingRecords.includes("DMARC") ? `Add a DMARC record: _dmarc.${baseDomain}. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@${baseDomain}"` : "",
        missingRecords.includes("DKIM") ? `Configure DKIM signing with your email provider and publish the public key as a TXT record under <selector>._domainkey.${baseDomain}` : "",
      ].filter(Boolean).join("\n"),
      cwe: "CWE-290",
      owasp: "A07:2021",
    });
  }

  // ── Phase: Dangling DNS re-check on discovered subdomains ────────────
  // Re-check subdomains that resolved earlier but may have CNAME targets pointing to unclaimed services
  const danglingCandidates = subdomains.filter((sub) => {
    // Skip subdomains already reported
    return !findings.some((f) => f.evidence?.includes(sub));
  });

  const danglingResults = await Promise.allSettled(
    danglingCandidates.slice(0, 15).map(async (sub) => {
      try {
        // Query CNAME via DNS-over-HTTPS
        const dnsRes = await scanFetch(`https://dns.google/resolve?name=${sub}&type=CNAME`, { timeoutMs: 5000, noCache: true });
        if (!dnsRes.ok) return null;
        const data = await dnsRes.json();
        const answers: { data: string }[] = data.Answer ?? [];
        if (answers.length === 0) return null;

        const cnameTarget = answers[0].data.replace(/\.$/, "").toLowerCase();

        // Check if the CNAME target itself resolves
        const targetRes = await scanFetch(`https://dns.google/resolve?name=${cnameTarget}&type=A`, { timeoutMs: 5000, noCache: true });
        if (!targetRes.ok) return null;
        const targetData = await targetRes.json();

        // NXDOMAIN (Status 3) or SERVFAIL (Status 2) on the CNAME target = dangling
        if (targetData.Status === 3 || targetData.Status === 2) {
          return { sub, cnameTarget, status: targetData.Status === 3 ? "NXDOMAIN" : "SERVFAIL" };
        }
        return null;
      } catch {
        return null;
      }
    }),
  );

  for (const r of danglingResults) {
    if (findings.length >= MAX_FINDINGS + 5) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `subdomain-dangling-cname-${findings.length}`,
      module: "subdomain",
      severity: "high",
      title: `Dangling CNAME detected: ${v.sub}`,
      description: `The subdomain ${v.sub} has a CNAME pointing to ${v.cnameTarget}, but the target returns ${v.status}. If an attacker can register ${v.cnameTarget}, they can serve content under your domain.`,
      evidence: `Subdomain: ${v.sub}\nCNAME target: ${v.cnameTarget}\nTarget DNS status: ${v.status}`,
      remediation: `Remove the CNAME record for ${v.sub} or re-point it to an active resource. The current target ${v.cnameTarget} is unresolvable and could be claimed by an attacker.`,
      codeSnippet: dnsCleanupSnippet(v.sub, "CNAME"),
      cwe: "CWE-672",
      owasp: "A05:2021",
    });
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
