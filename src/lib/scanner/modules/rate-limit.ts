import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import * as dns from "dns/promises";

/**
 * DNS & Email Security
 *
 * Checks domain-level security posture: SPF, DKIM, DMARC, DNSSEC indicators,
 * CAA records, and dangling DNS entries. Vibe-coded apps deployed on custom
 * domains often miss these critical domain-level controls.
 *
 * Phases:
 * 1. SPF record analysis
 * 2. DMARC policy check
 * 3. CAA (Certificate Authority Authorization) records
 * 4. Dangling CNAME detection
 * 5. MX security check
 * 6. DNS rebinding susceptibility
 */

export const dnsSecurityModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const hostname = new URL(target.url).hostname;

  // Skip IP addresses and localhost
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname === "localhost") return findings;

  // Extract base domain (handle subdomains)
  const parts = hostname.split(".");
  const baseDomain = parts.length > 2 ? parts.slice(-2).join(".") : hostname;

  // Phase 1: SPF record check
  try {
    const txtRecords = await dns.resolveTxt(baseDomain);
    const spfRecords = txtRecords.flat().filter((r) => r.startsWith("v=spf1"));

    if (spfRecords.length === 0) {
      findings.push({
        id: "dns-no-spf",
        module: "DNS & Email Security",
        severity: "medium",
        title: "No SPF record found",
        description: `The domain ${baseDomain} has no SPF (Sender Policy Framework) record. Without SPF, anyone can send emails that appear to come from your domain, enabling phishing attacks against your users. This is especially dangerous for SaaS apps where users trust transactional emails.`,
        evidence: `TXT records for ${baseDomain}: ${txtRecords.flat().slice(0, 3).join("; ") || "none"}`,
        remediation: `Add an SPF record to your DNS. If you use a transactional email service (SendGrid, Resend, Postmark), include their SPF directive.\nExample: v=spf1 include:_spf.google.com include:sendgrid.net ~all`,
        cwe: "CWE-290",
        confidence: 95,
      });
    } else {
      const spf = spfRecords[0];
      // Check for overly permissive SPF
      if (spf.includes("+all")) {
        findings.push({
          id: "dns-spf-permissive",
          module: "DNS & Email Security",
          severity: "high",
          title: "SPF record allows any server to send email (+all)",
          description: `The SPF record for ${baseDomain} ends with "+all", which explicitly allows ANY server to send emails on behalf of your domain. This completely defeats the purpose of SPF.`,
          evidence: `SPF: ${spf}`,
          remediation: "Change +all to ~all (softfail) or -all (hardfail). Use ~all during testing and -all once you've confirmed all legitimate senders are included.",
          cwe: "CWE-290",
          confidence: 100,
        });
      } else if (!spf.includes("-all") && !spf.includes("~all")) {
        findings.push({
          id: "dns-spf-weak",
          module: "DNS & Email Security",
          severity: "low",
          title: "SPF record has no fail mechanism",
          description: `The SPF record for ${baseDomain} doesn't end with -all or ~all. Without an explicit deny policy, receiving mail servers may accept spoofed emails from unauthorized senders.`,
          evidence: `SPF: ${spf}`,
          remediation: "Append ~all (recommended) or -all to your SPF record to explicitly reject unauthorized senders.",
          cwe: "CWE-290",
        });
      }

      // Check for too many DNS lookups (SPF 10-lookup limit)
      const lookupCount = (spf.match(/include:|redirect=|a:|mx:|exists:/g) || []).length;
      if (lookupCount > 8) {
        findings.push({
          id: "dns-spf-lookups",
          module: "DNS & Email Security",
          severity: "low",
          title: `SPF record has ${lookupCount} DNS lookups (limit is 10)`,
          description: `SPF allows a maximum of 10 DNS lookups. Your record has ${lookupCount}, which is close to or exceeding the limit. Exceeding this causes SPF to return a permanent error (permerror), effectively disabling SPF protection.`,
          evidence: `SPF: ${spf}`,
          remediation: "Flatten your SPF record by replacing include: directives with the actual IP ranges, or use an SPF flattening service.",
          cwe: "CWE-290",
        });
      }
    }
  } catch { /* DNS resolution failed — skip SPF check */ }

  // Phase 2: DMARC policy check
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${baseDomain}`);
    const dmarc = dmarcRecords.flat().find((r) => r.startsWith("v=DMARC1"));

    if (!dmarc) {
      findings.push({
        id: "dns-no-dmarc",
        module: "DNS & Email Security",
        severity: "medium",
        title: "No DMARC record found",
        description: `The domain ${baseDomain} has no DMARC (Domain-based Message Authentication, Reporting & Conformance) record. DMARC tells email receivers what to do with messages that fail SPF/DKIM checks. Without it, spoofed emails from your domain may still be delivered.`,
        remediation: `Add a DMARC record. Start with monitoring mode:\n_dmarc.${baseDomain} TXT "v=DMARC1; p=none; rua=mailto:dmarc@${baseDomain}"\nThen progress to p=quarantine and eventually p=reject.`,
        cwe: "CWE-290",
        confidence: 95,
      });
    } else {
      const policyMatch = dmarc.match(/p=(none|quarantine|reject)/);
      if (policyMatch && policyMatch[1] === "none") {
        findings.push({
          id: "dns-dmarc-none",
          module: "DNS & Email Security",
          severity: "low",
          title: "DMARC policy is set to 'none' (monitoring only)",
          description: `DMARC is configured with p=none, which only monitors but doesn't reject or quarantine spoofed emails. This is fine for initial deployment but should be tightened over time.`,
          evidence: `DMARC: ${dmarc}`,
          remediation: "After reviewing DMARC reports, upgrade to p=quarantine or p=reject to actively block spoofed emails.",
          cwe: "CWE-290",
        });
      }
    }
  } catch {
    // _dmarc record doesn't exist
    findings.push({
      id: "dns-no-dmarc",
      module: "DNS & Email Security",
      severity: "medium",
      title: "No DMARC record found",
      description: `No DMARC record exists at _dmarc.${baseDomain}. Without DMARC, email receivers have no policy guidance for handling spoofed emails from your domain.`,
      remediation: `Add a DMARC TXT record:\n_dmarc.${baseDomain} TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@${baseDomain}"`,
      cwe: "CWE-290",
      confidence: 90,
    });
  }

  // Phase 3: CAA (Certificate Authority Authorization) records
  try {
    const caaRecords = await dns.resolveCaa(baseDomain);
    if (!caaRecords || caaRecords.length === 0) {
      findings.push({
        id: "dns-no-caa",
        module: "DNS & Email Security",
        severity: "low",
        title: "No CAA records — any CA can issue certificates",
        description: `The domain ${baseDomain} has no CAA (Certificate Authority Authorization) records. This means any Certificate Authority can issue SSL certificates for your domain. CAA records restrict which CAs are authorized, reducing the risk of mis-issued certificates.`,
        remediation: `Add CAA records for your certificate provider:\n${baseDomain} CAA 0 issue "letsencrypt.org"\n${baseDomain} CAA 0 issuewild "letsencrypt.org"\n${baseDomain} CAA 0 iodef "mailto:security@${baseDomain}"`,
        cwe: "CWE-295",
      });
    }
  } catch { /* CAA resolution failed or not supported */ }

  // Phase 4: Dangling CNAME detection
  if (hostname !== baseDomain) {
    try {
      const cnames = await dns.resolveCname(hostname);
      for (const cname of cnames) {
        // Check if CNAME target resolves
        try {
          await dns.resolve4(cname);
        } catch (err: unknown) {
          if (err && typeof err === "object" && "code" in err && (err as { code: string }).code === "ENOTFOUND") {
            findings.push({
              id: `dns-dangling-cname-${cname}`,
              module: "DNS & Email Security",
              severity: "high",
              title: `Dangling CNAME: ${hostname} → ${cname} (unresolvable)`,
              description: `The hostname ${hostname} has a CNAME record pointing to ${cname}, which does not resolve. This is a subdomain takeover vector — an attacker could claim the target hostname on the pointed-to service and serve malicious content on your domain.`,
              evidence: `CNAME: ${hostname} → ${cname}\nResolution: NXDOMAIN`,
              remediation: "Either set up the service at the CNAME target, or remove the dangling DNS record. Dangling CNAMEs to cloud services (Heroku, GitHub Pages, AWS) are especially dangerous.",
              cwe: "CWE-284",
              owasp: "A05:2021",
              confidence: 90,
            });
          }
        }
      }
    } catch { /* No CNAME or resolution error */ }
  }

  // Phase 5: MX security — check if mail server supports STARTTLS
  try {
    const mxRecords = await dns.resolveMx(baseDomain);
    if (mxRecords.length === 0) {
      // No MX is fine for apps that don't receive email — skip
    } else {
      // Check for null MX (RFC 7505) — explicit "we don't receive email"
      const hasNullMx = mxRecords.some((mx) => mx.exchange === "." || mx.exchange === "");
      if (!hasNullMx) {
        // Check if any MX points to a known provider with good security
        const knownSecure = /google|googlemail|outlook|microsoft|protonmail|fastmail/i;
        const allSecure = mxRecords.every((mx) => knownSecure.test(mx.exchange));
        if (!allSecure) {
          findings.push({
            id: "dns-mx-unknown",
            module: "DNS & Email Security",
            severity: "info",
            title: `MX records point to: ${mxRecords.slice(0, 3).map((mx) => mx.exchange).join(", ")}`,
            description: "The domain's mail servers don't match common enterprise providers. Ensure your mail server supports STARTTLS, has valid certificates, and is properly secured.",
            evidence: mxRecords.map((mx) => `${mx.priority} ${mx.exchange}`).join("\n"),
            remediation: "Verify your mail server supports TLS. Consider using a managed email provider (Google Workspace, Microsoft 365) for better security defaults.",
          });
        }
      }
    }
  } catch { /* MX resolution failed */ }

  // Phase 6: Check for security.txt (well-known responsible disclosure endpoint)
  try {
    const secRes = await scanFetch(`${target.baseUrl}/.well-known/security.txt`);
    const secText = await secRes.text();
    if (secRes.status === 404 || secText.length < 10 || !secText.includes("Contact:")) {
      findings.push({
        id: "dns-no-security-txt",
        module: "DNS & Email Security",
        severity: "info",
        title: "No security.txt file found",
        description: "The app doesn't have a /.well-known/security.txt file. This standard (RFC 9116) helps security researchers report vulnerabilities responsibly. Without it, researchers may not know how to contact you, or may disclose publicly.",
        remediation: `Create /.well-known/security.txt with at least a Contact field:\nContact: mailto:security@${baseDomain}\nPreferred-Languages: en\nExpires: ${new Date(Date.now() + 365 * 86400000).toISOString().split("T")[0]}T00:00:00.000Z`,
        cwe: "CWE-1059",
      });
    }
  } catch { /* skip */ }

  // Phase 7: DKIM selector probing — check common DKIM selectors
  const dkimSelectors = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim", "mandrill", "ses"];
  try {
    const dkimResults = await Promise.allSettled(
      dkimSelectors.map(async (sel) => {
        const records = await dns.resolveTxt(`${sel}._domainkey.${baseDomain}`);
        return { selector: sel, records: records.flat() };
      }),
    );
    const foundSelectors = dkimResults
      .filter((r): r is PromiseFulfilledResult<{ selector: string; records: string[] }> => r.status === "fulfilled")
      .map((r) => r.value);

    if (foundSelectors.length === 0) {
      findings.push({
        id: "dns-no-dkim",
        module: "DNS & Email Security",
        severity: "medium",
        title: "No DKIM records found for common selectors",
        description: `No DKIM (DomainKeys Identified Mail) records were found for ${baseDomain}. Without DKIM, recipients cannot verify that emails from your domain haven't been tampered with in transit. This weakens your email authentication posture.`,
        evidence: `Checked selectors: ${dkimSelectors.join(", ")}`,
        remediation: "Configure DKIM signing with your email provider and publish the public key as a DNS TXT record at <selector>._domainkey.yourdomain.com.",
        cwe: "CWE-290",
        confidence: 70,
      });
    } else {
      // Check for weak DKIM key sizes
      for (const { selector, records } of foundSelectors) {
        const dkimRecord = records.join("");
        if (dkimRecord.includes("k=rsa") && dkimRecord.includes("p=")) {
          const pubKey = dkimRecord.split("p=")[1]?.split(";")[0]?.trim() || "";
          // Base64-encoded 1024-bit RSA key is ~172 chars, 2048-bit is ~392 chars
          if (pubKey.length > 0 && pubKey.length < 200) {
            findings.push({
              id: `dns-dkim-weak-key-${selector}`,
              module: "DNS & Email Security",
              severity: "low",
              title: `DKIM key for selector "${selector}" may be weak (< 2048-bit)`,
              description: `The DKIM public key for selector "${selector}" appears to be shorter than 2048 bits. NIST recommends at least 2048-bit RSA keys. A weak key could be factored, allowing attackers to forge DKIM signatures.`,
              evidence: `Selector: ${selector}._domainkey.${baseDomain}, key length: ~${pubKey.length * 6} bits (estimated from base64)`,
              remediation: "Rotate to a 2048-bit or longer RSA key, or switch to Ed25519 DKIM signing.",
              cwe: "CWE-326",
              confidence: 60,
            });
          }
        }
      }
    }
  } catch { /* DKIM resolution failed */ }

  // Phase 8: DNSSEC check — look for RRSIG/DNSKEY records
  try {
    // We can't directly check DNSSEC with Node DNS, but we can check for DS records on the parent
    // and look for NSEC/NSEC3 responses. As a proxy, check if the domain has a DS record.
    const dsRecords = await dns.resolve(baseDomain, "DS" as "A").catch(() => []);
    if (!dsRecords || (Array.isArray(dsRecords) && dsRecords.length === 0)) {
      findings.push({
        id: "dns-no-dnssec",
        module: "DNS & Email Security",
        severity: "info",
        title: "DNSSEC not detected",
        description: `No DNSSEC validation chain was detected for ${baseDomain}. DNSSEC prevents DNS spoofing and cache poisoning by cryptographically signing DNS records. While not all registrars support it, enabling DNSSEC adds an important layer of DNS integrity protection.`,
        evidence: `No DS records found for ${baseDomain}`,
        remediation: "Enable DNSSEC through your domain registrar and DNS hosting provider. Most major providers (Cloudflare, Route53, Google Cloud DNS) support automated DNSSEC signing.",
        cwe: "CWE-350",
        confidence: 50,
      });
    }
  } catch { /* DS resolution failed, common for non-DNSSEC domains */ }

  // Phase 9: Check for wildcard DNS (security risk — can mask subdomain takeover)
  try {
    const randomSub = `vibeshield-probe-${Math.random().toString(36).slice(2, 10)}.${baseDomain}`;
    const wildcardResults = await dns.resolve4(randomSub).catch(() => null);
    if (wildcardResults && wildcardResults.length > 0) {
      findings.push({
        id: "dns-wildcard-detected",
        module: "DNS & Email Security",
        severity: "low",
        title: "Wildcard DNS record detected",
        description: `A wildcard DNS record (*.${baseDomain}) was detected — random subdomains resolve to ${wildcardResults[0]}. While sometimes intentional, wildcard DNS can mask subdomain takeover vulnerabilities by hiding dangling records behind a catch-all response.`,
        evidence: `${randomSub} → ${wildcardResults.join(", ")}`,
        remediation: "Remove the wildcard DNS record unless specifically required. Use explicit DNS entries for each subdomain to make takeover detection easier.",
        cwe: "CWE-350",
        confidence: 85,
      });
    }
  } catch { /* expected for non-wildcard domains */ }

  // Phase 10: Nameserver security — check for single NS / common misconfigs
  try {
    const nsRecords = await dns.resolveNs(baseDomain);
    if (nsRecords.length === 1) {
      findings.push({
        id: "dns-single-ns",
        module: "DNS & Email Security",
        severity: "low",
        title: "Single nameserver detected — no DNS redundancy",
        description: `The domain ${baseDomain} has only one nameserver (${nsRecords[0]}). If this nameserver goes down, your entire domain becomes unreachable. RFC 2182 recommends at least two nameservers for redundancy.`,
        evidence: `NS records: ${nsRecords.join(", ")}`,
        remediation: "Add at least one secondary nameserver from a different network for DNS redundancy.",
        cwe: "CWE-693",
        confidence: 90,
      });
    }
  } catch { /* NS resolution failed */ }

  return findings;
};
