import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

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
      remediation: "Add Content-Security-Policy: frame-ancestors 'none' (preferred) or X-Frame-Options: DENY. Use 'self' instead of 'none' if you need same-origin framing.",
      cwe: "CWE-1021",
      owasp: "A05:2021",
      codeSnippet: `// next.config.ts headers()\n{ key: "X-Frame-Options", value: "DENY" },\n{ key: "Content-Security-Policy", value: "frame-ancestors 'none'" }`,
    });
  }

  // Check for CSP frame-ancestors * (wildcard = no protection)
  if (hasFrameAncestors && /frame-ancestors\s+\*[\s;]?/i.test(csp!)) {
    findings.push({
      id: "clickjacking-csp-wildcard",
      module: "Clickjacking",
      severity: "medium",
      title: "CSP frame-ancestors allows wildcard",
      description: "Content-Security-Policy has frame-ancestors set to * which allows any site to embed your app in an iframe.",
      evidence: `Content-Security-Policy: ...frame-ancestors *...`,
      remediation: "Set frame-ancestors to 'none' or 'self' instead of wildcard.",
      cwe: "CWE-1021",
      codeSnippet: `// Fix CSP frame-ancestors\n{ key: "Content-Security-Policy", value: "frame-ancestors 'self'" }`,
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
      codeSnippet: `// next.config.ts headers()\n{ key: "X-Frame-Options", value: "DENY" }`,
    });
  }

  // Check for conflicting X-Frame-Options and CSP frame-ancestors
  if (xfo && hasFrameAncestors) {
    const xfoUpper = xfo.toUpperCase();
    const ancestorsMatch = csp!.match(/frame-ancestors\s+([^;]+)/i);
    const ancestors = ancestorsMatch?.[1]?.trim() || "";
    // XFO says DENY but CSP allows framing, or vice versa
    if ((xfoUpper === "DENY" && ancestors !== "'none'") ||
        (xfoUpper === "SAMEORIGIN" && ancestors === "'none'")) {
      findings.push({
        id: "clickjacking-header-conflict",
        module: "Clickjacking",
        severity: "low",
        title: "Conflicting X-Frame-Options and CSP frame-ancestors",
        description: `X-Frame-Options is "${xfo}" but CSP frame-ancestors is "${ancestors}". Browsers that support CSP will ignore X-Frame-Options when frame-ancestors is present. Ensure CSP frame-ancestors has the policy you intend.`,
        evidence: `X-Frame-Options: ${xfo}\nCSP frame-ancestors: ${ancestors}`,
        remediation: "Align both headers. CSP frame-ancestors takes precedence in modern browsers. Remove X-Frame-Options if CSP is set correctly.",
        cwe: "CWE-1021",
        codeSnippet: `// Use CSP frame-ancestors as the primary control\n// X-Frame-Options is only for legacy browser fallback\n{ key: "Content-Security-Policy", value: "frame-ancestors 'self'" }`,
      });
    }
  }

  // Check for X-Frame-Options ALLOW-FROM with untrusted domain
  if (xfo && /ALLOW-FROM/i.test(xfo)) {
    const domainMatch = xfo.match(/ALLOW-FROM\s+(https?:\/\/[^\s]+)/i);
    const allowedDomain = domainMatch?.[1] || "unknown";
    findings.push({
      id: "clickjacking-allow-from",
      module: "Clickjacking",
      severity: "medium",
      title: "X-Frame-Options uses deprecated ALLOW-FROM directive",
      description: `X-Frame-Options: ALLOW-FROM is not supported in Chrome or Safari. Only Firefox honors it. Your site may be frameable in browsers that ignore this directive. Allowed domain: ${allowedDomain}`,
      evidence: `X-Frame-Options: ${xfo}`,
      remediation: "Use CSP frame-ancestors instead of X-Frame-Options ALLOW-FROM, which is supported across all modern browsers.",
      cwe: "CWE-1021",
      codeSnippet: `// Replace ALLOW-FROM with CSP frame-ancestors\n{ key: "Content-Security-Policy", value: "frame-ancestors 'self' ${allowedDomain}" }`,
    });
  }

  // Detect JS-only frame-busting (easily bypassed)
  const allJs = Array.from(target.jsContents.values()).join("\n");
  const frameBustingPatterns = [
    /if\s*\(\s*(?:window\.)?top\s*!==?\s*(?:window\.)?self\s*\)/,
    /if\s*\(\s*(?:window\.)?self\s*!==?\s*(?:window\.)?top\s*\)/,
    /if\s*\(\s*(?:window\.)?parent\s*!==?\s*(?:window\.)?self\s*\)/,
    /(?:window\.)?top\.location\s*=\s*(?:window\.)?(?:self\.)?location/,
    /if\s*\(\s*window\.frameElement\s*\)/,
  ];

  const hasJsFrameBusting = frameBustingPatterns.some((p) => p.test(allJs));
  if (hasJsFrameBusting && !xfo && !hasFrameAncestors) {
    findings.push({
      id: "clickjacking-js-frame-busting",
      module: "Clickjacking",
      severity: "medium",
      title: "JavaScript frame-busting without header protection",
      description: "Your app uses JavaScript-based frame-busting (top !== self) but lacks X-Frame-Options or CSP frame-ancestors headers. JS frame-busting can be bypassed using sandbox attributes (sandbox=\"allow-scripts\"), double framing, or disabling JavaScript.",
      evidence: "Detected top/self comparison or top.location assignment in JS bundles",
      remediation: "Add HTTP header-based protection (CSP frame-ancestors). JavaScript frame-busting is unreliable and should only be a defense-in-depth measure.",
      cwe: "CWE-1021", owasp: "A05:2021",
      codeSnippet: `// JS frame-busting is bypassable:\n// <iframe sandbox="allow-scripts" src="..."> disables top navigation\n\n// Use headers instead:\n{ key: "Content-Security-Policy", value: "frame-ancestors 'none'" },\n{ key: "X-Frame-Options", value: "DENY" }`,
    });
  }

  // Check if state-changing endpoints are frameable (different framing policy)
  if (target.apiEndpoints.length > 0 && (xfo || hasFrameAncestors)) {
    const stateChangingPaths = target.apiEndpoints
      .filter((ep) => /checkout|payment|settings|account|transfer|delete|admin/i.test(ep))
      .slice(0, 3);

    const frameCheckResults = await Promise.allSettled(
      stateChangingPaths.map(async (endpoint) => {
        const res = await scanFetch(endpoint, { timeoutMs: 5000 });
        const epXfo = res.headers.get("x-frame-options");
        const epCsp = res.headers.get("content-security-policy");
        const epHasFrameAncestors = epCsp && /frame-ancestors/i.test(epCsp);
        if (!epXfo && !epHasFrameAncestors) {
          return { endpoint, pathname: new URL(endpoint).pathname };
        }
        return null;
      }),
    );

    for (const r of frameCheckResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      findings.push({
        id: `clickjacking-endpoint-unprotected-${r.value.pathname.replace(/\//g, "-")}`,
        module: "Clickjacking",
        severity: "medium",
        title: `State-changing endpoint ${r.value.pathname} lacks framing protection`,
        description: "The main page has clickjacking protection but this state-changing endpoint does not. An attacker could iframe this specific endpoint to trick users into performing actions.",
        evidence: `Main page: X-Frame-Options: ${xfo || "(none)"}, frame-ancestors: ${hasFrameAncestors ? "present" : "(none)"}\nEndpoint ${r.value.pathname}: no framing headers`,
        remediation: "Apply X-Frame-Options and CSP frame-ancestors globally, not just on the main page.",
        cwe: "CWE-1021",
        codeSnippet: `// Apply globally in next.config.ts or middleware\n// next.config.ts\nasync headers() {\n  return [{ source: "/(.*)", headers: [\n    { key: "X-Frame-Options", value: "DENY" },\n    { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },\n  ]}];\n}`,
      });
      break; // One finding is enough
    }
  }

  // Check for pages with sensitive forms that could be targeted by clickjacking
  const sensitiveForms = target.forms.filter((f) =>
    f.method === "POST" && f.inputs.some((i) =>
      /password|card|cvv|ssn|amount|transfer|confirm|delete|remove/i.test(i.name),
    ),
  );
  if (sensitiveForms.length > 0 && !xfo && !hasFrameAncestors) {
    findings.push({
      id: "clickjacking-sensitive-forms",
      module: "Clickjacking",
      severity: "high",
      title: `${sensitiveForms.length} sensitive form(s) exposed to clickjacking`,
      description: `Found ${sensitiveForms.length} form(s) with sensitive fields (password, payment, delete, etc.) that lack clickjacking protection. An attacker can overlay these forms in an invisible iframe, tricking users into submitting sensitive data.`,
      evidence: `Sensitive forms:\n${sensitiveForms.slice(0, 3).map((f) => `  ${f.method} ${f.action} — fields: ${f.inputs.map((i) => i.name).join(", ")}`).join("\n")}`,
      remediation: "Add X-Frame-Options: DENY and CSP frame-ancestors: 'none' to prevent framing of pages with sensitive forms.",
      cwe: "CWE-1021",
      owasp: "A05:2021",
      codeSnippet: `// Protect all pages globally\n// next.config.ts\nasync headers() {\n  return [{ source: "/(.*)", headers: [\n    { key: "X-Frame-Options", value: "DENY" },\n    { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },\n  ]}];\n}`,
    });
  }

  // Check for window.opener vulnerability (reverse tabnapping)
  // Look for links with target="_blank" without rel="noopener"
  const mainPageRes = await scanFetch(target.url, { timeoutMs: 5000 }).catch(() => null);
  if (mainPageRes) {
    const html = await mainPageRes.text();
    const blankLinks = html.match(/<a[^>]*target\s*=\s*["']_blank["'][^>]*>/gi) || [];
    const unsafeLinks = blankLinks.filter((link) => !(/rel\s*=\s*["'][^"']*noopener/i.test(link)));
    if (unsafeLinks.length > 3) {
      findings.push({
        id: "clickjacking-tabnapping",
        module: "Clickjacking",
        severity: "low",
        title: `${unsafeLinks.length} external links without rel="noopener"`,
        description: `Found ${unsafeLinks.length} links with target="_blank" but without rel="noopener". The opened page can access window.opener and redirect your page to a phishing site (reverse tabnapping). Modern browsers mitigate this by default, but older browsers are still vulnerable.`,
        evidence: `${unsafeLinks.length} links with target="_blank" missing rel="noopener"\nExample: ${unsafeLinks[0]?.substring(0, 100)}`,
        remediation: "Add rel=\"noopener noreferrer\" to all external links with target=\"_blank\". React/Next.js does this automatically for <Link>, but not for raw <a> tags.",
        cwe: "CWE-1022",
        confidence: 80,
        codeSnippet: `// Always add rel="noopener" to external links\n<a href="https://external.com" target="_blank" rel="noopener noreferrer">\n  External Link\n</a>`,
      });
    }
  }

  // Check for CSP sandbox directive that might enable framing
  if (csp && /sandbox/i.test(csp)) {
    const sandboxMatch = csp.match(/sandbox\s+([^;]+)/i);
    const sandboxValue = sandboxMatch?.[1] || "";
    if (sandboxValue.includes("allow-scripts") && sandboxValue.includes("allow-same-origin")) {
      findings.push({
        id: "clickjacking-sandbox-escape",
        module: "Clickjacking",
        severity: "medium",
        title: "CSP sandbox allows both scripts and same-origin (escapable)",
        description: "The CSP sandbox directive allows both 'allow-scripts' and 'allow-same-origin'. This combination allows sandboxed content to remove the sandbox attribute via JavaScript, completely escaping the sandbox.",
        evidence: `CSP sandbox: ${sandboxValue}`,
        remediation: "Never combine allow-scripts and allow-same-origin in the sandbox directive. This combination defeats the purpose of sandboxing.",
        cwe: "CWE-693",
        owasp: "A05:2021",
      });
    }
  }

  return findings;
};
