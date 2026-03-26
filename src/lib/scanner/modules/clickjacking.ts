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

  // --- Phase: frame-ancestors CSP deep inspection ---
  if (hasFrameAncestors) {
    const ancestorsMatch = csp!.match(/frame-ancestors\s+([^;]+)/i);
    const ancestorsValue = ancestorsMatch?.[1]?.trim() || "";
    const origins = ancestorsValue.split(/\s+/);

    // Check for unsafe origins (http://, IP addresses, broad wildcards like *.com)
    const unsafeOrigins = origins.filter((o) =>
      /^http:\/\//i.test(o) ||
      /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(o) ||
      /^\*\.[a-z]{2,4}$/i.test(o),
    );
    if (unsafeOrigins.length > 0) {
      findings.push({
        id: "clickjacking-csp-unsafe-origins",
        module: "Clickjacking",
        severity: "medium",
        title: "CSP frame-ancestors contains unsafe origins",
        description: `The frame-ancestors directive includes origins that weaken clickjacking protection: ${unsafeOrigins.join(", ")}. HTTP origins can be MITM'd, IP addresses are easily spoofed in DNS, and broad wildcards (e.g. *.com) allow too many domains.`,
        evidence: `Content-Security-Policy: frame-ancestors ${ancestorsValue}`,
        remediation: "Only allow specific HTTPS origins in frame-ancestors. Remove HTTP origins, IP addresses, and overly broad wildcards.",
        cwe: "CWE-1021",
      });
    }

    // frame-ancestors 'self' vs X-Frame-Options SAMEORIGIN precedence analysis
    if (!xfo && origins.length > 3) {
      findings.push({
        id: "clickjacking-csp-too-many-ancestors",
        module: "Clickjacking",
        severity: "low",
        title: `CSP frame-ancestors allows ${origins.length} origins`,
        description: `The frame-ancestors directive lists ${origins.length} allowed origins. A large allowlist increases the attack surface — if any of those origins is compromised, your site can be clickjacked. No X-Frame-Options fallback is set for legacy browsers.`,
        evidence: `Content-Security-Policy: frame-ancestors ${ancestorsValue}`,
        remediation: "Minimize the number of allowed origins in frame-ancestors. Audit each origin periodically and add X-Frame-Options: SAMEORIGIN as a fallback for legacy browsers.",
        cwe: "CWE-1021",
        confidence: 60,
      });
    }
  }

  // --- Phase: Double-framing bypass detection ---
  if (xfo && !hasFrameAncestors) {
    findings.push({
      id: "clickjacking-double-framing",
      module: "Clickjacking",
      severity: "medium",
      title: "X-Frame-Options without CSP frame-ancestors (double-framing bypass)",
      description: "The site relies on X-Frame-Options without CSP frame-ancestors. Modern browsers prioritize CSP over XFO when both are present, but when only XFO is set, some older implementations are vulnerable to double-framing attacks (nesting iframes: attacker -> intermediate -> target). Additionally, XFO SAMEORIGIN checks vary across browsers — some only check the immediate parent, not the top-level frame.",
      evidence: `X-Frame-Options: ${xfo}\nCSP frame-ancestors: (not set)`,
      remediation: "Always set CSP frame-ancestors alongside X-Frame-Options. CSP frame-ancestors is the modern standard and is immune to double-framing bypasses because it checks the entire ancestor chain.",
      cwe: "CWE-1021",
      codeSnippet: `// Add CSP frame-ancestors to complement X-Frame-Options\n{ key: "Content-Security-Policy", value: "frame-ancestors 'self'" },\n{ key: "X-Frame-Options", value: "SAMEORIGIN" }`,
    });
  }

  // --- Phase: Drag-and-drop clickjacking detection ---
  // Look for draggable elements in HTML that could be exploited without frame protection
  if (mainPageRes) {
    const htmlBody = await mainPageRes.clone().text().catch(() => "");
    const draggableElements = htmlBody.match(/<[^>]*draggable\s*=\s*["']true["'][^>]*>/gi) || [];
    const contentEditableElements = htmlBody.match(/<[^>]*contenteditable\s*=\s*["']true["'][^>]*>/gi) || [];
    const dragTargets = [...draggableElements, ...contentEditableElements];

    if (dragTargets.length > 0 && !xfo && !hasFrameAncestors) {
      findings.push({
        id: "clickjacking-drag-drop",
        module: "Clickjacking",
        severity: "medium",
        title: `Drag-and-drop clickjacking: ${dragTargets.length} draggable/contenteditable element(s) without frame protection`,
        description: "The page contains draggable or contenteditable elements and lacks framing protection. An attacker can overlay an invisible iframe and trick users into dragging sensitive content (tokens, text, files) from your page to the attacker's page, or drag attacker-controlled content into your page's editable areas. This attack does not require clicking — only dragging.",
        evidence: `Draggable elements: ${draggableElements.length}\nContenteditable elements: ${contentEditableElements.length}\nExample: ${dragTargets[0]?.substring(0, 120)}`,
        remediation: "Add CSP frame-ancestors: 'none' to prevent framing. If draggable content is necessary, ensure it cannot leak sensitive data and consider adding event handlers to validate drag operations.",
        cwe: "CWE-1021",
        confidence: 65,
        codeSnippet: `// Prevent drag-based data exfiltration\nelement.addEventListener("dragstart", (e) => {\n  // Clear any auto-populated drag data\n  e.dataTransfer?.clearData();\n});\n\n// Better: prevent framing entirely\n{ key: "Content-Security-Policy", value: "frame-ancestors 'none'" }`,
      });
    }
  }

  // --- Phase: Likejacking detection (social media buttons without frame protection) ---
  const htmlForSocial = mainPageRes ? await mainPageRes.clone().text().catch(() => "") : "";
  const socialPatterns = [
    { name: "Facebook Like", pattern: /(?:facebook\.com\/plugins\/like|fb-like|class=["'][^"']*facebook-like)/i },
    { name: "Twitter/X Share", pattern: /(?:platform\.twitter\.com\/widgets|twitter-share-button|class=["'][^"']*tweet-button)/i },
    { name: "LinkedIn Share", pattern: /(?:platform\.linkedin\.com|linkedin-share|class=["'][^"']*linkedin-button)/i },
    { name: "Social iframe", pattern: /<iframe[^>]*(?:facebook|twitter|linkedin|social)[^>]*>/i },
  ];
  const detectedSocial = socialPatterns.filter((sp) => sp.pattern.test(htmlForSocial));
  if (detectedSocial.length > 0 && !xfo && !hasFrameAncestors) {
    findings.push({
      id: "clickjacking-likejacking",
      module: "Clickjacking",
      severity: "medium",
      title: `Likejacking risk: ${detectedSocial.map((s) => s.name).join(", ")} button(s) without frame protection`,
      description: `The page includes social media buttons (${detectedSocial.map((s) => s.name).join(", ")}) and lacks clickjacking protection. An attacker can overlay your page in a transparent iframe positioned so that social buttons align with decoy UI. Users think they're clicking a harmless button but actually Like/Share/Follow attacker-controlled content on social media.`,
      evidence: `Social widgets detected: ${detectedSocial.map((s) => s.name).join(", ")}\nFrame protection: none`,
      remediation: "Add CSP frame-ancestors: 'none' to prevent your page from being framed. Social media SDKs protect their own iframes but cannot protect your page from being iframed by attackers.",
      cwe: "CWE-1021",
      confidence: 70,
    });
  }

  // --- Phase: Cursor hijacking via CSS ---
  const allCss = Array.from(target.jsContents.values()).join("\n") + "\n" + htmlForSocial;
  const cursorHijackPatterns = [
    /cursor\s*:\s*none/i,
    /cursor\s*:\s*url\s*\([^)]+\)/i,
    /pointer-events\s*:\s*none/i,
  ];
  const detectedCursorHijacks = cursorHijackPatterns.filter((p) => p.test(allCss));
  // Only flag cursor: none or cursor: url() combined with lack of frame protection
  if (detectedCursorHijacks.length > 0 && !xfo && !hasFrameAncestors) {
    const hasCursorNone = /cursor\s*:\s*none/i.test(allCss);
    const hasCursorUrl = /cursor\s*:\s*url\s*\([^)]+\)/i.test(allCss);
    const hasPointerNone = /pointer-events\s*:\s*none/i.test(allCss);
    const techniques: string[] = [];
    if (hasCursorNone) techniques.push("cursor: none (hidden cursor)");
    if (hasCursorUrl) techniques.push("cursor: url() (custom cursor image)");
    if (hasPointerNone) techniques.push("pointer-events: none (click-through layer)");

    findings.push({
      id: "clickjacking-cursor-hijacking",
      module: "Clickjacking",
      severity: "low",
      title: "Potential cursor hijacking via CSS without frame protection",
      description: `The page uses CSS techniques that can facilitate cursor hijacking: ${techniques.join("; ")}. Without framing protection, an attacker can iframe your site and use these CSS properties to decouple the visible cursor from the actual click position. Users see the cursor in one place but click somewhere else — on hidden buttons, consent dialogs, or sensitive actions.`,
      evidence: `CSS techniques found: ${techniques.join(", ")}\nFrame protection: none`,
      remediation: "Add CSP frame-ancestors: 'none' to prevent framing. Avoid cursor: none on interactive elements. If custom cursors are needed, ensure they accurately represent the click target position.",
      cwe: "CWE-1021",
      confidence: 50,
    });
  }

  // --- Phase: Frame-busting script bypass detection ---
  if (hasJsFrameBusting) {
    // Check for sandbox-bypassable frame-busting
    const hasSandboxBypass = /sandbox\s*=\s*["'][^"']*allow-scripts[^"']*["']/i.test(htmlForSocial);
    // Check for onbeforeunload-based prevention that attackers use to block frame-busting
    const hasOnBeforeUnload = /onbeforeunload/i.test(allJs);
    // Check for XSS filter abuse pattern (legacy IE)
    const hasLocationAssign = /(?:window\.)?top\.location\s*(?:\.replace|\.assign|\.href\s*=)/i.test(allJs);
    const noHeaderProtection = !xfo && !hasFrameAncestors;

    // Detect specific bypass vectors
    const bypassVectors: string[] = [];
    // sandbox="allow-scripts" blocks top-navigation frame-busting
    if (/top\.location/i.test(allJs)) {
      bypassVectors.push("top.location assignment (blocked by sandbox='allow-scripts' without allow-top-navigation)");
    }
    // onbeforeunload can suppress navigation
    if (hasOnBeforeUnload) {
      bypassVectors.push("onbeforeunload handler detected (attacker can use this to suppress frame-busting navigation)");
    }
    // Double-framing defeats parent/self checks
    if (/(?:window\.)?parent\s*!==?\s*(?:window\.)?self/i.test(allJs) && !/(?:window\.)?top\s*!==?\s*(?:window\.)?self/i.test(allJs)) {
      bypassVectors.push("parent !== self check (bypassable via double-framing: only checks immediate parent, not top)");
    }
    // try/catch around location change
    if (/try\s*\{[^}]*top\.location[^}]*\}\s*catch/i.test(allJs)) {
      bypassVectors.push("try/catch around top.location (silently fails in sandboxed iframes)");
    }

    if (bypassVectors.length > 0 && noHeaderProtection) {
      findings.push({
        id: "clickjacking-frame-bust-bypass",
        module: "Clickjacking",
        severity: "medium",
        title: `Frame-busting script has ${bypassVectors.length} known bypass vector(s)`,
        description: `The JavaScript frame-busting code uses techniques with well-known bypasses:\n${bypassVectors.map((v, i) => `${i + 1}. ${v}`).join("\n")}\n\nAttackers can use iframe sandbox attributes, double-framing, or event handlers to neutralize these protections. No HTTP header protection (XFO/CSP) is set as a fallback.`,
        evidence: `Bypass vectors:\n${bypassVectors.join("\n")}\nHeader protection: none`,
        remediation: "Replace JS frame-busting with HTTP headers. Use CSP frame-ancestors: 'none' (or 'self') which cannot be bypassed by iframe attributes or JavaScript tricks.",
        cwe: "CWE-1021",
        owasp: "A05:2021",
        confidence: 75,
        codeSnippet: `// JS frame-busting is bypassable via:\n// <iframe sandbox="allow-scripts" src="your-site"> — blocks top navigation\n// <iframe onbeforeunload="return false"> — suppresses navigation\n// Double-framing: attacker -> middle -> your-site\n\n// Use headers instead (unbypassable):\n{ key: "Content-Security-Policy", value: "frame-ancestors 'none'" }`,
      });
    }
  }

  // --- Phase: Form action hijacking via base tag injection ---
  const formsWithoutAction = target.forms.filter((f) =>
    !f.action || f.action === "" || f.action === "#" ||
    (!/^https?:\/\//i.test(f.action) && !f.action.startsWith("/")),
  );
  if (formsWithoutAction.length > 0 && (!xfo || !hasFrameAncestors)) {
    findings.push({
      id: "clickjacking-form-action-hijack",
      module: "Clickjacking",
      severity: "medium",
      title: `${formsWithoutAction.length} form(s) vulnerable to base tag hijacking in framing context`,
      description: `Found ${formsWithoutAction.length} form(s) with missing or relative action URLs. In a framing attack combined with HTML injection, an attacker can inject a <base href="https://evil.com"> tag to redirect form submissions. Forms without explicit absolute action URLs inherit the base URL, sending user data to the attacker's server.`,
      evidence: `Forms with missing/relative action:\n${formsWithoutAction.slice(0, 5).map((f) => `  ${f.method} action="${f.action || "(empty)"}" — fields: ${f.inputs.map((i) => i.name).join(", ")}`).join("\n")}`,
      remediation: "Set explicit absolute URLs in form action attributes. Add CSP base-uri 'self' to prevent <base> tag injection. Ensure clickjacking headers (frame-ancestors) are set to prevent framing.",
      cwe: "CWE-1021",
      codeSnippet: `// Prevent base tag injection via CSP\n{ key: "Content-Security-Policy", value: "frame-ancestors 'none'; base-uri 'self'" }\n\n// Use absolute action URLs in forms\n<form action="https://yoursite.com/api/submit" method="POST">`,
    });
  }

  // --- Phase: Permission-Policy / Feature-Policy abuse in framing context ---
  const permPolicy = target.headers["permissions-policy"];
  const featPolicy = target.headers["feature-policy"];
  const policyHeader = permPolicy || featPolicy;
  const policyName = permPolicy ? "Permissions-Policy" : "Feature-Policy";

  const sensitivePPermissions = ["camera", "microphone", "geolocation", "payment", "usb", "bluetooth", "midi"];

  if (!policyHeader) {
    // No policy at all — all permissions available to framed content
    if (!xfo && !hasFrameAncestors) {
      findings.push({
        id: "clickjacking-no-permissions-policy",
        module: "Clickjacking",
        severity: "medium",
        title: "No Permissions-Policy header — sensitive APIs accessible in frames",
        description: "Neither Permissions-Policy nor Feature-Policy is set, and the page lacks framing protection. An attacker can iframe your site and abuse browser APIs (camera, microphone, geolocation, payment) through the framed context, potentially tricking users into granting permissions to the attacker's origin.",
        evidence: "Permissions-Policy: (not set)\nFeature-Policy: (not set)",
        remediation: "Add a Permissions-Policy header to restrict sensitive APIs. At minimum, deny camera, microphone, and geolocation to cross-origin frames.",
        cwe: "CWE-1021",
        codeSnippet: `// Restrict sensitive permissions\n{ key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" }`,
      });
    }
  } else {
    // Policy exists — check for overly permissive values on sensitive features
    const permissiveFeatures = sensitivePPermissions.filter((feat) => {
      // Permissions-Policy format: camera=*, camera=(self "https://example.com")
      // Feature-Policy format: camera *; microphone 'self'
      const permPolicyPattern = new RegExp(`${feat}\\s*=\\s*\\*`, "i");
      const featPolicyPattern = new RegExp(`${feat}\\s+\\*`, "i");
      return permPolicyPattern.test(policyHeader) || featPolicyPattern.test(policyHeader);
    });
    if (permissiveFeatures.length > 0) {
      findings.push({
        id: "clickjacking-permissive-permissions",
        module: "Clickjacking",
        severity: "medium",
        title: `${policyName} allows wildcard access to sensitive features`,
        description: `The ${policyName} header grants wildcard (*) access to sensitive features: ${permissiveFeatures.join(", ")}. In a framing context, any embedding page can access these APIs through your framed content, enabling permission-prompt phishing (tricking users into granting camera/microphone access to the attacker).`,
        evidence: `${policyName}: ${policyHeader.substring(0, 200)}${policyHeader.length > 200 ? "..." : ""}\nWildcard features: ${permissiveFeatures.join(", ")}`,
        remediation: `Set ${policyName} to restrict sensitive features to self or specific trusted origins. Use camera=(), microphone=(), geolocation=() to deny access entirely, or camera=(self) to allow only same-origin.`,
        cwe: "CWE-1021",
        codeSnippet: `// Restrict sensitive features to same-origin only\n{ key: "Permissions-Policy", value: "${permissiveFeatures.map((f) => `${f}=(self)`).join(", ")}" }`,
      });
    }
  }

  return findings;
};
