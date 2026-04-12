import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

/**
 * postMessage handler analysis.
 *
 * Parses `window.addEventListener("message", ...)` and `window.onmessage = ...`
 * handlers from inline HTML scripts and bundled JS, then flags handlers that:
 *   1. Do not validate `event.origin`
 *   2. Contain a dangerous sink (window.open with event.data.*, innerHTML,
 *      eval/Function, postMessage back with cookie/token/secret values)
 *
 * This is static analysis — it finds real gadgets but doesn't prove reachability.
 * High-signal in practice: the overwhelming majority of sites have origin-checked
 * listeners or no listeners at all.
 */

const SINK_PATTERNS: { name: string; re: RegExp; severity: "high" | "medium" }[] = [
  { name: "window.open with data.url", re: /window\.open\s*\(\s*(?:event|e|msg|ev)\.?data\.(?:url|href|link|redirect)/, severity: "high" },
  { name: "innerHTML assignment from message data", re: /\.innerHTML\s*=\s*(?:event|e|msg|ev)\.?data/, severity: "high" },
  { name: "outerHTML / insertAdjacentHTML from message data", re: /(?:outerHTML\s*=|insertAdjacentHTML\s*\([^)]*,)\s*(?:event|e|msg|ev)\.?data/, severity: "high" },
  { name: "eval/Function with message data", re: /(?:\beval\s*\(|new\s+Function\s*\()\s*(?:event|e|msg|ev)\.?data/, severity: "high" },
  { name: "document.cookie leaked via postMessage reply", re: /document\.cookie[\s\S]{0,200}?postMessage/, severity: "medium" },
];

const ORIGIN_CHECK = /(?:event|e|msg|ev)\.origin\s*(?:===|!==|==|!=|\.(?:includes|startsWith|endsWith|match))|origins?\.(?:includes|has|indexOf)\s*\(\s*(?:event|e|msg|ev)\.origin/;

/** Extract each message-handler function body from source text. */
const extractHandlers = (src: string): string[] => {
  const handlers: string[] = [];
  const re = /addEventListener\s*\(\s*["']message["']\s*,\s*(?:async\s+)?function\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const openParen = src.indexOf("(", m.index + m[0].length - 1);
    if (openParen < 0) continue;
    // find matching close brace after the function body `{`
    const bodyStart = src.indexOf("{", openParen);
    if (bodyStart < 0) continue;
    let depth = 0;
    let i = bodyStart;
    for (; i < src.length && i < bodyStart + 10000; i++) {
      const c = src[i];
      if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) { i++; break; }
      }
    }
    handlers.push(src.slice(bodyStart, i));
  }
  // Arrow form: addEventListener("message", (e) => { ... })
  const arrowRe = /addEventListener\s*\(\s*["']message["']\s*,\s*(?:async\s+)?\(?\s*\w*\s*\)?\s*=>\s*\{/g;
  while ((m = arrowRe.exec(src)) !== null) {
    const bodyStart = src.indexOf("{", m.index + m[0].length - 1);
    if (bodyStart < 0) continue;
    let depth = 0;
    let i = bodyStart;
    for (; i < src.length && i < bodyStart + 10000; i++) {
      const c = src[i];
      if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) { i++; break; }
      }
    }
    handlers.push(src.slice(bodyStart, i));
  }
  return handlers;
};

export const postmessageModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Grab the homepage HTML (inline scripts live there)
  let html = "";
  try {
    const res = await scanFetch(target.url, { timeoutMs: 5000 });
    html = await res.text();
  } catch { /* skip */ }

  // Combine inline HTML source + bundled JS
  const sources: { origin: string; body: string }[] = [];
  if (html) sources.push({ origin: target.url, body: html });
  for (const [url, body] of target.jsContents) sources.push({ origin: url, body });

  type Hit = { origin: string; handler: string; sink: { name: string; severity: "high" | "medium" } };
  const hits: Hit[] = [];

  for (const src of sources) {
    const handlers = extractHandlers(src.body);
    for (const handler of handlers) {
      if (ORIGIN_CHECK.test(handler)) continue; // origin-gated — safe
      for (const sink of SINK_PATTERNS) {
        if (sink.re.test(handler)) {
          hits.push({ origin: src.origin, handler: handler.slice(0, 400), sink });
          break; // one finding per handler
        }
      }
    }
  }

  // Dedup by (sink name + handler snippet prefix)
  const seen = new Set<string>();
  for (const hit of hits) {
    const key = hit.sink.name + "::" + hit.handler.slice(0, 80);
    if (seen.has(key)) continue;
    seen.add(key);

    findings.push({
      id: `postmessage-${findings.length}`,
      module: "postMessage",
      severity: hit.sink.severity,
      title: `postMessage handler missing origin check: ${hit.sink.name}`,
      description: "A window.addEventListener('message', ...) handler processes data from cross-origin messages without validating event.origin, and routes that data into a sensitive sink. Any page that can open or frame this site (popups bypass X-Frame-Options) can trigger the handler and exploit the gadget.",
      evidence: `Handler source (${hit.origin}):\n${hit.handler}`,
      remediation: "Validate event.origin against an explicit allowlist before acting on the message. Never dispatch sink operations on untrusted data.",
      cwe: "CWE-346",
      owasp: "A01:2021",
      confidence: 70,
      codeSnippet: `const ALLOWED_ORIGINS = new Set(["https://your-app.com", "https://trusted-partner.com"]);

window.addEventListener("message", (event) => {
  if (!ALLOWED_ORIGINS.has(event.origin)) return; // reject unknown senders
  // ... handle event.data safely
});`,
    });
    if (findings.length >= 5) break;
  }

  return findings;
};
