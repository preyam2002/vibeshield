import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const TRACKER_PATTERNS: { pattern: RegExp; name: string; category: string }[] = [
  { pattern: /google-analytics\.com|gtag\/js|GoogleAnalyticsObject|ga\s*\(\s*['"]create/i, name: "Google Analytics", category: "analytics" },
  { pattern: /googletagmanager\.com|gtm\.js/i, name: "Google Tag Manager", category: "tag-manager" },
  { pattern: /facebook\.net\/en_US\/fbevents|fbq\s*\(\s*['"]init/i, name: "Meta Pixel", category: "advertising" },
  { pattern: /snap\.licdn\.com|_linkedin_partner_id/i, name: "LinkedIn Insight", category: "advertising" },
  { pattern: /static\.hotjar\.com|hj\s*\(\s*['"]init/i, name: "Hotjar", category: "session-recording" },
  { pattern: /clarity\.ms|clarity\s*\(\s*['"]set/i, name: "Microsoft Clarity", category: "session-recording" },
  { pattern: /fullstory\.com|FS\.identify/i, name: "FullStory", category: "session-recording" },
  { pattern: /logrocket\.com|LogRocket\.init/i, name: "LogRocket", category: "session-recording" },
  { pattern: /mouseflow\.com|mouseflow/i, name: "Mouseflow", category: "session-recording" },
  { pattern: /segment\.com\/analytics|analytics\.load\(/i, name: "Segment", category: "analytics" },
  { pattern: /mixpanel\.com|mixpanel\.init/i, name: "Mixpanel", category: "analytics" },
  { pattern: /amplitude\.com|amplitude\.init/i, name: "Amplitude", category: "analytics" },
  { pattern: /posthog\.com|posthog\.init/i, name: "PostHog", category: "analytics" },
  { pattern: /plausible\.io/i, name: "Plausible", category: "analytics-privacy" },
  { pattern: /sentry\.io|Sentry\.init/i, name: "Sentry", category: "error-tracking" },
  { pattern: /intercom\.com|Intercom\s*\(\s*['"]/i, name: "Intercom", category: "chat" },
  { pattern: /crisp\.chat|CRISP_WEBSITE_ID/i, name: "Crisp", category: "chat" },
  { pattern: /tiktok\.com\/i18n\/pixel|ttq\.load/i, name: "TikTok Pixel", category: "advertising" },
  { pattern: /ads\.twitter\.com|twq\s*\(\s*['"]init/i, name: "Twitter/X Pixel", category: "advertising" },
];

const FINGERPRINT_PATTERNS: { pattern: RegExp; technique: string }[] = [
  { pattern: /canvas\.toDataURL|getImageData\s*\(/, technique: "Canvas fingerprinting" },
  { pattern: /AudioContext|OfflineAudioContext/, technique: "Audio fingerprinting" },
  { pattern: /webgl.*getParameter|WEBGL_debug_renderer_info/, technique: "WebGL fingerprinting" },
  { pattern: /navigator\.(?:plugins|mimeTypes|hardwareConcurrency|deviceMemory|connection)/i, technique: "Navigator fingerprinting" },
  { pattern: /screen\.(?:colorDepth|pixelDepth|availWidth|availHeight)/, technique: "Screen fingerprinting" },
  { pattern: /Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone/, technique: "Timezone fingerprinting" },
];

export const privacyModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Phase 1: Detect third-party trackers
  const detectedTrackers: { name: string; category: string }[] = [];
  for (const tracker of TRACKER_PATTERNS) {
    if (tracker.pattern.test(allJs)) {
      detectedTrackers.push({ name: tracker.name, category: tracker.category });
    }
  }

  // Also check external scripts for tracking domains
  const trackingDomains = ["google-analytics.com", "googletagmanager.com", "facebook.net", "hotjar.com",
    "clarity.ms", "fullstory.com", "segment.com", "mixpanel.com", "amplitude.com",
    "snap.licdn.com", "logrocket.com", "sentry.io", "intercom.com"];
  for (const script of target.scripts) {
    for (const domain of trackingDomains) {
      if (script.includes(domain)) {
        const name = TRACKER_PATTERNS.find((t) => script.match(new RegExp(domain.replace(".", "\\."), "i")))?.name || domain;
        if (!detectedTrackers.some((t) => t.name === name)) {
          const tracker = TRACKER_PATTERNS.find((t) => t.name === name);
          detectedTrackers.push({ name, category: tracker?.category || "analytics" });
        }
      }
    }
  }

  const sessionRecorders = detectedTrackers.filter((t) => t.category === "session-recording");
  const adTrackers = detectedTrackers.filter((t) => t.category === "advertising");

  if (sessionRecorders.length > 0) {
    findings.push({
      id: "privacy-session-recording",
      module: "Privacy",
      severity: "medium",
      title: `Session recording service${sessionRecorders.length > 1 ? "s" : ""} detected: ${sessionRecorders.map((t) => t.name).join(", ")}`,
      description: `Your app includes ${sessionRecorders.map((t) => t.name).join(" and ")} which record user sessions including mouse movements, clicks, and form inputs. This can inadvertently capture sensitive data (passwords, personal info, health data) and may require explicit user consent under GDPR/CCPA.`,
      evidence: `Session recording services: ${sessionRecorders.map((t) => t.name).join(", ")}`,
      remediation: "Configure session recording to mask sensitive form fields. Add a consent banner before loading these scripts. Exclude pages with sensitive data (payment, health, account settings).",
      cwe: "CWE-359",
      confidence: 90,
      codeSnippet: `// Load session recording only after consent\nconst consent = getCookieConsent();\nif (consent.analytics) {\n  // Dynamically load after consent\n  const script = document.createElement("script");\n  script.src = "https://static.hotjar.com/c/hotjar-XXXX.js";\n  document.head.appendChild(script);\n}\n\n// Mask sensitive fields\n// Hotjar: data-hj-suppress attribute\n// Clarity: data-clarity-mask attribute\n// FullStory: className="fs-exclude"`,
    });
  }

  if (adTrackers.length > 0) {
    findings.push({
      id: "privacy-ad-trackers",
      module: "Privacy",
      severity: "low",
      title: `${adTrackers.length} advertising tracker${adTrackers.length > 1 ? "s" : ""}: ${adTrackers.map((t) => t.name).join(", ")}`,
      description: `Your app includes advertising/marketing pixels that track user behavior across sites. Under GDPR, these require explicit opt-in consent before loading. Under CCPA, users must be able to opt out.`,
      evidence: `Ad trackers: ${adTrackers.map((t) => t.name).join(", ")}`,
      remediation: "Load advertising pixels only after the user explicitly consents to marketing cookies. Implement a cookie consent banner with granular controls.",
      cwe: "CWE-359",
      confidence: 90,
      codeSnippet: `// Next.js — conditional script loading based on consent\nimport Script from "next/script";\n\nexport function AdPixels({ consent }: { consent: boolean }) {\n  if (!consent) return null;\n  return (\n    <Script\n      src="https://connect.facebook.net/en_US/fbevents.js"\n      strategy="lazyOnload"\n    />\n  );\n}`,
    });
  }

  // Phase 2: Detect browser fingerprinting techniques
  const detectedFingerprints: string[] = [];
  for (const fp of FINGERPRINT_PATTERNS) {
    if (fp.pattern.test(allJs)) {
      detectedFingerprints.push(fp.technique);
    }
  }

  if (detectedFingerprints.length >= 3) {
    findings.push({
      id: "privacy-fingerprinting",
      module: "Privacy",
      severity: "medium",
      title: `Multiple browser fingerprinting techniques detected (${detectedFingerprints.length})`,
      description: `Your app uses ${detectedFingerprints.length} different fingerprinting techniques: ${detectedFingerprints.join(", ")}. Combined, these can create a unique identifier that persists even when cookies are cleared. This may violate GDPR's ePrivacy Directive and is flagged by privacy-focused browsers (Firefox, Brave).`,
      evidence: `Fingerprinting techniques:\n${detectedFingerprints.map((f) => `- ${f}`).join("\n")}`,
      remediation: "If fingerprinting is from a third-party library, audit whether it's necessary. For bot detection (legitimate use), consider server-side alternatives. Disclose fingerprinting in your privacy policy.",
      cwe: "CWE-359",
      confidence: 60,
    });
  }

  // Phase 3: Cookie consent check
  // Look for consent banner/manager patterns
  const hasConsentBanner = /cookie.?consent|cookie.?banner|consent.?manager|onetrust|cookiebot|osano|klaro|tarteaucitron|complianz/i.test(allJs);
  const hasCookiePolicyPage = target.pages.some((p) => /cookie.?policy|privacy.?policy|privacy/i.test(p));

  if (detectedTrackers.length > 2 && !hasConsentBanner) {
    findings.push({
      id: "privacy-no-consent",
      module: "Privacy",
      severity: "medium",
      title: `${detectedTrackers.length} tracking services loaded without cookie consent mechanism`,
      description: `Your app loads ${detectedTrackers.length} tracking services (${detectedTrackers.slice(0, 5).map((t) => t.name).join(", ")}) but no cookie consent mechanism was detected. Under GDPR, tracking cookies require explicit opt-in consent before being set. Under CCPA, users must be informed and given the right to opt out.`,
      evidence: `Trackers: ${detectedTrackers.map((t) => t.name).join(", ")}\nConsent banner: not detected\nPrivacy policy page: ${hasCookiePolicyPage ? "found" : "not found"}`,
      remediation: "Implement a cookie consent banner. Options: CookieBot, OneTrust (enterprise), or open-source solutions like Klaro or Tarteaucitron. Load tracking scripts only after consent.",
      cwe: "CWE-359",
      confidence: 75,
      codeSnippet: `// Simple consent-aware script loading\n"use client";\nimport { useState, useEffect } from "react";\n\nexport function CookieConsent() {\n  const [consent, setConsent] = useState<boolean | null>(null);\n  useEffect(() => {\n    const saved = localStorage.getItem("cookie-consent");\n    if (saved) setConsent(saved === "true");\n  }, []);\n\n  if (consent !== null) return null;\n  return (\n    <div className="fixed bottom-4 right-4 bg-white p-4 rounded-lg shadow-lg z-50">\n      <p>We use cookies for analytics.</p>\n      <button onClick={() => { setConsent(true); localStorage.setItem("cookie-consent", "true"); }}>\n        Accept\n      </button>\n      <button onClick={() => { setConsent(false); localStorage.setItem("cookie-consent", "false"); }}>\n        Decline\n      </button>\n    </div>\n  );\n}`,
    });
  }

  // Phase 4: Check for data exposure in URLs (PII in query params)
  const piiParams = /(?:email|phone|name|address|ssn|dob|birth|password|card|credit)=/i;
  const urlsWithPii = [...target.linkUrls, ...target.pages].filter((u) => piiParams.test(u));
  if (urlsWithPii.length > 0) {
    findings.push({
      id: "privacy-pii-in-urls",
      module: "Privacy",
      severity: "medium",
      title: `PII in URL parameters (${urlsWithPii.length} URL${urlsWithPii.length > 1 ? "s" : ""})`,
      description: "URLs contain query parameters that appear to carry personally identifiable information (email, phone, name, etc.). URL parameters are logged in server access logs, browser history, referrer headers, and CDN logs — all of which may violate data minimization principles.",
      evidence: urlsWithPii.slice(0, 3).map((u) => u.substring(0, 150)).join("\n"),
      remediation: "Pass PII in request bodies (POST) or encrypted cookies, never in URL parameters. If URLs must contain user identifiers, use opaque tokens instead of actual PII.",
      cwe: "CWE-598",
      owasp: "A01:2021",
      confidence: 80,
    });
  }

  // Phase 5: Check for third-party cookie leakage
  const thirdPartyCookies = target.cookies.filter((c) => {
    try {
      const siteDomain = new URL(target.url).hostname;
      return c.domain && !siteDomain.endsWith(c.domain.replace(/^\./, ""));
    } catch { return false; }
  });

  if (thirdPartyCookies.length > 0) {
    findings.push({
      id: "privacy-third-party-cookies",
      module: "Privacy",
      severity: "low",
      title: `${thirdPartyCookies.length} third-party cookie${thirdPartyCookies.length > 1 ? "s" : ""} detected`,
      description: `Your app sets ${thirdPartyCookies.length} cookie(s) for third-party domains. Third-party cookies are being phased out by major browsers (Chrome, Firefox, Safari) and indicate cross-site tracking.`,
      evidence: `Third-party cookies:\n${thirdPartyCookies.slice(0, 5).map((c) => `${c.name} (${c.domain})`).join("\n")}`,
      remediation: "Migrate away from third-party cookies. Use first-party data collection and server-side tracking instead.",
      cwe: "CWE-359",
    });
  }

  // Phase 6: Check for exposed analytics/tracking IDs that reveal infrastructure
  const analyticsIds: { type: string; id: string }[] = [];
  const gaMatch = allJs.match(/(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10,})/);
  if (gaMatch) analyticsIds.push({ type: "Google Analytics", id: gaMatch[0] });
  const fbMatch = allJs.match(/fbq\s*\(\s*['"]init['"]\s*,\s*['"](\d{10,})["']/);
  if (fbMatch) analyticsIds.push({ type: "Meta Pixel", id: fbMatch[1] });
  const gtmMatch = allJs.match(/GTM-[A-Z0-9]{5,}/);
  if (gtmMatch) analyticsIds.push({ type: "GTM Container", id: gtmMatch[0] });

  if (analyticsIds.length > 0) {
    findings.push({
      id: "privacy-analytics-ids",
      module: "Privacy",
      severity: "info",
      title: `${analyticsIds.length} tracking ID${analyticsIds.length > 1 ? "s" : ""} found: ${analyticsIds.map((a) => a.type).join(", ")}`,
      description: `Your app exposes tracking IDs (${analyticsIds.map((a) => `${a.type}: ${a.id}`).join(", ")}). While expected for client-side analytics, these can be used to discover other properties you own (via reverse lookup services) or to inject fake analytics data.`,
      evidence: analyticsIds.map((a) => `${a.type}: ${a.id}`).join("\n"),
      remediation: "This is informational — tracking IDs in client code are expected. Ensure your analytics accounts have proper access controls and consider using a server-side proxy for analytics.",
    });
  }

  // Phase 7: Detect hardcoded PII or credentials in client JS
  const piiPatterns: { re: RegExp; type: string }[] = [
    { re: /["'](?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["']/, type: "email address" },
    { re: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']/i, type: "API key/secret" },
    { re: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/i, type: "password" },
    { re: /sk[-_](?:live|test)[-_][a-zA-Z0-9]{24,}/i, type: "Stripe secret key" },
    { re: /AKIA[0-9A-Z]{16}/, type: "AWS access key" },
    { re: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/, type: "GitHub token" },
  ];
  const exposedSecrets: { type: string; snippet: string }[] = [];
  for (const { re, type } of piiPatterns) {
    const match = allJs.match(re);
    if (match) {
      const val = match[0];
      // Skip obvious false positives (placeholder, example values)
      if (/example|placeholder|your[_-]?|xxx|test|dummy|TODO/i.test(val)) continue;
      exposedSecrets.push({ type, snippet: val.substring(0, 60) });
    }
  }
  if (exposedSecrets.length > 0) {
    findings.push({
      id: "privacy-exposed-secrets",
      module: "Privacy",
      severity: exposedSecrets.some((s) => s.type.includes("key") || s.type.includes("token") || s.type.includes("password") || s.type === "AWS access key") ? "critical" : "medium",
      title: `${exposedSecrets.length} potential secret${exposedSecrets.length > 1 ? "s" : ""} in client JavaScript`,
      description: `Client-side JavaScript contains what appears to be ${exposedSecrets.map((s) => s.type).join(", ")}. Secrets in client bundles are visible to anyone and should be moved to server-side environment variables.`,
      evidence: exposedSecrets.map((s) => `${s.type}: ${s.snippet}...`).join("\n"),
      remediation: "Move secrets to server-side environment variables. Use Next.js server actions or API routes to proxy calls that require secrets. Only NEXT_PUBLIC_ prefixed env vars should be in client code.",
      cwe: "CWE-798",
      owasp: "A07:2021",
      confidence: 70,
      codeSnippet: `// BAD: secret in client code\nconst stripe = new Stripe("sk_live_abc123...");\n\n// GOOD: call via server action\n"use server";\nexport async function createCheckout() {\n  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\n  return stripe.checkout.sessions.create({ ... });\n}`,
    });
  }

  // Phase 8: localStorage / sessionStorage sensitive data patterns
  const storagePatterns = [
    /localStorage\.setItem\s*\(\s*["'](?:token|access_token|auth_token|jwt|password|session|refresh_token|api_key)/i,
    /sessionStorage\.setItem\s*\(\s*["'](?:token|access_token|auth_token|jwt|password|api_key)/i,
  ];
  const storageLeak = storagePatterns.some((re) => re.test(allJs));
  if (storageLeak) {
    findings.push({
      id: "privacy-storage-secrets",
      module: "Privacy",
      severity: "medium",
      title: "Sensitive data stored in localStorage/sessionStorage",
      description: "The app stores authentication tokens or secrets in Web Storage. Unlike HttpOnly cookies, localStorage is accessible to any JavaScript on the page — including XSS payloads and third-party scripts. This is the #1 token storage mistake in vibe-coded apps.",
      evidence: "Pattern: localStorage.setItem('token', ...) or similar detected in client JS",
      remediation: "Store tokens in HttpOnly, Secure, SameSite cookies set by the server. If you must use client-side storage, use sessionStorage (cleared on tab close) and ensure robust XSS protection.",
      cwe: "CWE-922",
      owasp: "A05:2021",
      confidence: 85,
      codeSnippet: `// BAD: token in localStorage — any XSS can steal it\nlocalStorage.setItem("token", jwt);\n\n// GOOD: HttpOnly cookie set by server\n// Server response:\n// Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Lax; Path=/\n\n// Client reads user state from API, not from stored token\nconst { data: user } = useSWR("/api/me");`,
    });
  }

  // Phase 9: Detect Do Not Track / GPC header respect
  if (detectedTrackers.length > 0) {
    const res = await scanFetch(target.url, { headers: { "DNT": "1", "Sec-GPC": "1" } });
    const resNoGpc = await scanFetch(target.url);
    if (res.ok && resNoGpc.ok) {
      const htmlGpc = await res.text();
      const htmlNormal = await resNoGpc.text();
      // If response is identical despite GPC header, trackers aren't respecting it
      const sameTrackers = TRACKER_PATTERNS.filter((t) => t.pattern.test(htmlGpc) && t.pattern.test(htmlNormal));
      if (sameTrackers.length >= 2) {
        findings.push({
          id: "privacy-gpc-ignored",
          module: "Privacy",
          severity: "info",
          title: "Global Privacy Control (GPC) signal not honored",
          description: "The app loads the same tracking scripts regardless of the Sec-GPC: 1 header. Under California law (CCPA/CPRA), websites must honor the GPC signal as a valid opt-out of sale/sharing of personal information.",
          evidence: `Trackers loaded with GPC=1: ${sameTrackers.map((t) => t.name).join(", ")}`,
          remediation: "Check for the Sec-GPC header server-side and suppress non-essential tracking scripts when it's set to '1'. Most consent platforms (OneTrust, CookieBot) support GPC natively.",
          cwe: "CWE-359",
        });
      }
    }
  }

  // Phase 10-14: Parallel async checks
  const parallelResults = await Promise.allSettled([
    // Phase 10: Third-party tracker detection without consent mechanism
    (async (): Promise<Finding[]> => {
      const phase10: Finding[] = [];
      const knownTrackerScripts: { domain: string; name: string }[] = [
        { domain: "google-analytics.com", name: "Google Analytics" },
        { domain: "googletagmanager.com", name: "Google Tag Manager" },
        { domain: "connect.facebook.net", name: "Facebook Pixel" },
        { domain: "static.hotjar.com", name: "Hotjar" },
        { domain: "cdn.segment.com", name: "Segment" },
        { domain: "cdn.mxpnl.com", name: "Mixpanel" },
      ];

      const loadedWithoutConsent: string[] = [];
      const consentGatePatterns = /addEventListener\s*\(\s*['"]consent|onConsentChange|cookieconsent.*callback|__tcfapi|__cmp\s*\(|Cookiebot\.consent/i;
      const hasConsentGating = consentGatePatterns.test(allJs);

      for (const tracker of knownTrackerScripts) {
        const isInScripts = target.scripts.some((s) => s.includes(tracker.domain));
        const isInJs = new RegExp(tracker.domain.replace(".", "\\."), "i").test(allJs);
        if (isInScripts || isInJs) {
          // Check if the script loading is behind a consent gate
          const consentWrapped = new RegExp(`consent[\\s\\S]{0,200}${tracker.domain.replace(".", "\\.")}|${tracker.domain.replace(".", "\\.")}[\\s\\S]{0,200}consent`, "i").test(allJs);
          if (!consentWrapped && !hasConsentGating) {
            loadedWithoutConsent.push(tracker.name);
          }
        }
      }

      if (loadedWithoutConsent.length > 0) {
        phase10.push({
          id: "privacy-trackers-no-consent-gate",
          module: "Privacy",
          severity: "medium",
          title: `${loadedWithoutConsent.length} tracker${loadedWithoutConsent.length > 1 ? "s" : ""} loaded without consent gating: ${loadedWithoutConsent.join(", ")}`,
          description: `The following tracking scripts appear to be loaded unconditionally without waiting for user consent: ${loadedWithoutConsent.join(", ")}. Under GDPR Article 5(3) and the ePrivacy Directive, non-essential tracking scripts must not execute until the user gives explicit consent.`,
          evidence: `Trackers loaded without consent mechanism:\n${loadedWithoutConsent.map((t) => `- ${t}`).join("\n")}\nConsent API detected: ${hasConsentGating ? "yes" : "no"}`,
          remediation: "Wrap all third-party tracking script loads behind a consent check. Use the TCF (Transparency & Consent Framework) API or a CMP like CookieBot/OneTrust to gate script loading. Scripts should be injected dynamically only after opt-in.",
          cwe: "CWE-359",
          confidence: 75,
          codeSnippet: `// Gate tracker loading behind consent\nwindow.addEventListener("CookiebotOnAccept", () => {\n  if (Cookiebot.consent.statistics) {\n    const s = document.createElement("script");\n    s.src = "https://www.googletagmanager.com/gtag/js?id=G-XXXXX";\n    document.head.appendChild(s);\n  }\n});`,
        });
      }
      return phase10;
    })(),

    // Phase 11: Cookie consent compliance — cookies set before consent
    (async (): Promise<Finding[]> => {
      const phase11: Finding[] = [];

      // Check if cookies are already set on the initial page load (before any consent)
      const res = await scanFetch(target.url, { redirect: "follow" });
      if (res.ok) {
        const setCookieHeader = res.headers.get("set-cookie") || "";
        const nonEssentialCookiePatterns = /_ga|_gid|_fbp|_fbc|hjSession|_hj|mp_|ajs_|_mkto|hubspot|__hs|_uet|_tt_/i;
        const trackingCookiesOnLoad = setCookieHeader.split(",").filter((c) => nonEssentialCookiePatterns.test(c));
        const trackingCookiesFromTarget = target.cookies.filter((c) => nonEssentialCookiePatterns.test(c.name));

        const preConsentCookies = [
          ...trackingCookiesOnLoad.map((c) => c.split("=")[0].trim()),
          ...trackingCookiesFromTarget.map((c) => c.name),
        ];

        // Deduplicate
        const uniquePreConsentCookies = Array.from(new Set(preConsentCookies));

        if (uniquePreConsentCookies.length > 0) {
          const hasConsentMechanism = /cookie.?consent|cookie.?banner|consent.?manager|onetrust|cookiebot|osano|klaro|tarteaucitron|complianz|__tcfapi|__cmp/i.test(allJs);
          phase11.push({
            id: "privacy-cookies-before-consent",
            module: "Privacy",
            severity: "high",
            title: `${uniquePreConsentCookies.length} tracking cookie${uniquePreConsentCookies.length > 1 ? "s" : ""} set before user consent`,
            description: `The server sets tracking/analytics cookies (${uniquePreConsentCookies.slice(0, 5).join(", ")}) on the initial page load before the user has had a chance to consent. This is a direct GDPR violation — non-essential cookies must not be set until the user explicitly opts in. ${hasConsentMechanism ? "A consent banner was detected, but cookies are still set before interaction." : "No consent mechanism was detected."}`,
            evidence: `Pre-consent tracking cookies:\n${uniquePreConsentCookies.slice(0, 10).map((c) => `- ${c}`).join("\n")}\nConsent mechanism present: ${hasConsentMechanism ? "yes (but cookies set anyway)" : "no"}`,
            remediation: "Ensure tracking cookies are only set after explicit user consent. Configure your server and analytics scripts to defer cookie creation. Use a Tag Manager with consent mode (e.g., Google Consent Mode v2) to hold cookies until consent is granted.",
            cwe: "CWE-359",
            confidence: 85,
            codeSnippet: `// Google Analytics with Consent Mode v2\ngtag("consent", "default", {\n  analytics_storage: "denied",\n  ad_storage: "denied",\n});\n\n// After user consents:\ngtag("consent", "update", {\n  analytics_storage: "granted",\n});`,
          });
        }
      }
      return phase11;
    })(),

    // Phase 12: Canvas/WebGL fingerprinting library detection
    (async (): Promise<Finding[]> => {
      const phase12: Finding[] = [];
      const fingerprintLibPatterns: { pattern: RegExp; name: string }[] = [
        { pattern: /fingerprintjs|FingerprintJS|Fingerprint2|fpjs/i, name: "FingerprintJS" },
        { pattern: /clientjs|ClientJS/i, name: "ClientJS" },
        { pattern: /imprintjs|ImprintJS/i, name: "ImprintJS" },
        { pattern: /evercookie|Evercookie/i, name: "Evercookie" },
        { pattern: /browserfp|BrowserFP/i, name: "BrowserFP" },
        { pattern: /valve\.fingerprintjs|@fingerprintjs\/fingerprintjs-pro/i, name: "FingerprintJS Pro" },
        { pattern: /CreepJS|creepjsCfp/i, name: "CreepJS" },
      ];

      const detectedLibs: string[] = [];
      for (const lib of fingerprintLibPatterns) {
        if (lib.pattern.test(allJs)) {
          detectedLibs.push(lib.name);
        }
      }

      // Also check script URLs
      for (const script of target.scripts) {
        if (/fingerprintjs|fpjs\.io|fpcdn\.io/i.test(script)) {
          if (!detectedLibs.includes("FingerprintJS") && !detectedLibs.includes("FingerprintJS Pro")) {
            detectedLibs.push("FingerprintJS");
          }
        }
      }

      // Check for raw canvas/WebGL fingerprinting code patterns (not just API usage, but collection patterns)
      const canvasFpPattern = /canvas\.toDataURL\(\)[.\s\S]{0,50}(?:hash|fingerprint|fp|send|post|beacon)/i;
      const webglFpPattern = /WEBGL_debug_renderer_info[.\s\S]{0,100}(?:hash|fingerprint|fp|send|collect)/i;
      if (canvasFpPattern.test(allJs)) detectedLibs.push("Custom canvas fingerprinting");
      if (webglFpPattern.test(allJs)) detectedLibs.push("Custom WebGL fingerprinting");

      if (detectedLibs.length > 0) {
        phase12.push({
          id: "privacy-fingerprint-library",
          module: "Privacy",
          severity: "high",
          title: `Fingerprinting library detected: ${detectedLibs.join(", ")}`,
          description: `The page source includes ${detectedLibs.join(" and ")}, which ${detectedLibs.length > 1 ? "are libraries" : "is a library"} specifically designed to generate persistent browser fingerprints. Unlike cookies, fingerprints cannot be cleared by the user and persist across private browsing sessions. This technique is considered a dark pattern by privacy regulators and is explicitly called out in GDPR recital 30 and the ePrivacy Directive.`,
          evidence: `Fingerprinting libraries:\n${detectedLibs.map((l) => `- ${l}`).join("\n")}`,
          remediation: "Remove fingerprinting libraries unless strictly required for fraud detection. If used for bot/fraud detection, disclose it in your privacy policy, obtain consent, and consider server-side alternatives like CAPTCHA or risk-based authentication.",
          cwe: "CWE-359",
          confidence: 90,
        });
      }
      return phase12;
    })(),

    // Phase 13: Referrer-Policy header check
    (async (): Promise<Finding[]> => {
      const phase13: Finding[] = [];
      const res = await scanFetch(target.url);
      if (res.ok) {
        const referrerPolicy = res.headers.get("referrer-policy") || target.headers["referrer-policy"] || "";
        const safeValues = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
        const unsafeValues = ["unsafe-url", "no-referrer-when-downgrade"];

        if (!referrerPolicy) {
          phase13.push({
            id: "privacy-no-referrer-policy",
            module: "Privacy",
            severity: "medium",
            title: "Missing Referrer-Policy header",
            description: "The server does not set a Referrer-Policy header. Without this header, browsers default to 'strict-origin-when-cross-origin' (modern browsers) or 'no-referrer-when-downgrade' (older browsers). This can leak full URLs — including sensitive path segments and query parameters — to third-party services loaded on the page (analytics, CDNs, ads).",
            evidence: "Referrer-Policy header: not set",
            remediation: "Set the Referrer-Policy header to 'strict-origin-when-cross-origin' (recommended default) or 'no-referrer' for maximum privacy. Add it via your web server config or framework middleware.",
            cwe: "CWE-200",
            confidence: 100,
            codeSnippet: `// Next.js — next.config.js\nmodule.exports = {\n  async headers() {\n    return [{\n      source: "/(.*)",\n      headers: [\n        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },\n      ],\n    }];\n  },\n};`,
          });
        } else if (unsafeValues.includes(referrerPolicy.toLowerCase().trim())) {
          phase13.push({
            id: "privacy-unsafe-referrer-policy",
            module: "Privacy",
            severity: "medium",
            title: `Unsafe Referrer-Policy: ${referrerPolicy}`,
            description: `The Referrer-Policy is set to '${referrerPolicy}' which sends the full URL (including path and query string) to third-party origins. This can leak sensitive information such as session tokens in URLs, internal path structures, search queries, and user-specific page paths.`,
            evidence: `Referrer-Policy: ${referrerPolicy}`,
            remediation: `Change Referrer-Policy from '${referrerPolicy}' to 'strict-origin-when-cross-origin' or 'no-referrer'. Safe values: ${safeValues.join(", ")}.`,
            cwe: "CWE-200",
            confidence: 100,
          });
        }
      }
      return phase13;
    })(),

    // Phase 14: Privacy policy link detection
    (async (): Promise<Finding[]> => {
      const phase14: Finding[] = [];
      const res = await scanFetch(target.url);
      if (res.ok) {
        const html = await res.text();

        // Check for privacy policy links in the HTML
        const privacyLinkPattern = /<a\s[^>]*href\s*=\s*["'][^"']*(?:privacy|datenschutz|privacidad|confidentialite|cookie-policy)[^"']*["'][^>]*>/i;
        const privacyTextPattern = /privacy\s*policy|data\s*protection\s*policy|datenschutz|politique\s*de\s*confidentialit/i;
        const hasPrivacyLink = privacyLinkPattern.test(html);
        const hasPrivacyText = privacyTextPattern.test(html);

        // Also check target pages for privacy-related URLs
        const hasPrivacyPage = target.pages.some((p) => /privacy|datenschutz|data-protection|cookie-policy/i.test(p));
        // Check link URLs
        const hasPrivacyLinkUrl = target.linkUrls.some((u) => /privacy|datenschutz|data-protection|cookie-policy/i.test(u));

        if (!hasPrivacyLink && !hasPrivacyText && !hasPrivacyPage && !hasPrivacyLinkUrl) {
          phase14.push({
            id: "privacy-no-privacy-policy",
            module: "Privacy",
            severity: "medium",
            title: "No privacy policy link detected",
            description: "The page does not appear to have a link to a privacy policy. A privacy policy is legally required under GDPR (Article 13/14), CCPA, CalOPPA, and most data protection laws worldwide when collecting any user data. This is also required by Google Analytics, Facebook, and most third-party service terms of service.",
            evidence: "Privacy policy link: not found in page HTML, navigation, or discovered pages",
            remediation: "Add a visible privacy policy link in your site footer. The privacy policy should cover: what data you collect, why you collect it, who you share it with, how long you retain it, and user rights (access, deletion, opt-out). Consider using a generator like Termly, Iubenda, or consulting a lawyer.",
            cwe: "CWE-693",
            confidence: 70,
          });
        }
      }
      return phase14;
    })(),
  ]);

  // Collect findings from all parallel phases
  for (const result of parallelResults) {
    if (result.status === "fulfilled") {
      findings.push(...result.value);
    }
  }

  return findings;
};
