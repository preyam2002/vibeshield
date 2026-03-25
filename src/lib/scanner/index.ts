import type { ScanModuleDefinition, ScanTarget, Finding } from "./types";
import {
  createScan,
  getScan,
  updateScanStatus,
  addFindings,
  setModules,
  updateModule,
  setTechInfo,
  setSurface,
  registerAbort,
  cleanupAbort,
} from "./store";
import { clearScanCache } from "./fetch";
import { runRecon } from "./modules/recon";
import { headersModule } from "./modules/headers";
import { sslModule } from "./modules/ssl";
import { corsModule } from "./modules/cors";
import { secretsModule } from "./modules/secrets";
import { sourceMapsModule } from "./modules/source-maps";
import { supabaseModule } from "./modules/supabase";
import { firebaseModule } from "./modules/firebase";
import { authModule } from "./modules/auth";
import { idorModule } from "./modules/idor";
import { injectionModule } from "./modules/injection";
import { jwtModule } from "./modules/jwt-check";
import { cookiesModule } from "./modules/cookies";
import { directoriesModule } from "./modules/directories";
import { infoLeakModule } from "./modules/info-leak";
import { openRedirectModule } from "./modules/open-redirect";
import { graphqlModule } from "./modules/graphql";
import { websocketModule } from "./modules/websocket";
import { httpMethodsModule } from "./modules/http-methods";
import { clickjackingModule } from "./modules/clickjacking";
import { emailEnumModule } from "./modules/email-enum";
import { nextjsModule } from "./modules/nextjs";
import { stripeModule } from "./modules/stripe";
import { csrfModule } from "./modules/csrf";
import { loadModule } from "./modules/stress/load";
import { raceConditionModule } from "./modules/stress/race";
import { rateLimitModule } from "./modules/stress/rate-limit";
import { costAttackModule } from "./modules/stress/cost";
import { errorLeakModule } from "./modules/stress/error-leak";
import { connectionExhaustionModule } from "./modules/stress/connection";
import { exposedToolsModule } from "./modules/exposed-tools";
import { apiSecurityModule } from "./modules/api-security";
import { envLeakModule } from "./modules/env-leak";
import { aiSecurityModule } from "./modules/ai-security";
import { ssrfModule } from "./modules/ssrf";
import { fileUploadModule } from "./modules/file-upload";
import { crlfModule } from "./modules/crlf";
import { hostHeaderModule } from "./modules/host-header";
import { subdomainModule } from "./modules/subdomain";
import { dependenciesModule } from "./modules/dependencies";
import { pathTraversalModule } from "./modules/path-traversal";
import { commandInjectionModule } from "./modules/command-injection";
import { nosqlInjectionModule } from "./modules/nosql-injection";
import { cachePoisoningModule } from "./modules/cache-poisoning";
import { businessLogicModule } from "./modules/business-logic";
import { oauthModule } from "./modules/oauth";
import { apiVersioningModule } from "./modules/api-versioning";
import { cspModule } from "./modules/csp";
import { storageModule } from "./modules/storage";
import { sessionModule } from "./modules/session";
import {
  MODULE_TIMEOUT_MS,
  MAX_FINDINGS_PER_MODULE,
  SECURITY_BATCH_SIZE,
  CIRCUIT_BREAKER_THRESHOLD,
} from "./config";

// Ordered by signal-to-time ratio: fastest/highest-signal modules first
const SECURITY_MODULES: ScanModuleDefinition[] = [
  // Batch 1: Fast, high-signal checks (headers, config, static analysis)
  { name: "Security Headers", description: "Check HTTP security headers", category: "security", run: headersModule },
  { name: "SSL/TLS", description: "Check HTTPS and TLS configuration", category: "security", run: sslModule },
  { name: "Cookies", description: "Check cookie security flags", category: "security", run: cookiesModule },
  { name: "Clickjacking", description: "Test clickjacking protection", category: "security", run: clickjackingModule },
  { name: "CSP Analysis", description: "Deep Content Security Policy analysis for bypasses", category: "security", run: cspModule },
  { name: "Secret Detection", description: "Scan JS bundles for exposed API keys and secrets", category: "security", run: secretsModule },
  { name: "Source Maps", description: "Check for exposed source maps", category: "security", run: sourceMapsModule },
  { name: "Dependencies", description: "Detect vulnerable client-side library versions", category: "security", run: dependenciesModule },
  { name: "JWT Security", description: "Analyze JSON Web Token security", category: "security", run: jwtModule },
  { name: "HTTP Methods", description: "Test for dangerous HTTP methods", category: "security", run: httpMethodsModule },
  { name: "CORS", description: "Test Cross-Origin Resource Sharing policies", category: "security", run: corsModule },
  { name: "Information Leakage", description: "Test for verbose errors and data exposure", category: "security", run: infoLeakModule },
  { name: "Environment Leak", description: "Deep scan for environment variable and config leaks", category: "security", run: envLeakModule },
  { name: "Directory & File Exposure", description: "Check for exposed files and directories", category: "security", run: directoriesModule },
  { name: "Exposed Dev Tools", description: "Check for exposed developer tools (Prisma Studio, Swagger, Storybook)", category: "security", run: exposedToolsModule },
  // Batch 2: Medium-speed, per-endpoint testing
  { name: "Authentication", description: "Test for unauthenticated access to protected resources", category: "security", run: authModule },
  { name: "IDOR", description: "Test for Insecure Direct Object References", category: "security", run: idorModule },
  { name: "SQL Injection & XSS", description: "Test for injection vulnerabilities", category: "security", run: injectionModule },
  { name: "CSRF", description: "Test Cross-Site Request Forgery protection", category: "security", run: csrfModule },
  { name: "Open Redirect", description: "Test for open redirect vulnerabilities", category: "security", run: openRedirectModule },
  { name: "Supabase", description: "Test Supabase RLS policies and configuration", category: "security", run: supabaseModule },
  { name: "Firebase", description: "Test Firebase security rules", category: "security", run: firebaseModule },
  { name: "Next.js", description: "Next.js-specific security checks", category: "security", run: nextjsModule },
  { name: "GraphQL", description: "Test GraphQL introspection and security", category: "security", run: graphqlModule },
  { name: "Email Enumeration", description: "Test for user enumeration via auth endpoints", category: "security", run: emailEnumModule },
  { name: "Session Management", description: "Test session handling, fixation, invalidation, and storage", category: "security", run: sessionModule },
  { name: "Stripe", description: "Test Stripe payment integration security", category: "security", run: stripeModule },
  { name: "WebSocket", description: "Check WebSocket security", category: "security", run: websocketModule },
  { name: "OAuth/OIDC", description: "Test OAuth flows, redirect_uri validation, and state parameter checks", category: "security", run: oauthModule },
  { name: "API Security", description: "Test for prototype pollution, over-fetching, and mass assignment", category: "security", run: apiSecurityModule },
  // Batch 3: Slower, deeper probing modules
  { name: "SSRF", description: "Test for Server-Side Request Forgery vulnerabilities", category: "security", run: ssrfModule },
  { name: "File Upload", description: "Test file upload security and type validation", category: "security", run: fileUploadModule },
  { name: "CRLF Injection", description: "Test for HTTP header injection via CRLF characters", category: "security", run: crlfModule },
  { name: "Host Header", description: "Test for Host header injection and password reset poisoning", category: "security", run: hostHeaderModule },
  { name: "Path Traversal", description: "Test for directory traversal and file inclusion", category: "security", run: pathTraversalModule },
  { name: "Command Injection", description: "Test for OS command injection vulnerabilities", category: "security", run: commandInjectionModule },
  { name: "NoSQL Injection", description: "Test for MongoDB/NoSQL operator injection and auth bypass", category: "security", run: nosqlInjectionModule },
  { name: "AI Security", description: "Test AI/LLM endpoint security and prompt injection", category: "security", run: aiSecurityModule },
  { name: "Cache Poisoning", description: "Test for CDN/proxy cache poisoning via header injection", category: "security", run: cachePoisoningModule },
  { name: "Business Logic", description: "Test for negative values, zero-price bypass, and idempotency issues", category: "security", run: businessLogicModule },
  { name: "API Versioning", description: "Detect hidden API versions, path normalization bypass, and endpoint shadowing", category: "security", run: apiVersioningModule },
  { name: "Cloud Storage", description: "Check for misconfigured S3/GCS/Azure storage buckets", category: "security", run: storageModule },
  { name: "Subdomain Takeover", description: "Discover subdomains via CT logs and check for takeover", category: "security", run: subdomainModule },
];

const STRESS_MODULES: ScanModuleDefinition[] = [
  { name: "Load Testing", description: "Test app performance under concurrent load", category: "stress", run: loadModule },
  { name: "Race Conditions", description: "Test for race condition vulnerabilities", category: "stress", run: raceConditionModule },
  { name: "Rate Limiting", description: "Check rate limiting on critical endpoints", category: "stress", run: rateLimitModule },
  { name: "Cost Attack", description: "Estimate cost of API abuse attacks", category: "stress", run: costAttackModule },
  { name: "Error Leakage Under Stress", description: "Check for data leaks when server is stressed", category: "stress", run: errorLeakModule },
  { name: "Connection Exhaustion", description: "Test connection handling under sustained load", category: "stress", run: connectionExhaustionModule },
];

const ALL_MODULES = [...SECURITY_MODULES, ...STRESS_MODULES];

// Quick mode: only the fastest, highest-signal modules (~10s total)
const QUICK_MODULE_NAMES = new Set([
  "Security Headers", "SSL/TLS", "CORS", "Secret Detection", "Source Maps",
  "Cookies", "Clickjacking", "CSP Analysis", "Directory & File Exposure", "Dependencies",
  "JWT Security", "HTTP Methods", "Environment Leak",
]);
const QUICK_MODULES = SECURITY_MODULES.filter((m) => QUICK_MODULE_NAMES.has(m.name));

export type ScanMode = "full" | "security" | "quick";

export const startScan = (scanId: string, targetUrl: string, callbackUrl?: string, mode: ScanMode = "full", gateConfig?: { minScore?: number; failOnCritical?: boolean }) => {
  createScan(scanId, targetUrl, mode);

  const activeModules = mode === "quick" ? QUICK_MODULES : mode === "security" ? SECURITY_MODULES : ALL_MODULES;
  const moduleStatuses = [
    { name: "Recon", status: "pending" as const, findingsCount: 0 },
    ...activeModules.map((m) => ({
      name: m.name,
      status: "pending" as const,
      findingsCount: 0,
    })),
  ];
  setModules(scanId, moduleStatuses);
  updateScanStatus(scanId, "scanning");

  const abortController = new AbortController();
  registerAbort(scanId, abortController);

  setTimeout(() => {
    runScan(scanId, targetUrl, mode, abortController.signal).then(() => {
      cleanupAbort(scanId);
      if (callbackUrl) sendCallback(callbackUrl, scanId, gateConfig).catch(() => {});
    }).catch((err) => {
      cleanupAbort(scanId);
      if (!abortController.signal.aborted) {
        console.error(`Scan ${scanId} failed:`, err);
        updateScanStatus(scanId, "failed", humanizeError(err, targetUrl));
      }
      if (callbackUrl) sendCallback(callbackUrl, scanId, gateConfig).catch(() => {});
    });
  }, 0);
};

const runScan = async (scanId: string, targetUrl: string, mode: ScanMode = "full", abortSignal?: AbortSignal) => {
  clearScanCache();
  // Phase 1: Recon
  updateModule(scanId, "Recon", { status: "running" });
  const reconStart = Date.now();
  let target: ScanTarget;
  try {
    target = await runRecon(targetUrl);
    setTechInfo(scanId, target.technologies, target.isSpa);
    setSurface(scanId, {
      pages: target.pages.length,
      apiEndpoints: target.apiEndpoints.length,
      jsFiles: target.jsContents.size,
      forms: target.forms.length,
      cookies: target.cookies.length,
    });
    updateModule(scanId, "Recon", { status: "completed", durationMs: Date.now() - reconStart });
  } catch (err) {
    const errorMsg = humanizeError(err, targetUrl);
    updateModule(scanId, "Recon", { status: "failed", error: errorMsg, durationMs: Date.now() - reconStart });
    updateScanStatus(scanId, "failed", errorMsg);
    return;
  }

  // Circuit breaker: if too many modules fail with the same error class, abort early
  let consecutiveFailures = 0;

  const runModule = async (mod: ScanModuleDefinition) => {
    if (abortSignal?.aborted || consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD) {
      updateModule(scanId, mod.name, { status: "skipped" });
      return;
    }
    updateModule(scanId, mod.name, { status: "running" });
    const start = Date.now();
    try {
      const findings = await Promise.race([
        mod.run(target),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Module timed out after ${MODULE_TIMEOUT_MS / 1000}s`)), MODULE_TIMEOUT_MS),
        ),
        ...(abortSignal ? [new Promise<never>((_, reject) => {
          abortSignal.addEventListener("abort", () => reject(new Error("Scan cancelled")), { once: true });
        })] : []),
      ]);
      // Apply default confidence scores based on module type if not set by module
      const enriched = findings.map((f) => ({
        ...f,
        confidence: f.confidence ?? getDefaultConfidence(mod.name, f),
      }));
      addFindings(scanId, enriched.slice(0, MAX_FINDINGS_PER_MODULE));
      updateModule(scanId, mod.name, {
        status: "completed",
        findingsCount: findings.length,
        durationMs: Date.now() - start,
      });
      consecutiveFailures = 0; // Reset on success
    } catch (err) {
      const cancelled = abortSignal?.aborted;
      updateModule(scanId, mod.name, {
        status: cancelled ? "skipped" : "failed",
        error: cancelled ? undefined : String(err),
        durationMs: Date.now() - start,
      });
      if (!cancelled) {
        consecutiveFailures++;
        console.error(`Module ${mod.name} failed:`, err);
      }
    }
  };

  // Quick mode: run all modules in one batch (they're fast)
  // Security/full: batch security modules, then stress sequentially
  if (abortSignal?.aborted) { return; }

  if (mode === "quick") {
    await Promise.all(QUICK_MODULES.map(runModule));
  } else {
    for (let i = 0; i < SECURITY_MODULES.length; i += SECURITY_BATCH_SIZE) {
      if (abortSignal?.aborted) break;
      const batch = SECURITY_MODULES.slice(i, i + SECURITY_BATCH_SIZE);
      await Promise.all(batch.map(runModule));
    }
    if (mode === "full" && !abortSignal?.aborted) {
      await Promise.all(STRESS_MODULES.map(runModule));
    }
  }

  // If circuit breaker tripped, mark remaining modules as skipped and note the early termination
  if (consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD) {
    const scan = getScan(scanId);
    if (scan) {
      for (const mod of scan.modules) {
        if (mod.status === "pending") mod.status = "skipped";
      }
    }
    console.warn(`Scan ${scanId}: circuit breaker tripped after ${CIRCUIT_BREAKER_THRESHOLD} consecutive module failures`);
  }

  if (!abortSignal?.aborted) {
    updateScanStatus(scanId, "completed");
  }
};

/** Default confidence scores by module and finding characteristics */
const HIGH_CONFIDENCE_MODULES = new Set([
  "Security Headers", "SSL/TLS", "Cookies", "Clickjacking", "CSP Analysis",
  "Secret Detection", "Source Maps", "Dependencies", "JWT Security",
  "Environment Leak", "Directory & File Exposure",
]);
const MEDIUM_CONFIDENCE_MODULES = new Set([
  "CORS", "HTTP Methods", "Information Leakage", "Supabase", "Firebase",
  "Stripe", "GraphQL", "WebSocket", "CSRF", "Authentication", "Open Redirect",
  "Email Enumeration", "IDOR",
]);
// Everything else (injection, SSRF, business logic, etc.) gets lower default

const getDefaultConfidence = (moduleName: string, finding: Finding): number => {
  // Modules that check deterministic things (headers, config, static analysis) = high confidence
  if (HIGH_CONFIDENCE_MODULES.has(moduleName)) return 95;
  // Modules that test network behavior with clear signals = medium-high
  if (MEDIUM_CONFIDENCE_MODULES.has(moduleName)) return 80;
  // Heuristic/behavior-based modules (injection, SSRF, business logic) = moderate
  // Higher severity findings from these modules get slightly lower confidence
  // (more likely false positive if severity is critical from heuristic)
  if (finding.severity === "critical") return 65;
  if (finding.severity === "high") return 70;
  return 75;
};

const humanizeError = (err: unknown, targetUrl: string): string => {
  const msg = String(err);
  const causeMsg = err instanceof Error && err.cause ? String(err.cause) : "";
  let hostname = "the target";
  try { hostname = new URL(targetUrl).hostname; } catch {}

  const combined = msg + " " + causeMsg;
  if (combined.includes("ENOTFOUND") || combined.includes("getaddrinfo")) {
    return `DNS lookup failed for ${hostname}. The domain may not exist or DNS is misconfigured.`;
  }
  if (combined.includes("ECONNREFUSED")) {
    return `Connection refused by ${hostname}. The server may be down or not accepting connections on this port.`;
  }
  if (combined.includes("ETIMEDOUT") || combined.includes("CONNECT_TIMEOUT") || combined.includes("UND_ERR_CONNECT_TIMEOUT")) {
    return `Connection to ${hostname} timed out. The server may be unreachable or behind a firewall.`;
  }
  if (combined.includes("ECONNRESET")) {
    return `Connection reset by ${hostname}. The server closed the connection unexpectedly.`;
  }
  if (combined.includes("CERT_") || combined.includes("certificate") || combined.includes("SSL")) {
    return `SSL/TLS error connecting to ${hostname}. The certificate may be invalid or expired.`;
  }
  if (combined.includes("AbortError") || combined.includes("abort")) {
    return `Request to ${hostname} was aborted (timeout). The server took too long to respond.`;
  }
  if (combined.includes("403") || combined.includes("Forbidden")) {
    return `${hostname} returned 403 Forbidden. The server is blocking our requests (WAF/bot protection).`;
  }
  if (combined.includes("fetch failed") && !causeMsg) {
    return `Could not connect to ${hostname}. The server may be down or the URL may be incorrect.`;
  }
  if (combined.includes("fetch failed") && causeMsg) {
    return `Could not connect to ${hostname}: ${causeMsg.length > 150 ? causeMsg.substring(0, 150) + "..." : causeMsg}`;
  }
  return `Failed to scan ${hostname}: ${msg.length > 200 ? msg.substring(0, 200) + "..." : msg}`;
};

const sendCallback = async (callbackUrl: string, scanId: string, gateConfig?: { minScore?: number; failOnCritical?: boolean }) => {
  const scan = getScan(scanId);
  if (!scan) return;

  // CI/CD gating: determine pass/fail based on gate config
  let gate: { passed: boolean; reason?: string } | undefined;
  if (gateConfig && scan.status === "completed") {
    const reasons: string[] = [];
    if (gateConfig.minScore !== undefined && scan.score < gateConfig.minScore) {
      reasons.push(`Score ${scan.score} < threshold ${gateConfig.minScore}`);
    }
    if (gateConfig.failOnCritical && scan.summary.critical > 0) {
      reasons.push(`${scan.summary.critical} critical finding${scan.summary.critical > 1 ? "s" : ""} found`);
    }
    gate = { passed: reasons.length === 0, ...(reasons.length > 0 ? { reason: reasons.join("; ") } : {}) };
  }

  // Module health summary
  const failedModules = scan.modules.filter((m) => m.status === "failed").length;
  const skippedModules = scan.modules.filter((m) => m.status === "skipped").length;

  const payload = JSON.stringify({
    event: scan.status === "failed" ? "scan.failed" : "scan.completed",
    scanId: scan.id,
    target: scan.target,
    status: scan.status,
    grade: scan.grade,
    score: scan.score,
    summary: scan.summary,
    resultUrl: `/scan/${scan.id}`,
    ...(scan.error ? { error: scan.error } : {}),
    ...(gate ? { gate } : {}),
    ...(failedModules > 0 || skippedModules > 0 ? { moduleHealth: { failed: failedModules, skipped: skippedModules, total: scan.modules.length } } : {}),
  });

  // Generate HMAC signature for webhook verification
  const timestamp = Math.floor(Date.now() / 1000).toString();
  let signature = "";
  try {
    const encoder = new TextEncoder();
    const signingKey = process.env.VIBESHIELD_WEBHOOK_SECRET || "";
    if (signingKey) {
      const key = await crypto.subtle.importKey("raw", encoder.encode(signingKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(`${timestamp}.${payload}`));
      signature = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
  } catch { /* skip if crypto unavailable */ }

  // Retry with exponential backoff (3 attempts)
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(callbackUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(signature ? { "X-VibeShield-Signature": `sha256=${signature}`, "X-VibeShield-Timestamp": timestamp } : {}),
        },
        body: payload,
      });
      if (res.ok || res.status < 500) return; // Success or client error (don't retry 4xx)
    } catch (err) {
      if (attempt === 2) {
        console.error(`Callback to ${callbackUrl} failed after 3 attempts:`, err);
        return;
      }
    }
    await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt))); // 1s, 2s, 4s
  }
};
