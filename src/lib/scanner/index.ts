import type { ScanModuleDefinition, ScanTarget } from "./types";
import {
  createScan,
  getScan,
  updateScanStatus,
  addFindings,
  setModules,
  updateModule,
  setTechInfo,
  setSurface,
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

// Ordered by signal-to-time ratio: fastest/highest-signal modules first
const SECURITY_MODULES: ScanModuleDefinition[] = [
  // Batch 1: Fast, high-signal checks (headers, config, static analysis)
  { name: "Security Headers", description: "Check HTTP security headers", category: "security", run: headersModule },
  { name: "SSL/TLS", description: "Check HTTPS and TLS configuration", category: "security", run: sslModule },
  { name: "Cookies", description: "Check cookie security flags", category: "security", run: cookiesModule },
  { name: "Clickjacking", description: "Test clickjacking protection", category: "security", run: clickjackingModule },
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
  "Cookies", "Clickjacking", "Directory & File Exposure", "Dependencies",
  "JWT Security", "HTTP Methods", "Environment Leak",
]);
const QUICK_MODULES = SECURITY_MODULES.filter((m) => QUICK_MODULE_NAMES.has(m.name));

export type ScanMode = "full" | "security" | "quick";

export const startScan = (scanId: string, targetUrl: string, callbackUrl?: string, mode: ScanMode = "full") => {
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

  setTimeout(() => {
    runScan(scanId, targetUrl, mode).then(() => {
      if (callbackUrl) sendCallback(callbackUrl, scanId).catch(() => {});
    }).catch((err) => {
      console.error(`Scan ${scanId} failed:`, err);
      updateScanStatus(scanId, "failed");
      if (callbackUrl) sendCallback(callbackUrl, scanId).catch(() => {});
    });
  }, 0);
};

const runScan = async (scanId: string, targetUrl: string, mode: ScanMode = "full") => {
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
    updateModule(scanId, "Recon", { status: "failed", error: String(err), durationMs: Date.now() - reconStart });
    updateScanStatus(scanId, "failed");
    return;
  }

  const MODULE_TIMEOUT = 120_000; // 2 minutes per module max

  const runModule = async (mod: ScanModuleDefinition) => {
    updateModule(scanId, mod.name, { status: "running" });
    const start = Date.now();
    try {
      const MAX_PER_MODULE = 8;
      const findings = await Promise.race([
        mod.run(target),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Module timed out after ${MODULE_TIMEOUT / 1000}s`)), MODULE_TIMEOUT),
        ),
      ]);
      addFindings(scanId, findings.slice(0, MAX_PER_MODULE));
      updateModule(scanId, mod.name, {
        status: "completed",
        findingsCount: findings.length,
        durationMs: Date.now() - start,
      });
    } catch (err) {
      console.error(`Module ${mod.name} failed:`, err);
      updateModule(scanId, mod.name, {
        status: "failed",
        error: String(err),
        durationMs: Date.now() - start,
      });
    }
  };

  // Quick mode: run all modules in one batch (they're fast)
  // Security/full: batch security modules, then stress sequentially
  if (mode === "quick") {
    await Promise.all(QUICK_MODULES.map(runModule));
  } else {
    const BATCH_SIZE = 15;
    for (let i = 0; i < SECURITY_MODULES.length; i += BATCH_SIZE) {
      const batch = SECURITY_MODULES.slice(i, i + BATCH_SIZE);
      await Promise.all(batch.map(runModule));
    }
    if (mode === "full") {
      // Run stress modules in small batches (not fully parallel to avoid overwhelming target)
      for (let i = 0; i < STRESS_MODULES.length; i += 3) {
        const batch = STRESS_MODULES.slice(i, i + 3);
        await Promise.all(batch.map(runModule));
      }
    }
  }

  updateScanStatus(scanId, "completed");
};

const sendCallback = async (callbackUrl: string, scanId: string) => {
  const scan = getScan(scanId);
  if (!scan) return;
  try {
    await fetch(callbackUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event: "scan.completed",
        scanId: scan.id,
        target: scan.target,
        status: scan.status,
        grade: scan.grade,
        score: scan.score,
        summary: scan.summary,
        resultUrl: `/scan/${scan.id}`,
      }),
    });
  } catch (err) {
    console.error(`Callback to ${callbackUrl} failed:`, err);
  }
};
