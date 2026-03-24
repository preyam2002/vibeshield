import type { ScanModuleDefinition, ScanTarget } from "./types";
import {
  createScan,
  updateScanStatus,
  addFindings,
  setModules,
  updateModule,
  setTechInfo,
} from "./store";
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

const SECURITY_MODULES: ScanModuleDefinition[] = [
  { name: "Security Headers", description: "Check HTTP security headers", category: "security", run: headersModule },
  { name: "SSL/TLS", description: "Check HTTPS and TLS configuration", category: "security", run: sslModule },
  { name: "CORS", description: "Test Cross-Origin Resource Sharing policies", category: "security", run: corsModule },
  { name: "Secret Detection", description: "Scan JS bundles for exposed API keys and secrets", category: "security", run: secretsModule },
  { name: "Source Maps", description: "Check for exposed source maps", category: "security", run: sourceMapsModule },
  { name: "Supabase", description: "Test Supabase RLS policies and configuration", category: "security", run: supabaseModule },
  { name: "Firebase", description: "Test Firebase security rules", category: "security", run: firebaseModule },
  { name: "Authentication", description: "Test for unauthenticated access to protected resources", category: "security", run: authModule },
  { name: "IDOR", description: "Test for Insecure Direct Object References", category: "security", run: idorModule },
  { name: "SQL Injection & XSS", description: "Test for injection vulnerabilities", category: "security", run: injectionModule },
  { name: "JWT Security", description: "Analyze JSON Web Token security", category: "security", run: jwtModule },
  { name: "Cookies", description: "Check cookie security flags", category: "security", run: cookiesModule },
  { name: "Directory & File Exposure", description: "Check for exposed files and directories", category: "security", run: directoriesModule },
  { name: "Information Leakage", description: "Test for verbose errors and data exposure", category: "security", run: infoLeakModule },
  { name: "Open Redirect", description: "Test for open redirect vulnerabilities", category: "security", run: openRedirectModule },
  { name: "GraphQL", description: "Test GraphQL introspection and security", category: "security", run: graphqlModule },
  { name: "WebSocket", description: "Check WebSocket security", category: "security", run: websocketModule },
  { name: "HTTP Methods", description: "Test for dangerous HTTP methods", category: "security", run: httpMethodsModule },
  { name: "Clickjacking", description: "Test clickjacking protection", category: "security", run: clickjackingModule },
  { name: "Email Enumeration", description: "Test for user enumeration via auth endpoints", category: "security", run: emailEnumModule },
  { name: "Next.js", description: "Next.js-specific security checks", category: "security", run: nextjsModule },
  { name: "Stripe", description: "Test Stripe payment integration security", category: "security", run: stripeModule },
  { name: "CSRF", description: "Test Cross-Site Request Forgery protection", category: "security", run: csrfModule },
  { name: "Exposed Dev Tools", description: "Check for exposed developer tools (Prisma Studio, Swagger, Storybook)", category: "security", run: exposedToolsModule },
  { name: "API Security", description: "Test for prototype pollution, over-fetching, and mass assignment", category: "security", run: apiSecurityModule },
  { name: "Environment Leak", description: "Deep scan for environment variable and config leaks", category: "security", run: envLeakModule },
  { name: "AI Security", description: "Test AI/LLM endpoint security and prompt injection", category: "security", run: aiSecurityModule },
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

export const startScan = (scanId: string, targetUrl: string) => {
  createScan(scanId, targetUrl);

  const moduleStatuses = [
    { name: "Recon", status: "pending" as const, findingsCount: 0 },
    ...ALL_MODULES.map((m) => ({
      name: m.name,
      status: "pending" as const,
      findingsCount: 0,
    })),
  ];
  setModules(scanId, moduleStatuses);
  updateScanStatus(scanId, "scanning");

  // Detach from the request using setTimeout so the API response returns immediately
  setTimeout(() => {
    runScan(scanId, targetUrl).catch((err) => {
      console.error(`Scan ${scanId} failed:`, err);
      updateScanStatus(scanId, "failed");
    });
  }, 0);
};

const runScan = async (scanId: string, targetUrl: string) => {
  // Phase 1: Recon
  updateModule(scanId, "Recon", { status: "running" });
  let target: ScanTarget;
  try {
    target = await runRecon(targetUrl);
    setTechInfo(scanId, target.technologies, target.isSpa);
    updateModule(scanId, "Recon", { status: "completed" });
  } catch (err) {
    updateModule(scanId, "Recon", { status: "failed", error: String(err) });
    updateScanStatus(scanId, "failed");
    return;
  }

  const runModule = async (mod: ScanModuleDefinition) => {
    updateModule(scanId, mod.name, { status: "running" });
    try {
      const findings = await mod.run(target);
      addFindings(scanId, findings);
      updateModule(scanId, mod.name, {
        status: "completed",
        findingsCount: findings.length,
      });
    } catch (err) {
      console.error(`Module ${mod.name} failed:`, err);
      updateModule(scanId, mod.name, {
        status: "failed",
        error: String(err),
      });
    }
  };

  // Run security modules in batches of 4 for speed, stress modules sequentially
  const BATCH_SIZE = 4;
  for (let i = 0; i < SECURITY_MODULES.length; i += BATCH_SIZE) {
    const batch = SECURITY_MODULES.slice(i, i + BATCH_SIZE);
    await Promise.all(batch.map(runModule));
  }
  for (const mod of STRESS_MODULES) {
    await runModule(mod);
  }

  updateScanStatus(scanId, "completed");
};
