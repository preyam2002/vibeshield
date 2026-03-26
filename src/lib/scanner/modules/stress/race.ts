import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

export const raceConditionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Only test endpoints that look like one-time actions — generic POSTs cause too many false positives
  const stateEndpoints = target.apiEndpoints.filter((ep) =>
    /coupon|redeem|claim|transfer|withdraw|vote|checkout|purchase|apply|bonus|reward|credit|discount|activate|upgrade|downgrade/i.test(ep),
  );

  if (stateEndpoints.length === 0 && target.apiEndpoints.length === 0) return findings;
  const testEndpoints = stateEndpoints.slice(0, 6);

  for (const endpoint of testEndpoints) {
    // Send N identical requests simultaneously
    const N = 20;
    const results = await Promise.allSettled(
      Array.from({ length: N }, () =>
        scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        }).then(async (res) => ({
          status: res.status,
          body: await res.text().catch(() => ""),
        })),
      ),
    );

    const successes = results.filter(
      (r) => r.status === "fulfilled" && (r.value.status === 200 || r.value.status === 201),
    );

    // If a "claim"-type endpoint succeeds multiple times, that's a race condition
    const isSensitive = /coupon|redeem|claim|transfer|withdraw|checkout|purchase|bonus|reward|credit|discount|activate|upgrade/i.test(endpoint);
    if (isSensitive && successes.length > 1) {
      findings.push({
        id: `race-${findings.length}`,
        module: "Race Conditions",
        severity: "high",
        title: `Potential race condition on ${new URL(endpoint).pathname}`,
        description: `Sent ${N} simultaneous POST requests to a state-changing endpoint. ${successes.length} succeeded. If this endpoint handles one-time actions (coupons, transfers, claims), the action may execute multiple times.`,
        evidence: `Endpoint: ${endpoint}\nSimultaneous requests: ${N}\nSuccessful: ${successes.length}`,
        remediation: "Implement idempotency keys or database-level locks (SELECT ... FOR UPDATE) for state-changing operations. Use unique constraints to prevent double-execution.",
        codeSnippet: `// Use a DB transaction with row-level locking
const result = await prisma.$transaction(async (tx) => {
  const coupon = await tx.coupon.findUnique({
    where: { code: "SAVE20" },
    select: { id: true, usedAt: true },
  });
  if (coupon?.usedAt) throw new Error("Coupon already redeemed");

  return tx.coupon.update({
    where: { id: coupon.id, usedAt: null }, // optimistic lock
    data: { usedAt: new Date(), usedBy: userId },
  });
});

// Or use an idempotency key
const idempotencyKey = req.headers["idempotency-key"];
const existing = await redis.get(\`idempotency:\${idempotencyKey}\`);
if (existing) return JSON.parse(existing);`,
        cwe: "CWE-362",
        owasp: "A04:2021",
      });
    }

    // Test for double-spend: send two requests with same idempotency key
    const idempotencyKey = `vibeshield-race-${Date.now()}`;
    const idempResults = await Promise.allSettled(
      Array.from({ length: 2 }, () =>
        scanFetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotencyKey,
            "X-Idempotency-Key": idempotencyKey,
          },
          body: JSON.stringify({}),
        }).then(async (res) => ({ status: res.status, body: await res.text().catch(() => "") })),
      ),
    );
    const idempSuccesses = idempResults.filter(
      (r) => r.status === "fulfilled" && (r.value.status === 200 || r.value.status === 201),
    );
    if (isSensitive && idempSuccesses.length === 2) {
      const bodies = idempSuccesses.map((r) => (r as PromiseFulfilledResult<{ status: number; body: string }>).value.body);
      if (bodies[0] !== bodies[1] || bodies[0].length > 5) {
        findings.push({
          id: `race-no-idempotency-${findings.length}`,
          module: "Race Conditions",
          severity: "high",
          title: `Missing idempotency enforcement on ${new URL(endpoint).pathname}`,
          description: `Two POST requests with the same Idempotency-Key both returned success. The endpoint does not enforce idempotency, enabling double-spend or duplicate action attacks.`,
          evidence: `Endpoint: ${endpoint}\nIdempotency-Key: ${idempotencyKey}\nBoth requests returned 2xx`,
          remediation: "Implement idempotency key checking. Store the key and its response, return the cached response for duplicate keys.",
          cwe: "CWE-362",
          owasp: "A04:2021",
          codeSnippet: `// Idempotency key middleware\nconst key = req.headers["idempotency-key"];\nif (key) {\n  const cached = await redis.get(\`idempotency:\${key}\`);\n  if (cached) return Response.json(JSON.parse(cached));\n}\nconst result = await processRequest(req);\nif (key) await redis.set(\`idempotency:\${key}\`, JSON.stringify(result), "EX", 86400);\nreturn Response.json(result);`,
        });
      }
    }

    // Test for response inconsistency (sign of race condition in reads)
    const bodies = results
      .filter((r) => r.status === "fulfilled" && r.value.status === 200)
      .map((r) => (r as PromiseFulfilledResult<{ status: number; body: string }>).value.body);

    const uniqueBodies = new Set(bodies);
    if (uniqueBodies.size > 1 && bodies.length >= 3) {
      findings.push({
        id: `race-inconsistent-${findings.length}`,
        module: "Race Conditions",
        severity: "medium",
        title: `Inconsistent responses under concurrency on ${new URL(endpoint).pathname}`,
        description: `${uniqueBodies.size} different response bodies from ${bodies.length} concurrent identical requests. This may indicate race conditions in data reads.`,
        evidence: `Concurrent requests: ${N}\nUnique responses: ${uniqueBodies.size}`,
        remediation: "Review transaction isolation levels. Ensure reads within a request are consistent.",
        codeSnippet: `// Use serializable isolation for consistent reads
const data = await prisma.$transaction(
  async (tx) => {
    const balance = await tx.account.findUnique({ where: { id: userId } });
    const orders = await tx.order.findMany({ where: { userId } });
    return { balance, orders };
  },
  { isolationLevel: "Serializable" }
);`,
        cwe: "CWE-362",
      });
    }
  }

  // --- Phase 2: Double-spend / double-submit detection for payment/credit endpoints ---
  const paymentEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(pay|payment|charge|bill|subscribe|tip|donate|fund|topup|top-up|debit|send-money)\b/i.test(ep),
  ).slice(0, 3);

  for (const endpoint of paymentEndpoints) {
    const paymentBody = JSON.stringify({
      amount: 1,
      currency: "usd",
      idempotencyKey: `vibeshield-dblspend-${Date.now()}`,
    });

    const N = 10;
    const results = await Promise.allSettled(
      Array.from({ length: N }, () =>
        scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: paymentBody,
        }).then(async (res) => ({
          status: res.status,
          body: await res.text().catch(() => ""),
        })),
      ),
    );

    const successes = results.filter(
      (r) => r.status === "fulfilled" && (r.value.status === 200 || r.value.status === 201),
    );

    if (successes.length > 1) {
      findings.push({
        id: `race-double-spend-${findings.length}`,
        module: "Race Conditions",
        severity: "critical",
        title: `Double-spend vulnerability on ${new URL(endpoint).pathname}`,
        description: `${successes.length}/${N} concurrent payment requests succeeded with identical payloads. An attacker can submit the same payment multiple times simultaneously, potentially charging or crediting an account multiple times.`,
        evidence: `Endpoint: ${endpoint}\nConcurrent requests: ${N}\nSuccessful: ${successes.length}\nPayload: identical for all requests`,
        remediation:
          "Use database-level unique constraints on transaction IDs. Implement optimistic locking with version fields. Process payments within serializable transactions. Require client-generated idempotency keys and enforce them server-side.",
        codeSnippet: `// Prevent double-spend with atomic balance + idempotency
const result = await prisma.$transaction(async (tx) => {
  // Check idempotency first
  const existing = await tx.transaction.findUnique({
    where: { idempotencyKey },
  });
  if (existing) return existing; // already processed

  // Atomic deduction — prevents negative balance race
  const updated = await tx.account.updateMany({
    where: { id: userId, balance: { gte: amount } },
    data: { balance: { decrement: amount } },
  });
  if (updated.count === 0) throw new Error("Insufficient balance");

  return tx.transaction.create({
    data: { idempotencyKey, userId, amount, status: "completed" },
  });
}, { isolationLevel: "Serializable" });`,
        cwe: "CWE-362",
        owasp: "A04:2021",
        confidence: 80,
      });
    }
  }

  // --- Phase 3: Signup/registration race condition — duplicate account creation ---
  const signupEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(register|signup|sign-up|create-account|join)\b/i.test(ep),
  ).slice(0, 2);

  for (const endpoint of signupEndpoints) {
    const testEmail = `vibeshield-race-${Date.now()}@test.invalid`;
    const N = 10;
    const results = await Promise.allSettled(
      Array.from({ length: N }, () =>
        scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: testEmail, password: "TestP@ss123!" }),
        }).then(async (res) => ({
          status: res.status,
          body: await res.text().catch(() => ""),
        })),
      ),
    );

    const created = results.filter(
      (r) => r.status === "fulfilled" && (r.value.status === 200 || r.value.status === 201),
    );
    if (created.length > 1) {
      findings.push({
        id: `race-signup-${findings.length}`,
        module: "Race Conditions",
        severity: "high",
        title: `Duplicate account creation via race condition on ${new URL(endpoint).pathname}`,
        description: `${created.length}/${N} concurrent signup requests succeeded with the same email. This can create duplicate accounts, bypass uniqueness constraints, or grant multiple signup bonuses.`,
        evidence: `Endpoint: ${endpoint}\nConcurrent signups: ${N}\nCreated: ${created.length}`,
        remediation: "Use a unique database constraint on email/username and handle the constraint violation error. Add rate limiting to signup endpoints.",
        cwe: "CWE-362",
        owasp: "A04:2021",
        codeSnippet: `// Use unique constraint + retry logic\ntry {\n  await db.user.create({ data: { email, password: hashedPassword } });\n} catch (e) {\n  if (e.code === "P2002") { // Prisma unique constraint\n    return Response.json({ error: "Email already registered" }, { status: 409 });\n  }\n  throw e;\n}`,
      });
    }
  }

  // --- Phase 4: Session creation race conditions ---
  const sessionEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(login|signin|sign-in|auth|session|token|oauth|callback)\b/i.test(ep),
  ).slice(0, 2);

  for (const endpoint of sessionEndpoints) {
    const N = 15;
    const results = await Promise.allSettled(
      Array.from({ length: N }, () =>
        scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: "vibeshield-session-test@test.invalid",
            password: "TestP@ss123!",
          }),
        }).then(async (res) => {
          const body = await res.text().catch(() => "");
          const setCookies = res.headers.get("set-cookie") || "";
          return { status: res.status, body, setCookies };
        }),
      ),
    );

    const successes = results.filter(
      (r) => r.status === "fulfilled" && (r.value.status === 200 || r.value.status === 201),
    );

    if (successes.length > 1) {
      // Extract session tokens from set-cookie or body
      const sessionTokens = successes
        .map((r) => {
          const val = (r as PromiseFulfilledResult<{ status: number; body: string; setCookies: string }>).value;
          const cookieMatch = val.setCookies.match(/(?:session|token|sid|jwt)[^=]*=([^;]+)/i);
          if (cookieMatch) return cookieMatch[1];
          try {
            const parsed = JSON.parse(val.body);
            return parsed.token || parsed.accessToken || parsed.access_token || parsed.sessionId || "";
          } catch {
            return "";
          }
        })
        .filter(Boolean);

      const uniqueTokens = new Set(sessionTokens);

      // Multiple different sessions for the same login = session proliferation
      if (uniqueTokens.size > 1 && uniqueTokens.size >= successes.length * 0.5) {
        findings.push({
          id: `race-session-proliferation-${findings.length}`,
          module: "Race Conditions",
          severity: "medium",
          title: `Session proliferation via concurrent login on ${new URL(endpoint).pathname}`,
          description: `${uniqueTokens.size} different session tokens were created from ${successes.length} concurrent login requests. This allows an attacker to create many valid sessions simultaneously, making session revocation difficult and potentially bypassing "single active session" policies.`,
          evidence: `Endpoint: ${endpoint}\nConcurrent logins: ${N}\nSuccessful: ${successes.length}\nUnique session tokens: ${uniqueTokens.size}`,
          remediation:
            "Implement session locking: before creating a new session, invalidate all existing sessions for the user within a transaction. Use a distributed lock (Redis SETNX) to serialize session creation per user.",
          codeSnippet: `// Serialize session creation per user with Redis lock
const lockKey = \`session-lock:\${userId}\`;
const acquired = await redis.set(lockKey, "1", "NX", "EX", 5);
if (!acquired) {
  return Response.json({ error: "Login in progress" }, { status: 429 });
}
try {
  // Invalidate existing sessions
  await db.session.deleteMany({ where: { userId } });
  // Create new session
  const session = await db.session.create({ data: { userId, token: crypto.randomUUID() } });
  return Response.json({ token: session.token });
} finally {
  await redis.del(lockKey);
}`,
          cwe: "CWE-362",
          confidence: 70,
        });
      }
    }
  }

  // --- Phase 5: TOCTOU on balance/inventory endpoints ---
  const balanceEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(balance|wallet|credits?|stock|inventory|quota|limit|allowance)\b/i.test(ep),
  ).slice(0, 3);

  for (const endpoint of balanceEndpoints) {
    const N = 15;
    const results = await Promise.allSettled(
      Array.from({ length: N }, () =>
        scanFetch(endpoint, { timeoutMs: 5000, noCache: true }).then(async (res) => {
          if (!res.ok) return null;
          const ct = res.headers.get("content-type") || "";
          if (!ct.includes("json")) return null;
          return { body: await res.text().catch(() => "") };
        }),
      ),
    );

    const valid = results
      .filter((r) => r.status === "fulfilled" && r.value)
      .map((r) => (r as PromiseFulfilledResult<{ body: string }>).value.body);

    const unique = new Set(valid);
    if (unique.size > 1 && valid.length >= 5) {
      findings.push({
        id: `race-toctou-${findings.length}`,
        module: "Race Conditions",
        severity: "medium",
        title: `Potential TOCTOU on ${new URL(endpoint).pathname}`,
        description: `${unique.size} different responses from ${valid.length} concurrent GET requests to a balance/state endpoint. Inconsistent reads suggest the endpoint is vulnerable to time-of-check/time-of-use attacks where an attacker reads a stale balance before a deduction completes.`,
        evidence: `Endpoint: ${endpoint}\nConcurrent reads: ${N}\nUnique responses: ${unique.size}`,
        remediation: "Use atomic database operations (UPDATE ... SET balance = balance - amount WHERE balance >= amount) instead of read-check-update patterns.",
        cwe: "CWE-367",
        owasp: "A04:2021",
        codeSnippet: `// Atomic balance deduction — no TOCTOU\nconst result = await db.$executeRaw\`\n  UPDATE accounts\n  SET balance = balance - \${amount}\n  WHERE id = \${userId}\n  AND balance >= \${amount}\n\`;\nif (result.count === 0) {\n  return Response.json({ error: "Insufficient balance" }, { status: 400 });\n}`,
      });
    }
  }

  // --- Phase 6: TOCTOU on state-changing endpoints (read-then-write pattern) ---
  const stateChangeEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(settings|profile|config|preferences|update|edit|modify|toggle|enable|disable)\b/i.test(ep),
  ).slice(0, 3);

  for (const endpoint of stateChangeEndpoints) {
    // Interleave reads and writes to detect TOCTOU
    const readPromise = scanFetch(endpoint, { timeoutMs: 5000, noCache: true })
      .then(async (res) => ({ status: res.status, body: await res.text().catch(() => "") }))
      .catch(() => ({ status: 0, body: "" }));

    const writePromises = Array.from({ length: 5 }, () =>
      scanFetch(endpoint, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ _vibeshield_toctou_test: true }),
        timeoutMs: 5000,
      })
        .then(async (res) => ({ status: res.status, body: await res.text().catch(() => "") }))
        .catch(() => ({ status: 0, body: "" })),
    );

    const [readResult, ...writeResults] = await Promise.allSettled([
      readPromise,
      ...writePromises,
    ]);

    if (readResult.status === "fulfilled") {
      const read = readResult.value;
      const writeSuccesses = writeResults.filter(
        (r) => r.status === "fulfilled" && (r.value.status === 200 || r.value.status === 204),
      );

      // If multiple concurrent writes succeed, there's no mutex protecting the resource
      if (writeSuccesses.length > 2 && read.status === 200) {
        findings.push({
          id: `race-toctou-write-${findings.length}`,
          module: "Race Conditions",
          severity: "medium",
          title: `No write serialization on ${new URL(endpoint).pathname}`,
          description: `${writeSuccesses.length}/5 concurrent PUT requests succeeded without conflict. State-changing endpoints without optimistic concurrency control or locking are vulnerable to TOCTOU — a user can overwrite another user's changes if requests overlap.`,
          evidence: `Endpoint: ${endpoint}\nConcurrent PUTs: 5\nSuccessful: ${writeSuccesses.length}\nGET status: ${read.status}`,
          remediation:
            "Implement optimistic concurrency control using ETags or version numbers. Reject updates where the version has changed since the client's last read.",
          codeSnippet: `// Optimistic concurrency with version field
export async function PUT(req: Request) {
  const { id, version, ...data } = await req.json();
  const updated = await prisma.resource.updateMany({
    where: { id, version }, // only update if version matches
    data: { ...data, version: { increment: 1 } },
  });
  if (updated.count === 0) {
    return Response.json(
      { error: "Conflict — resource was modified by another request" },
      { status: 409 }
    );
  }
  return Response.json({ success: true });
}`,
          cwe: "CWE-367",
          confidence: 60,
        });
      }
    }
  }

  // --- Phase 7: File upload race conditions ---
  const uploadEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(upload|attach|import|file|media|avatar|photo|image|document)\b/i.test(ep),
  ).slice(0, 2);

  for (const endpoint of uploadEndpoints) {
    // Send concurrent uploads with different filenames to detect overwrite races
    const boundary = "----VibeshieldBoundary" + Date.now();
    const makeUploadBody = (filename: string) =>
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: text/plain\r\n\r\nvibeshield-race-test-${Date.now()}\r\n--${boundary}--\r\n`;

    const N = 8;
    const results = await Promise.allSettled(
      Array.from({ length: N }, (_, i) =>
        scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
          body: makeUploadBody(`vibeshield-race-test-${i}.txt`),
          timeoutMs: 10000,
        }).then(async (res) => ({
          status: res.status,
          body: await res.text().catch(() => ""),
        })),
      ),
    );

    const uploadSuccesses = results.filter(
      (r) => r.status === "fulfilled" && (r.value.status === 200 || r.value.status === 201),
    );

    if (uploadSuccesses.length > 1) {
      // Check if responses indicate different file paths/URLs — same path = overwrite race
      const uploadBodies = uploadSuccesses.map(
        (r) => (r as PromiseFulfilledResult<{ status: number; body: string }>).value.body,
      );

      // Try to extract URLs from responses
      const urlPattern = /https?:\/\/[^\s"']+/g;
      const extractedUrls = uploadBodies.flatMap((b) => b.match(urlPattern) || []);
      const uniqueUrls = new Set(extractedUrls);

      // If multiple uploads succeed but produce the same URL = overwrite race
      if (extractedUrls.length > 1 && uniqueUrls.size < extractedUrls.length * 0.5) {
        findings.push({
          id: `race-upload-overwrite-${findings.length}`,
          module: "Race Conditions",
          severity: "high",
          title: `File upload overwrite race on ${new URL(endpoint).pathname}`,
          description: `${uploadSuccesses.length} concurrent file uploads succeeded but produced overlapping file URLs. Concurrent uploads may overwrite each other, leading to data loss or serving the wrong file to users.`,
          evidence: `Endpoint: ${endpoint}\nConcurrent uploads: ${N}\nSuccessful: ${uploadSuccesses.length}\nUnique URLs: ${uniqueUrls.size}/${extractedUrls.length}`,
          remediation:
            "Use unique file names (UUID or content hash) for uploads. Never allow user-controlled filenames to determine storage paths. Process uploads atomically with temp files renamed after completion.",
          codeSnippet: `// Safe file upload with unique names
import { randomUUID } from "crypto";
import { extname } from "path";

export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get("file") as File;
  const ext = extname(file.name);
  // UUID filename prevents overwrite races
  const safeName = \`\${randomUUID()}\${ext}\`;
  // Write to temp, then atomic rename
  const tmpPath = \`/tmp/upload-\${safeName}\`;
  const finalPath = \`/uploads/\${safeName}\`;
  await writeFile(tmpPath, Buffer.from(await file.arrayBuffer()));
  await rename(tmpPath, finalPath); // atomic on same filesystem
  return Response.json({ url: \`/uploads/\${safeName}\` });
}`,
          cwe: "CWE-362",
          confidence: 65,
        });
      }

      // If all uploads succeed and there's no dedup = no upload rate limiting
      if (uploadSuccesses.length >= N * 0.8) {
        findings.push({
          id: `race-upload-flood-${findings.length}`,
          module: "Race Conditions",
          severity: "medium",
          title: `Upload endpoint accepts unlimited concurrent uploads at ${new URL(endpoint).pathname}`,
          description: `${uploadSuccesses.length}/${N} concurrent upload requests succeeded. Without concurrency limits on uploads, an attacker can exhaust disk space, memory, or processing capacity by flooding the upload endpoint.`,
          evidence: `Endpoint: ${endpoint}\nConcurrent uploads: ${N}\nSuccessful: ${uploadSuccesses.length}`,
          remediation:
            "Add per-user upload rate limiting, enforce maximum file sizes, limit concurrent uploads per session, and use a queue for processing uploads.",
          codeSnippet: `// Rate limit uploads per user
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const uploadLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "60 s"), // 5 uploads per minute
});

export async function POST(req: Request) {
  const userId = getUserId(req);
  const { success } = await uploadLimiter.limit(userId);
  if (!success) {
    return Response.json({ error: "Upload rate limit exceeded" }, { status: 429 });
  }
  // Process upload...
}`,
          cwe: "CWE-400",
          confidence: 70,
        });
      }
    }
  }

  return findings;
};
