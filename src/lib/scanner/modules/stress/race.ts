import type { ScanModule, Finding } from "../../types";
import { scanFetch } from "../../fetch";

export const raceConditionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Only test endpoints that look like one-time actions — generic POSTs cause too many false positives
  const stateEndpoints = target.apiEndpoints.filter((ep) =>
    /coupon|redeem|claim|transfer|withdraw|vote|checkout|purchase|apply|bonus|reward|credit|discount|activate|upgrade|downgrade/i.test(ep),
  );

  if (stateEndpoints.length === 0) return findings;
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
    // If both succeed, the server ignores idempotency keys
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
      // If both return different bodies, idempotency is not enforced
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

  // Phase 2: Signup/registration race condition — duplicate account creation
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

  // Phase 3: TOCTOU on balance/inventory endpoints
  // Look for endpoints that might read-then-update state (balance, stock, quota)
  const balanceEndpoints = target.apiEndpoints.filter((ep) =>
    /\/(balance|wallet|credits?|stock|inventory|quota|limit|allowance)\b/i.test(ep),
  ).slice(0, 3);

  for (const endpoint of balanceEndpoints) {
    // Send concurrent reads — if we get inconsistent values, there's a potential TOCTOU
    const N = 15;
    const results = await Promise.allSettled(
      Array.from({ length: N }, () =>
        scanFetch(endpoint, { timeoutMs: 5000 }).then(async (res) => {
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
      // Multiple different values from concurrent reads = potential TOCTOU
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

  return findings;
};
