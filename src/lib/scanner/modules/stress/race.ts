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

  return findings;
};
