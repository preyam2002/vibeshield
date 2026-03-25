import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml, isSoft404 } from "../soft404";

/** Endpoints likely to have business logic */
const BIZ_ENDPOINT_PATTERNS = /checkout|payment|order|cart|subscribe|billing|purchase|redeem|coupon|discount|promo|credit|transfer|withdraw|deposit|invite|referral|upgrade|downgrade|cancel|refund/i;

/** Parameter names that affect business logic */
const BIZ_PARAMS = ["price", "amount", "quantity", "qty", "total", "discount", "coupon", "promo", "code", "plan", "tier"];

export const businessLogicModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Find business-critical endpoints
  const bizEndpoints = target.apiEndpoints.filter((ep) => BIZ_ENDPOINT_PATTERNS.test(ep));
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Also discover from JS bundles
  const jsBizPatterns = /["'`](\/api\/[a-zA-Z0-9/_-]*(?:checkout|payment|order|cart|subscribe|billing|purchase|redeem|coupon|discount|promo|credit|transfer|invite|referral|upgrade)[a-zA-Z0-9/_-]*)["'`]/gi;
  for (const m of allJs.matchAll(jsBizPatterns)) {
    if (m[1]) {
      const url = target.baseUrl + m[1];
      if (!bizEndpoints.includes(url)) bizEndpoints.push(url);
    }
  }

  if (bizEndpoints.length === 0) return findings;

  // Run all tests in parallel
  const [negativeResults, zeroResults, duplicateResults, paramTamperResults, overflowResults, couponResults] = await Promise.all([
    // Test 1: Negative value injection
    Promise.allSettled(
      bizEndpoints.slice(0, 5).flatMap((endpoint) =>
        [{ price: -1, amount: -100, quantity: -1 }, { price: 0.01, amount: 0.01, quantity: 0 }].map(async (body) => {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            timeoutMs: 5000,
          });
          if (!res.ok) return null;
          const text = await res.text();
          if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
          if (text.length < 10) return null;
          // Check if negative/zero values were accepted
          const hasNegative = Object.values(body).some((v) => v < 0);
          if (hasNegative && /success|created|accepted|url|session|redirect|order/i.test(text)) {
            return { endpoint, pathname: new URL(endpoint).pathname, body, text: text.substring(0, 200), type: "negative" as const };
          }
          return null;
        }),
      ),
    ),

    // Test 2: Zero-price bypass
    Promise.allSettled(
      bizEndpoints.slice(0, 3).filter((ep) => /checkout|payment|purchase|subscribe/i.test(ep)).map(async (endpoint) => {
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ price: 0, amount: 0, total: 0, quantity: 1 }),
          timeoutMs: 5000,
        });
        if (!res.ok) return null;
        const text = await res.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
        if (text.length < 10) return null;
        if (/success|url|session|checkout|redirect/i.test(text) && !/error|invalid|required|minimum/i.test(text.substring(0, 200))) {
          return { endpoint, pathname: new URL(endpoint).pathname, text: text.substring(0, 200) };
        }
        return null;
      }),
    ),

    // Test 3: Duplicate request detection (idempotency)
    Promise.allSettled(
      bizEndpoints.slice(0, 3).filter((ep) => /order|payment|purchase|transfer|redeem/i.test(ep)).map(async (endpoint) => {
        const body = JSON.stringify({ test: "vibeshield-idempotency-check", amount: 1 });
        const [res1, res2] = await Promise.all([
          scanFetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body, timeoutMs: 5000 }),
          scanFetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body, timeoutMs: 5000 }),
        ]);
        if (!res1.ok || !res2.ok) return null;
        const [text1, text2] = await Promise.all([res1.text(), res2.text()]);
        if (looksLikeHtml(text1)) return null;
        // If both succeed with different IDs/timestamps, no idempotency protection
        if (text1.length > 10 && text2.length > 10) {
          try {
            const j1 = JSON.parse(text1);
            const j2 = JSON.parse(text2);
            if (j1.id && j2.id && j1.id !== j2.id) {
              return { endpoint, pathname: new URL(endpoint).pathname };
            }
          } catch { /* not JSON */ }
        }
        return null;
      }),
    ),

    // Test 4: Query param tampering on business endpoints
    Promise.allSettled(
      bizEndpoints.slice(0, 5).flatMap((endpoint) =>
        BIZ_PARAMS.slice(0, 4).map(async (param) => {
          const url = new URL(endpoint);
          url.searchParams.set(param, "-1");
          const res = await scanFetch(url.href, { timeoutMs: 5000 });
          if (!res.ok) return null;
          const text = await res.text();
          if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
          if (text.length < 10) return null;
          if (text.includes("-1") && /price|amount|total|quantity/i.test(text)) {
            return { endpoint, pathname: new URL(endpoint).pathname, param, text: text.substring(0, 200) };
          }
          return null;
        }),
      ),
    ),

    // Test 5: Integer overflow / MAX_SAFE_INTEGER quantity
    Promise.allSettled(
      bizEndpoints.slice(0, 3).filter((ep) => /cart|order|checkout|purchase/i.test(ep)).map(async (endpoint) => {
        const overflowPayloads = [
          { quantity: 999999999, amount: 1 },
          { quantity: Number.MAX_SAFE_INTEGER, amount: 1 },
          { quantity: 2147483647, price: 1 },  // INT32_MAX
        ];
        for (const body of overflowPayloads) {
          const res = await scanFetch(endpoint, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body), timeoutMs: 5000,
          });
          if (!res.ok) continue;
          const text = await res.text();
          if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) continue;
          if (text.length < 10) continue;
          // If accepted without error, may cause integer overflow in total calculation
          if (/success|created|order|session|url/i.test(text) && !/error|invalid|too (large|many|high)|exceeded|limit|maximum/i.test(text.substring(0, 300))) {
            return { endpoint, pathname: new URL(endpoint).pathname, qty: body.quantity, text: text.substring(0, 200) };
          }
        }
        return null;
      }),
    ),

    // Test 6: Coupon/promo code stacking
    Promise.allSettled(
      bizEndpoints.slice(0, 3).filter((ep) => /coupon|discount|promo|redeem/i.test(ep)).map(async (endpoint) => {
        // Try applying multiple coupon codes at once
        const stackPayloads = [
          { codes: ["TEST", "DISCOUNT", "PROMO"], coupon: "TEST" },
          { coupon: ["TEST", "DISCOUNT"], code: "PROMO" },
          { coupons: "TEST,DISCOUNT,PROMO" },
        ];
        for (const body of stackPayloads) {
          const res = await scanFetch(endpoint, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body), timeoutMs: 5000,
          });
          if (!res.ok) continue;
          const text = await res.text();
          if (looksLikeHtml(text)) continue;
          if (text.length < 10) continue;
          // If server processes array of coupons, it may stack discounts
          if (/applied|success|discount|saved/i.test(text) && !/error|invalid|expired|single|one coupon/i.test(text.substring(0, 300))) {
            return { endpoint, pathname: new URL(endpoint).pathname, text: text.substring(0, 200) };
          }
        }
        return null;
      }),
    ),
  ]);

  // Collect findings
  for (const r of negativeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `biz-negative-${findings.length}`, module: "Business Logic", severity: "high",
      title: `Negative value accepted on ${v.pathname}`,
      description: "The endpoint accepted negative price/amount/quantity values. This could allow attackers to get credits, refunds, or reverse transactions.",
      evidence: `POST ${v.endpoint}\nPayload: ${JSON.stringify(v.body)}\nResponse: ${v.text}`,
      remediation: "Validate all monetary and quantity values server-side. Reject negative values, zero values for required payments, and values outside expected ranges.",
      cwe: "CWE-20", owasp: "A04:2021",
      codeSnippet: `// Validate monetary values with Zod\nimport { z } from "zod";\nconst OrderSchema = z.object({\n  price: z.number().positive("Price must be positive"),\n  quantity: z.number().int().min(1, "Min 1"),\n  amount: z.number().positive(),\n});\nconst validated = OrderSchema.parse(req.body);`,
    });
    break; // One finding per type
  }

  for (const r of zeroResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `biz-zero-price-${findings.length}`, module: "Business Logic", severity: "critical",
      title: `Zero-price checkout accepted on ${v.pathname}`,
      description: "The payment/checkout endpoint accepted a zero price and returned a success response. Attackers can get products or services for free.",
      evidence: `POST ${v.endpoint} with price:0, amount:0\nResponse: ${v.text}`,
      remediation: "Always calculate prices server-side from your database. Never accept client-submitted prices. Validate minimum amounts before creating payment sessions.",
      cwe: "CWE-472", owasp: "A04:2021",
      codeSnippet: `// Never trust client-submitted prices\nexport async function POST(req: Request) {\n  const { productId, quantity } = await req.json();\n  const product = await db.products.findById(productId);\n  const total = product.priceCents * quantity;\n  if (total < 50) throw new Error("Amount too low");\n  const session = await stripe.checkout.sessions.create({\n    line_items: [{ price: product.stripePriceId, quantity }],\n  });\n}`,
    });
    break;
  }

  for (const r of duplicateResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `biz-no-idempotency-${findings.length}`, module: "Business Logic", severity: "medium",
      title: `No duplicate request protection on ${v.pathname}`,
      description: "Sending the same request twice creates two separate records. Attackers can exploit this with race conditions to double-redeem coupons, duplicate orders, or transfer funds multiple times.",
      evidence: `Two simultaneous POST requests to ${v.endpoint} created different records`,
      remediation: "Implement idempotency keys. Require a unique request ID and reject duplicates. Use database constraints to prevent double-processing.",
      cwe: "CWE-799", owasp: "A04:2021",
      codeSnippet: `// Idempotency key pattern\nexport async function POST(req: Request) {\n  const key = req.headers.get("idempotency-key");\n  if (!key) return Response.json({ error: "Idempotency-Key required" }, { status: 400 });\n  const existing = await db.idempotencyKeys.findOne({ key });\n  if (existing) return Response.json(existing.response);\n  // ... process request, then store result\n  await db.idempotencyKeys.create({ key, response: result });\n}`,
    });
    break;
  }

  for (const r of paramTamperResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `biz-param-tamper-${findings.length}`, module: "Business Logic", severity: "high",
      title: `Business parameter tampering on ${v.pathname} (${v.param})`,
      description: `The "${v.param}" parameter accepts negative values and reflects them in the response. Attackers may be able to manipulate prices, quantities, or other business-critical values.`,
      evidence: `GET ${v.endpoint}?${v.param}=-1\nResponse: ${v.text}`,
      remediation: "Validate all business parameters server-side. Use allowlists for valid ranges. Never trust client-submitted business values.",
      cwe: "CWE-20", owasp: "A04:2021",
      codeSnippet: `// Validate query params server-side\nconst quantity = Math.max(1, Math.min(100, parseInt(params.quantity) || 1));\nconst price = await db.products.findById(params.id).then(p => p.price);\n// Never use client-submitted price/amount values`,
    });
    break;
  }

  for (const r of overflowResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `biz-overflow-${findings.length}`, module: "Business Logic", severity: "high",
      title: `Integer overflow quantity accepted on ${v.pathname}`,
      description: `The endpoint accepted quantity=${v.qty} without validation. Extremely large quantities can cause integer overflow in price calculations (e.g., qty * price wrapping to a negative or zero total).`,
      evidence: `POST ${v.endpoint}\nQuantity: ${v.qty}\nResponse: ${v.text}`,
      remediation: "Set maximum limits on quantity fields. Validate that total calculations don't overflow. Use BigInt or decimal libraries for monetary math.",
      cwe: "CWE-190", owasp: "A04:2021",
      codeSnippet: `// Validate quantity within safe bounds\nconst MAX_QUANTITY = 10000;\nconst qty = Math.min(MAX_QUANTITY, Math.max(1, Math.floor(Number(input))));\nif (!Number.isSafeInteger(qty * priceCents)) {\n  throw new Error("Calculation overflow");\n}`,
    });
    break;
  }

  for (const r of couponResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `biz-coupon-stack-${findings.length}`, module: "Business Logic", severity: "medium",
      title: `Possible coupon stacking on ${v.pathname}`,
      description: "The coupon/promo endpoint accepted an array or multiple codes without rejecting them. If discounts are applied cumulatively, attackers can stack coupons to get products for free or at deep discounts.",
      evidence: `POST ${v.endpoint} with multiple coupon codes\nResponse: ${v.text}`,
      remediation: "Only accept a single coupon code per order. Validate server-side that only one discount is applied. Cap maximum discount percentage.",
      cwe: "CWE-799", owasp: "A04:2021",
      codeSnippet: `// Enforce single coupon per order\nconst coupon = z.string().parse(req.body.coupon); // reject arrays\nconst discount = await validateCoupon(coupon, order);\nif (discount.percent > 50) throw new Error("Max 50% discount");`,
    });
    break;
  }

  return findings;
};
