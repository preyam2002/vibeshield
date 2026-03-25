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
  const [negativeResults, zeroResults, duplicateResults, paramTamperResults] = await Promise.all([
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
          // Check if negative value was reflected or accepted
          if (text.includes("-1") && /price|amount|total|quantity/i.test(text)) {
            return { endpoint, pathname: new URL(endpoint).pathname, param, text: text.substring(0, 200) };
          }
          return null;
        }),
      ),
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
    });
    break;
  }

  return findings;
};
