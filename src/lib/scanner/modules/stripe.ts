import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

export const stripeModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  if (!target.technologies.includes("Stripe") && !/stripe/i.test(allJs)) return findings;

  // Check for webhook endpoint without signature verification + price manipulation in parallel
  const webhookPaths = [
    "/api/webhook", "/api/webhooks", "/api/stripe/webhook",
    "/api/stripe", "/api/payments/webhook", "/webhook",
    "/webhooks/stripe",
  ];

  const priceEndpoints = target.apiEndpoints.filter((ep) =>
    /checkout|payment|price|subscribe|billing/i.test(ep),
  );

  const [webhookResults, priceResults] = await Promise.all([
    // Webhook tests in parallel
    Promise.allSettled(
      webhookPaths.map(async (path) => {
        const res = await scanFetch(target.baseUrl + path, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: "checkout.session.completed", data: { object: { id: "cs_test_fake", payment_status: "paid", amount_total: 0 } } }),
        });
        if (res.status !== 200 && res.status !== 201) return null;
        const text = await res.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
        if (text.length < 5) return null;
        return { path, status: res.status };
      }),
    ),
    // Price manipulation tests in parallel
    Promise.allSettled(
      priceEndpoints.slice(0, 3).map(async (endpoint) => {
        const res = await scanFetch(endpoint, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ price: 1, amount: 1, priceId: "price_test" }),
        });
        if (!res.ok) return null;
        const text = await res.text();
        if (looksLikeHtml(text) || text.length < 10) return null;
        if (/checkout|session|url|redirect|payment/i.test(text)) {
          return { endpoint, pathname: new URL(endpoint).pathname, status: res.status, text: text.substring(0, 200) };
        }
        return null;
      }),
    ),
  ]);

  for (const r of webhookResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `stripe-webhook-no-verify-${findings.length}`, module: "Stripe", severity: "critical",
      title: `Stripe webhook accepts unverified events: ${r.value.path}`,
      description: "The webhook endpoint accepted a fake Stripe event without signature verification.",
      evidence: `POST ${target.baseUrl + r.value.path}\nSent fake checkout.session.completed event\nStatus: ${r.value.status}`,
      remediation: "Verify Stripe webhook signatures using stripe.webhooks.constructEvent().",
      cwe: "CWE-345", owasp: "A02:2021",
    });
  }

  for (const r of priceResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `stripe-price-manip-${findings.length}`, module: "Stripe", severity: "high",
      title: `Potential price manipulation on ${v.pathname}`,
      description: "The payment endpoint accepts client-sent price/amount values and returns checkout-related data.",
      evidence: `POST ${v.endpoint} with amount:1 → ${v.status}\nResponse preview: ${v.text}`,
      remediation: "Never accept prices from the client. Look up prices server-side using Stripe Price IDs from your database.",
      cwe: "CWE-472",
    });
  }

  // Check for success URL bypass
  const successUrls = allJs.match(/success_url.*?["'](https?:\/\/[^"']+)["']/gi);
  if (successUrls) {
    for (const match of successUrls.slice(0, 2)) {
      const urlMatch = match.match(/["'](https?:\/\/[^"']+)["']/);
      if (urlMatch) {
        try {
          const successUrl = urlMatch[1].replace(/\{.*?\}/g, "test");
          const res = await scanFetch(successUrl);
          if (res.ok) {
            findings.push({
              id: `stripe-success-bypass-${findings.length}`,
              module: "Stripe",
              severity: "high",
              title: "Stripe success URL is directly accessible",
              description: "The payment success URL can be accessed directly without completing payment. If this page grants access or fulfills orders, users can skip payment entirely.",
              evidence: `Success URL: ${successUrl}\nStatus: ${res.status}`,
              remediation: "Don't rely on the success URL for fulfillment. Use Stripe webhooks to confirm payment, then update the user's access server-side.",
              cwe: "CWE-862",
            });
          }
        } catch {
          // skip
        }
      }
    }
  }

  return findings;
};
