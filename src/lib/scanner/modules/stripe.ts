import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { isSoft404, looksLikeHtml } from "../soft404";

export const stripeModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  if (!target.technologies.includes("Stripe") && !/stripe/i.test(allJs)) return findings;

  // Check for webhook endpoint without signature verification
  const webhookPaths = [
    "/api/webhook", "/api/webhooks", "/api/stripe/webhook",
    "/api/stripe", "/api/payments/webhook", "/webhook",
    "/webhooks/stripe",
  ];

  for (const path of webhookPaths) {
    try {
      const res = await scanFetch(target.baseUrl + path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "checkout.session.completed",
          data: { object: { id: "cs_test_fake", payment_status: "paid", amount_total: 0 } },
        }),
      });

      // If it doesn't return 400 (missing signature), webhook verification might be missing
      if (res.status === 200 || res.status === 201) {
        const text = await res.text();
        // Skip if SPA returning its shell HTML for any POST route
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) continue;
        // Skip empty responses — likely not a real webhook handler
        if (text.length < 5) continue;
        findings.push({
          id: `stripe-webhook-no-verify-${findings.length}`,
          module: "Stripe",
          severity: "critical",
          title: `Stripe webhook accepts unverified events: ${path}`,
          description: "The webhook endpoint accepted a fake Stripe event without signature verification. Attackers can send fake payment confirmations to grant themselves access to paid features.",
          evidence: `POST ${target.baseUrl + path}\nSent fake checkout.session.completed event\nStatus: ${res.status}`,
          remediation: "Verify Stripe webhook signatures using stripe.webhooks.constructEvent(). Never trust webhook data without signature verification.",
          cwe: "CWE-345",
          owasp: "A02:2021",
        });
      }
    } catch {
      // skip
    }
  }

  // Check for client-side price manipulation
  const priceEndpoints = target.apiEndpoints.filter((ep) =>
    /checkout|payment|price|subscribe|billing/i.test(ep),
  );

  for (const endpoint of priceEndpoints.slice(0, 3)) {
    try {
      // Try sending a modified price
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ price: 1, amount: 1, priceId: "price_test" }),
      });
      if (res.ok) {
        findings.push({
          id: `stripe-price-manip-${findings.length}`,
          module: "Stripe",
          severity: "high",
          title: `Potential price manipulation on ${new URL(endpoint).pathname}`,
          description: "The payment endpoint accepts client-sent price/amount values. If these are used to create Stripe sessions, attackers can pay arbitrary amounts.",
          evidence: `POST ${endpoint} with amount:1 → ${res.status}`,
          remediation: "Never accept prices from the client. Look up prices server-side using Stripe Price IDs from your database.",
          cwe: "CWE-472",
        });
      }
    } catch {
      // skip
    }
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
