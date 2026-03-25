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
      codeSnippet: `// Verify webhook signature before processing\nconst sig = req.headers["stripe-signature"];\nconst event = stripe.webhooks.constructEvent(\n  req.body, // raw body, not parsed JSON\n  sig,\n  process.env.STRIPE_WEBHOOK_SECRET\n);\n\n// Now safe to handle\nif (event.type === "checkout.session.completed") {\n  await fulfillOrder(event.data.object);\n}`,
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
      codeSnippet: `// Look up price server-side — never trust client-sent amounts\nconst plan = await db.plan.findUnique({ where: { id: planId } });\n\nconst session = await stripe.checkout.sessions.create({\n  line_items: [{\n    price: plan.stripePriceId, // from your DB, not the request\n    quantity: 1,\n  }],\n  mode: "subscription",\n});`,
      cwe: "CWE-472",
    });
  }

  // Check for Stripe secret key in client-side code
  const secretKeyMatch = allJs.match(/sk_live_[a-zA-Z0-9]{20,}/);
  if (secretKeyMatch) {
    findings.push({
      id: "stripe-secret-key-exposed", module: "Stripe", severity: "critical",
      title: "Stripe secret key exposed in client-side JavaScript",
      description: "A live Stripe secret key (sk_live_*) is embedded in client-side code. Anyone can use this to create charges, read customer data, issue refunds, and more.",
      evidence: `Key found: ${secretKeyMatch[0].substring(0, 12)}...${secretKeyMatch[0].slice(-4)}`,
      remediation: "Remove the secret key from client code IMMEDIATELY. Rotate the key in the Stripe dashboard. Only use publishable keys (pk_live_*) client-side.",
      cwe: "CWE-798", owasp: "A07:2021",
      codeSnippet: `// Client-side: only use the publishable key\nconst stripe = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);\n\n// Server-side: use the secret key\n// app/api/checkout/route.ts\nimport Stripe from "stripe";\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!); // no NEXT_PUBLIC_`,
    });
  }

  // Check for test key in production
  const testKeyMatch = allJs.match(/sk_test_[a-zA-Z0-9]{20,}/);
  if (testKeyMatch) {
    findings.push({
      id: "stripe-test-key-exposed", module: "Stripe", severity: "high",
      title: "Stripe test secret key in client-side code",
      description: "A Stripe test secret key (sk_test_*) is embedded in client code. While it can't affect live data, it reveals your test environment and should be server-side only.",
      evidence: `Key found: ${testKeyMatch[0].substring(0, 12)}...`,
      remediation: "Move the test secret key to a server-side environment variable.",
      cwe: "CWE-798",
      codeSnippet: `// .env.local (not committed to git)\nSTRIPE_SECRET_KEY=sk_test_...\n\n// Server-only API route\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);`,
    });
  }

  // Check for quantity/plan tampering on payment endpoints
  const quantityResults = await Promise.allSettled(
    priceEndpoints.slice(0, 3).map(async (endpoint) => {
      // Try setting quantity to 0 or negative
      const tamperPayloads = [
        { quantity: 0, desc: "zero quantity" },
        { quantity: -1, desc: "negative quantity" },
        { amount: 1, currency: "usd", desc: "custom amount" },
      ];
      for (const payload of tamperPayloads) {
        const { desc, ...body } = payload;
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          timeoutMs: 5000,
        });
        if (!res.ok) continue;
        const text = await res.text();
        if (looksLikeHtml(text) || text.length < 10) continue;
        if (/checkout|session|url|redirect|payment/i.test(text) && !/error|invalid|minimum/i.test(text.substring(0, 200))) {
          return { endpoint, pathname: new URL(endpoint).pathname, desc, text: text.substring(0, 200) };
        }
      }
      return null;
    }),
  );

  for (const r of quantityResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `stripe-quantity-tamper-${findings.length}`, module: "Stripe", severity: "high",
      title: `Payment quantity/amount tampering on ${v.pathname}`,
      description: `The checkout endpoint accepted ${v.desc} and returned a checkout session. Attackers can manipulate quantities or amounts to pay less or nothing.`,
      evidence: `POST ${v.endpoint} with ${v.desc}\nResponse: ${v.text}`,
      remediation: "Validate quantity > 0 and amounts server-side before creating checkout sessions. Never accept amounts from client requests.",
      cwe: "CWE-472", owasp: "A04:2021",
      codeSnippet: `// Validate quantity and use server-side pricing\nconst qty = Math.max(1, Math.min(100, Math.floor(Number(body.quantity))));\nif (!Number.isFinite(qty)) throw new Error("Invalid quantity");\n\nconst session = await stripe.checkout.sessions.create({\n  line_items: [{ price: product.stripePriceId, quantity: qty }],\n});`,
    });
    break;
  }

  // Check for Stripe customer portal bypass
  const portalPaths = ["/api/billing", "/api/portal", "/api/customer-portal", "/api/stripe/portal", "/api/billing/portal"];
  const portalResults = await Promise.allSettled(
    portalPaths.map(async (path) => {
      const url = target.baseUrl + path;
      const res = await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
        timeoutMs: 5000,
      });
      if (!res.ok) return null;
      const text = await res.text();
      if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
      if (text.length < 10) return null;
      if (/billing\.stripe\.com|customer.*portal|url.*http/i.test(text)) {
        return { path, text: text.substring(0, 300) };
      }
      return null;
    }),
  );

  for (const r of portalResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `stripe-portal-no-auth-${findings.length}`, module: "Stripe", severity: "high",
      title: `Stripe Customer Portal accessible without auth: ${r.value.path}`,
      description: "The billing portal endpoint returns a Stripe portal URL without verifying the user's identity. An attacker can access the portal to view billing info, cancel subscriptions, or change payment methods.",
      evidence: `POST ${target.baseUrl + r.value.path} (no auth)\nResponse: ${r.value.text}`,
      remediation: "Authenticate the user before creating a portal session. Verify the Stripe customer ID belongs to the authenticated user.",
      cwe: "CWE-306", owasp: "A07:2021",
      codeSnippet: `// Authenticate before creating portal session\nexport async function POST(req: Request) {\n  const session = await auth();\n  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  const user = await db.user.findUnique({ where: { id: session.userId } });\n  if (!user?.stripeCustomerId) return Response.json({ error: "No billing" }, { status: 400 });\n  const portal = await stripe.billingPortal.sessions.create({\n    customer: user.stripeCustomerId, // from YOUR database, not the request\n    return_url: req.headers.get("origin") + "/settings",\n  });\n  return Response.json({ url: portal.url });\n}`,
    });
    break;
  }

  // Check for coupon/promo code abuse
  const couponEndpoints = target.apiEndpoints.filter((ep) =>
    /coupon|promo|discount|redeem|code/i.test(ep),
  );
  const couponJsMatches = allJs.matchAll(/["'`](\/api\/[a-zA-Z0-9/_-]*(?:coupon|promo|discount|redeem)[a-zA-Z0-9/_-]*)["'`]/gi);
  for (const m of couponJsMatches) {
    if (m[1]) {
      const url = target.baseUrl + m[1];
      if (!couponEndpoints.includes(url)) couponEndpoints.push(url);
    }
  }

  if (couponEndpoints.length > 0) {
    const couponAbuse = await Promise.allSettled(
      couponEndpoints.slice(0, 3).map(async (endpoint) => {
        const testCodes = [
          { code: "100OFF", desc: "common promo code" },
          { code: "INTERNAL", desc: "internal discount" },
          { code: "TEST", desc: "test coupon" },
          { code: "WELCOME100", desc: "max discount code" },
          { code: "ADMIN", desc: "admin coupon" },
        ];
        for (const { code, desc } of testCodes) {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code, coupon: code, promo_code: code }),
            timeoutMs: 5000,
          });
          if (!res.ok) continue;
          const text = await res.text();
          if (/discount|percent|amount_off|valid|applied|success/i.test(text) && !/invalid|expired|not found/i.test(text.substring(0, 200))) {
            return { endpoint, pathname: new URL(endpoint).pathname, code, desc, text: text.substring(0, 200) };
          }
        }
        return null;
      }),
    );

    for (const r of couponAbuse) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `stripe-coupon-abuse-${findings.length}`, module: "Stripe", severity: "medium",
        title: `Coupon/promo endpoint accepts guessable codes on ${v.pathname}`,
        description: `The coupon endpoint accepted "${v.code}" (${v.desc}) and returned discount information. Attackers can brute-force or guess common promo codes to get unauthorized discounts.`,
        evidence: `POST ${v.endpoint}\nCode: ${v.code}\nResponse: ${v.text}`,
        remediation: "Rate-limit coupon validation. Use random, unguessable coupon codes. Validate coupons server-side against your database, not client-side.",
        cwe: "CWE-330", owasp: "A04:2021",
        codeSnippet: `// Rate-limit coupon validation\nimport { Ratelimit } from "@upstash/ratelimit";\nconst ratelimit = new Ratelimit({ limiter: Ratelimit.slidingWindow(5, "1 m") });\n\nexport async function POST(req: Request) {\n  const { success } = await ratelimit.limit(getIP(req));\n  if (!success) return Response.json({ error: "Too many attempts" }, { status: 429 });\n  const { code } = await req.json();\n  // Validate against Stripe API, not local lookup\n  const promo = await stripe.promotionCodes.list({ code, active: true, limit: 1 });\n  if (!promo.data.length) return Response.json({ error: "Invalid code" });\n}`,
      });
      break;
    }
  }

  // Check for subscription plan manipulation (downgrade/upgrade without auth)
  const subEndpoints = target.apiEndpoints.filter((ep) =>
    /subscribe|subscription|plan|upgrade|downgrade/i.test(ep),
  );
  if (subEndpoints.length > 0) {
    const subResults = await Promise.allSettled(
      subEndpoints.slice(0, 3).map(async (endpoint) => {
        const payloads = [
          { plan: "free", desc: "downgrade to free" },
          { plan: "enterprise", desc: "upgrade to enterprise" },
          { plan_id: "price_fake_enterprise", desc: "fake price ID" },
          { interval: "year", desc: "interval switch" },
        ];
        for (const { desc, ...body } of payloads) {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            timeoutMs: 5000,
          });
          if (!res.ok) continue;
          const text = await res.text();
          if (looksLikeHtml(text) || text.length < 10) continue;
          if (/success|updated|subscription|plan|changed/i.test(text) && !/unauthorized|forbidden|login/i.test(text.substring(0, 200))) {
            return { endpoint, pathname: new URL(endpoint).pathname, desc, text: text.substring(0, 200) };
          }
        }
        return null;
      }),
    );

    for (const r of subResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `stripe-sub-tamper-${findings.length}`, module: "Stripe", severity: "high",
        title: `Subscription plan tampering on ${v.pathname}`,
        description: `The subscription endpoint accepted a "${v.desc}" request without proper authentication or validation. Users may be able to upgrade to premium plans without paying.`,
        evidence: `POST ${v.endpoint}\nPayload: ${v.desc}\nResponse: ${v.text}`,
        remediation: "Authenticate users before plan changes. Validate the plan ID against your allowed plans. Always change subscriptions via the Stripe API, not by updating your database directly.",
        cwe: "CWE-862", owasp: "A01:2021",
        codeSnippet: `// Secure plan change via Stripe API\nexport async function POST(req: Request) {\n  const user = await getAuthUser(req);\n  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  const { planId } = await req.json();\n  // Validate planId against your known plans\n  const plan = ALLOWED_PLANS.find(p => p.id === planId);\n  if (!plan) return Response.json({ error: "Invalid plan" }, { status: 400 });\n  // Use Stripe API to change subscription\n  await stripe.subscriptions.update(user.stripeSubId, {\n    items: [{ id: user.stripeItemId, price: plan.stripePriceId }],\n  });\n}`,
      });
      break;
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
              codeSnippet: `// In your webhook handler, grant access after confirmed payment\nif (event.type === "checkout.session.completed") {\n  const session = event.data.object;\n  await db.user.update({\n    where: { email: session.customer_email },\n    data: { plan: "pro", paidAt: new Date() },\n  });\n}\n\n// In your success page, check actual payment status\nconst user = await getUser(session);\nif (!user.paidAt) redirect("/pricing");`,
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
