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

  // Phase: Stripe publishable key in client-side code (informational)
  const pubKeyMatch = allJs.match(/pk_live_[a-zA-Z0-9]{20,}/);
  if (pubKeyMatch) {
    findings.push({
      id: "stripe-publishable-key-client",
      module: "Stripe",
      severity: "info",
      title: "Stripe publishable key found in client-side code",
      description: "A live Stripe publishable key (pk_live_*) was found in client-side JavaScript. This is expected for Stripe.js integration, but worth noting for asset inventory. Ensure no additional metadata or internal identifiers are exposed alongside it.",
      evidence: `Key found: ${pubKeyMatch[0].substring(0, 12)}...${pubKeyMatch[0].slice(-4)}`,
      remediation: "No action required if this is intentional. Verify the key is the publishable key (pk_live_*) and not a secret key. Ensure the key is loaded via environment variables (e.g. NEXT_PUBLIC_STRIPE_KEY) rather than hardcoded.",
      cwe: "CWE-200",
      codeSnippet: `// Expected: publishable key loaded via env var\nconst stripe = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);\n\n// Avoid: hardcoded key in source\nconst stripe = loadStripe("pk_live_abc123...");`,
    });
  }

  // Phase: Stripe secret key exposure in page source and JS bundles
  const pageSource = target.pages.length > 0 ? "" : ""; // allJs already covers bundles
  const allContent = allJs + "\n" + Array.from(target.jsContents.entries()).map(([url]) => url).join("\n");
  const skLiveInSource = allContent.match(/sk_live_[a-zA-Z0-9]{20,}/g);
  const skTestInSource = allContent.match(/sk_test_[a-zA-Z0-9]{20,}/g);
  // Scan page HTML for secret keys (fetch each page and check)
  const pageSecretKeyResults = await Promise.allSettled(
    target.pages.slice(0, 5).map(async (pageUrl) => {
      const res = await scanFetch(pageUrl, { timeoutMs: 5000 });
      if (!res.ok) return null;
      const html = await res.text();
      const liveMatch = html.match(/sk_live_[a-zA-Z0-9]{20,}/);
      const testMatch = html.match(/sk_test_[a-zA-Z0-9]{20,}/);
      if (liveMatch) return { pageUrl, key: liveMatch[0], type: "live" as const };
      if (testMatch) return { pageUrl, key: testMatch[0], type: "test" as const };
      return null;
    }),
  );

  for (const r of pageSecretKeyResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const masked = `${v.key.substring(0, 12)}...${v.key.slice(-4)}`;
    if (v.type === "live") {
      findings.push({
        id: `stripe-secret-key-page-source-${findings.length}`,
        module: "Stripe",
        severity: "critical",
        title: `Stripe live secret key exposed in page source: ${v.pageUrl}`,
        description: "A live Stripe secret key (sk_live_*) was found in the HTML page source. This key grants full API access including charges, refunds, and customer data.",
        evidence: `Page: ${v.pageUrl}\nKey found: ${masked}`,
        remediation: "Remove the secret key from page source IMMEDIATELY. Rotate the key in the Stripe dashboard. Secret keys must only exist server-side in environment variables.",
        cwe: "CWE-798",
        owasp: "A07:2021",
        codeSnippet: `// NEVER render secret keys in HTML/templates\n// Bad: <script>const key = "sk_live_..."</script>\n\n// Good: keep secret keys server-side only\n// .env (not committed)\nSTRIPE_SECRET_KEY=sk_live_...\n\n// Server-only code\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);`,
      });
    } else {
      findings.push({
        id: `stripe-test-secret-key-page-source-${findings.length}`,
        module: "Stripe",
        severity: "high",
        title: `Stripe test secret key exposed in page source: ${v.pageUrl}`,
        description: "A Stripe test secret key (sk_test_*) was found in the HTML page source. While it cannot affect live data, it exposes your test environment credentials.",
        evidence: `Page: ${v.pageUrl}\nKey found: ${masked}`,
        remediation: "Remove the test secret key from page source. Move it to a server-side environment variable.",
        cwe: "CWE-798",
        owasp: "A07:2021",
      });
    }
  }

  // Phase: Stripe webhook signature bypass — test endpoints without Stripe-Signature header
  const webhookSigPaths = [
    "/api/webhook", "/api/webhooks", "/api/stripe/webhook",
    "/api/stripe", "/api/payments/webhook", "/webhook",
    "/webhooks/stripe", "/api/stripe/webhooks",
  ];
  const webhookSigResults = await Promise.allSettled(
    webhookSigPaths.map(async (path) => {
      const url = target.baseUrl + path;
      // Send a well-formed event WITHOUT Stripe-Signature header
      const res = await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: "evt_test_signature_bypass",
          object: "event",
          type: "invoice.payment_succeeded",
          data: { object: { id: "in_test_fake", customer: "cus_test_fake", amount_paid: 9900, status: "paid" } },
        }),
        timeoutMs: 5000,
      });
      // A properly secured endpoint should return 400/401/403 when no signature is present
      if (res.status >= 400) return null;
      const text = await res.text();
      if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) return null;
      if (text.length < 5) return null;
      // Check if the response indicates the event was processed
      if (/received|processed|success|ok|handled|acknowledged/i.test(text)) {
        return { path, status: res.status, text: text.substring(0, 200) };
      }
      // Even a 200 with a non-error body is suspicious
      if (res.status === 200 && !/error|invalid|missing.*signature|unauthorized/i.test(text.substring(0, 300))) {
        return { path, status: res.status, text: text.substring(0, 200) };
      }
      return null;
    }),
  );

  for (const r of webhookSigResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    findings.push({
      id: `stripe-webhook-sig-bypass-${findings.length}`,
      module: "Stripe",
      severity: "critical",
      title: `Webhook accepts events without Stripe-Signature: ${r.value.path}`,
      description: "The webhook endpoint processed a Stripe event sent without a Stripe-Signature header. An attacker can forge webhook events to trigger fulfillment, grant subscriptions, or manipulate account state.",
      evidence: `POST ${target.baseUrl + r.value.path} (no Stripe-Signature header)\nEvent type: invoice.payment_succeeded\nStatus: ${r.value.status}\nResponse: ${r.value.text}`,
      remediation: "Always verify the Stripe-Signature header using stripe.webhooks.constructEvent(). Reject requests missing the header entirely.",
      cwe: "CWE-345",
      owasp: "A02:2021",
      codeSnippet: `// Reject requests without valid Stripe-Signature\nexport async function POST(req: Request) {\n  const sig = req.headers.get("stripe-signature");\n  if (!sig) return new Response("Missing signature", { status: 400 });\n  let event: Stripe.Event;\n  try {\n    event = stripe.webhooks.constructEvent(\n      await req.text(), // raw body\n      sig,\n      process.env.STRIPE_WEBHOOK_SECRET!\n    );\n  } catch (err) {\n    return new Response("Invalid signature", { status: 400 });\n  }\n  // Only process verified events\n  switch (event.type) { /* ... */ }\n}`,
    });
  }

  // Phase: Payment amount manipulation — test Stripe Checkout patterns for client-controlled amounts
  const checkoutEndpoints = target.apiEndpoints.filter((ep) =>
    /checkout|create-session|payment-intent|create-payment/i.test(ep),
  );
  // Also search JS for checkout API routes
  const checkoutJsMatches = Array.from(allJs.matchAll(/["'`](\/api\/[a-zA-Z0-9/_-]*(?:checkout|create-session|payment-intent|create-payment)[a-zA-Z0-9/_-]*)["'`]/gi));
  for (const m of checkoutJsMatches) {
    if (m[1]) {
      const url = target.baseUrl + m[1];
      if (!checkoutEndpoints.includes(url)) checkoutEndpoints.push(url);
    }
  }

  if (checkoutEndpoints.length > 0) {
    const amountManipResults = await Promise.allSettled(
      checkoutEndpoints.slice(0, 4).map(async (endpoint) => {
        const manipPayloads = [
          { amount: 1, currency: "usd", desc: "amount set to $0.01" },
          { unit_amount: 1, desc: "unit_amount set to 1 cent" },
          { price_data: { unit_amount: 1, currency: "usd", product_data: { name: "test" } }, desc: "inline price_data with $0.01" },
          { line_items: [{ price_data: { unit_amount: 1, currency: "usd", product_data: { name: "test" } }, quantity: 1 }], desc: "line_items with manipulated price" },
        ];
        for (const { desc, ...body } of manipPayloads) {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            timeoutMs: 5000,
          });
          if (!res.ok) continue;
          const text = await res.text();
          if (looksLikeHtml(text) || text.length < 10) continue;
          if (/checkout\.stripe\.com|cs_|session|client_secret|payment_intent|url.*https?/i.test(text) && !/error|invalid|minimum/i.test(text.substring(0, 200))) {
            return { endpoint, pathname: new URL(endpoint).pathname, desc, text: text.substring(0, 200) };
          }
        }
        return null;
      }),
    );

    for (const r of amountManipResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `stripe-amount-manipulation-${findings.length}`,
        module: "Stripe",
        severity: "critical",
        title: `Payment amount manipulation on ${v.pathname}`,
        description: `The checkout endpoint accepted a client-supplied ${v.desc} and returned a valid session. Attackers can pay arbitrary amounts for any product or service.`,
        evidence: `POST ${v.endpoint}\nPayload: ${v.desc}\nResponse: ${v.text}`,
        remediation: "Never accept amounts or price_data from the client. Use pre-created Stripe Price IDs stored server-side. Validate all checkout parameters against your product catalog.",
        cwe: "CWE-472",
        owasp: "A04:2021",
        codeSnippet: `// Secure: use server-side Price IDs only\nexport async function POST(req: Request) {\n  const { productId } = await req.json();\n  const product = await db.product.findUnique({ where: { id: productId } });\n  if (!product) return Response.json({ error: "Not found" }, { status: 404 });\n  const session = await stripe.checkout.sessions.create({\n    line_items: [{\n      price: product.stripePriceId, // from DB, never from client\n      quantity: 1,\n    }],\n    mode: "payment",\n  });\n  return Response.json({ url: session.url });\n}`,
      });
      break;
    }
  }

  // Phase: Stripe Connect account enumeration
  const connectPaths = [
    "/v1/accounts", "/api/connect/accounts", "/api/stripe/accounts",
    "/api/merchants", "/api/sellers", "/api/connect",
    "/api/stripe/connect", "/api/payouts/accounts",
  ];
  const connectResults = await Promise.allSettled(
    connectPaths.map(async (path) => {
      const url = target.baseUrl + path;
      const [getRes, listRes] = await Promise.all([
        scanFetch(url, { timeoutMs: 5000 }),
        scanFetch(url + "?limit=100", { timeoutMs: 5000 }),
      ]);
      for (const res of [getRes, listRes]) {
        if (!res.ok) continue;
        const text = await res.text();
        if (looksLikeHtml(text) && (isSoft404(text, target) || target.isSpa)) continue;
        if (text.length < 10) continue;
        // Look for account-related data in the response
        if (/acct_[a-zA-Z0-9]+|"account"|"merchant"|"seller"|"connected_account"|"stripe_user_id"|"payouts_enabled"/i.test(text)) {
          return { path, text: text.substring(0, 300), status: res.status };
        }
        // Check for list responses with account data
        if (/\{"data"\s*:\s*\[|"has_more"|"total_count"/i.test(text) && /email|business|account/i.test(text)) {
          return { path, text: text.substring(0, 300), status: res.status };
        }
      }
      return null;
    }),
  );

  for (const r of connectResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `stripe-connect-enum-${findings.length}`,
      module: "Stripe",
      severity: "high",
      title: `Stripe Connect account data exposed: ${v.path}`,
      description: "A Connect-related endpoint exposes merchant or connected account information without proper authorization. Attackers can enumerate sellers, view payout details, or access business information of connected accounts.",
      evidence: `GET ${target.baseUrl + v.path}\nStatus: ${v.status}\nResponse: ${v.text}`,
      remediation: "Authenticate and authorize all Connect account endpoints. Only expose account data to the account owner or platform admins. Never list all connected accounts in a client-accessible endpoint.",
      cwe: "CWE-200",
      owasp: "A01:2021",
      codeSnippet: `// Secure Connect account access\nexport async function GET(req: Request) {\n  const user = await getAuthUser(req);\n  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  // Only return the current user's connected account\n  const account = await db.connectedAccount.findUnique({\n    where: { userId: user.id },\n  });\n  if (!account) return Response.json({ error: "Not found" }, { status: 404 });\n  // Return limited fields only\n  return Response.json({\n    id: account.stripeAccountId,\n    payoutsEnabled: account.payoutsEnabled,\n  });\n}`,
    });
  }

  return findings;
};
