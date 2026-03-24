import * as cheerio from "cheerio";
import type { ScanTarget, FormField, CookieInfo } from "../types";
import { scanFetch } from "../fetch";

const COMMON_API_PATHS = [
  "/api", "/api/auth", "/api/auth/session", "/api/auth/signin",
  "/api/auth/signup", "/api/auth/callback", "/api/users", "/api/user",
  "/api/me", "/api/profile", "/api/admin", "/api/config",
  "/api/health", "/api/status", "/api/graphql", "/api/webhook",
  "/api/webhooks", "/api/payments", "/api/stripe", "/api/checkout",
  "/api/upload", "/api/files", "/api/search", "/api/data",
  "/api/export", "/api/import", "/api/settings", "/api/notifications",
  "/api/messages", "/api/chat", "/api/ai", "/api/generate",
  "/api/trpc", "/api/v1", "/api/v2",
  "/rest/v1", "/auth/v1", "/storage/v1", // Supabase
  "/graphql", "/_next/data",
  "/.well-known/openid-configuration", "/.well-known/security.txt",
  "/.well-known/jwks.json", "/.well-known/assetlinks.json",
  "/v1", "/v2", "/v3", "/gql", "/rpc",
];

const TECH_SIGNATURES: Record<string, RegExp[]> = {
  "Next.js": [/__next/i, /_next\/static/i, /next-router/i],
  Supabase: [/supabase/i, /\.supabase\.co/i, /supabaseUrl/i],
  Firebase: [/firebase/i, /firebaseConfig/i, /\.firebaseapp\.com/i, /firebasestorage\.googleapis/i],
  React: [/__react/i, /react-dom/i, /reactMount/i],
  Vue: [/__vue/i, /vue\.runtime/i],
  Svelte: [/svelte/i, /__svelte/i],
  Tailwind: [/tailwindcss/i],
  Stripe: [/stripe/i, /js\.stripe\.com/i, /pk_live_/i, /pk_test_/i],
  Clerk: [/clerk/i, /\.clerk\.com/i],
  Auth0: [/auth0/i, /\.auth0\.com/i],
  Vercel: [/vercel/i, /\.vercel\.app/i],
  Netlify: [/netlify/i, /\.netlify\.app/i],
  Prisma: [/prisma/i],
  MongoDB: [/mongodb/i, /mongoose/i],
  OpenAI: [/openai/i, /api\.openai\.com/i],
  Anthropic: [/anthropic/i, /api\.anthropic\.com/i],
  Resend: [/resend/i],
  Upstash: [/upstash/i],
  PlanetScale: [/planetscale/i],
  Convex: [/convex/i, /\.convex\.dev/i],
  Appwrite: [/appwrite/i],
  Remix: [/__remix/i, /remix\.run/i, /entry\.client/i],
  Astro: [/astro/i, /__astro/i, /astro\.config/i],
  Vite: [/vite/i, /@vite\/client/i, /modulepreload/i],
  Angular: [/angular/i, /ng-version/i, /\bng\b.*module/i],
  Nuxt: [/__nuxt/i, /nuxt/i, /\.nuxt\./i],
  SvelteKit: [/sveltekit/i, /__sveltekit/i],
  Drizzle: [/drizzle/i, /drizzle-orm/i],
  tRPC: [/trpc/i, /\.trpc\./i],
  Neon: [/neon\.tech/i, /neondb/i],
  Turso: [/turso/i, /\.turso\.io/i],
};

export const runRecon = async (inputUrl: string): Promise<ScanTarget> => {
  const url = inputUrl.replace(/\/+$/, "");
  const baseUrl = new URL(url).origin;

  const target: ScanTarget = {
    url,
    baseUrl,
    pages: [],
    scripts: [],
    apiEndpoints: [],
    forms: [],
    cookies: [],
    headers: {},
    technologies: [],
    jsContents: new Map(),
    linkUrls: [],
    redirectUrls: [],
    soft404Body: "",
    isSpa: false,
  };

  // Fetch main page
  const mainRes = await scanFetch(url, {
    headers: { "User-Agent": "VibeShield/1.0 Security Scanner" },
    redirect: "follow",
  });

  // Capture headers
  mainRes.headers.forEach((v, k) => { target.headers[k.toLowerCase()] = v; });

  // Parse cookies
  const setCookies = mainRes.headers.getSetCookie?.() ?? [];
  for (const raw of setCookies) {
    target.cookies.push(parseCookie(raw));
  }

  const html = await mainRes.text();
  const $ = cheerio.load(html);

  // Extract pages (links)
  const seen = new Set<string>();
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;
    const resolved = resolveUrl(href, baseUrl);
    if (resolved && resolved.startsWith(baseUrl) && !seen.has(resolved)) {
      seen.add(resolved);
      target.pages.push(resolved);
      target.linkUrls.push(resolved);
    }
  });

  // Extract scripts
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (src) {
      const resolved = resolveUrl(src, baseUrl);
      if (resolved) target.scripts.push(resolved);
    }
  });

  // Extract inline script content for tech detection + dynamic imports
  let inlineJs = "";
  $("script:not([src])").each((_, el) => {
    const text = $(el).text();
    inlineJs += text + "\n";
    // Extract dynamic import() URLs from inline scripts
    const importMatches = text.matchAll(/import\s*\(\s*["']([^"']+\.(?:js|mjs|ts))["']\s*\)/g);
    for (const m of importMatches) {
      const resolved = resolveUrl(m[1], baseUrl);
      if (resolved && !target.scripts.includes(resolved)) {
        target.scripts.push(resolved);
      }
    }
  });

  // Extract modulepreload links (modern bundlers like Vite use these)
  $('link[rel="modulepreload"][href]').each((_, el) => {
    const href = $(el).attr("href");
    if (href) {
      const resolved = resolveUrl(href, baseUrl);
      if (resolved && !target.scripts.includes(resolved)) {
        target.scripts.push(resolved);
      }
    }
  });

  // Extract forms
  $("form").each((_, el) => {
    const form: FormField = {
      action: $(el).attr("action") || url,
      method: ($(el).attr("method") || "GET").toUpperCase(),
      inputs: [],
    };
    $(el).find("input, textarea, select").each((_, inp) => {
      form.inputs.push({
        name: $(inp).attr("name") || "",
        type: $(inp).attr("type") || "text",
      });
    });
    target.forms.push(form);
  });

  // Fetch JS bundles (parallel, limit to 20)
  const jsToFetch = target.scripts.slice(0, 20);
  const jsResults = await Promise.allSettled(
    jsToFetch.map(async (scriptUrl) => {
      const res = await scanFetch(scriptUrl, { redirect: "follow" });
      const text = await res.text();
      return { url: scriptUrl, content: text };
    }),
  );

  for (const r of jsResults) {
    if (r.status === "fulfilled") {
      target.jsContents.set(r.value.url, r.value.content);
    }
  }

  // Combine all JS for tech detection
  const allJs = Array.from(target.jsContents.values()).join("\n") + "\n" + inlineJs;

  // Detect technologies
  for (const [tech, patterns] of Object.entries(TECH_SIGNATURES)) {
    if (patterns.some((p) => p.test(allJs) || p.test(html))) {
      target.technologies.push(tech);
    }
  }

  // Also check headers for tech hints
  const server = target.headers["server"] || "";
  const poweredBy = target.headers["x-powered-by"] || "";
  if (/next/i.test(server) || /next/i.test(poweredBy)) target.technologies.push("Next.js");
  if (/vercel/i.test(server)) target.technologies.push("Vercel");

  target.technologies = [...new Set(target.technologies)];

  // Extract API endpoints referenced in JS bundles
  const apiFromJs = new Set<string>();
  const apiPatterns = [
    /fetch\s*\(\s*["'`](\/api\/[^"'`\s]+)["'`]/g,
    /["'`](\/api\/[a-zA-Z0-9/_-]{2,})["'`]/g,
    /["'`](\/rest\/v\d\/[a-zA-Z0-9/_-]+)["'`]/g,
    /["'`](\/auth\/v\d\/[a-zA-Z0-9/_-]+)["'`]/g,
    /["'`](\/graphql)["'`]/g,
    /["'`](\/v[1-3]\/[a-zA-Z0-9/_-]{2,})["'`]/g,
    /["'`](\/rpc\/[a-zA-Z0-9/_-]{2,})["'`]/g,
    /["'`](\/gql)["'`]/g,
  ];
  for (const pat of apiPatterns) {
    for (const m of allJs.matchAll(pat)) {
      const path = m[1];
      if (path && path.length < 100 && !path.includes("${")) {
        apiFromJs.add(baseUrl + path);
      }
    }
  }

  // Probe common API endpoints + JS-discovered ones
  const allApiPaths = [...new Set([
    ...COMMON_API_PATHS.map((p) => baseUrl + p),
    ...apiFromJs,
  ])];
  const probeResults = await Promise.allSettled(
    allApiPaths.slice(0, 60).map(async (testUrl) => {
      const res = await scanFetch(testUrl, { method: "GET", redirect: "follow", timeoutMs: 5000 });
      return { path: testUrl, status: res.status, contentType: res.headers.get("content-type") || "" };
    }),
  );

  for (const r of probeResults) {
    if (r.status !== "fulfilled") continue;
    const { status, contentType, path: probePath } = r.value;
    if (status === 404) continue;
    // Skip SPA catch-all: non-JSON responses from API-like paths are likely the SPA shell
    if (status === 200 && contentType.includes("text/html")) continue;
    // Skip empty responses (CDN/SPA returning 200 with no body)
    if (status === 200 && !contentType) continue;
    target.apiEndpoints.push(probePath);
  }

  // Crawl discovered pages (up to 10) for more endpoints/forms
  const pagesToCrawl = target.pages.slice(0, 10);
  const pageResults = await Promise.allSettled(
    pagesToCrawl.map(async (pageUrl) => {
      const res = await scanFetch(pageUrl, { redirect: "follow", timeoutMs: 5000 });
      return { url: pageUrl, html: await res.text() };
    }),
  );

  for (const r of pageResults) {
    if (r.status !== "fulfilled") continue;
    const p$ = cheerio.load(r.value.html);
    p$("a[href]").each((_, el) => {
      const href = p$(el).attr("href");
      if (!href) return;
      const resolved = resolveUrl(href, baseUrl);
      if (resolved && resolved.startsWith(baseUrl) && !seen.has(resolved)) {
        seen.add(resolved);
        target.pages.push(resolved);
      }
    });
    p$("script[src]").each((_, el) => {
      const src = p$(el).attr("src");
      if (src) {
        const resolved = resolveUrl(src, baseUrl);
        if (resolved && !target.scripts.includes(resolved)) target.scripts.push(resolved);
      }
    });
  }

  // Parse robots.txt and sitemap.xml for more URLs
  try {
    const robotsRes = await scanFetch(baseUrl + "/robots.txt", { timeoutMs: 5000 });
    if (robotsRes.status === 200) {
      const robotsTxt = await robotsRes.text();
      if (!robotsTxt.includes("<!DOCTYPE") && !robotsTxt.includes("<html")) {
        // Extract Disallow and Sitemap entries
        for (const line of robotsTxt.split("\n")) {
          const disallow = line.match(/^Disallow:\s*(.+)/i)?.[1]?.trim();
          if (disallow && disallow !== "/" && disallow.startsWith("/")) {
            const resolved = baseUrl + disallow;
            if (!seen.has(resolved)) { seen.add(resolved); target.pages.push(resolved); }
          }
          const sitemap = line.match(/^Sitemap:\s*(.+)/i)?.[1]?.trim();
          if (sitemap) {
            try {
              const smRes = await scanFetch(sitemap, { timeoutMs: 5000 });
              if (smRes.status === 200) {
                const smText = await smRes.text();
                const urlMatches = smText.matchAll(/<loc>([^<]+)<\/loc>/g);
                let count = 0;
                for (const m of urlMatches) {
                  if (count++ > 50) break;
                  const u = m[1];
                  if (u.startsWith(baseUrl) && !seen.has(u)) { seen.add(u); target.pages.push(u); }
                }
              }
            } catch {}
          }
        }
      }
    }
  } catch {}

  // Soft 404 detection: fetch a URL that definitely doesn't exist
  try {
    const canaryUrl = baseUrl + "/vibeshield-canary-404-test-" + Date.now();
    const canaryRes = await scanFetch(canaryUrl, { redirect: "follow", timeoutMs: 5000 });
    if (canaryRes.status === 200) {
      target.soft404Body = await canaryRes.text();
      // If the canary 200 body is very similar to the main page, this is a SPA
      const mainLen = html.length;
      const canaryLen = target.soft404Body.length;
      const ratio = canaryLen / mainLen;
      target.isSpa = ratio > 0.7 && ratio < 1.3;
    }
  } catch {
    // skip — soft404 detection is best-effort
  }

  return target;
};

const resolveUrl = (href: string, base: string): string | null => {
  try {
    if (href.startsWith("javascript:") || href.startsWith("mailto:") || href.startsWith("#")) return null;
    return new URL(href, base).href;
  } catch {
    return null;
  }
};

const parseCookie = (raw: string): CookieInfo => {
  const parts = raw.split(";").map((s) => s.trim());
  const [nameVal] = parts;
  const [name, ...valParts] = nameVal.split("=");
  const value = valParts.join("=");
  const flags = parts.slice(1).map((p) => p.toLowerCase());

  return {
    name: name.trim(),
    value,
    secure: flags.some((f) => f === "secure"),
    httpOnly: flags.some((f) => f === "httponly"),
    sameSite: flags.find((f) => f.startsWith("samesite"))?.split("=")[1]?.trim() || "",
    domain: flags.find((f) => f.startsWith("domain"))?.split("=")[1] || "",
    path: flags.find((f) => f.startsWith("path"))?.split("=")[1] || "/",
  };
};
