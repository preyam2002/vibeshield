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

const OPENAPI_PATHS = [
  "/openapi.json", "/swagger.json", "/api-docs", "/api/docs",
  "/api/swagger.json", "/api/openapi.json", "/docs/openapi.json",
  "/swagger/v1/swagger.json", "/v1/openapi.json", "/v2/openapi.json",
  "/api/v1/openapi.json", "/api/v2/openapi.json",
  "/.well-known/openapi.json",
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
  "Lemon Squeezy": [/lemonsqueezy/i, /\.lemonsqueezy\.com/i],
  Sentry: [/sentry/i, /\.sentry\.io/i, /Sentry\.init/i],
  PostHog: [/posthog/i, /\.posthog\.com/i],
  Plausible: [/plausible/i, /plausible\.io/i],
  "Radix UI": [/radix-ui/i, /@radix/i],
  Shadcn: [/shadcn/i, /\bcn\(/],
  Zustand: [/zustand/i],
  "React Query": [/tanstack.*query/i, /react-query/i],
  Zod: [/\bzod\b/i, /z\.object/],
  "Google AI": [/generativelanguage\.googleapis/i, /gemini/i],
  DeepSeek: [/deepseek/i, /api\.deepseek\.com/i],
  Groq: [/groq/i, /api\.groq\.com/i],
  Replicate: [/replicate/i, /api\.replicate\.com/i],
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
    apiParams: new Map(),
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

  // Fetch JS bundles (parallel, limit to 40 for better coverage)
  const jsToFetch = target.scripts.slice(0, 40);
  const jsResults = await Promise.allSettled(
    jsToFetch.map(async (scriptUrl) => {
      const res = await scanFetch(scriptUrl, { redirect: "follow", timeoutMs: 8000 });
      const text = await res.text();
      // Skip very large bundles (>2MB) to avoid memory issues
      if (text.length > 2_000_000) return { url: scriptUrl, content: text.substring(0, 500_000) };
      return { url: scriptUrl, content: text };
    }),
  );

  for (const r of jsResults) {
    if (r.status === "fulfilled") {
      target.jsContents.set(r.value.url, r.value.content);
    }
  }

  // Discover additional JS chunks from webpack/Vite chunk references
  const allJsEarly = Array.from(target.jsContents.values()).join("\n");
  const chunkUrls = new Set<string>();
  // Webpack chunk patterns: __webpack_require__.p + "static/chunks/" + chunkId + ".js"
  for (const m of allJsEarly.matchAll(/["'](_next\/static\/chunks\/[a-zA-Z0-9._-]+\.js)["']/g)) {
    const resolved = resolveUrl(m[1], baseUrl);
    if (resolved && !target.jsContents.has(resolved)) chunkUrls.add(resolved);
  }
  // Vite dynamic imports
  for (const m of allJsEarly.matchAll(/["'](\/assets\/[a-zA-Z0-9._-]+\.js)["']/g)) {
    const resolved = resolveUrl(m[1], baseUrl);
    if (resolved && !target.jsContents.has(resolved)) chunkUrls.add(resolved);
  }
  // Fetch discovered chunks (up to 20 more)
  if (chunkUrls.size > 0) {
    const chunkResults = await Promise.allSettled(
      [...chunkUrls].slice(0, 20).map(async (chunkUrl) => {
        const res = await scanFetch(chunkUrl, { redirect: "follow", timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        if (text.length > 2_000_000) return { url: chunkUrl, content: text.substring(0, 500_000) };
        return { url: chunkUrl, content: text };
      }),
    );
    for (const r of chunkResults) {
      if (r.status === "fulfilled" && r.value) {
        target.jsContents.set(r.value.url, r.value.content);
        target.scripts.push(r.value.url);
      }
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
    /["'`](\/api\/[a-zA-Z0-9/_.-]{2,})["'`]/g,
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

  // Extract tRPC procedure names (common in vibe-coded apps)
  const trpcPatterns = [
    /trpc\.\s*([a-zA-Z]+)\.\s*(?:query|mutate|useQuery|useMutation)/g,
    /["'`]([a-zA-Z]+\.[a-zA-Z]+)["'`]\s*(?:,|\))/g, // tRPC v11: "user.getProfile"
    /api\.([a-zA-Z]+)\.([a-zA-Z]+)\s*\(/g, // trpc client: api.user.getAll()
  ];
  const trpcBase = apiFromJs.has(baseUrl + "/api/trpc") ? "/api/trpc/" : null;
  if (trpcBase || target.technologies.includes("tRPC")) {
    const prefix = trpcBase || "/api/trpc/";
    for (const pat of trpcPatterns) {
      for (const m of allJs.matchAll(pat)) {
        const proc = m[2] ? `${m[1]}.${m[2]}` : m[1];
        if (proc && proc.length < 50 && /^[a-zA-Z.]+$/.test(proc)) {
          apiFromJs.add(baseUrl + prefix + proc);
        }
      }
    }
  }

  // Extract Next.js route manifest for page discovery
  const routeManifestMatch = allJs.match(/self\.__next_f\.push\(\[[\d,]*"([^"]*(?:pages|app)[^"]*)".*?\]\)/);
  if (!routeManifestMatch) {
    // Try __BUILD_MANIFEST pattern
    const buildManifest = allJs.match(/__BUILD_MANIFEST\s*=\s*\{([^}]{100,})\}/);
    if (buildManifest) {
      for (const m of buildManifest[1].matchAll(/["'](\/?[a-zA-Z0-9/_[\]-]+)["']\s*:/g)) {
        const route = m[1].startsWith("/") ? m[1] : "/" + m[1];
        if (route.length < 80 && !route.includes("[") && !seen.has(baseUrl + route)) {
          seen.add(baseUrl + route);
          target.pages.push(baseUrl + route);
        }
      }
    }
  }

  // Extract POST body parameter names from fetch/axios calls in JS
  const bodyParamPatterns = [
    // fetch('/api/foo', { body: JSON.stringify({ name, email, password }) })
    /fetch\s*\(\s*["'`](\/api\/[^"'`]+)["'`]\s*,\s*\{[^}]*body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{2,200})\}/g,
    // axios.post('/api/foo', { name, email })
    /axios\.(?:post|put|patch)\s*\(\s*["'`](\/api\/[^"'`]+)["'`]\s*,\s*\{([^}]{2,200})\}/g,
  ];
  for (const pat of bodyParamPatterns) {
    for (const m of allJs.matchAll(pat)) {
      const endpoint = m[1];
      const paramsStr = m[2];
      if (!endpoint || !paramsStr) continue;
      // Extract parameter names from object shorthand or key:value
      const params: string[] = [];
      for (const pm of paramsStr.matchAll(/(\w+)\s*(?::|,|\})/g)) {
        const name = pm[1];
        if (name && name.length < 30 && !/^(?:true|false|null|undefined|const|let|var|function|return)$/.test(name)) {
          params.push(name);
        }
      }
      if (params.length > 0) {
        const fullUrl = baseUrl + endpoint;
        const existing = target.apiParams.get(fullUrl) || [];
        target.apiParams.set(fullUrl, [...new Set([...existing, ...params])]);
      }
    }
  }

  // JS-discovered endpoints are already confirmed from code — add them directly
  for (const ep of apiFromJs) {
    target.apiEndpoints.push(ep);
  }

  // Extract CSP from meta tags (apps that set CSP via <meta> instead of headers)
  const metaCSP = $('meta[http-equiv="Content-Security-Policy"]').attr("content");
  if (metaCSP && !target.headers["content-security-policy"]) {
    target.headers["content-security-policy"] = metaCSP;
  }

  // Run API probing, page crawling, robots/sitemap, OpenAPI discovery, and soft404 in parallel
  const apiEndpointSet = new Set(apiFromJs);
  const probeCommonPaths = COMMON_API_PATHS.map((p) => baseUrl + p).filter((p) => !apiEndpointSet.has(p));

  const [probeResults, pageResults] = await Promise.all([
    // Probe common API paths (skip ones already found in JS)
    Promise.allSettled(
      probeCommonPaths.slice(0, 50).map(async (testUrl) => {
        const res = await scanFetch(testUrl, { method: "GET", redirect: "follow", timeoutMs: 4000 });
        return { path: testUrl, status: res.status, contentType: res.headers.get("content-type") || "" };
      }),
    ),
    // Crawl discovered pages for more endpoints/forms
    Promise.allSettled(
      target.pages.slice(0, 20).map(async (pageUrl) => {
        const res = await scanFetch(pageUrl, { redirect: "follow", timeoutMs: 5000 });
        return { url: pageUrl, html: await res.text() };
      }),
    ),
    // Robots.txt + sitemap (fire and forget into target.pages)
    (async () => {
      try {
        const robotsRes = await scanFetch(baseUrl + "/robots.txt", { timeoutMs: 4000 });
        if (robotsRes.status !== 200) return;
        const robotsTxt = await robotsRes.text();
        if (robotsTxt.includes("<!DOCTYPE") || robotsTxt.includes("<html")) return;
        const sitemapUrls: string[] = [];
        for (const line of robotsTxt.split("\n")) {
          const disallow = line.match(/^Disallow:\s*(.+)/i)?.[1]?.trim();
          if (disallow && disallow !== "/" && disallow.startsWith("/")) {
            const resolved = baseUrl + disallow;
            if (!seen.has(resolved)) { seen.add(resolved); target.pages.push(resolved); }
          }
          const sitemap = line.match(/^Sitemap:\s*(.+)/i)?.[1]?.trim();
          if (sitemap) sitemapUrls.push(sitemap);
        }
        await Promise.allSettled(sitemapUrls.slice(0, 3).map(async (smUrl) => {
          const smRes = await scanFetch(smUrl, { timeoutMs: 4000 });
          if (smRes.status !== 200) return;
          const smText = await smRes.text();
          let count = 0;
          for (const m of smText.matchAll(/<loc>([^<]+)<\/loc>/g)) {
            if (count++ > 50) break;
            const u = m[1];
            if (u.startsWith(baseUrl) && !seen.has(u)) { seen.add(u); target.pages.push(u); }
          }
        }));
      } catch {}
    })(),
    // OpenAPI/Swagger spec discovery — extract all API endpoints from exposed specs
    (async () => {
      try {
        const specResults = await Promise.allSettled(
          OPENAPI_PATHS.map(async (p) => {
            const res = await scanFetch(baseUrl + p, { timeoutMs: 4000 });
            if (!res.ok) return null;
            const ct = res.headers.get("content-type") || "";
            // Must be JSON — skip HTML responses (common for 200 soft-404s)
            if (ct.includes("text/html")) return null;
            const text = await res.text();
            if (!text.startsWith("{") && !text.startsWith("[")) return null;
            return { path: p, body: text };
          }),
        );
        for (const r of specResults) {
          if (r.status !== "fulfilled" || !r.value) continue;
          try {
            const spec = JSON.parse(r.value.body);
            // OpenAPI 3.x: spec.paths or OpenAPI 2.x (Swagger): spec.paths
            const paths = spec.paths;
            if (!paths || typeof paths !== "object") continue;
            const basePath = spec.basePath || "";
            for (const [path, methods] of Object.entries(paths)) {
              if (typeof methods !== "object" || !methods) continue;
              const fullPath = basePath + path;
              // Replace path parameters: /users/{id} → /users/1
              const normalized = fullPath.replace(/\{[^}]+\}/g, "1");
              const ep = baseUrl + normalized;
              if (!apiEndpointSet.has(ep)) {
                apiEndpointSet.add(ep);
                target.apiEndpoints.push(ep);
              }
              // Extract parameter names from spec
              for (const method of Object.values(methods as Record<string, unknown>)) {
                if (!method || typeof method !== "object") continue;
                const params = (method as Record<string, unknown>).parameters;
                if (!Array.isArray(params)) continue;
                const paramNames: string[] = [];
                for (const param of params) {
                  if (param && typeof param === "object" && "name" in param) {
                    paramNames.push(String((param as { name: unknown }).name));
                  }
                }
                if (paramNames.length > 0) {
                  const existing = target.apiParams.get(ep) || [];
                  target.apiParams.set(ep, [...new Set([...existing, ...paramNames])]);
                }
              }
            }
            // Exposed spec is itself a finding-worthy discovery — flag the path
            if (!apiEndpointSet.has(baseUrl + r.value.path)) {
              target.apiEndpoints.push(baseUrl + r.value.path);
            }
          } catch { /* malformed JSON */ }
          break; // Only need one valid spec
        }
      } catch {}
    })(),
    // Soft 404 detection + SPA detection
    (async () => {
      try {
        const canaryUrl = baseUrl + "/vibeshield-canary-404-test-" + Date.now();
        const canaryRes = await scanFetch(canaryUrl, { redirect: "follow", timeoutMs: 4000 });
        if (canaryRes.status === 200) {
          target.soft404Body = await canaryRes.text();
          const ratio = target.soft404Body.length / html.length;
          target.isSpa = ratio > 0.7 && ratio < 1.3;
        }
      } catch {}
      // Enhanced SPA detection via framework markers
      if (!target.isSpa) {
        const spaMarkers = [
          /<div\s+id="__next"/i, /<div\s+id="root"/i, /<div\s+id="app"/i,
          /window\.__NEXT_DATA__/i, /window\.__NUXT__/i, /window\.__remixContext/i,
        ];
        if (spaMarkers.some((m) => m.test(html))) target.isSpa = true;
      }
    })(),
  ]);

  for (const r of probeResults) {
    if (r.status !== "fulfilled") continue;
    const { status, contentType, path: probePath } = r.value;
    if (status === 404) continue;
    if (status === 200 && contentType.includes("text/html")) continue;
    if (status === 200 && !contentType) continue;
    target.apiEndpoints.push(probePath);
  }

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
    // Extract forms from crawled pages too
    p$("form").each((_, el) => {
      const form: FormField = {
        action: p$(el).attr("action") || r.value.url,
        method: (p$(el).attr("method") || "GET").toUpperCase(),
        inputs: [],
      };
      p$(el).find("input, textarea, select").each((_, inp) => {
        form.inputs.push({ name: p$(inp).attr("name") || "", type: p$(inp).attr("type") || "text" });
      });
      if (form.inputs.length > 0) target.forms.push(form);
    });
  }

  // Extract __NEXT_DATA__ for additional routes and props
  const nextDataMatch = html.match(/<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/i);
  if (nextDataMatch) {
    try {
      const nextData = JSON.parse(nextDataMatch[1]);
      // Extract dynamic routes from buildManifest
      if (nextData.buildId) {
        const routePages = Object.keys(nextData.page ? { [nextData.page]: true } : {});
        for (const route of routePages) {
          const resolved = baseUrl + route;
          if (!seen.has(resolved)) { seen.add(resolved); target.pages.push(resolved); }
        }
      }
      // Extract API endpoints from props (common pattern: pages fetch data in getServerSideProps)
      const propsStr = JSON.stringify(nextData.props || {});
      for (const m of propsStr.matchAll(/["'](\/api\/[a-zA-Z0-9/_.-]+)["']/g)) {
        const ep = baseUrl + m[1];
        if (!target.apiEndpoints.includes(ep)) target.apiEndpoints.push(ep);
      }
    } catch { /* malformed JSON */ }
  }

  // Extract hash-based routes from JS bundles (SPA hash routing: /#/dashboard, /#/settings)
  const hashRoutes = new Set<string>();
  for (const m of allJs.matchAll(/["'`](#\/[a-zA-Z0-9/_-]{2,50})["'`]/g)) {
    hashRoutes.add(m[1]);
  }
  // Hash routes can hint at API endpoints (/#/users → /api/users)
  for (const hashRoute of hashRoutes) {
    const path = hashRoute.replace(/^#/, "");
    const apiGuess = baseUrl + "/api" + path;
    if (!target.apiEndpoints.includes(apiGuess)) {
      // Don't probe — just note it as a discovered page path
      const pagePath = baseUrl + path;
      if (!seen.has(pagePath)) { seen.add(pagePath); target.pages.push(pagePath); }
    }
  }

  // Deduplicate API endpoints
  target.apiEndpoints = [...new Set(target.apiEndpoints)];

  return target;
};

const resolveUrl = (href: string, base: string): string | null => {
  try {
    if (href.startsWith("javascript:") || href.startsWith("mailto:")) return null;
    if (href.startsWith("#")) return null; // hash-only links handled separately in recon
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
