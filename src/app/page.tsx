"use client";

import { useState, useEffect, type FormEvent } from "react";
import { useRouter } from "next/navigation";

const ATTACK_MODULES = [
  { name: "Secret Detection", desc: "API keys, tokens, passwords in JS bundles", icon: "🔑" },
  { name: "Supabase RLS", desc: "RLS bypass, RPC enum, edge function auth, realtime leaks", icon: "🛡" },
  { name: "Firebase Rules", desc: "Firestore/RTDB rules, Cloud Functions auth, service account leak", icon: "🔥" },
  { name: "Auth Bypass", desc: "Path traversal, case bypass, verb tampering, token validation", icon: "🚪" },
  { name: "IDOR", desc: "Sequential ID enum, method-based access, privilege escalation", icon: "🔢" },
  { name: "SQL Injection", desc: "SQLi payloads + time-based blind injection", icon: "💉" },
  { name: "XSS", desc: "Reflected XSS + DOM source/sink analysis on JS bundles", icon: "📜" },
  { name: "SSTI", desc: "Server-Side Template Injection detection", icon: "⚙" },
  { name: "CORS Misconfig", desc: "Test for wildcard and reflected origins", icon: "🌐" },
  { name: "JWT Analysis", desc: "alg:none bypass, JWK injection, kid abuse, missing aud/iss", icon: "🎫" },
  { name: "Source Maps", desc: "Inline/external maps, SourceMap headers, build manifests, env leak detection", icon: "🗺" },
  { name: "Directory Exposure", desc: ".env, .git, backup files, admin panels", icon: "📁" },
  { name: "GraphQL", desc: "Introspection, depth/alias abuse, subscription leak, APQ bypass", icon: "◈" },
  { name: "Stripe Webhook", desc: "Unverified webhooks, price tampering, coupon abuse, plan hijacking", icon: "💳" },
  { name: "Next.js Specific", desc: "Middleware bypass, RSC leaks, preview tokens, catch-all routes, Server Action fuzzing", icon: "▲" },
  { name: "Open Redirect", desc: "15 bypass variants, meta refresh, JS redirect, fragment-based", icon: "↗" },
  { name: "CSRF", desc: "Login CSRF, double-submit bypass, Referer evasion, content-type confusion", icon: "🔄" },
  { name: "Email Enumeration", desc: "User existence disclosure via auth", icon: "📧" },
  { name: "Session Security", desc: "Token in URL, logout invalidation, localStorage storage, concurrent sessions", icon: "🔐" },
  { name: "Cookie Security", desc: "HttpOnly, Secure, SameSite, __Host- prefix, cookie tossing", icon: "🍪" },
  { name: "Security Headers", desc: "CSP, HSTS, X-Frame-Options, and more", icon: "📋" },
  { name: "SSL/TLS", desc: "HTTPS, cert validity, mixed content", icon: "🔒" },
  { name: "WebSocket", desc: "WS auth, CSWSH, Ably/Pusher/PartyKit/Liveblocks detection", icon: "🔌" },
  { name: "Clickjacking", desc: "Frame protection, ALLOW-FROM bypass, JS frame-busting detection", icon: "🖼" },
  { name: "HTTP Methods", desc: "TRACE, method override, unauthenticated PUT/PATCH/DELETE", icon: "📡" },
  { name: "Info Leakage", desc: "Stack traces, env var leak, internal URLs, verbose errors", icon: "💬" },
  { name: "Load Test", desc: "Ramp to 100 concurrent users, find breaking point", icon: "📈" },
  { name: "Race Conditions", desc: "Double-spend, idempotency bypass, signup race, TOCTOU", icon: "🏁" },
  { name: "Rate Limiting", desc: "50 rapid-fire requests, IP header bypass, forgotten endpoint detection", icon: "⏱" },
  { name: "Cost Attack", desc: "AI API, serverless, email/SMS, image transform cost estimation", icon: "💸" },
  { name: "Error Leak Under Stress", desc: "Verbose errors when server overloaded", icon: "🔥" },
  { name: "Connection Exhaustion", desc: "Slowloris, HTTP rapid flood, 200 concurrent connections", icon: "🔌" },
  { name: "Exposed Dev Tools", desc: "Prisma/Drizzle Studio, Grafana, Redis, MinIO, MailHog, Swagger, Storybook", icon: "🔧" },
  { name: "API Security", desc: "Prototype pollution, over-fetching, mass assignment", icon: "🧬" },
  { name: "Env Variable Leak", desc: "Exposed env vars, dev configs, localhost URLs", icon: "🔐" },
  { name: "AI/LLM Security", desc: "Prompt injection, system prompt leak, model switching, token abuse", icon: "🤖" },
  { name: "SSRF", desc: "Cloud metadata, IAM creds, blind timing, Redis, file://, filter bypasses", icon: "🌀" },
  { name: "File Upload", desc: "HTML/SVG XSS, polyglot bypass, null byte, double extension, dir listing", icon: "📤" },
  { name: "CRLF Injection", desc: "Header/cookie/path injection, response splitting, POST body CRLF", icon: "↵" },
  { name: "Host Header", desc: "DNS rebinding, port/double Host injection, IP spoofing, password reset poisoning", icon: "🏠" },
  { name: "Subdomain Takeover", desc: "CT log discovery, wildcard DNS, common subdomain enumeration", icon: "🌐" },
  { name: "Dependencies", desc: "Detect vulnerable JS library versions in bundles", icon: "📦" },
  { name: "Path Traversal", desc: "Unicode/UTF-8 overlong, double encoding, null byte, URL path traversal", icon: "📂" },
  { name: "Command Injection", desc: "Time-based + output-based, IFS/brace/quote filter evasion", icon: "💀" },
  { name: "NoSQL Injection", desc: "MongoDB operator injection, auth bypass, prototype pollution", icon: "🍃" },
  { name: "Cache Poisoning", desc: "CDN poisoning, cache deception, unkeyed param XSS, method override", icon: "🧊" },
  { name: "Business Logic", desc: "Negative values, zero-price, integer overflow, coupon stacking", icon: "🧮" },
  { name: "OAuth/OIDC", desc: "Redirect URI bypass variants, PKCE, nonce, implicit flow", icon: "🔐" },
  { name: "API Versioning", desc: "Hidden versions, path bypass, endpoint shadowing", icon: "🔀" },
  { name: "CSP Analysis", desc: "Unsafe directives, CDN/JSONP bypasses, Trusted Types, nonce checks", icon: "🛡" },
  { name: "Cloud Storage", desc: "Bucket listing, write access, CORS, ACL exposure, presigned URL leaks", icon: "☁" },
  { name: "Privacy & Tracking", desc: "Session recording, ad pixels, fingerprinting, consent gaps, PII in URLs", icon: "👁" },
  { name: "Request Smuggling", desc: "CL.TE desync, hop-by-hop header abuse, method override bypass, WS upgrade", icon: "🔀" },
  { name: "Response Security", desc: "MIME confusion, content-disposition, sensitive caching, error stack leaks", icon: "📨" },
  { name: "Type Confusion", desc: "JSON type coercion, content-type confusion, server prototype pollution, XXE", icon: "🔄" },
  { name: "DNS & Email Security", desc: "SPF/DMARC analysis, CAA records, dangling CNAMEs, security.txt", icon: "🌐" },
];

interface RecentScan {
  id: string;
  target: string;
  grade: string;
  status: string;
  findings: number;
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
}

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-400 border-green-500/30", "A-": "text-green-400 border-green-500/30",
  "B+": "text-lime-400 border-lime-500/30", B: "text-lime-400 border-lime-500/30",
  "C+": "text-yellow-400 border-yellow-500/30", C: "text-yellow-400 border-yellow-500/30",
  "D+": "text-orange-400 border-orange-500/30", D: "text-orange-400 border-orange-500/30",
  F: "text-red-400 border-red-500/30",
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"full" | "security" | "quick">("full");
  const [visibleModules, setVisibleModules] = useState(0);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [stats, setStats] = useState<{ totalScans: number; totalFindings: number; uniqueTargets: number } | null>(null);
  const router = useRouter();

  useEffect(() => {
    const timer = setInterval(() => {
      setVisibleModules((prev) => (prev < ATTACK_MODULES.length ? prev + 2 : prev));
    }, 25);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    fetch("/api/stats").then((r) => r.json()).then(setStats).catch(() => {});
  }, []);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch("/api/scans");
        const serverScans: RecentScan[] = await res.json();
        // Merge server scans with localStorage history
        const stored: RecentScan[] = JSON.parse(localStorage.getItem("vibeshield-history") || "[]");
        const merged = new Map<string, RecentScan>();
        for (const s of stored) merged.set(s.id, s);
        for (const s of serverScans) merged.set(s.id, s); // server data takes priority
        const all = [...merged.values()].slice(0, 20);
        // Persist completed scans to localStorage
        const toStore = all.filter((s) => s.status === "completed" || s.status === "failed").slice(0, 20);
        localStorage.setItem("vibeshield-history", JSON.stringify(toStore));
        setRecentScans(all);
      } catch {
        // Fallback to localStorage only
        try {
          const stored: RecentScan[] = JSON.parse(localStorage.getItem("vibeshield-history") || "[]");
          if (stored.length > 0) setRecentScans(stored);
        } catch { /* skip */ }
      }
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  const normalizeUrl = (input: string): string => {
    let u = input.trim();
    if (!u) return u;
    // Auto-prepend https:// if no protocol
    if (!/^https?:\/\//i.test(u)) u = `https://${u}`;
    return u;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const normalized = normalizeUrl(url);
    if (!normalized) return;

    // Client-side validation
    try {
      const parsed = new URL(normalized);
      if (!parsed.hostname.includes(".") && parsed.hostname !== "localhost") {
        setError("Enter a valid URL like https://your-app.vercel.app");
        return;
      }
    } catch {
      setError("Enter a valid URL like https://your-app.vercel.app");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized, mode }),
      });

      if (!res.ok) {
        const data = await res.json();
        const msg = data.error || "Failed to start scan";
        // Friendlier error messages
        if (res.status === 429) {
          setError("Too many scans recently — wait a minute and try again.");
        } else if (msg.includes("private") || msg.includes("local")) {
          setError("Can't scan local/private addresses. Enter a public URL.");
        } else {
          setError(msg);
        }
        setLoading(false);
        return;
      }

      const data = await res.json();
      router.push(`/scan/${data.id}`);
    } catch (err) {
      setError(err instanceof TypeError ? "Network error — check your connection and try again." : "Failed to start scan. Please try again.");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* Subtle grid background */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,0.015)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.015)_1px,transparent_1px)] bg-[size:64px_64px] pointer-events-none" />
      <div className="fixed inset-0 bg-radial-[ellipse_at_top] from-red-950/20 via-transparent to-transparent pointer-events-none" />

      {/* Nav */}
      <nav className="relative z-10 border-b border-zinc-800/50 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
            VibeShield
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-zinc-600 hidden sm:block">Black-box pentesting for vibe-coded apps</span>
            <a href="/scans" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">All Scans</a>
            <a href="/docs" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">API</a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <main className="relative z-10 flex-1 flex flex-col items-center justify-center px-4 py-16">
        <div className="max-w-3xl w-full text-center space-y-6">
          <div className="inline-flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-full px-4 py-1.5 text-red-400 text-sm font-medium">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
            </span>
            {ATTACK_MODULES.length} attack modules &middot; Security + Stress testing
          </div>

          <h1 className="text-5xl sm:text-7xl font-black tracking-tight leading-none">
            <span className="text-transparent bg-clip-text bg-linear-to-r from-red-500 via-orange-400 to-amber-300">
              Pentest
            </span>
            <br />
            <span className="text-zinc-100">your vibe-coded app</span>
          </h1>

          <p className="text-lg sm:text-xl text-zinc-400 max-w-xl mx-auto leading-relaxed">
            Paste a URL. We run {ATTACK_MODULES.length} attack modules against your live app.
            No code access needed. Results in minutes.
          </p>

          {stats && stats.totalScans > 0 && (
            <div className="flex items-center justify-center gap-6 text-xs text-zinc-600">
              <span><span className="text-zinc-400 font-medium tabular-nums">{stats.totalScans}</span> scans run</span>
              <span><span className="text-zinc-400 font-medium tabular-nums">{stats.totalFindings}</span> vulnerabilities found</span>
              <span><span className="text-zinc-400 font-medium tabular-nums">{stats.uniqueTargets}</span> apps tested</span>
            </div>
          )}

          {/* Scan form */}
          <form onSubmit={handleSubmit} className="mt-8 max-w-xl mx-auto">
            <div className="flex gap-2 bg-zinc-900/80 border border-zinc-800 rounded-xl p-1.5 backdrop-blur focus-within:border-red-500/40 focus-within:ring-1 focus-within:ring-red-500/20 transition-all">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://your-app.vercel.app"
                className="flex-1 bg-transparent px-4 py-3 text-zinc-100 placeholder-zinc-600 focus:outline-none text-sm sm:text-base"
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 disabled:from-zinc-800 disabled:to-zinc-800 disabled:text-zinc-600 text-white font-semibold px-5 sm:px-8 py-3 rounded-lg transition-all whitespace-nowrap text-sm sm:text-base"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Scanning...
                  </span>
                ) : (
                  "Scan Now"
                )}
              </button>
            </div>

            {error && (
              <p className="text-red-400 text-sm mt-3">{error}</p>
            )}

            <div className="flex items-center justify-center gap-4 mt-3">
              <p className="text-xs text-zinc-600">
                No signup required. No code access needed.
              </p>
              <div className="flex items-center bg-zinc-900/50 border border-zinc-800/50 rounded-lg overflow-hidden">
                {([
                  { key: "quick" as const, label: "Quick (~10s)", title: "13 modules: headers, SSL, secrets, CORS, cookies, CSP, dependencies, source maps" },
                  { key: "security" as const, label: "Security (~45s)", title: "48 modules: all security checks including injection, auth bypass, SSRF, IDOR" },
                  { key: "full" as const, label: "Full + Stress (~90s)", title: "54 modules: everything + load testing, race conditions, rate limit checks" },
                ]).map((m) => (
                  <button
                    key={m.key}
                    type="button"
                    onClick={() => setMode(m.key)}
                    title={m.title}
                    className={`text-[10px] px-2.5 py-1 transition-colors ${mode === m.key ? "bg-zinc-800 text-zinc-300" : "text-zinc-600 hover:text-zinc-400"}`}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>

            {!loading && (
              <div className="flex items-center justify-center gap-2 mt-3">
                <span className="text-[10px] text-zinc-700">Try:</span>
                {["https://bolt.new", "https://lovable.dev", "https://cal.com"].map((demo) => (
                  <button
                    key={demo}
                    onClick={() => setUrl(demo)}
                    className="text-[10px] text-zinc-600 hover:text-zinc-400 transition-colors underline underline-offset-2"
                  >
                    {new URL(demo).hostname}
                  </button>
                ))}
              </div>
            )}
          </form>

          {/* Trust badges */}
          <div className="flex flex-wrap items-center justify-center gap-3 mt-8">
            {[
              "OWASP Top 10",
              "Code Fixes",
              "SARIF Export",
              "CI/CD Ready",
              "Zero Config",
            ].map((badge) => (
              <span key={badge} className="text-[10px] font-medium text-zinc-500 bg-zinc-900/50 border border-zinc-800/50 rounded-full px-3 py-1">
                {badge}
              </span>
            ))}
          </div>
        </div>

        {/* Recent scans */}
        {recentScans.length > 0 && (
          <div className="mt-16 max-w-3xl w-full px-4">
            <a href="/scans" className="block text-center text-zinc-600 text-xs font-semibold uppercase tracking-widest mb-4 hover:text-zinc-400 transition-colors">
              Recent Scans →
            </a>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {recentScans.slice(0, 6).map((s) => (
                <a
                  key={s.id}
                  href={`/scan/${s.id}`}
                  className="bg-zinc-900/50 border border-zinc-800/50 rounded-lg px-4 py-3 flex items-center gap-3 hover:border-zinc-700/50 transition-colors"
                >
                  {s.status === "scanning" || s.status === "queued" ? (
                    <svg className="animate-spin h-6 w-6 text-red-500 shrink-0" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : (
                    <div className={`text-2xl font-black ${GRADE_COLORS[s.grade]?.split(" ")[0] || "text-zinc-600"}`}>
                      {s.grade}
                    </div>
                  )}
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-zinc-300 truncate">
                      {(() => { try { return new URL(s.target).hostname; } catch { return s.target; } })()}
                    </div>
                    <div className="text-xs text-zinc-600">
                      {s.status === "scanning" ? (
                        <span className="text-red-400">Scanning...</span>
                      ) : (
                        <>
                          {s.findings} findings
                          {s.summary.high > 0 && <span className="text-orange-400"> &middot; {s.summary.high} high</span>}
                          {s.summary.critical > 0 && <span className="text-red-400"> &middot; {s.summary.critical} critical</span>}
                        </>
                      )}
                    </div>
                  </div>
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Stats */}
        {recentScans.filter((s) => s.status === "completed").length > 0 && (
          <div className="mt-16 max-w-3xl w-full px-4">
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: "Apps Scanned", value: recentScans.filter((s) => s.status === "completed").length },
                { label: "Vulns Found", value: recentScans.filter((s) => s.status === "completed").reduce((acc, s) => acc + s.findings, 0) },
                { label: "Avg Score", value: (() => { const completed = recentScans.filter((s) => s.status === "completed"); const gMap: Record<string, number> = { A: 95, "A-": 90, "B+": 85, B: 80, "C+": 75, C: 70, "D+": 65, D: 60, F: 40 }; return completed.length > 0 ? Math.round(completed.reduce((a, s) => a + (gMap[s.grade] || 50), 0) / completed.length) : "-"; })() },
              ].map((stat) => (
                <div key={stat.label} className="text-center">
                  <div className="text-2xl font-bold text-zinc-200">{stat.value}</div>
                  <div className="text-[10px] text-zinc-600 uppercase tracking-wider">{stat.label}</div>
                </div>
              ))}
            </div>
            {/* Grade distribution bar */}
            {(() => {
              const completed = recentScans.filter((s) => s.status === "completed");
              if (completed.length < 2) return null;
              const gradeGroups: Record<string, { count: number; color: string }> = {
                "A/A-": { count: completed.filter((s) => s.grade === "A" || s.grade === "A-").length, color: "bg-green-500" },
                "B/B+": { count: completed.filter((s) => s.grade === "B" || s.grade === "B+").length, color: "bg-lime-500" },
                "C/C+": { count: completed.filter((s) => s.grade === "C" || s.grade === "C+").length, color: "bg-yellow-500" },
                "D/D+": { count: completed.filter((s) => s.grade === "D" || s.grade === "D+").length, color: "bg-orange-500" },
                "F": { count: completed.filter((s) => s.grade === "F").length, color: "bg-red-500" },
              };
              const nonEmpty = Object.entries(gradeGroups).filter(([, v]) => v.count > 0);
              if (nonEmpty.length === 0) return null;
              return (
                <div className="mt-4">
                  <div className="flex h-2 rounded-full overflow-hidden bg-zinc-800/50">
                    {nonEmpty.map(([label, { count, color }]) => (
                      <div key={label} className={`${color} transition-all`} style={{ width: `${(count / completed.length) * 100}%` }} title={`${label}: ${count}`} />
                    ))}
                  </div>
                  <div className="flex justify-center gap-3 mt-2">
                    {nonEmpty.map(([label, { count, color }]) => (
                      <div key={label} className="flex items-center gap-1 text-[10px] text-zinc-600">
                        <span className={`w-2 h-2 rounded-full ${color}`} />
                        {label} ({count})
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* Attack modules grid */}
        <div className="mt-20 max-w-5xl w-full px-4">
          <h2 className="text-center text-zinc-600 text-xs font-semibold uppercase tracking-widest mb-2">
            What We Test
          </h2>
          <p className="text-center text-zinc-500 text-sm mb-8">
            Every scan runs all {ATTACK_MODULES.length} modules against your app
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {ATTACK_MODULES.map((mod, i) => (
              <div
                key={mod.name}
                className={`bg-zinc-900/30 border border-zinc-800/30 rounded-lg px-3 py-2.5 hover:border-zinc-700/50 hover:bg-zinc-900/60 transition-all duration-300 ${
                  i < visibleModules ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="text-xs">{mod.icon}</span>
                  <span className="text-sm font-medium text-zinc-300">{mod.name}</span>
                </div>
                <div className="text-xs text-zinc-600 mt-0.5 pl-5">{mod.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* How it works */}
        <div className="mt-20 max-w-3xl w-full px-4">
          <h2 className="text-center text-zinc-600 text-xs font-semibold uppercase tracking-widest mb-8">
            How It Works
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
            {[
              { step: "1", title: "Paste your URL", desc: "Any live web app. No code access, no agents to install." },
              { step: "2", title: "We attack it", desc: `${ATTACK_MODULES.length} modules run in parallel. Recon, security checks, and stress tests.` },
              { step: "3", title: "Get your report", desc: "Severity-ranked findings with evidence, copy-paste code fixes, and export to PDF/SARIF." },
            ].map((item) => (
              <div key={item.step} className="text-center">
                <div className="inline-flex items-center justify-center w-10 h-10 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 font-bold text-sm mb-3">
                  {item.step}
                </div>
                <h3 className="text-sm font-semibold text-zinc-200 mb-1">{item.title}</h3>
                <p className="text-xs text-zinc-500 leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-zinc-800/50 text-center py-6 text-zinc-700 text-xs">
        VibeShield — Ship with confidence, not with vulnerabilities.
      </footer>
    </div>
  );
}
