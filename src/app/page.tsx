"use client";

import { useState, useEffect, type FormEvent } from "react";
import { useRouter } from "next/navigation";

const ATTACK_MODULES = [
  { name: "Secret Detection", desc: "API keys, tokens, passwords in JS bundles", icon: "🔑" },
  { name: "Supabase RLS", desc: "Test Row Level Security with anon key", icon: "🛡" },
  { name: "Firebase Rules", desc: "Test Firestore & RTDB read/write access", icon: "🔥" },
  { name: "Auth Bypass", desc: "Access API endpoints without authentication", icon: "🚪" },
  { name: "IDOR", desc: "Sequential ID enumeration on all endpoints", icon: "🔢" },
  { name: "SQL Injection", desc: "SQLi payloads + time-based blind injection", icon: "💉" },
  { name: "XSS", desc: "Reflected cross-site scripting on all inputs", icon: "📜" },
  { name: "SSTI", desc: "Server-Side Template Injection detection", icon: "⚙" },
  { name: "CORS Misconfig", desc: "Test for wildcard and reflected origins", icon: "🌐" },
  { name: "JWT Analysis", desc: "alg:none bypass, weak secrets, no expiry", icon: "🎫" },
  { name: "Source Maps", desc: "Check if .map files expose source code", icon: "🗺" },
  { name: "Directory Exposure", desc: ".env, .git, backup files, admin panels", icon: "📁" },
  { name: "GraphQL", desc: "Schema exposure, depth limits, batching", icon: "◈" },
  { name: "Stripe Webhook", desc: "Unverified webhooks, price manipulation", icon: "💳" },
  { name: "Next.js Specific", desc: "Middleware bypass, RSC data leaks, SSR props", icon: "▲" },
  { name: "Open Redirect", desc: "Redirect parameter abuse on all endpoints", icon: "↗" },
  { name: "CSRF", desc: "Cross-site request forgery protection", icon: "🔄" },
  { name: "Email Enumeration", desc: "User existence disclosure via auth", icon: "📧" },
  { name: "Cookie Security", desc: "HttpOnly, Secure, SameSite flags", icon: "🍪" },
  { name: "Security Headers", desc: "CSP, HSTS, X-Frame-Options, and more", icon: "📋" },
  { name: "SSL/TLS", desc: "HTTPS, cert validity, mixed content", icon: "🔒" },
  { name: "WebSocket", desc: "Unencrypted WS, unauthenticated sockets", icon: "🔌" },
  { name: "Clickjacking", desc: "Frame protection and embedding policies", icon: "🖼" },
  { name: "HTTP Methods", desc: "TRACE, DEBUG, and other dangerous methods", icon: "📡" },
  { name: "Info Leakage", desc: "Stack traces, server paths in error responses", icon: "💬" },
  { name: "Load Test", desc: "Ramp to 100 concurrent users, find breaking point", icon: "📈" },
  { name: "Race Conditions", desc: "20 simultaneous requests on state-changing endpoints", icon: "🏁" },
  { name: "Rate Limiting", desc: "50 rapid-fire requests on auth & AI endpoints", icon: "⏱" },
  { name: "Cost Attack", desc: "Estimate $/hour of API abuse on serverless", icon: "💸" },
  { name: "Error Leak Under Stress", desc: "Verbose errors when server overloaded", icon: "🔥" },
  { name: "Connection Exhaustion", desc: "100 sustained connections, measure degradation", icon: "🔌" },
  { name: "Exposed Dev Tools", desc: "Prisma Studio, Swagger, Storybook, debug endpoints", icon: "🔧" },
  { name: "API Security", desc: "Prototype pollution, over-fetching, mass assignment", icon: "🧬" },
  { name: "Env Variable Leak", desc: "Exposed env vars, dev configs, localhost URLs", icon: "🔐" },
  { name: "AI/LLM Security", desc: "Prompt injection, system prompt leak, unauthed AI", icon: "🤖" },
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
  const [visibleModules, setVisibleModules] = useState(0);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const router = useRouter();

  useEffect(() => {
    const timer = setInterval(() => {
      setVisibleModules((prev) => (prev < ATTACK_MODULES.length ? prev + 1 : prev));
    }, 40);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const load = () => fetch("/api/scans").then((r) => r.json()).then(setRecentScans).catch(() => {});
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!res.ok) {
        const data = await res.json();
        setError(data.error || "Failed to start scan");
        setLoading(false);
        return;
      }

      const data = await res.json();
      router.push(`/scan/${data.id}`);
    } catch {
      setError("Failed to connect. Is the server running?");
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

            <p className="text-xs text-zinc-600 mt-3">
              No signup required. No code access needed. We scan the live app from the outside.
            </p>
          </form>
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
                { label: "Avg Grade", value: (() => { const grades = recentScans.filter((s) => s.status === "completed").map((s) => s.grade); const gMap: Record<string, number> = { A: 95, "A-": 90, "B+": 85, B: 80, "C+": 75, C: 70, "D+": 65, D: 60, F: 40 }; const avg = grades.reduce((a, g) => a + (gMap[g] || 50), 0) / grades.length; if (avg >= 90) return "A"; if (avg >= 80) return "B"; if (avg >= 70) return "C"; if (avg >= 60) return "D"; return "F"; })() },
              ].map((stat) => (
                <div key={stat.label} className="text-center">
                  <div className="text-2xl font-bold text-zinc-200">{stat.value}</div>
                  <div className="text-[10px] text-zinc-600 uppercase tracking-wider">{stat.label}</div>
                </div>
              ))}
            </div>
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
              { step: "3", title: "Get your report", desc: "Severity-ranked findings with evidence and exact fix instructions." },
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
