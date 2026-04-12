import { NextResponse, type NextRequest } from "next/server";

/** Allowed CORS origins — same-origin + env-configured origins */
const ALLOWED_ORIGINS = (() => {
  const origins = new Set<string>();
  const appUrl = process.env.NEXT_PUBLIC_URL;
  if (appUrl) try { origins.add(new URL(appUrl).origin); } catch {}
  const extra = process.env.VIBESHIELD_CORS_ORIGINS;
  if (extra) extra.split(",").map(s => s.trim()).filter(Boolean).forEach(o => origins.add(o));
  if (process.env.NODE_ENV !== "production") {
    origins.add("http://localhost:3000");
    origins.add("http://localhost:3001");
  }
  return origins;
})();

/**
 * Security middleware — sets best-practice headers on all responses.
 * VibeShield eats its own dog food.
 */
export function middleware(req: NextRequest) {
  const res = NextResponse.next();
  const headers = res.headers;

  // Request ID for observability
  const requestId = req.headers.get("x-request-id") || crypto.randomUUID();
  headers.set("X-Request-Id", requestId);

  // Server timing (helps debug slow requests)
  headers.set("Server-Timing", `edge;desc="middleware"`);

  // Core security headers
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-XSS-Protection", "0"); // Modern browsers use CSP, this header can introduce issues
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()");

  // HSTS — only on HTTPS
  if (req.nextUrl.protocol === "https:") {
    headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }

  // Cross-origin isolation headers
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");

  // CSP — permissive enough for the app but still protective
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Next.js requires these
    "style-src 'self' 'unsafe-inline'", // Tailwind inline styles
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
  headers.set("Content-Security-Policy", csp);

  // API endpoints get CORS headers
  if (req.nextUrl.pathname.startsWith("/api/")) {
    headers.set("X-Frame-Options", "DENY");
    const origin = req.headers.get("origin");
    if (origin && ALLOWED_ORIGINS.has(origin)) {
      headers.set("Access-Control-Allow-Origin", origin);
      headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key");
      headers.set("Access-Control-Max-Age", "86400");
    }

    // Handle CORS preflight
    if (req.method === "OPTIONS") {
      return new NextResponse(null, { status: 204, headers });
    }
  }

  return res;
}

export const config = {
  matcher: [
    // Match all paths except static files and Next.js internals
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
