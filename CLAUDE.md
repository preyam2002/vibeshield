# VibeShield

Black-box security scanner for vibe-coded web apps. Paste a URL, get a pentest report with 54 attack modules.

## Tech Stack

- **Framework**: Next.js 16, React 19, TypeScript (strict)
- **Styling**: Tailwind CSS v4
- **Storage**: In-memory Map (primary) + SQLite via better-sqlite3 (persistence) + Upstash Redis (optional)
- **Parsing**: Cheerio (DOM), native Fetch
- **Deploy**: Docker (multi-stage), Vercel
- **Testing**: Vitest

## Project Structure

```
src/
├── app/
│   ├── page.tsx              # Landing page with scan form
│   ├── scan/[id]/page.tsx    # Scan results page (~1100 lines, largest file)
│   ├── scans/page.tsx        # All scans list with filters/sort
│   ├── dashboard/page.tsx    # Dashboard with scheduled scans, domain health
│   ├── compare/page.tsx      # Side-by-side scan comparison
│   ├── docs/page.tsx         # API documentation page
│   └── api/
│       ├── scan/route.ts          # POST to start scan
│       ├── scan/[id]/route.ts     # GET result, DELETE cancel/delete
│       ├── scan/[id]/pdf/         # PDF export
│       ├── scan/[id]/sarif/       # SARIF export
│       ├── scan/[id]/csv/         # CSV export
│       ├── scan/[id]/junit/       # JUnit XML export
│       ├── scan/[id]/badge/       # SVG badge
│       ├── scan/[id]/remediation/ # Remediation plan
│       ├── scan/[id]/github-action/ # GH Action YAML
│       ├── scan/schedule/         # Scheduled scans CRUD
│       ├── scan/bulk/             # Bulk scan
│       ├── scan/suppressions/     # Finding suppressions
│       ├── scan/policies/         # Scan policies
│       ├── scan/compare/          # Comparison API
│       ├── scan/modules/          # Module listing
│       ├── scans/                 # List all scans
│       ├── stats/                 # Aggregate stats
│       └── health/                # Health check
├── lib/
│   ├── scanner/
│   │   ├── index.ts           # Scan orchestrator
│   │   ├── modules/           # 54 attack modules
│   │   │   └── stress/        # 6 stress test modules
│   │   ├── store.ts           # In-memory scan storage
│   │   ├── fetch.ts           # HTTP client with caching
│   │   ├── config.ts          # Environment config
│   │   ├── types.ts           # TypeScript types
│   │   ├── cvss.ts            # CVSS scoring
│   │   └── soft404.ts         # Soft 404 detection
│   ├── db.ts                  # SQLite persistence layer
│   ├── auth.ts                # API key validation
│   └── logger.ts              # Pino logger
└── middleware.ts               # Security headers middleware
```

## Key Patterns

- **Scan storage**: Dual-layer — in-memory Map for active scans, SQLite for persistence. Falls back gracefully if SQLite unavailable.
- **Scan lifecycle**: queued → scanning → completed/failed. Modules run in batches with circuit breaker.
- **Client caching**: localStorage caches completed scans and scan history for offline/resilience.
- **No auth by default**: API key auth is opt-in via `VIBESHIELD_API_KEY` env var.
- **All pages are client components** ("use client") — no RSC for the UI pages.

## Commands

```bash
npm run dev          # Start dev server
npm run build        # Production build
npm test             # Run vitest (42 tests)
npx tsc --noEmit     # Type check
```

## Scan Modes

- **Quick** (~10s): 13 modules — headers, SSL, secrets, CORS, cookies, CSP, dependencies, source maps
- **Security** (~45s): 48 modules — all security checks
- **Full + Stress** (~90s): 54 modules — everything including load test, race conditions, rate limits

## Notes

- `scan/[id]/page.tsx` is the largest file (~1100 lines). It contains the entire scan results UI including finding cards, export actions, keyboard shortcuts, and progress tracking.
- The nav is duplicated across pages (no shared layout component beyond root).
- Badge endpoint exists at `/api/scan/[id]/badge` and is exposed in the scan results UI.
