# VibeShield

Black-box security scanner for web applications. Paste a URL, get a comprehensive penetration test with 54 attack modules — no code access required.

## Features

- **54 security modules** — headers, SSL, injection (SQL/XSS/command), auth bypass, IDOR, CORS, CSRF, JWT, OAuth, SSRF, GraphQL, WebSocket, and more
- **3 scan modes** — Quick (~10s, 13 modules), Security (~45s, 48 modules), Full + Stress (~90s, all 54)
- **Stress testing** — load testing, race conditions, rate limit bypass, cost attacks
- **Platform-specific** — Next.js, Supabase, Firebase, Stripe-specific security checks
- **AI/LLM testing** — prompt injection, model extraction, training data leaks
- **Grade scoring** — A-F grade with 0-100 numeric score, CWE/OWASP mappings
- **Export formats** — PDF, CSV, SARIF, JUnit XML, JSON
- **CI/CD integration** — webhook callbacks, GitHub Actions, fail gates (minScore, failOnCritical)
- **Scan comparison** — side-by-side diffs with delta tracking
- **Rate limiting** — per-IP, per-target, global concurrency limits

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 16, React 19, TypeScript |
| Styling | Tailwind CSS v4 |
| Storage | Upstash Redis + in-memory fallback |
| Parsing | Cheerio (DOM), native Fetch |
| Deploy | Docker (multi-stage build) |

## Quick Start

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), enter a URL, and scan.

## API

```bash
# Start a scan
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "mode": "security"}'

# Get results
curl http://localhost:3000/api/scan/{id}

# Export as SARIF
curl http://localhost:3000/api/scan/{id}/export?format=sarif
```

## Attack Modules

| Category | Modules |
|----------|---------|
| Recon | Target discovery, tech stack fingerprinting |
| Headers & TLS | Security headers, SSL/TLS validation, cookies |
| Injection | SQL, NoSQL, command, CRLF, XSS, SSTI |
| Auth | Bypass, IDOR, email enumeration, JWT, OAuth |
| Infrastructure | CORS, CSRF, SSRF, clickjacking, CSP |
| API | GraphQL, WebSocket, REST enumeration |
| Platform | Next.js, Supabase, Firebase, Stripe checks |
| AI/LLM | Prompt injection, model extraction |
| Stress | Load testing, race conditions, rate limits |

## Architecture

```
src/lib/scanner/
├── index.ts        # Orchestrator (recon → security → stress)
├── modules/        # 54 attack modules
│   └── stress/     # Load, race, rate-limit modules
├── store.ts        # Redis + in-memory storage
├── fetch.ts        # HTTP client with caching
└── config.ts       # Environment-driven config
```

## License

ISC — Built by [Preyam](https://github.com/preyam2002)
