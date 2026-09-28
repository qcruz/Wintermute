# Wintermute

An open-source, AI-assisted bug bounty hunting pipeline. Wintermute automates reconnaissance, vulnerability scanning, and report generation against public bug bounty programs on HackerOne — with strict scope enforcement at every step.

Built to explore whether an individual equipped with AI agents and open-source tooling can meaningfully contribute to internet security through responsible disclosure.

## How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│                      WINTERMUTE PIPELINE                        │
│                                                                 │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐      │
│  │  SCOPE  │ -> │  RECON  │ -> │  SCAN   │ -> │ REPORT  │      │
│  │  CHECK  │    │         │    │         │    │         │      │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘      │
│                                                                 │
│  Fetch program   Enumerate     Run 9 check    Generate          │
│  scope from      subdomains,   modules        professional      │
│  HackerOne API,  validate      against each   reports, dedup,   │
│  build allow/    DNS, finger-  target         submit via API    │
│  deny lists      print tech                                     │
└──────────────────────────────────────────────────────────────────┘
```

**Scope is a hard gate.** Every target is checked against the program's scope before any interaction. Default deny. No exceptions.

## Scanner Architecture

Wintermute runs 10 vulnerability check modules against discovered targets. Each module is independent, safe (read-only / GET-only), and produces findings with confidence scores.

### Quick Checks (fast, low request count)

| Module | What It Detects | How It Works |
|--------|----------------|-------------|
| **Subdomain Takeover** | Dangling CNAME records pointing to unclaimed services | Resolves CNAME chains, matches against 20+ known vulnerable services (S3, Heroku, GitHub Pages, etc.), verifies via HTTP fingerprint |
| **CORS Misconfiguration** | Wildcard origin reflection, null origin, credential-inclusive open CORS | Sends requests with test `Origin` header, checks if arbitrary origins are reflected with `Access-Control-Allow-Credentials: true` |
| **SSL/TLS Issues** | Expired certs, weak protocols (TLS 1.0/1.1), hostname mismatches, self-signed certs | Connects via `ssl` module, inspects certificate chain, protocol version, and subject/SAN fields |
| **Security Headers** | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy | Fetches response headers, compares against required security headers, classifies severity per header |

### Deep Checks (more thorough, higher request count)

| Module | What It Detects | How It Works |
|--------|----------------|-------------|
| **Content Discovery** | Hidden API docs (Swagger, GraphQL), admin panels, debug endpoints (Actuator, pprof), dev artifacts | Probes 80+ curated high-value paths prioritized by severity, fingerprints responses to distinguish real pages from custom 404s, mines `robots.txt` Disallow entries |
| **Injection Testing** | Reflected XSS, SQL injection (error-based), open redirects, Server-Side Template Injection (SSTI) | Discovers parameters from page links/forms, injects safe canary strings, checks for reflection (XSS), SQL error patterns (15+ DB signatures), redirect behavior, and template evaluation (`{{7*7}}` -> `49`) |
| **Auth Checks** | Insecure cookies, unauthenticated API access, JWT exposure, login form CSRF, HTTP credential submission | Analyzes Set-Cookie flags (Secure, HttpOnly, SameSite), probes 24 sensitive endpoints without auth, extracts and decodes JWT headers, inspects login forms |
| **Business Logic** | Stack trace / error leaks, version disclosure, dangerous HTTP methods, clickjacking, missing HTTPS redirect, cache issues | Triggers error pages and inspects for debug info (15 patterns across Python/Java/.NET/PHP/Node), checks OPTIONS response, tests X-Frame-Options/CSP frame-ancestors |
| **IDOR Detection** | Insecure Direct Object References — unauthenticated access to user data via sequential API IDs | Probes 30 common REST API patterns (`/api/users/{id}`, `/api/orders/{id}`, etc.), tests sequential IDs, compares responses for different data objects, checks for sensitive fields (email, phone, PII) |
| **Exposed Files** | `.git/`, `.env`, `.DS_Store`, backup files, admin panels, config files | Checks for known sensitive file paths with content validation to reduce false positives |

### False Positive Reduction

Every module includes defenses against common false positives:

- **Custom 404 detection** — baseline comparison prevents flagging custom error pages as real endpoints
- **Third-party site detection** — skips Google Sites, Auth0, Okta, and other hosted platforms that redirect everything to login
- **Blanket-403 detection** — skips hosts that return Forbidden for all paths
- **Content fingerprinting** — requires specific content markers (not just HTTP 200) to confirm findings
- **SSTI confirmation** — re-requests to filter out "49" appearing in random Cloudflare/session tokens
- **Open redirect validation** — requires redirect target to start with canary URL, not just contain it
- **DB deduplication** — prevents storing the same finding across multiple scan runs

## Confidence Scoring

Every finding includes a confidence score (0.0 - 1.0):

| Range | Meaning | Action |
|-------|---------|--------|
| 0.9 - 1.0 | Very high confidence, strong evidence | Review for submission |
| 0.7 - 0.89 | High confidence, likely real | Manual verification recommended |
| 0.5 - 0.69 | Medium confidence, possible false positive | Investigate before reporting |
| < 0.5 | Low confidence, probably noise | Usually filtered out |

## Reporting Engine

Findings that pass confidence thresholds are turned into professional reports:

- **19 report templates** covering all vulnerability classes
- **Duplicate detection** — checks internal DB and HackerOne API for prior submissions
- **Duplicate probability scoring** — flags common/low-value findings (e.g., missing HSTS: 95% likely duplicate)
- **Interactive review** — human always previews and approves before submission
- **HackerOne API submission** — formats and submits via API with proper severity, CWE references, and reproduction steps

## Quick Start

```bash
# Setup
cd Wintermute
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Add your HackerOne API credentials

# Full pipeline: recon -> scan -> report
python -m scripts.wintermute <program_handle>

# Quick scan (4 fast checks only)
python -m scripts.wintermute <program_handle> --quick

# Targeted scan
python -m scripts.wintermute <program_handle> --scan-only --limit 5 --filter api
python -m scripts.wintermute <program_handle> --checks injection,auth_checks

# Scout for new programs
python -m scripts.wintermute scout

# Review and submit reports
python -m scripts.run_reports <program_handle>
```

## Project Structure

```
src/
  core/         Config, DB models (SQLAlchemy/SQLite), scope checker, pipeline runner
  platforms/    HackerOne API client (auth, scope, submissions)
  recon/        Subdomain enumeration (crt.sh), DNS validation, header fingerprinting
  scanner/      9 vulnerability check modules + scan pipeline orchestrator
  reporting/    19 report templates, duplicate detection, submission pipeline
scripts/        CLI entry points
tests/          51 tests (pytest)
docs/           Educational documentation, roadmap, ethics guidelines
```

## Safety & Ethics

- **Scope enforcement** — hard gate, default deny, full audit logging
- **No destructive payloads** — all injection tests use safe canary values
- **GET-only scanning** — no POST/PUT/DELETE for fuzzing
- **No credential brute-forcing** — auth checks only analyze public responses
- **Human review required** — auto-submit is off by default
- **Rate-limit aware** — respects program guidelines

See `docs/ETHICS.md` for the full rules of engagement.

## Documentation

- [Roadmap](docs/ROADMAP.md) — Project plan and progress
- [How It Works](docs/how-it-works.md) — Step-by-step pipeline explanation
- [Vulnerability Detection](docs/vulnerability-detection.md) — How each check works
- [Reporting Engine](docs/reporting-engine.md) — Report generation and submission
- [Submission Guide](docs/submission-guide.md) — When to submit and risks of oversubmitting
- [Operations](docs/operations.md) — Command reference and workflow
- [Ethics](docs/ETHICS.md) — Rules of engagement
- [Glossary](docs/GLOSSARY.md) — Plain-language definitions
- [Session Log](docs/SESSION_LOG.md) — What happened each session
- [Strategy](docs/STRATEGY.md) — Strategic analysis and research

## License

TBD
