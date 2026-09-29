# Wintermute — Claude Code Instructions

## Project Overview

Wintermute is an automated bug bounty hunting pipeline. It discovers programs on HackerOne, enumerates attack surfaces, scans for vulnerabilities, and generates professional reports for submission. The GitHub repo is the public-facing, educational release.

**Specialty focus: AI agent security.** The long-term goal is to develop expertise in vulnerabilities specifically exposed by AI agents — prompt injection, tool-use abuse, agent authorization flaws, MCP server exploits, insecure AI integrations, and emerging AI-specific attack surfaces. This is a growing area (prompt injection reports +540% on HackerOne in 2026) and represents the project's strategic differentiation. General web security scanning remains the foundation, but AI-targeted capabilities are the priority for R&D investment.

- **Owner**: quanahcruz (HackerOne: cruzquanahs)
- **Platform**: HackerOne (API v1, basic auth)
- **Language**: Python 3.14, virtualenv at `.venv/`
- **Database**: SQLite (`wintermute.db`, gitignored)
- **Credentials**: `.env` file (gitignored), never commit

## Session Continuation Protocol

**Every new session must start by reading `docs/ROADMAP.md` and picking up the first item in the next cycle due for rotation.** Do not ask the user "what would you like to do?" — check the cycles, pick up where we left off, and go.

### How It Works

The roadmap has 4 work cycles, each with a queue of items:
1. **Scanning & Operations** — active scanning, program management
2. **Scanner R&D & Buildout** — new detection capabilities
3. **Research & Strategic Planning** — market research, competitive analysis
4. **Project Organization & Docs** — code quality, testing, documentation

Each session:
1. Check which cycle has been idle longest (via session log)
2. **Work the FIRST item** in that cycle's queue
3. When done: **remove completed items**, **rotate continuous items to the bottom**
4. This ensures the project naturally covers its full scope with no blind spots

### Session startup checklist

```
□ Read docs/ROADMAP.md (check cycle queues — first item in each)
□ Read docs/SESSION_LOG.md (what was done last, what's queued)
□ Run: python -m scripts.wintermute status
□ Check: git log --oneline -5
□ Identify which cycle has been idle longest
□ Work the FIRST item in that cycle's queue
□ Brief the user on plan (1-2 sentences), then execute
□ At end of session:
  □ Update the cycle queue (remove completed, rotate continuous)
  □ Append entry to docs/SESSION_LOG.md
  □ Commit and push
```

### Rules
- Don't work the same cycle 3 sessions in a row
- Scanning (Cycle 1) should happen most often — it's the core activity
- R&D (Cycle 2) feeds Scanning — build then scan with the new capability
- Combine Docs (Cycle 4) with other cycles as a secondary task when natural

## Scan Sizing Guidelines

**Keep scans short and incremental.** Never launch a long-running scan without user approval. Deep checks (IDOR, path traversal, GraphQL) take ~2 min per target — plan accordingly.

| Program Size | Recon | Scan Strategy |
|-------------|-------|---------------|
| Small (<6 targets) | Full recon + scan in one session | Can deep scan all targets (~12 min) |
| Medium (6-20 targets) | Recon + quick scan in one session | Deep checks: `--limit 3` per batch, check in with user between batches |
| Large (20-50 targets) | Recon in one session, scan in next | `--limit 3 --filter <keyword>` per batch |
| Huge (50+ targets) | Recon is its own session | `--scan-only --limit 3 --filter api` — slice by keyword across sessions |

**Rules:**
- **Never run scans unattended for long periods.** Check in with the user between batches.
- `--limit 3` is the default batch size for deep checks (~6 min per batch)
- Use `--quick` for first pass (fast), then `--scan-only --checks <specific>` for deeper dives
- Use `--filter` to focus on high-value subdomains (api, admin, dev, staging, internal, portal)
- If recon alone takes >5 min, let it finish and save scanning for the next session
- The user will specify when a long scan can run. Don't assume.
- Progress is cumulative — findings persist in the DB across sessions, so there's no rush

## Key Commands

```bash
# Activate environment
cd ~/Desktop/Wintermute && source .venv/bin/activate

# Full pipeline
python -m scripts.wintermute <handle>

# Quick scan (fast checks only)
python -m scripts.wintermute <handle> --quick

# Targeted scan
python -m scripts.wintermute <handle> --scan-only --limit 5 --filter api
python -m scripts.wintermute <handle> --checks injection,auth_checks

# Scout for new programs
python -m scripts.wintermute scout

# Review reports
python -m scripts.run_reports <handle>

# Status
python -m scripts.wintermute status
```

## Architecture

```
src/
  core/         config, db models, scope checker, pipeline runner
  platforms/    HackerOne API client
  recon/        subdomain enum, header fingerprinting, recon pipeline
  scanner/      14 check modules + pipeline orchestrator
  reporting/    26 templates, dedup, reporting pipeline
scripts/        CLI entry points (wintermute, h1_explore, run_*)
tests/          110 tests (pytest)
docs/           educational docs, roadmap, strategy, ethics, glossary
```

## Submission Criteria

Before submitting any report, check `docs/submission-guide.md`. Key rules:
- All 5 criteria must pass: real vuln, in scope, security impact, not duplicate, clear repro
- Never submit informational/best-practice findings — they tank Signal score
- Severity must be honest — over-rating damages credibility
- Human always reviews before submission
- When in doubt, don't submit. A skipped report costs nothing; a bad one costs reputation.

## Safety Rules (Non-Negotiable)

- **Scope is a hard gate.** Every target is checked against program scope before any interaction. Default deny.
- **No credentials in git.** `.env`, `*.key`, `*.pem`, `Keys/` are all gitignored.
- **No destructive payloads.** All injection tests use safe canary values. No POST/PUT/DELETE for fuzzing.
- **Human reviews reports before submission.** Auto-submit is off by default.
- **Read `docs/ETHICS.md`** if adding any new scanner capability.

## Git & GitHub

- Remote: `git@github-wintermute:qcruz/Wintermute.git` (SSH deploy key alias)
- Always commit with descriptive messages
- Never commit `.env`, `wintermute.db`, or scan results
- Push updates at end of productive sessions

## Preferences

- Keep code simple and direct — no over-engineering
- Educational docs grow with the project — update them when adding features
- Use the existing patterns (dataclass results, logger, pipeline orchestration)
- Tests live in `tests/` — add tests for new scanner modules
