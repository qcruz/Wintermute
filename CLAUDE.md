# Wintermute — Claude Code Instructions

## Project Overview

Wintermute is an automated bug bounty hunting pipeline. It discovers programs on HackerOne, enumerates attack surfaces, scans for vulnerabilities, and generates professional reports for submission. The GitHub repo is the public-facing, educational release.

- **Owner**: quanahcruz (HackerOne: cruzquanahs)
- **Platform**: HackerOne (API v1, basic auth)
- **Language**: Python 3.14, virtualenv at `.venv/`
- **Database**: SQLite (`wintermute.db`, gitignored)
- **Credentials**: `.env` file (gitignored), never commit

## Session Continuation Protocol

**Every new session must start by reading `docs/ROADMAP.md` and checking the Operating Cycle below to determine what to do next.** Do not ask the user "what would you like to do?" — check the cycle, pick up where we left off, and go.

### Operating Cycle

Wintermute follows a rotating cycle to maintain balanced progress across scanning, scouting, R&D, and review. Each session should advance one or more steps. Track progress in the cycle by checking what was done last (DB status, git log, roadmap checkboxes).

```
┌─────────────────────────────────────────────────────┐
│                 WINTERMUTE OPERATING CYCLE           │
│                                                     │
│  1. SCAN (active program)                           │
│     - Quick scan a current target: --quick          │
│     - Or deep scan with new checks: --scan-only     │
│     - Review findings, submit strong reports        │
│                                                     │
│  2. SCOUT (every 2-3 sessions)                      │
│     - Run: python -m scripts.wintermute scout       │
│     - Pick 1-2 new programs to quick-scan           │
│     - Broaden coverage, avoid tunnel vision          │
│                                                     │
│  3. R&D (every 3-4 sessions)                        │
│     - Check Phase 6 candidate list in ROADMAP.md    │
│     - Pick one bug class to prototype               │
│     - Build, test, integrate into pipeline           │
│                                                     │
│  4. REVIEW & MAINTAIN (as needed)                   │
│     - Check submission outcomes on HackerOne        │
│     - Update docs with lessons learned              │
│     - Fix false positives, tune confidence scores   │
│     - Commit and push updates to GitHub             │
│                                                     │
│  Repeat. Vary the mix. Don't do the same step       │
│  three sessions in a row.                           │
└─────────────────────────────────────────────────────┘
```

### How to determine what's next

1. Read `docs/ROADMAP.md` — check what's marked done, what's in progress
2. Run `python -m scripts.wintermute status` — see what programs/findings exist
3. Check recent git history — `git log --oneline -10`
4. Based on the above, pick the next cycle step:
   - If last session was a scan → scout or R&D this session
   - If last session was R&D → scan with the new capability
   - If last session was scout → scan one of the new programs found
   - If we haven't reviewed reports in a while → do that
5. Tell the user what you're picking up and why, then execute

### Session startup checklist

```
□ Read docs/ROADMAP.md
□ Read docs/SESSION_LOG.md (check last session's findings and queued work)
□ Run: python -m scripts.wintermute status
□ Check: git log --oneline -5
□ Determine cycle step (scan / scout / R&D / review)
□ Brief the user on plan (1-2 sentences)
□ Execute
□ At end of session: append entry to docs/SESSION_LOG.md
```

## Scan Sizing Guidelines

**Keep scans short and incremental.** A single session should never block on a scan longer than ~5 minutes. Large programs (100+ subdomains) must be broken into multiple sessions.

| Program Size | Recon | Scan Strategy |
|-------------|-------|---------------|
| Small (<20 targets) | Full recon + quick scan in one session | Can deep scan all targets |
| Medium (20-50 targets) | Recon in one session, scan in next | `--limit 10` per session, rotate batches |
| Large (50-300 targets) | Recon is its own session | `--limit 5 --filter <keyword>` to focus on interesting hosts |
| Huge (300+ targets like Hyatt) | Recon is its own session | `--scan-only --limit 5 --filter api` — slice by keyword (api, admin, dev, staging, etc.) across sessions |

**Rules:**
- Always use `--limit` on programs with 20+ targets
- Use `--filter` to focus on high-value subdomains (api, admin, dev, staging, internal, portal)
- Use `--quick` for first pass, then `--scan-only --checks <specific>` for deeper dives
- If recon alone takes >5 min, let it finish and save scanning for the next session
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
  scanner/      9 check modules + pipeline orchestrator
  reporting/    templates, dedup, reporting pipeline
scripts/        CLI entry points (wintermute, h1_explore, run_*)
tests/          51 tests (pytest)
docs/           educational docs, roadmap, ethics, glossary
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
