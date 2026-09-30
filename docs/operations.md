# Wintermute — Operations Guide

How to run Wintermute day-to-day: commands, scheduling, and monitoring.

---

## Quick Start

```bash
# Activate the environment
cd ~/Desktop/Wintermute
source .venv/bin/activate

# Run the full pipeline against a program
python -m scripts.wintermute <program_handle>

# Check what's in the database
python -m scripts.wintermute status

# Review and submit reports
python -m scripts.run_reports <program_handle>
```

---

## Commands Reference

### Main Pipeline

```bash
# Full pipeline: recon → scan → report generation
python -m scripts.wintermute <handle>

# Skip recon, just re-scan existing targets
python -m scripts.wintermute <handle> --scan-only

# Quick scan — only fast checks (takeover, CORS, SSL, headers)
python -m scripts.wintermute <handle> --quick

# Scan only 5 targets (good for testing or quick passes)
python -m scripts.wintermute <handle> --limit 5

# Scan only targets matching a filter
python -m scripts.wintermute <handle> --filter api

# Run only specific checks
python -m scripts.wintermute <handle> --checks cors,injection,auth_checks

# Combine options: quick scan of 3 API-related targets
python -m scripts.wintermute <handle> --scan-only --quick --limit 3 --filter api
```

### Authenticated Scanning

```bash
# Scan with authentication (loads cookies/headers from .auth/<handle>.json)
python -m scripts.wintermute <handle> --auth --scan-only --filter api

# Set up auth config (copy template, fill in real values)
cp .auth/example.json .auth/<handle>.json
# Edit with real session cookies and/or API tokens
```

Auth config format (`.auth/<handle>.json`):
```json
{
    "cookies": {
        "session_id": "YOUR_SESSION_COOKIE",
        "csrf_token": "YOUR_CSRF_TOKEN"
    },
    "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
    }
}
```

Auth is passed to: `content_discovery`, `ai_prompt_injection`, `ai_data_exfil`, `mcp_security`. The `.auth/` directory is gitignored.

### Available Checks (16 modules)

| Check | In `--quick` | Description |
|-------|:---:|-------------|
| `subdomain_takeover` | Yes | Dangling CNAME detection |
| `cors` | Yes | CORS origin reflection, null origin |
| `ssl_tls` | Yes | Certificate and protocol issues |
| `security_headers` | Yes | Missing security headers |
| `exposed_files` | | Sensitive files (.git, .env, backups) |
| `content_discovery` | | API docs, admin panels, debug endpoints |
| `injection` | | XSS, SQLi, open redirect, SSTI |
| `auth_checks` | | Cookie flags, missing auth, JWT issues |
| `business_logic` | | Error leaks, version disclosure, clickjacking |
| `idor` | | Sequential ID enumeration, PII detection |
| `path_traversal` | | Directory traversal with encoding bypasses |
| `graphql` | | Introspection, schema analysis |
| `js_analysis` | | Secret detection in JavaScript files |
| `ai_prompt_injection` | | AI endpoint discovery, injection canaries, system prompt extraction |
| `ai_data_exfil` | | AI context extraction, PII/backend leak detection |
| `mcp_security` | | MCP server discovery, auth bypass, tool poisoning, path traversal |

### Individual Phases

```bash
# Browse available programs
python -m scripts.wintermute programs

# Explore a specific program's scope
python -m scripts.h1_explore show <handle>

# Run only recon
python -m scripts.run_recon <handle>

# Run only vulnerability scanning
python -m scripts.run_scan <handle>

# Generate and review reports
python -m scripts.run_reports <handle>
python -m scripts.run_reports <handle> --preview   # Preview only, no submit option
```

### Status & Monitoring

```bash
# Show database status (programs, targets, findings)
python -m scripts.wintermute status

# Scout for new programs to target
python -m scripts.wintermute scout
```

---

## Scheduling Recurring Scans

To run Wintermute automatically on a schedule, use cron (macOS/Linux).

### Set Up a Cron Job

```bash
# Open crontab editor
crontab -e

# Run full pipeline every day at 2 AM against "security" program
0 2 * * * cd ~/Desktop/Wintermute && .venv/bin/python -m scripts.wintermute security >> logs/daily.log 2>&1

# Run against multiple programs
0 2 * * * cd ~/Desktop/Wintermute && .venv/bin/python -m scripts.wintermute security >> logs/daily.log 2>&1
0 3 * * * cd ~/Desktop/Wintermute && .venv/bin/python -m scripts.wintermute <other_program> >> logs/daily.log 2>&1
```

### Cron Schedule Cheatsheet

```
* * * * *
│ │ │ │ └── Day of week (0-7, Sun=0)
│ │ │ └──── Month (1-12)
│ │ └────── Day of month (1-31)
│ └──────── Hour (0-23)
└────────── Minute (0-59)

Examples:
  0 2 * * *     Every day at 2:00 AM
  0 */6 * * *   Every 6 hours
  0 2 * * 1     Every Monday at 2:00 AM
  0 2 1 * *     First of every month at 2:00 AM
```

---

## Workflow for Working a New Program

1. **Scout programs**: `python -m scripts.wintermute scout`
2. **Check the scope**: `python -m scripts.h1_explore show <handle>`
3. **Read the policy**: Visit the program page on HackerOne
4. **Quick scan first**: `python -m scripts.wintermute <handle> --quick --limit 10`
5. **Review quick results**: Are there promising targets worth deep scanning?
6. **Deep scan**: `python -m scripts.wintermute <handle> --scan-only` (full checks)
7. **Review reports**: `python -m scripts.run_reports <handle>`
8. **Submit or skip**: Approve reports you're confident about
9. **Rotate**: Don't spend too long on one program — `scout` for new ones
10. **Learn**: If a report is rejected, note why and adjust

## Diversification Strategy

Avoid getting stuck on a single program or bug type:

- **Weekly scout**: Run `scout` at least weekly to find new programs
- **Rotate programs**: Work 2-3 programs in parallel, not just one
- **Vary scan depth**: Quick scans across many programs, then deep dives on promising ones
- **Track patterns**: Which check types produce accepted findings? Double down on those
- **Explore new areas**: Periodically try check types you haven't used much

---

## Tips for Choosing Programs

- **New programs** have less competition — scan them first
- **High bounty ranges** are worth the effort but have more hunters
- **Fast response times** mean you'll get feedback quickly
- **Wide scope** (wildcards like `*.example.com`) gives more surface area
- **Avoid** programs that explicitly prohibit automated scanning
- **Start small**: Test against programs with smaller scope to learn

---

## Log Files

Create a logs directory for scheduled runs:

```bash
mkdir -p ~/Desktop/Wintermute/logs
```

Logs capture the full pipeline output including:
- Scope loading and validation
- Subdomain discovery counts
- Scope check results (allowed/denied)
- Vulnerability findings
- Report generation summary

---

## Database Management

The SQLite database (`wintermute.db`) stores all data locally:

- **Programs**: synced from HackerOne
- **Scopes**: in-scope and out-of-scope assets
- **Targets**: discovered subdomains with IPs
- **Services**: ports and technologies (future)
- **Findings**: vulnerability detections with confidence scores

The database is gitignored — it stays on your machine.

To start fresh:
```bash
rm wintermute.db
# Next pipeline run will recreate it
```

---

*Last updated: 2026-09-30*
