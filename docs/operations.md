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
```

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

1. **Find the program**: `python -m scripts.wintermute programs`
2. **Check the scope**: `python -m scripts.h1_explore show <handle>`
3. **Read the policy**: Visit the program page on HackerOne to understand
   any special rules or restrictions
4. **Run the pipeline**: `python -m scripts.wintermute <handle>`
5. **Review findings**: Check the summary output
6. **Review reports**: `python -m scripts.run_reports <handle>`
7. **Submit or skip**: Approve reports you're confident about
8. **Track outcomes**: Check HackerOne for triage responses
9. **Learn**: If a report is rejected, note why and adjust

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

*Last updated: 2026-09-27*
