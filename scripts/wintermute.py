#!/usr/bin/env python3
"""Wintermute — main entry point.

Run the full pipeline or individual phases against a bug bounty program.

Usage:
  python -m scripts.wintermute <handle>                        # Full pipeline
  python -m scripts.wintermute <handle> --scan-only            # Skip recon
  python -m scripts.wintermute <handle> --quick                # Quick scan (4 fast checks)
  python -m scripts.wintermute <handle> --limit 5              # Scan only 5 targets
  python -m scripts.wintermute <handle> --filter api           # Only targets containing "api"
  python -m scripts.wintermute <handle> --checks cors,injection  # Only specific checks
  python -m scripts.wintermute <handle> --auth                   # Authenticated scan (.auth/<handle>.json)
  python -m scripts.wintermute <handle> --add-targets h1,h2,h3  # Inject specific hostnames
  python -m scripts.wintermute status                          # Show database status
  python -m scripts.wintermute programs                        # List available programs
  python -m scripts.wintermute scout                           # Discover new programs to work
"""

import logging
import sys
from datetime import datetime, timezone

from src.core.runner import print_summary, run_full_pipeline
from src.scanner.pipeline import ALL_CHECKS, QUICK_CHECKS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)


def show_status() -> None:
    """Show pipeline dashboard with program coverage and finding stats."""
    from collections import Counter

    from src.core.db import Finding, Program, Submission, Target, get_session

    session = get_session()
    programs = session.query(Program).all()

    if not programs:
        print("No programs in database. Run a scan first.")
        session.close()
        return

    all_findings = session.query(Finding).all()
    all_targets = session.query(Target).all()

    # ── Summary ────────────────────────────────────────────────
    total_targets = len(all_targets)
    total_alive = sum(1 for t in all_targets if t.alive)
    total_findings = len(all_findings)
    high_conf = sum(1 for f in all_findings if f.confidence >= 0.7)
    by_severity = Counter(f.severity for f in all_findings)
    by_type = Counter(f.vuln_type for f in all_findings)

    print("=" * 64)
    print("  WINTERMUTE DASHBOARD")
    print("=" * 64)
    print(f"\n  Programs: {len(programs):>4d}     Targets: {total_targets:>4d} ({total_alive} alive)")
    print(f"  Findings: {total_findings:>4d}     High-confidence (≥0.7): {high_conf}")
    print()

    # ── Severity breakdown ─────────────────────────────────────
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_parts = []
    for s in sev_order:
        if by_severity.get(s):
            sev_parts.append(f"{s}: {by_severity[s]}")
    if sev_parts:
        print(f"  Severity: {', '.join(sev_parts)}")

    # ── Top finding types ──────────────────────────────────────
    print(f"\n  {'Finding Type':<28s} {'Count':>5s}  {'High-Conf':>9s}")
    print("  " + "-" * 46)
    for vtype, count in by_type.most_common(10):
        hc = sum(1 for f in all_findings if f.vuln_type == vtype and f.confidence >= 0.7)
        print(f"  {vtype:<28s} {count:>5d}  {hc:>9d}")

    # ── Per-program table ──────────────────────────────────────
    print(f"\n  {'Program':<22s} {'Targets':>7s} {'Alive':>5s} {'Finds':>5s} {'Hi-C':>4s} {'Last Scan':<12s}")
    print("  " + "-" * 60)

    prog_data = []
    for prog in programs:
        targets = [t for t in all_targets if t.program_id == prog.id]
        alive = sum(1 for t in targets if t.alive)
        findings = [f for f in all_findings if any(
            t.id == f.target_id and t.program_id == prog.id for t in targets
        )]
        hc = sum(1 for f in findings if f.confidence >= 0.7)
        synced = str(prog.last_synced)[:10] if prog.last_synced else "never"
        prog_data.append((prog.handle, len(targets), alive, len(findings), hc, synced))

    # Sort by findings count descending
    prog_data.sort(key=lambda x: x[3], reverse=True)
    for handle, tgt, alv, fnd, hc, syn in prog_data:
        print(f"  {handle:<22s} {tgt:>7d} {alv:>5d} {fnd:>5d} {hc:>4d} {syn:<12s}")

    # ── Submissions ──────────────────────────────────────────────
    subs = session.query(Submission).all()
    if subs:
        accepted = sum(1 for s in subs if s.outcome == "accepted")
        duped = sum(1 for s in subs if s.outcome == "duplicate")
        total_bounty = sum(s.bounty_amount or 0 for s in subs)
        print(f"\n  SUBMISSIONS: {len(subs)} sent, {accepted} accepted, {duped} duplicate, ${total_bounty:.0f} earned")

    # ── Actionable findings (exclude noise: HSTS, SSL cert, info-level) ─
    noise_types = {"missing_security_header", "ssl_tls", "cache_issue"}
    actionable = [
        f for f in all_findings
        if f.confidence >= 0.7
        and f.severity in ("critical", "high", "medium")
        and f.vuln_type not in noise_types
    ]
    noise_count = sum(
        1 for f in all_findings
        if f.confidence >= 0.7
        and f.severity in ("critical", "high", "medium")
        and f.vuln_type in noise_types
    )
    if actionable:
        print(f"\n  ACTIONABLE FINDINGS ({len(actionable)}):")
        if noise_count:
            print(f"  ({noise_count} noise findings hidden: HSTS, SSL, cache)")
        print("  " + "-" * 60)
        for f in actionable[:20]:
            target = next((t for t in all_targets if t.id == f.target_id), None)
            host = target.hostname if target else "?"
            title = (f.title or f.description or "")[:50]
            print(f"  [{f.severity.upper():<8s}] {host}: {title}")
        if len(actionable) > 20:
            print(f"  ... and {len(actionable) - 20} more")
    else:
        print(f"\n  No actionable findings ({noise_count} noise findings hidden)")

    session.close()
    print()


def list_programs() -> None:
    """List available HackerOne programs."""
    from src.platforms.hackerone import HackerOneClient

    print("Fetching programs from HackerOne...")
    with HackerOneClient() as client:
        programs = client._get("/hackers/programs", {"page[size]": 50})

    print(f"\n{'Handle':<35s} {'Name'}")
    print("-" * 60)
    for p in programs.get("data", []):
        attrs = p.get("attributes", {})
        handle = attrs.get("handle", "?")
        name = attrs.get("name", "?")
        print(f"  {handle:<33s} {name}")


def scout_programs() -> None:
    """Discover and evaluate programs for targeting.

    Shows programs sorted by opportunity signals:
    - Newer programs (less competition)
    - Wide scope (wildcard domains)
    - Bounty eligibility
    - Response efficiency
    """
    from src.core.db import Program, get_session
    from src.platforms.hackerone import HackerOneClient

    print("Scouting HackerOne for programs...")
    print("=" * 70)

    with HackerOneClient() as client:
        data = client._get("/hackers/programs", {"page[size]": 100})

    programs = data.get("data", [])

    # Score and rank programs
    scored = []
    for p in programs:
        attrs = p.get("attributes", {})
        handle = attrs.get("handle", "?")
        name = attrs.get("name", "?")
        submission_state = attrs.get("submission_state", "")
        offers_bounties = attrs.get("offers_bounties", False)
        started_accepting = attrs.get("started_accepting_at", "")

        # Only programs accepting submissions
        if submission_state != "open":
            continue

        scored.append({
            "handle": handle,
            "name": name,
            "bounty": offers_bounties,
            "started": started_accepting[:10] if started_accepting else "unknown",
        })

    # Check which ones we've already scanned
    session = get_session()
    scanned_handles = {
        p.handle for p in session.query(Program).all()
    }
    session.close()

    # Sort: unscanned first, then by start date (newer first)
    scored.sort(key=lambda p: (p["handle"] in scanned_handles, p["started"]))
    scored.reverse()

    print(f"\n  {'Handle':<30s} {'Bounty':<8s} {'Started':<12s} {'Status'}")
    print("  " + "-" * 68)

    for p in scored[:40]:
        bounty = "Yes" if p["bounty"] else "No"
        status = "SCANNED" if p["handle"] in scanned_handles else "NEW"
        marker = "  " if status == "NEW" else "  ✓ "
        print(f"  {marker}{p['handle']:<28s} {bounty:<8s} {p['started']:<12s} {status}")

    print(f"\n  Total: {len(scored)} programs ({len(scored) - len(scanned_handles & {p['handle'] for p in scored})} new)")
    print()
    print("  Tips:")
    print("  - NEW programs have less competition")
    print("  - Rotate targets periodically to avoid tunnel vision")
    print("  - Run 'python -m scripts.h1_explore show <handle>' to check scope")
    print()


def add_targets(handle: str, hostnames: list[str]) -> None:
    """Manually inject specific hostnames into a program's target list.

    Checks scope, resolves DNS, and stores in DB. Skips subdomain enumeration.
    The program must already exist in the DB (run recon first, or it will be
    created with minimal info from HackerOne).
    """
    from datetime import datetime, timezone

    from src.core.db import Program, Target, get_session
    from src.core.scope import ScopeChecker
    from src.platforms.hackerone import HackerOneClient, parse_scope
    from src.recon.subdomain import _resolve_hostname

    session = get_session()

    # Ensure program exists
    program = session.query(Program).filter_by(handle=handle).first()
    if not program:
        print(f"Program '{handle}' not in DB. Fetching from HackerOne...")
        with HackerOneClient() as client:
            program_data = client.get_program(handle)
        attrs = program_data.get("attributes", {})
        program = Program(
            handle=handle,
            name=attrs.get("name", handle),
            platform="hackerone",
            submission_state=attrs.get("submission_state", "open"),
        )
        session.add(program)
        session.flush()

    # Build scope checker
    with HackerOneClient() as client:
        raw_scopes = client.get_structured_scopes(handle)
    parsed = parse_scope(raw_scopes)
    checker = ScopeChecker.from_parsed_scope(handle, parsed)

    added = 0
    skipped = 0
    for hostname in hostnames:
        hostname = hostname.strip().lower()
        if not hostname:
            continue

        # Check scope
        check = checker.check(hostname)
        if not check.allowed:
            print(f"  SKIP {hostname} — out of scope ({check.reason})")
            skipped += 1
            continue

        # Check if already in DB
        existing = session.query(Target).filter_by(
            program_id=program.id, hostname=hostname
        ).first()
        if existing:
            print(f"  EXISTS {hostname} (alive={existing.alive})")
            continue

        # Resolve DNS
        ips, alive = _resolve_hostname(hostname)

        target = Target(
            program_id=program.id,
            hostname=hostname,
            source="manual",
            ip_address=", ".join(ips),
            alive=alive,
        )
        session.add(target)
        status = "ALIVE" if alive else "NO DNS"
        print(f"  ADDED {hostname} — {status} ({', '.join(ips) if ips else 'no IPs'})")
        added += 1

    session.commit()
    session.close()
    print(f"\nDone: {added} added, {skipped} out-of-scope")


def record_outcome(report_id: str, outcome: str, bounty: str = "", lesson: str = "") -> None:
    """Record or update the outcome of a HackerOne submission.

    Usage:
      python -m scripts.wintermute outcome 4077213 duplicate --lesson "CORS misconfigs are over-hunted"
      python -m scripts.wintermute outcome 4077213 accepted --bounty 500 --lesson "First bounty!"
    """
    from src.core.db import Submission, Finding, get_session

    valid_outcomes = {"pending", "triaged", "duplicate", "accepted", "rejected", "informative", "na"}
    if outcome not in valid_outcomes:
        print(f"Invalid outcome: {outcome}")
        print(f"Valid outcomes: {', '.join(sorted(valid_outcomes))}")
        return

    session = get_session()

    # Find submission by report ID
    sub = session.query(Submission).filter_by(report_id=report_id).first()

    if not sub:
        # Maybe user wants to backfill a submission that predates this feature
        print(f"No submission found with report ID {report_id}.")
        print("Creating a backfill entry. Enter the finding details:")

        # Try to find by report_id in finding evidence or let user specify
        handle = input("  Program handle: ").strip()
        finding_title = input("  Finding title (for reference): ").strip()

        # Create a submission record without linking to a finding
        sub = Submission(
            finding_id=0,  # Will be updated if we find the finding
            program_handle=handle,
            report_id=report_id,
        )

        # Try to find a matching finding
        findings = (
            session.query(Finding)
            .filter(Finding.status == "reported")
            .all()
        )
        for f in findings:
            if finding_title.lower() in (f.title or "").lower():
                sub.finding_id = f.id
                print(f"  Linked to finding #{f.id}: {f.title}")
                break

        if sub.finding_id == 0:
            print("  No matching finding found — recording without link")

        session.add(sub)

    # Update outcome
    old_outcome = sub.outcome
    sub.outcome = outcome
    if bounty:
        sub.bounty_amount = float(bounty)
    if lesson:
        sub.lesson = lesson
    if outcome not in ("pending", "triaged"):
        sub.resolved_at = datetime.now(timezone.utc)

    session.commit()

    print(f"\nSubmission #{report_id} updated:")
    print(f"  Outcome: {old_outcome} → {outcome}")
    if bounty:
        print(f"  Bounty: ${float(bounty):.0f}")
    if lesson:
        print(f"  Lesson: {lesson}")

    session.close()


def show_submissions() -> None:
    """Show all submission outcomes."""
    from src.core.db import Finding, Submission, get_session

    session = get_session()
    subs = session.query(Submission).order_by(Submission.submitted_at.desc()).all()

    if not subs:
        print("No submissions recorded yet.")
        session.close()
        return

    print("=" * 70)
    print("  SUBMISSION HISTORY")
    print("=" * 70)
    print(f"\n  {'Report ID':<12s} {'Program':<16s} {'Outcome':<12s} {'Bounty':>8s} {'Date':<12s}")
    print("  " + "-" * 66)

    total_bounty = 0
    for sub in subs:
        bounty_str = f"${sub.bounty_amount:.0f}" if sub.bounty_amount else "—"
        date_str = str(sub.submitted_at)[:10] if sub.submitted_at else "?"
        total_bounty += sub.bounty_amount or 0
        print(f"  {sub.report_id:<12s} {sub.program_handle:<16s} {sub.outcome:<12s} {bounty_str:>8s} {date_str:<12s}")
        if sub.lesson:
            print(f"    Lesson: {sub.lesson}")

    print(f"\n  Total: {len(subs)} submissions, ${total_bounty:.0f} earned")

    # Outcome breakdown
    from collections import Counter
    outcomes = Counter(s.outcome for s in subs)
    parts = [f"{o}: {c}" for o, c in outcomes.most_common()]
    print(f"  Outcomes: {', '.join(parts)}")

    session.close()
    print()


def _parse_arg(args: list[str], flag: str, default: str = "") -> str:
    """Extract a flag value like --limit 5 from args."""
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1]
    return default


def main() -> None:
    if len(sys.argv) < 2:
        print("Wintermute — Automated Bug Bounty Pipeline")
        print()
        print("Usage:")
        print("  python -m scripts.wintermute <handle>                    Full pipeline")
        print("  python -m scripts.wintermute <handle> --scan-only        Skip recon")
        print("  python -m scripts.wintermute <handle> --quick            Quick scan (fast checks)")
        print("  python -m scripts.wintermute <handle> --limit N          Scan N targets max")
        print("  python -m scripts.wintermute <handle> --filter TERM      Only matching hostnames")
        print("  python -m scripts.wintermute <handle> --checks a,b,c     Only specific checks")
        print("  python -m scripts.wintermute <handle> --auth              Authenticated scanning")
        print("  python -m scripts.wintermute <handle> --add-targets a,b   Inject specific hostnames")
        print("  python -m scripts.wintermute status                      DB status")
        print("  python -m scripts.wintermute programs                    List programs")
        print("  python -m scripts.wintermute scout                       Find new programs")
        print("  python -m scripts.wintermute submissions                  View submission history")
        print("  python -m scripts.wintermute outcome <id> <result>        Record submission outcome")
        print()
        print("Available checks:")
        for check in sorted(ALL_CHECKS):
            marker = "*" if check in QUICK_CHECKS else " "
            print(f"  {marker} {check}")
        print("  (* = included in --quick)")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "status":
        show_status()
        return

    if cmd == "programs":
        list_programs()
        return

    if cmd == "scout":
        scout_programs()
        return

    if cmd == "submissions":
        show_submissions()
        return

    if cmd == "outcome":
        if len(sys.argv) < 4:
            print("Usage: python -m scripts.wintermute outcome <report_id> <outcome> [--bounty N] [--lesson 'text']")
            print("Outcomes: pending, triaged, duplicate, accepted, rejected, informative, na")
            sys.exit(1)
        report_id = sys.argv[2]
        outcome = sys.argv[3]
        args = sys.argv[4:]
        bounty = _parse_arg(args, "--bounty")
        lesson = _parse_arg(args, "--lesson")
        record_outcome(report_id, outcome, bounty, lesson)
        return

    # Full pipeline
    handle = cmd
    args = sys.argv[2:]

    # Handle --add-targets before anything else
    targets_str = _parse_arg(args, "--add-targets")
    if targets_str:
        hostnames = [h.strip() for h in targets_str.split(",") if h.strip()]
        if not hostnames:
            print("Usage: --add-targets host1,host2,host3")
            sys.exit(1)
        print(f"Adding {len(hostnames)} targets to {handle}...")
        add_targets(handle, hostnames)
        return

    scan_only = "--scan-only" in args
    quick = "--quick" in args
    use_auth = "--auth" in args

    # Parse --limit N
    limit_str = _parse_arg(args, "--limit")
    max_targets = int(limit_str) if limit_str else 0

    # Parse --filter TERM
    hostname_filter = _parse_arg(args, "--filter")

    # Parse --checks a,b,c
    checks_str = _parse_arg(args, "--checks")
    if checks_str:
        checks = [c.strip() for c in checks_str.split(",")]
        invalid = [c for c in checks if c not in ALL_CHECKS]
        if invalid:
            print(f"Unknown checks: {', '.join(invalid)}")
            print(f"Available: {', '.join(sorted(ALL_CHECKS))}")
            sys.exit(1)
    elif quick:
        checks = list(QUICK_CHECKS)
    else:
        checks = None  # All checks

    # Display scan plan
    print(f"Wintermute starting pipeline for: {handle}")
    if max_targets:
        print(f"  Target limit: {max_targets}")
    if hostname_filter:
        print(f"  Hostname filter: *{hostname_filter}*")
    if checks:
        print(f"  Checks: {', '.join(sorted(checks))}")
    if use_auth:
        print("  Auth: enabled (.auth/<handle>.json)")
    if scan_only:
        print("  Mode: scan-only (skip recon)")
    print("=" * 60)

    result = run_full_pipeline(
        program_handle=handle,
        skip_recon=scan_only,
        max_targets=max_targets,
        checks=checks,
        hostname_filter=hostname_filter,
        use_auth=use_auth,
    )

    print_summary(result)


if __name__ == "__main__":
    main()
