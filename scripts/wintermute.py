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

from src.core.runner import print_summary, run_full_pipeline
from src.scanner.pipeline import ALL_CHECKS, QUICK_CHECKS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)


def show_status() -> None:
    """Show current database status."""
    from src.core.db import Finding, Program, Target, get_session

    session = get_session()
    programs = session.query(Program).all()

    if not programs:
        print("No programs in database. Run a scan first.")
        session.close()
        return

    print("=" * 60)
    print("WINTERMUTE STATUS")
    print("=" * 60)

    for prog in programs:
        targets = session.query(Target).filter_by(program_id=prog.id).all()
        alive = sum(1 for t in targets if t.alive)
        findings = (
            session.query(Finding)
            .join(Finding.target)
            .filter(Target.program_id == prog.id)
            .all()
        )

        by_status = {}
        by_severity = {}
        for f in findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        print(f"\n  Program: {prog.name} ({prog.handle})")
        print(f"  Platform: {prog.platform}")
        print(f"  Last synced: {prog.last_synced}")
        print(f"  Targets: {len(targets)} total, {alive} alive")
        print(f"  Findings: {len(findings)} total")
        if by_severity:
            severity_str = ", ".join(
                f"{k}: {v}" for k, v in sorted(by_severity.items())
            )
            print(f"    By severity: {severity_str}")
        if by_status:
            status_str = ", ".join(
                f"{k}: {v}" for k, v in sorted(by_status.items())
            )
            print(f"    By status: {status_str}")

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
