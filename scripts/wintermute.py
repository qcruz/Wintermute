#!/usr/bin/env python3
"""Wintermute — main entry point.

Run the full pipeline or individual phases against a bug bounty program.

Usage:
  python -m scripts.wintermute <program_handle>              # Full pipeline
  python -m scripts.wintermute <program_handle> --scan-only   # Skip recon, scan existing data
  python -m scripts.wintermute status                         # Show database status
  python -m scripts.wintermute programs                       # List available programs
"""

import logging
import sys

from src.core.runner import run_full_pipeline, print_summary

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)


def show_status() -> None:
    """Show current database status."""
    from src.core.db import Program, Target, Finding, get_session

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


def main() -> None:
    if len(sys.argv) < 2:
        print("Wintermute — Automated Bug Bounty Pipeline")
        print()
        print("Usage:")
        print("  python -m scripts.wintermute <program_handle>       Full pipeline")
        print("  python -m scripts.wintermute <handle> --scan-only   Skip recon")
        print("  python -m scripts.wintermute status                 DB status")
        print("  python -m scripts.wintermute programs               List programs")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "status":
        show_status()
        return

    if cmd == "programs":
        list_programs()
        return

    # Full pipeline
    handle = cmd
    scan_only = "--scan-only" in sys.argv

    print(f"Wintermute starting pipeline for: {handle}")
    print("=" * 60)

    result = run_full_pipeline(
        program_handle=handle,
        skip_recon=scan_only,
    )

    print_summary(result)


if __name__ == "__main__":
    main()
