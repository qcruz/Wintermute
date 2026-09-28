#!/usr/bin/env python3
"""Run vulnerability scans against a program's discovered targets.

Prerequisites: run_recon.py must have been run first for this program.
"""

import logging
import sys

from src.scanner.pipeline import run_scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
# Quiet down httpx request logging
logging.getLogger("httpx").setLevel(logging.WARNING)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.run_scan <program_handle>")
        print("Example: python -m scripts.run_scan security")
        print()
        print("Note: Run 'python -m scripts.run_recon <handle>' first to discover targets.")
        sys.exit(1)

    handle = sys.argv[1]
    print(f"Starting vulnerability scan for: {handle}")
    print("=" * 60)

    result = run_scan(handle)

    print()
    print("=" * 60)
    print(f"Scan Summary: {handle}")
    print(f"  Targets scanned:     {result.targets_scanned}")
    print(f"  Total findings:      {result.finding_count}")
    print(f"  High-confidence:     {len(result.high_confidence_findings)}")
    print()
    print("Checks performed:")
    for check_name, count in sorted(result.checks_run.items()):
        print(f"  {check_name:25s} {count} targets")

    if result.findings:
        print()
        print("-" * 60)
        print("FINDINGS:")
        print("-" * 60)

        # Sort by confidence (highest first), then severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            result.findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence),
        )

        for i, f in enumerate(sorted_findings, 1):
            conf_pct = int(f.confidence * 100)
            print(f"\n  [{i}] {f.severity.upper()} (confidence: {conf_pct}%)")
            print(f"      {f.title}")
            print(f"      Type: {f.vuln_type}")
            if f.description:
                # Truncate long descriptions
                desc = f.description[:200]
                print(f"      Detail: {desc}")
            if f.remediation:
                rem = f.remediation[:200]
                print(f"      Fix: {rem}")
    else:
        print()
        print("No findings detected.")


if __name__ == "__main__":
    main()
