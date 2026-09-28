#!/usr/bin/env python3
"""Generate and review vulnerability reports for a program.

Prerequisites: run_recon.py and run_scan.py must have been run first.

Usage:
  python -m scripts.run_reports security           # Generate and review
  python -m scripts.run_reports security --preview  # Preview only, no submit
"""

import logging
import sys

from src.reporting.pipeline import generate_reports, submit_candidate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.run_reports <program_handle> [--preview]")
        print()
        print("Generates reports from scan findings and presents them for review.")
        print("Use --preview to see reports without the option to submit.")
        sys.exit(1)

    handle = sys.argv[1]
    preview_only = "--preview" in sys.argv

    print(f"Generating reports for: {handle}")
    print("=" * 60)

    result = generate_reports(handle, auto_submit=False)

    print()
    print("=" * 60)
    print(f"Report Generation Summary: {handle}")
    print(f"  Total findings:         {result.total_findings}")
    print(f"  Below threshold:        {result.below_threshold}")
    print(f"  Duplicates skipped:     {result.duplicates_skipped}")
    print(f"  Reports generated:      {result.reports_generated}")

    if not result.candidates:
        print()
        print("No reportable findings. This could mean:")
        print("  - All findings were below confidence threshold")
        print("  - All findings were likely duplicates")
        print("  - All findings were info/low severity")
        return

    # Present candidates for review
    print()
    print("=" * 60)
    print("REPORT REVIEW QUEUE")
    print("=" * 60)

    for i, candidate in enumerate(result.candidates, 1):
        conf_pct = int(candidate.confidence * 100)
        dup_warn = candidate.duplicate_warning

        print(f"\n{'─' * 60}")
        print(f"Report {i}/{len(result.candidates)}{dup_warn}")
        print(f"{'─' * 60}")
        print(candidate.report.preview())
        print()

        if preview_only:
            print(f"[PREVIEW MODE — not submitting]")
            continue

        if not candidate.is_reportable:
            print(f"[SKIPPED — {'likely duplicate' if candidate.dedup.confidence >= 0.8 else 'below threshold'}]")
            continue

        # Interactive review
        while True:
            action = input(
                f"  Action? [s]ubmit / [k]ip / [q]uit: "
            ).strip().lower()

            if action in ("s", "submit"):
                print(f"  Submitting to HackerOne...")
                success = submit_candidate(candidate, handle)
                if success:
                    print(f"  ✓ Report submitted successfully!")
                else:
                    print(f"  ✗ Submission failed. Check logs for details.")
                break
            elif action in ("k", "skip"):
                print(f"  Skipped.")
                break
            elif action in ("q", "quit"):
                print("Exiting review queue.")
                return
            else:
                print("  Invalid choice. Enter 's' to submit, 'k' to skip, or 'q' to quit.")

    print()
    print("=" * 60)
    print("Review complete.")
    if not preview_only:
        submitted = sum(1 for c in result.candidates if c.status == "submitted")
        print(f"  Reports submitted: {submitted}")


if __name__ == "__main__":
    main()
