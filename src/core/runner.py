"""Full pipeline runner — recon, scan, and report in one command.

This is the main entry point for running Wintermute against a program.
It chains all three phases together and produces a unified summary.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from src.core.http_client import load_auth
from src.recon.pipeline import ReconResult, run_recon
from src.reporting.pipeline import ReportingResult, generate_reports
from src.scanner.pipeline import ScanResult, run_scan

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Full pipeline execution summary."""

    program_handle: str
    started_at: str = ""
    finished_at: str = ""
    recon: ReconResult | None = None
    scan: ScanResult | None = None
    reporting: ReportingResult | None = None
    error: str = ""

    @property
    def duration_display(self) -> str:
        if not self.started_at or not self.finished_at:
            return "unknown"
        start = datetime.fromisoformat(self.started_at)
        end = datetime.fromisoformat(self.finished_at)
        delta = end - start
        minutes = int(delta.total_seconds() // 60)
        seconds = int(delta.total_seconds() % 60)
        return f"{minutes}m {seconds}s"


def run_full_pipeline(
    program_handle: str,
    min_confidence: float = 0.7,
    skip_recon: bool = False,
    max_targets: int = 0,
    checks: list[str] | None = None,
    hostname_filter: str = "",
    use_auth: bool = False,
) -> PipelineResult:
    """Run the complete Wintermute pipeline against a program.

    Phases:
      1. Recon — discover subdomains, fingerprint technologies
      2. Scan — check for vulnerabilities
      3. Report — generate reports, check for duplicates

    Args:
        program_handle: HackerOne program handle
        min_confidence: Minimum finding confidence to generate reports
        skip_recon: If True, skip recon and use existing DB data
        max_targets: Limit number of targets to scan (0 = all)
        checks: List of check names to run (None = all)
        hostname_filter: Only scan hostnames containing this substring
    """
    result = PipelineResult(program_handle=program_handle)
    result.started_at = datetime.now(timezone.utc).isoformat()

    # Phase 1: Recon
    if not skip_recon:
        logger.info("=" * 50)
        logger.info("PHASE 1: RECONNAISSANCE")
        logger.info("=" * 50)
        try:
            result.recon = run_recon(program_handle)
            logger.info(
                "Recon complete: %d subdomains, %d in-scope targets",
                result.recon.subdomains_found,
                result.recon.in_scope_targets,
            )
        except Exception as e:
            result.error = f"Recon failed: {e}"
            logger.error(result.error)
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result
    else:
        logger.info("Skipping recon (using existing data)")

    # Phase 2: Scan
    logger.info("=" * 50)
    logger.info("PHASE 2: VULNERABILITY SCANNING")
    logger.info("=" * 50)
    # Load auth config if requested
    auth = load_auth(program_handle) if use_auth else None
    if auth and auth.is_configured:
        logger.info("Authenticated scanning enabled for %s", program_handle)

    try:
        result.scan = run_scan(
            program_handle,
            max_targets=max_targets,
            checks=checks,
            hostname_filter=hostname_filter,
            auth=auth,
        )
        logger.info(
            "Scan complete: %d targets, %d findings",
            result.scan.targets_scanned,
            result.scan.finding_count,
        )
    except Exception as e:
        result.error = f"Scan failed: {e}"
        logger.error(result.error)
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result

    # Phase 3: Report generation (no auto-submit)
    logger.info("=" * 50)
    logger.info("PHASE 3: REPORT GENERATION")
    logger.info("=" * 50)
    try:
        result.reporting = generate_reports(
            program_handle,
            min_confidence=min_confidence,
            auto_submit=False,
        )
        logger.info(
            "Reports generated: %d candidates (%d duplicates skipped)",
            result.reporting.reports_generated,
            result.reporting.duplicates_skipped,
        )
    except Exception as e:
        result.error = f"Reporting failed: {e}"
        logger.error(result.error)

    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result


def print_summary(result: PipelineResult) -> None:
    """Print a human-readable summary of the pipeline run."""
    print()
    print("=" * 60)
    print(f"WINTERMUTE PIPELINE SUMMARY: {result.program_handle}")
    print(f"Duration: {result.duration_display}")
    print("=" * 60)

    if result.error:
        print(f"\nERROR: {result.error}")

    if result.recon:
        r = result.recon
        print("\n  RECON:")
        print(f"    Subdomains discovered:  {r.subdomains_found}")
        print(f"    Alive:                  {r.subdomains_alive}")
        print(f"    In-scope targets:       {r.in_scope_targets}")
        print(f"    Filtered out:           {r.out_of_scope_filtered}")

    if result.scan:
        s = result.scan
        print("\n  SCAN:")
        print(f"    Targets scanned:        {s.targets_scanned}")
        print(f"    Findings:               {s.finding_count}")
        print(f"    High-confidence:        {len(s.high_confidence_findings)}")
        if s.checks_run:
            print("    Checks run:")
            for check, count in sorted(s.checks_run.items()):
                print(f"      {check:25s} {count}")

    if result.reporting:
        rp = result.reporting
        print("\n  REPORTS:")
        print(f"    Total findings:         {rp.total_findings}")
        print(f"    Below threshold:        {rp.below_threshold}")
        print(f"    Duplicates skipped:     {rp.duplicates_skipped}")
        print(f"    Reports ready:          {rp.reports_generated}")

        if rp.candidates:
            print("\n  REPORTABLE FINDINGS:")
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_candidates = sorted(
                rp.candidates,
                key=lambda c: (severity_order.get(c.severity, 5), -c.confidence),
            )
            for c in sorted_candidates:
                dup = c.duplicate_warning
                print(f"    [{c.severity.upper():8s}] {c.report.title}{dup}")

    print()
    print("=" * 60)
    print("Run 'python -m scripts.run_reports {handle}' to review and submit.")
    print("=" * 60)
