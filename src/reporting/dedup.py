"""Duplicate detection — avoid submitting findings that have already been reported.

Three layers of dedup:
  1. Internal: check our own database for previous submissions
  2. Platform: check our HackerOne report history via API
  3. Heuristic: estimate likelihood of duplication based on program popularity
     and finding type
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from src.core.db import Finding, Program, get_session
from src.platforms.hackerone import HackerOneClient

logger = logging.getLogger(__name__)


@dataclass
class DedupResult:
    """Result of a duplicate check."""

    is_duplicate: bool = False
    reason: str = ""
    confidence: float = 0.0  # How sure we are it's a duplicate


def check_internal_duplicate(
    program_handle: str,
    hostname: str,
    vuln_type: str,
) -> DedupResult:
    """Check if we've already reported this finding.

    Looks at our local database for findings on the same host with the
    same vulnerability type that have already been submitted (status = 'reported').
    """
    session = get_session()
    try:
        program = session.query(Program).filter_by(handle=program_handle).first()
        if not program:
            return DedupResult()

        # Look for existing reported findings on same target + vuln type
        existing = (
            session.query(Finding)
            .join(Finding.target)
            .filter(
                Finding.status.in_(["reported", "duplicate", "verified"]),
                Finding.vuln_type == vuln_type,
                Finding.target.has(hostname=hostname, program_id=program.id),
            )
            .first()
        )

        if existing:
            return DedupResult(
                is_duplicate=True,
                reason=f"Previously submitted as finding #{existing.id} (status: {existing.status})",
                confidence=0.95,
            )

    finally:
        session.close()

    return DedupResult()


def check_platform_duplicate(
    program_handle: str,
    hostname: str,
    vuln_type: str,
) -> DedupResult:
    """Check our HackerOne report history for similar submissions.

    Queries the API for our own past reports and checks if any match
    the current finding.
    """
    try:
        with HackerOneClient() as client:
            reports = client.list_my_reports()

        for report in reports:
            attrs = report.get("attributes", {})
            title = (attrs.get("title", "") or "").lower()
            # Check if this report is about the same host and vuln type
            if hostname.lower() in title and vuln_type.replace("_", " ") in title:
                state = attrs.get("state", "")
                return DedupResult(
                    is_duplicate=True,
                    reason=f"Similar report found on platform (state: {state}): {attrs.get('title', '')}",
                    confidence=0.8,
                )

    except Exception as e:
        logger.warning("Platform dedup check failed: %s", e)

    return DedupResult()


# Heuristic scoring: how likely is this finding type to be a duplicate
# on a well-known, heavily-tested program?
COMMON_FINDING_SCORES = {
    "missing_security_header": 0.95,    # Almost always already reported
    "ssl_tls": 0.85,                    # Very commonly reported
    "exposed_file": 0.6,               # Depends on the file
    "cors_misconfiguration": 0.5,       # Sometimes novel
    "subdomain_takeover": 0.4,          # Often novel, especially new subdomains
}

# Programs known to be heavily tested (just handle names)
HEAVILY_TESTED_PROGRAMS = {
    "security",         # HackerOne itself
    "github",
    "gitlab",
    "shopify",
    "twitter",
    "slack",
    "uber",
    "dropbox",
    "paypal",
    "google",
    "facebook",
    "microsoft",
}


def check_heuristic_duplicate(
    program_handle: str,
    vuln_type: str,
) -> DedupResult:
    """Estimate probability this is a duplicate based on heuristics.

    Considers:
      - How commonly this vuln type is reported
      - How heavily tested this program is
    """
    base_score = COMMON_FINDING_SCORES.get(vuln_type, 0.3)

    if program_handle.lower() in HEAVILY_TESTED_PROGRAMS:
        # Heavily tested programs have much higher duplicate rates
        adjusted = min(base_score + 0.2, 0.99)
    else:
        adjusted = base_score

    if adjusted >= 0.8:
        return DedupResult(
            is_duplicate=False,  # Don't auto-skip, but flag it
            reason=f"High duplicate probability ({int(adjusted * 100)}%) — consider manual review",
            confidence=adjusted,
        )

    return DedupResult(confidence=adjusted)


def full_dedup_check(
    program_handle: str,
    hostname: str,
    vuln_type: str,
) -> DedupResult:
    """Run all dedup checks and return the strongest signal.

    Order of checks:
      1. Internal DB (cheapest, most reliable)
      2. Heuristic (fast estimate)
      3. Platform API (slow, rate-limited)

    Returns the first definitive duplicate, or the heuristic estimate.
    """
    # Check 1: Internal
    internal = check_internal_duplicate(program_handle, hostname, vuln_type)
    if internal.is_duplicate:
        logger.info("Dedup: internal match for %s/%s on %s", program_handle, vuln_type, hostname)
        return internal

    # Check 2: Heuristic
    heuristic = check_heuristic_duplicate(program_handle, vuln_type)

    # Check 3: Platform (only if heuristic didn't flag high probability)
    if heuristic.confidence < 0.8:
        platform = check_platform_duplicate(program_handle, hostname, vuln_type)
        if platform.is_duplicate:
            logger.info("Dedup: platform match for %s/%s on %s", program_handle, vuln_type, hostname)
            return platform

    return heuristic
