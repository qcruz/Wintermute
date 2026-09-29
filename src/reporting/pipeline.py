"""Reporting pipeline — generates reports from findings and manages submission.

This is the Phase 4 orchestrator. It takes findings from the scan pipeline,
runs duplicate checks, generates professional reports from templates, and
queues them for review or submission.

Flow:
  1. Load new findings from database
  2. Filter by confidence threshold
  3. Run duplicate checks
  4. Generate reports from templates
  5. Present review queue to user
  6. Submit approved reports via HackerOne API
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.core.db import Finding, Program, Target, get_session
from src.platforms.hackerone import HackerOneClient
from src.reporting.dedup import DedupResult, full_dedup_check
from src.reporting.templates import (
    Report,
    auth_finding_report,
    business_logic_report,
    content_discovery_report,
    cors_misconfiguration_report,
    exposed_file_report,
    idor_report,
    injection_report,
    graphql_introspection_report,
    js_secret_report,
    path_traversal_report,
    missing_security_header_report,
    ssl_tls_report,
    subdomain_takeover_report,
)

logger = logging.getLogger(__name__)

# Minimum confidence to consider a finding reportable
MIN_CONFIDENCE = 0.7

# Minimum severity to auto-generate reports (skip info-level)
REPORTABLE_SEVERITIES = {"critical", "high", "medium"}


@dataclass
class ReportCandidate:
    """A finding paired with its generated report and dedup status."""

    finding_id: int
    hostname: str
    vuln_type: str
    severity: str
    confidence: float
    report: Report
    dedup: DedupResult
    status: str = "pending"  # pending, approved, submitted, skipped

    @property
    def is_reportable(self) -> bool:
        """Should this be presented for review?"""
        return (
            not self.dedup.is_duplicate
            and self.severity in REPORTABLE_SEVERITIES
            and self.confidence >= MIN_CONFIDENCE
        )

    @property
    def duplicate_warning(self) -> str:
        if self.dedup.confidence >= 0.8:
            return f" [LIKELY DUP: {self.dedup.reason}]"
        return ""


@dataclass
class ReportingResult:
    """Summary of the reporting pipeline run."""

    program_handle: str
    total_findings: int = 0
    below_threshold: int = 0
    duplicates_skipped: int = 0
    reports_generated: int = 0
    reports_submitted: int = 0
    candidates: list[ReportCandidate] = field(default_factory=list)


def generate_reports(
    program_handle: str,
    min_confidence: float = MIN_CONFIDENCE,
    auto_submit: bool = False,
) -> ReportingResult:
    """Generate reports for all new findings on a program.

    Args:
        program_handle: The HackerOne program handle
        min_confidence: Minimum confidence threshold (0.0 - 1.0)
        auto_submit: If True, submit high-confidence reports automatically.
                     Default False — always review first.
    """
    result = ReportingResult(program_handle=program_handle)
    session = get_session()

    try:
        program = session.query(Program).filter_by(handle=program_handle).first()
        if not program:
            logger.error("Program %s not found in database", program_handle)
            return result

        # Step 1: Load new findings above confidence threshold
        findings = (
            session.query(Finding)
            .join(Finding.target)
            .filter(
                Target.program_id == program.id,
                Finding.status == "new",
            )
            .all()
        )

        result.total_findings = len(findings)

        for finding in findings:
            target = finding.target

            # Step 2: Filter by confidence
            if finding.confidence < min_confidence:
                result.below_threshold += 1
                continue

            # Skip info-level findings
            if finding.severity not in REPORTABLE_SEVERITIES:
                result.below_threshold += 1
                continue

            # Step 3: Duplicate check
            dedup = full_dedup_check(
                program_handle, target.hostname, finding.vuln_type
            )

            if dedup.is_duplicate:
                result.duplicates_skipped += 1
                finding.status = "duplicate"
                session.commit()
                continue

            # Step 4: Generate report from template
            report = _generate_report(finding, target)
            if not report:
                continue

            candidate = ReportCandidate(
                finding_id=finding.id,
                hostname=target.hostname,
                vuln_type=finding.vuln_type,
                severity=finding.severity,
                confidence=finding.confidence,
                report=report,
                dedup=dedup,
            )

            result.candidates.append(candidate)
            result.reports_generated += 1

        # Step 5: Submit if auto_submit is enabled (default: off)
        if auto_submit:
            for candidate in result.candidates:
                if candidate.is_reportable and candidate.confidence >= 0.9:
                    success = _submit_report(candidate, program_handle, session)
                    if success:
                        result.reports_submitted += 1

        session.commit()

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    return result


def submit_candidate(
    candidate: ReportCandidate,
    program_handle: str,
) -> bool:
    """Submit a single approved report candidate to HackerOne.

    Call this after human review approves a report.
    """
    session = get_session()
    try:
        success = _submit_report(candidate, program_handle, session)
        session.commit()
        return success
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _submit_report(
    candidate: ReportCandidate,
    program_handle: str,
    session,
) -> bool:
    """Submit a report to HackerOne via the API."""
    report = candidate.report

    try:
        with HackerOneClient() as client:
            response = client.submit_report(
                team_handle=program_handle,
                title=report.title,
                vulnerability_information=report.vulnerability_information,
                impact=report.impact,
                severity_rating=report.severity_rating,
            )

        # Update finding status in database
        finding = session.query(Finding).get(candidate.finding_id)
        if finding:
            finding.status = "reported"
            finding.reported_at = datetime.now(timezone.utc)

        candidate.status = "submitted"
        report_id = response.get("data", {}).get("id", "unknown")
        logger.info(
            "Submitted report for %s on %s (report ID: %s)",
            candidate.vuln_type, candidate.hostname, report_id,
        )
        return True

    except Exception as e:
        logger.error("Failed to submit report for %s: %s", candidate.hostname, e)
        candidate.status = "error"
        return False


def _generate_report(finding: Finding, target: Target) -> Report | None:
    """Generate a report from a finding using the appropriate template."""
    try:
        if finding.vuln_type == "subdomain_takeover":
            # Extract CNAME and service from evidence/description
            desc = finding.description or ""
            evidence = finding.evidence or ""

            # Parse CNAME from description like "hostname has a CNAME record pointing to X (Service)"
            cname = ""
            service = ""
            if "pointing to" in desc:
                parts = desc.split("pointing to")
                if len(parts) > 1:
                    rest = parts[1].strip()
                    if "(" in rest:
                        cname = rest.split("(")[0].strip().rstrip(",")
                        service = rest.split("(")[1].split(")")[0]
                    else:
                        cname = rest.split(",")[0].strip()

            return subdomain_takeover_report(
                hostname=target.hostname,
                cname=cname,
                service=service,
                evidence=evidence,
            )

        elif finding.vuln_type == "cors_misconfiguration":
            return cors_misconfiguration_report(
                hostname=target.hostname,
                issue=finding.description or "",
                details={},  # Details not stored in DB currently
            )

        elif finding.vuln_type == "exposed_file":
            # Extract path from title like "Exposed sensitive file on host: /path"
            path = ""
            title = finding.title or ""
            if ": " in title:
                path = title.split(": ")[-1]

            return exposed_file_report(
                hostname=target.hostname,
                path=path,
                description=finding.description or "",
                evidence=finding.evidence or "",
                severity=finding.severity,
            )

        elif finding.vuln_type == "missing_security_header":
            # Extract header name from title
            header = ""
            title = finding.title or ""
            if "Missing" in title and "on" in title:
                header = title.split("on")[0].replace("Missing", "").strip()

            return missing_security_header_report(
                hostname=target.hostname,
                header=header,
                header_description=finding.description or "",
                remediation=finding.evidence or "",
            )

        elif finding.vuln_type == "ssl_tls":
            return ssl_tls_report(
                hostname=target.hostname,
                issue=finding.description or "",
                tls_version="",
                cert_info=finding.evidence or "",
            )

        elif finding.vuln_type == "content_discovery":
            # Extract path from title like "Discovered X at host/path"
            path = ""
            title = finding.title or ""
            if " at " in title:
                after_at = title.split(" at ")[-1]
                if "/" in after_at:
                    path = "/" + after_at.split("/", 1)[-1]

            return content_discovery_report(
                hostname=target.hostname,
                path=path,
                description=finding.description or "",
                category="",
                evidence=finding.evidence or "",
                severity=finding.severity,
            )

        elif finding.vuln_type in ("xss", "sqli", "open_redirect", "ssti"):
            # Extract parameter from evidence like "Parameter: X, Payload: Y"
            parameter = ""
            payload = ""
            evidence = finding.evidence or ""
            if "Parameter:" in evidence:
                parameter = evidence.split("Parameter:")[1].split(",")[0].strip()
            if "Payload:" in evidence:
                payload = evidence.split("Payload:")[1].split("\n")[0].strip()

            return injection_report(
                hostname=target.hostname,
                vuln_type=finding.vuln_type,
                parameter=parameter,
                description=finding.description or "",
                evidence=evidence,
                payload=payload,
            )

        elif finding.vuln_type in ("insecure_cookie", "missing_auth", "jwt_issue", "session_issue"):
            return auth_finding_report(
                hostname=target.hostname,
                vuln_type=finding.vuln_type,
                title=finding.title or "",
                description=finding.description or "",
                evidence=finding.evidence or "",
            )

        elif finding.vuln_type == "idor":
            return idor_report(finding)

        elif finding.vuln_type == "path_traversal":
            return path_traversal_report(finding)

        elif finding.vuln_type == "graphql_introspection":
            return graphql_introspection_report(finding)

        elif finding.vuln_type == "js_secret":
            return js_secret_report(finding)

        elif finding.vuln_type in ("info_disclosure", "error_leak", "method_allowed", "clickjack", "cache_issue"):
            return business_logic_report(
                hostname=target.hostname,
                vuln_type=finding.vuln_type,
                title=finding.title or "",
                description=finding.description or "",
                evidence=finding.evidence or "",
            )

        else:
            logger.warning("No template for vuln type: %s", finding.vuln_type)
            return None

    except Exception as e:
        logger.error(
            "Failed to generate report for finding %d: %s", finding.id, e
        )
        return None
