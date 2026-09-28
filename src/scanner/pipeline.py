"""Vulnerability scanning pipeline — runs all checks against recon results.

This is the Phase 3 orchestrator. It takes the output of the recon pipeline
(discovered targets) and runs every vulnerability check against them,
respecting scope at every step.

Flow:
  1. Load targets from database (discovered in recon phase)
  2. For each target, run all applicable checks
  3. Collect findings with confidence scores
  4. Store findings in database
  5. Return summary for review
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.core.db import Finding, Program, Target, get_session
from src.core.scope import ScopeChecker
from src.platforms.hackerone import HackerOneClient, parse_scope
from src.recon.headers import analyze_headers
from src.scanner.cors import CORSCheck, check_cors
from src.scanner.exposed_files import ExposedFilesResult, check_exposed_files
from src.scanner.security_headers import (
    HeaderAnalysisResult,
    analyze_missing_headers,
)
from src.scanner.ssl_check import SSLCheck, check_ssl
from src.scanner.subdomain_takeover import TakeoverCheck, check_takeover

logger = logging.getLogger(__name__)


@dataclass
class ScanFinding:
    """A vulnerability finding from the scan pipeline."""

    hostname: str
    vuln_type: str
    title: str
    severity: str
    confidence: float
    description: str
    evidence: str
    remediation: str = ""


@dataclass
class ScanResult:
    """Summary of a full vulnerability scan."""

    program_handle: str
    targets_scanned: int = 0
    findings: list[ScanFinding] = field(default_factory=list)
    checks_run: dict[str, int] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def high_confidence_findings(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.confidence >= 0.7]


def run_scan(program_handle: str) -> ScanResult:
    """Run all vulnerability checks against a program's discovered targets.

    Prerequisites: recon pipeline must have been run first (targets in DB).
    """
    result = ScanResult(program_handle=program_handle)

    # Step 1: Build scope checker
    logger.info("Loading scope for %s", program_handle)
    with HackerOneClient() as client:
        raw_scopes = client.get_structured_scopes(program_handle)

    parsed = parse_scope(raw_scopes)
    checker = ScopeChecker.from_parsed_scope(program_handle, parsed)

    # Step 2: Load targets from database
    session = get_session()
    program = session.query(Program).filter_by(handle=program_handle).first()
    if not program:
        logger.error("Program %s not found in database. Run recon first.", program_handle)
        session.close()
        return result

    targets = session.query(Target).filter_by(program_id=program.id, alive=True).all()
    hostnames = [t.hostname for t in targets]
    target_map = {t.hostname: t for t in targets}

    logger.info("Loaded %d alive targets for %s", len(hostnames), program_handle)

    # Step 3: Run each check type
    for hostname in hostnames:
        # Re-verify scope (defense in depth)
        scope_result = checker.check(hostname)
        if not scope_result.allowed:
            logger.warning("Skipping %s — failed scope re-check", hostname)
            continue

        result.targets_scanned += 1

        # ── Subdomain Takeover ───────────────────────────────────
        takeover = check_takeover(hostname)
        result.checks_run["subdomain_takeover"] = result.checks_run.get("subdomain_takeover", 0) + 1
        if takeover.vulnerable:
            result.findings.append(ScanFinding(
                hostname=hostname,
                vuln_type="subdomain_takeover",
                title=f"Subdomain takeover possible on {hostname}",
                severity="high",
                confidence=takeover.confidence,
                description=(
                    f"{hostname} has a CNAME record pointing to {takeover.cname} "
                    f"({takeover.service}), which appears to be unclaimed."
                ),
                evidence=takeover.evidence,
                remediation=(
                    f"Remove the DNS record for {hostname}, or reclaim the "
                    f"{takeover.service} resource at {takeover.cname}."
                ),
            ))

        # ── CORS Misconfiguration ────────────────────────────────
        cors = check_cors(hostname)
        result.checks_run["cors"] = result.checks_run.get("cors", 0) + 1
        if cors.vulnerable:
            result.findings.append(ScanFinding(
                hostname=hostname,
                vuln_type="cors_misconfiguration",
                title=f"CORS misconfiguration on {hostname}",
                severity="medium" if cors.confidence < 0.9 else "high",
                confidence=cors.confidence,
                description=cors.issue,
                evidence=str(cors.details),
                remediation=(
                    "Configure CORS to only allow specific trusted origins. "
                    "Do not reflect the Origin header back unconditionally."
                ),
            ))

        # ── SSL/TLS Issues ───────────────────────────────────────
        ssl_result = check_ssl(hostname)
        result.checks_run["ssl_tls"] = result.checks_run.get("ssl_tls", 0) + 1
        for issue in ssl_result.issues:
            severity = "medium"
            if "expired" in issue.lower():
                severity = "medium"
            elif "deprecated" in issue.lower():
                severity = "low"
            elif "self-signed" in issue.lower():
                severity = "medium"

            result.findings.append(ScanFinding(
                hostname=hostname,
                vuln_type="ssl_tls",
                title=f"SSL/TLS issue on {hostname}: {issue}",
                severity=severity,
                confidence=ssl_result.confidence,
                description=issue,
                evidence=f"TLS version: {ssl_result.tls_version}, Cert: {ssl_result.cert_subject}",
                remediation=_ssl_remediation(issue),
            ))

        # ── Exposed Files ────────────────────────────────────────
        files_result = check_exposed_files(hostname)
        result.checks_run["exposed_files"] = result.checks_run.get("exposed_files", 0) + 1
        for finding in files_result.findings:
            confidence = 0.9 if finding.evidence else 0.5
            result.findings.append(ScanFinding(
                hostname=hostname,
                vuln_type="exposed_file",
                title=f"Exposed sensitive file on {hostname}: {finding.path}",
                severity=finding.severity,
                confidence=confidence,
                description=finding.evidence,
                evidence=f"HTTP {finding.status_code}, {finding.content_length} bytes",
                remediation=(
                    f"Remove or restrict access to {finding.path}. "
                    "Configure your web server to deny access to sensitive paths."
                ),
            ))

        # ── Security Headers ─────────────────────────────────────
        header_analysis = analyze_headers(hostname)
        result.checks_run["security_headers"] = result.checks_run.get("security_headers", 0) + 1
        if header_analysis.missing_security_headers:
            header_result = analyze_missing_headers(
                hostname, header_analysis.missing_security_headers
            )
            for hf in header_result.findings:
                # Only report medium+ header findings (info/low are too noisy)
                if hf.severity in ("medium", "high", "critical"):
                    result.findings.append(ScanFinding(
                        hostname=hostname,
                        vuln_type="missing_security_header",
                        title=f"{hf.title} on {hostname}",
                        severity=hf.severity,
                        confidence=hf.confidence,
                        description=hf.description,
                        evidence=f"Header '{hf.header}' not present in response",
                        remediation=hf.remediation,
                    ))

    # Step 4: Store findings in database
    _store_findings(session, target_map, result.findings)
    session.close()

    logger.info(
        "Scan complete for %s: %d targets, %d findings (%d high-confidence)",
        program_handle,
        result.targets_scanned,
        result.finding_count,
        len(result.high_confidence_findings),
    )

    return result


def _ssl_remediation(issue: str) -> str:
    """Generate remediation advice for SSL/TLS issues."""
    if "expired" in issue.lower():
        return "Renew the SSL/TLS certificate immediately."
    if "deprecated" in issue.lower() or "tls" in issue.lower():
        return (
            "Disable TLS 1.0 and 1.1. Configure the server to only "
            "accept TLS 1.2 and TLS 1.3."
        )
    if "self-signed" in issue.lower():
        return "Replace the self-signed certificate with one from a trusted CA."
    if "mismatch" in issue.lower():
        return "Ensure the certificate's Common Name or SAN matches the hostname."
    return "Review and fix the SSL/TLS configuration."


def _store_findings(
    session, target_map: dict[str, Target], findings: list[ScanFinding]
) -> None:
    """Persist scan findings to the database."""
    try:
        for f in findings:
            target = target_map.get(f.hostname)
            if not target:
                continue

            db_finding = Finding(
                target_id=target.id,
                vuln_type=f.vuln_type,
                severity=f.severity,
                confidence=f.confidence,
                title=f.title,
                description=f.description,
                evidence=f.evidence,
                status="new",
            )
            session.add(db_finding)

        session.commit()
        logger.info("Stored %d findings in database", len(findings))
    except Exception:
        session.rollback()
        raise
