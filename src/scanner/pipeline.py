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
from src.scanner.auth_checks import check_auth
from src.scanner.business_logic import analyze_business_logic
from src.scanner.content_discovery import discover_content
from src.scanner.cors import CORSCheck, check_cors
from src.scanner.exposed_files import ExposedFilesResult, check_exposed_files
from src.scanner.idor import check_idor
from src.scanner.injection import test_injection
from src.scanner.path_traversal import check_path_traversal
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


ALL_CHECKS = [
    "subdomain_takeover", "cors", "ssl_tls", "exposed_files",
    "security_headers", "content_discovery", "injection",
    "auth_checks", "business_logic", "idor", "path_traversal",
]

# Lighter check set for quick scans (fast, low request count per target)
QUICK_CHECKS = [
    "subdomain_takeover", "cors", "ssl_tls", "security_headers",
]


def run_scan(
    program_handle: str,
    max_targets: int = 0,
    checks: list[str] | None = None,
    hostname_filter: str = "",
) -> ScanResult:
    """Run vulnerability checks against a program's discovered targets.

    Args:
        program_handle: HackerOne program handle
        max_targets: Limit number of targets to scan (0 = all)
        checks: List of check names to run (None = all). Use QUICK_CHECKS for fast scans.
        hostname_filter: Only scan hostnames containing this substring

    Prerequisites: recon pipeline must have been run first (targets in DB).
    """
    enabled_checks = set(checks or ALL_CHECKS)
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

    # Apply hostname filter
    if hostname_filter:
        targets = [t for t in targets if hostname_filter in t.hostname]

    hostnames = [t.hostname for t in targets]
    target_map = {t.hostname: t for t in targets}

    # Apply target limit
    if max_targets > 0:
        hostnames = hostnames[:max_targets]

    logger.info(
        "Loaded %d alive targets for %s (scanning %d, checks: %s)",
        len(targets), program_handle, len(hostnames),
        ", ".join(sorted(enabled_checks)),
    )

    # Step 3: Run each check type
    for hostname in hostnames:
        # Re-verify scope (defense in depth)
        scope_result = checker.check(hostname)
        if not scope_result.allowed:
            logger.warning("Skipping %s — failed scope re-check", hostname)
            continue

        result.targets_scanned += 1

        # ── Subdomain Takeover ───────────────────────────────────
        if "subdomain_takeover" in enabled_checks:
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
        if "cors" in enabled_checks:
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
        if "ssl_tls" in enabled_checks:
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
        if "exposed_files" in enabled_checks:
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
        if "security_headers" in enabled_checks:
            header_analysis = analyze_headers(hostname)
            result.checks_run["security_headers"] = result.checks_run.get("security_headers", 0) + 1
            if header_analysis.missing_security_headers:
                header_result = analyze_missing_headers(
                    hostname, header_analysis.missing_security_headers
                )
                for hf in header_result.findings:
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

        # ── Content Discovery ─────────────────────────────────────
        if "content_discovery" in enabled_checks:
            content_result = discover_content(hostname)
            result.checks_run["content_discovery"] = result.checks_run.get("content_discovery", 0) + 1
            for ep in content_result.endpoints:
                if ep.severity in ("info",):
                    continue
                result.findings.append(ScanFinding(
                    hostname=hostname,
                    vuln_type="content_discovery",
                    title=f"Discovered {ep.description} at {hostname}{ep.path}",
                    severity=ep.severity,
                    confidence=0.8 if ep.evidence and "fingerprint" in ep.evidence.lower() else 0.6,
                    description=(
                        f"Active content discovery found {ep.description} at "
                        f"{hostname}{ep.path} (category: {ep.category})."
                    ),
                    evidence=ep.evidence,
                    remediation=(
                        f"Restrict access to {ep.path} if it should not be publicly "
                        f"accessible. Remove development/debug endpoints from production."
                    ),
                ))

        # ── Injection Testing ─────────────────────────────────────
        if "injection" in enabled_checks:
            injection_result = test_injection(hostname)
            result.checks_run["injection"] = result.checks_run.get("injection", 0) + 1
            for finding in injection_result.findings:
                result.findings.append(ScanFinding(
                    hostname=hostname,
                    vuln_type=finding.vuln_type,
                    title=finding.description,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    description=finding.description,
                    evidence=f"Parameter: {finding.parameter}, Payload: {finding.payload_used}\n{finding.evidence}",
                    remediation=_injection_remediation(finding.vuln_type),
                ))

        # ── Authentication Checks ─────────────────────────────────
        if "auth_checks" in enabled_checks:
            auth_result = check_auth(hostname)
            result.checks_run["auth_checks"] = result.checks_run.get("auth_checks", 0) + 1
            for finding in auth_result.findings:
                result.findings.append(ScanFinding(
                    hostname=hostname,
                    vuln_type=finding.vuln_type,
                    title=finding.title,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    description=finding.description,
                    evidence=finding.evidence,
                    remediation=_auth_remediation(finding.vuln_type),
                ))

        # ── Business Logic Analysis ───────────────────────────────
        if "business_logic" in enabled_checks:
            biz_result = analyze_business_logic(hostname)
            result.checks_run["business_logic"] = result.checks_run.get("business_logic", 0) + 1
            for finding in biz_result.findings:
                result.findings.append(ScanFinding(
                    hostname=hostname,
                    vuln_type=finding.vuln_type,
                    title=finding.title,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    description=finding.description,
                    evidence=finding.evidence,
                    remediation=_business_remediation(finding.vuln_type),
                ))

        # ── IDOR Detection ──────────────────────────────────────────
        if "idor" in enabled_checks:
            idor_result = check_idor(hostname)
            result.checks_run["idor"] = result.checks_run.get("idor", 0) + 1
            for finding in idor_result.findings:
                result.findings.append(ScanFinding(
                    hostname=hostname,
                    vuln_type=finding.vuln_type,
                    title=finding.title,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    description=finding.description,
                    evidence=finding.evidence,
                    remediation=(
                        "Implement proper authorization checks on all API endpoints. "
                        "Verify that the authenticated user owns or has permission to "
                        "access the requested resource. Use UUIDs instead of sequential "
                        "IDs to make enumeration harder (defense in depth, not a fix)."
                    ),
                ))

        # ── Path Traversal / LFI ──
        if "path_traversal" in enabled_checks:
            traversal_result = check_path_traversal(hostname)
            result.checks_run["path_traversal"] = result.checks_run.get("path_traversal", 0) + 1
            for finding in traversal_result.findings:
                result.findings.append(ScanFinding(
                    hostname=hostname,
                    vuln_type=finding.vuln_type,
                    title=f"Path Traversal via '{finding.parameter}' on {hostname}",
                    severity=finding.severity,
                    confidence=finding.confidence,
                    description=finding.description,
                    evidence=finding.evidence,
                    remediation=(
                        "Never use user input directly in file paths. Use an allowlist of "
                        "permitted files, resolve paths with realpath() and verify they stay "
                        "within the intended directory, and strip or reject directory traversal "
                        "sequences (../, ..\\, URL-encoded variants)."
                    ),
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


def _injection_remediation(vuln_type: str) -> str:
    """Generate remediation advice for injection findings."""
    remediations = {
        "xss": (
            "Sanitize and encode all user input before rendering in HTML. "
            "Use Content-Security-Policy headers and context-aware output encoding."
        ),
        "sqli": (
            "Use parameterized queries or prepared statements for all database queries. "
            "Never concatenate user input into SQL strings. Disable verbose error messages."
        ),
        "open_redirect": (
            "Validate redirect URLs against an allowlist of trusted destinations. "
            "Never use user-supplied URLs directly in redirect responses."
        ),
        "ssti": (
            "Never pass user input directly into template engines. "
            "Use sandboxed template environments and validate all template variables."
        ),
    }
    return remediations.get(vuln_type, "Validate and sanitize all user input.")


def _auth_remediation(vuln_type: str) -> str:
    """Generate remediation advice for auth findings."""
    remediations = {
        "insecure_cookie": (
            "Set Secure, HttpOnly, and SameSite flags on all session cookies. "
            "Example: Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Lax"
        ),
        "missing_auth": (
            "Require authentication for all sensitive endpoints. "
            "Implement proper access control checks on the server side."
        ),
        "jwt_issue": (
            "Use strong asymmetric algorithms (RS256/ES256) for JWT signing. "
            "Never accept 'none' algorithm. Validate all JWT claims server-side."
        ),
        "session_issue": (
            "Implement CSRF tokens on all state-changing forms. "
            "Ensure login forms submit over HTTPS only."
        ),
    }
    return remediations.get(vuln_type, "Review and strengthen authentication controls.")


def _business_remediation(vuln_type: str) -> str:
    """Generate remediation advice for business logic findings."""
    remediations = {
        "info_disclosure": (
            "Remove version information from response headers. "
            "Configure the server to minimize information exposure."
        ),
        "error_leak": (
            "Configure custom error pages that don't expose stack traces or internal paths. "
            "Disable debug mode in production environments."
        ),
        "method_allowed": (
            "Disable unnecessary HTTP methods (PUT, DELETE, TRACE) on the web server. "
            "Only allow methods that are explicitly needed."
        ),
        "clickjack": (
            "Set X-Frame-Options: DENY or SAMEORIGIN header, or use "
            "Content-Security-Policy: frame-ancestors 'self'."
        ),
        "cache_issue": (
            "Set Cache-Control: no-store, no-cache on pages with sensitive data. "
            "Add Pragma: no-cache for HTTP/1.0 compatibility."
        ),
    }
    return remediations.get(vuln_type, "Review the application's security configuration.")


def _store_findings(
    session, target_map: dict[str, Target], findings: list[ScanFinding]
) -> None:
    """Persist scan findings to the database, skipping duplicates."""
    stored = 0
    skipped = 0

    try:
        for f in findings:
            target = target_map.get(f.hostname)
            if not target:
                continue

            # Skip if we already have this exact finding
            existing = (
                session.query(Finding)
                .filter_by(
                    target_id=target.id,
                    vuln_type=f.vuln_type,
                    title=f.title,
                )
                .first()
            )
            if existing:
                skipped += 1
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
            stored += 1

        session.commit()
        logger.info("Stored %d findings in database (%d duplicates skipped)", stored, skipped)
    except Exception:
        session.rollback()
        raise
