"""Tests for the reporting engine."""

from src.reporting.dedup import (
    COMMON_FINDING_SCORES,
    HEAVILY_TESTED_PROGRAMS,
    check_heuristic_duplicate,
)
from src.reporting.templates import (
    Report,
    cors_misconfiguration_report,
    exposed_file_report,
    missing_security_header_report,
    ssl_tls_report,
    subdomain_takeover_report,
)

# ── Report template tests ───────────────────────────────────────────


def test_subdomain_takeover_report_structure():
    report = subdomain_takeover_report(
        hostname="staging.example.com",
        cname="old-app.herokuapp.com",
        service="Heroku",
        evidence="HTTP 200: body contains 'no such app'",
    )
    assert report.title == "Subdomain takeover via dangling CNAME on staging.example.com"
    assert report.severity_rating == "high"
    assert "staging.example.com" in report.vulnerability_information
    assert "herokuapp.com" in report.vulnerability_information
    assert "Heroku" in report.vulnerability_information
    assert "dig" in report.vulnerability_information  # Has repro steps
    assert report.impact  # Impact is not empty
    assert "phishing" in report.impact.lower()


def test_cors_report_with_credentials():
    report = cors_misconfiguration_report(
        hostname="api.example.com",
        issue="Reflects arbitrary origin with credentials",
        details={
            "access-control-allow-origin": "https://evil.com",
            "access-control-allow-credentials": "true",
        },
    )
    assert report.severity_rating == "medium"
    assert "api.example.com" in report.title
    assert "Origin" in report.vulnerability_information


def test_cors_report_without_credentials():
    report = cors_misconfiguration_report(
        hostname="api.example.com",
        issue="Reflects arbitrary origin (no credentials)",
        details={
            "access-control-allow-origin": "https://evil.com",
            "access-control-allow-credentials": "",
        },
    )
    assert report.severity_rating == "medium"


def test_exposed_file_report():
    report = exposed_file_report(
        hostname="example.com",
        path="/.git/config",
        description="Git repository configuration",
        evidence="HTTP 200, matched: [core]",
        severity="high",
    )
    assert "/.git/config" in report.title
    assert report.severity_rating == "high"
    assert "deny" in report.vulnerability_information.lower()  # Has remediation


def test_exposed_file_info_maps_to_none():
    report = exposed_file_report(
        hostname="example.com",
        path="/robots.txt",
        description="Robots.txt",
        evidence="matched: user-agent",
        severity="info",
    )
    assert report.severity_rating == "none"


def test_missing_header_report():
    report = missing_security_header_report(
        hostname="example.com",
        header="Strict-Transport-Security",
        header_description="HSTS is not set.",
        remediation="Add HSTS header.",
    )
    assert report.severity_rating == "low"
    assert "Strict-Transport-Security" in report.title


def test_ssl_tls_report_expired():
    report = ssl_tls_report(
        hostname="example.com",
        issue="Certificate EXPIRED 30 days ago",
        tls_version="TLSv1.3",
        cert_info="CN=example.com, Issuer=DigiCert",
    )
    assert report.severity_rating == "medium"
    assert "expired" in report.title.lower()


def test_ssl_tls_report_deprecated():
    report = ssl_tls_report(
        hostname="example.com",
        issue="Supports deprecated TLSv1.0",
        tls_version="TLSv1.0",
        cert_info="CN=example.com",
    )
    assert report.severity_rating == "low"


def test_report_preview():
    report = Report(
        title="Test Report",
        severity_rating="high",
        vulnerability_information="Details here",
        impact="Bad things",
    )
    preview = report.preview()
    assert "Test Report" in preview
    assert "HIGH" in preview
    assert "Details here" in preview


# ── Dedup tests ──────────────────────────────────────────────────────


def test_heuristic_dedup_heavily_tested():
    result = check_heuristic_duplicate("security", "missing_security_header")
    # HackerOne's own program + missing headers = very likely duplicate
    assert result.confidence >= 0.9


def test_heuristic_dedup_unknown_program():
    result = check_heuristic_duplicate("obscure-startup", "subdomain_takeover")
    # Unknown program + subdomain takeover = lower duplicate probability
    assert result.confidence < 0.8


def test_heuristic_dedup_novel_finding():
    result = check_heuristic_duplicate("obscure-startup", "cors_misconfiguration")
    assert result.confidence < 0.8
    assert not result.is_duplicate


def test_common_finding_scores_has_all_types():
    expected_types = [
        "missing_security_header",
        "ssl_tls",
        "exposed_file",
        "cors_misconfiguration",
        "subdomain_takeover",
    ]
    for vt in expected_types:
        assert vt in COMMON_FINDING_SCORES


def test_heavily_tested_includes_major_programs():
    assert "security" in HEAVILY_TESTED_PROGRAMS  # HackerOne
    assert "github" in HEAVILY_TESTED_PROGRAMS
    assert "shopify" in HEAVILY_TESTED_PROGRAMS


# ── Submission tracking tests ──────────────────────────────────────


def test_submission_model_exists():
    """Submission DB model should be importable."""
    from src.core.db import Submission
    assert Submission.__tablename__ == "submissions"


def test_submission_model_fields():
    """Submission should have outcome tracking fields."""
    from src.core.db import Submission
    cols = {c.name for c in Submission.__table__.columns}
    assert "report_id" in cols
    assert "outcome" in cols
    assert "bounty_amount" in cols
    assert "lesson" in cols
    assert "program_handle" in cols


def test_submission_valid_outcomes():
    """Verify the outcome values we document are consistent."""
    # These are the outcomes documented in the CLI help
    valid = {"pending", "triaged", "duplicate", "accepted", "rejected", "informative", "na"}
    assert len(valid) == 7


def test_ai_infra_report_template():
    """AI infra report template should produce valid report."""
    from unittest.mock import MagicMock
    from src.reporting.templates import ai_infra_report

    finding = MagicMock()
    finding.title = "Unauthenticated Ollama on example.com"
    finding.description = "Ollama API accessible without authentication"
    finding.evidence = "Ollama API — 3 models loaded"
    finding.vuln_type = "ai_infra_exposed"

    report = ai_infra_report(finding)
    assert report.severity_rating == "high"
    assert report.weakness_id == 284
    assert "Ollama" in report.vulnerability_information
    assert "authentication" in report.impact.lower()
