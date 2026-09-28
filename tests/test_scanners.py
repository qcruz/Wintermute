"""Tests for vulnerability scanners."""

from src.scanner.security_headers import analyze_missing_headers, SEVERITY_ORDER
from src.scanner.subdomain_takeover import _match_service, _get_cname
from src.scanner.cors import TEST_ORIGIN


# ── Security Headers ─────────────────────────────────────────────────


def test_missing_hsts_is_medium():
    result = analyze_missing_headers("test.com", ["strict-transport-security"])
    assert len(result.findings) == 1
    assert result.findings[0].severity == "medium"
    assert result.worst_severity == "medium"


def test_missing_csp_is_low():
    result = analyze_missing_headers("test.com", ["content-security-policy"])
    assert len(result.findings) == 1
    assert result.findings[0].severity == "low"


def test_multiple_missing_headers():
    missing = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    result = analyze_missing_headers("test.com", missing)
    assert result.total_missing == 6
    assert len(result.findings) == 6
    assert result.worst_severity == "medium"


def test_no_missing_headers():
    result = analyze_missing_headers("test.com", [])
    assert result.total_missing == 0
    assert not result.has_findings


# ── Subdomain Takeover ───────────────────────────────────────────────


def test_match_heroku_service():
    service, fps = _match_service("myapp.herokuapp.com")
    assert service == "Heroku"
    assert len(fps) > 0


def test_match_github_pages():
    service, fps = _match_service("myorg.github.io")
    assert service == "GitHub Pages"


def test_match_s3():
    service, fps = _match_service("mybucket.s3.amazonaws.com")
    assert service == "AWS S3"


def test_no_match_normal_domain():
    service, fps = _match_service("www.google.com")
    assert service == ""
    assert fps == []


def test_match_is_case_insensitive():
    service, _ = _match_service("MyApp.HerokuApp.COM")
    assert service == "Heroku"


# ── CORS ─────────────────────────────────────────────────────────────


def test_test_origin_is_not_real_domain():
    assert "example.com" in TEST_ORIGIN
    assert "wintermute" in TEST_ORIGIN.lower()


# ── Severity ordering ───────────────────────────────────────────────


def test_severity_order():
    assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"]
    assert SEVERITY_ORDER["high"] > SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] > SEVERITY_ORDER["low"]
    assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["info"]
