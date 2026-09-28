"""Tests for vulnerability scanners."""

from src.scanner.security_headers import analyze_missing_headers, SEVERITY_ORDER
from src.scanner.subdomain_takeover import _match_service, _get_cname
from src.scanner.cors import TEST_ORIGIN
from src.scanner.idor import (
    _looks_like_data_object,
    _count_unique_responses,
    SENSITIVE_FIELDS,
    API_PATTERNS,
    TEST_IDS,
)


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


# ── IDOR Detection ─────────────────────────────────────────────────


def test_looks_like_data_object_with_id():
    obj = {"id": 1, "name": "Alice", "email": "alice@example.com", "created_at": "2024-01-01"}
    assert _looks_like_data_object(obj) is True


def test_looks_like_data_object_error_message():
    obj = {"message": "Not found", "error": "404", "status": "error"}
    assert _looks_like_data_object(obj) is False


def test_looks_like_data_object_too_simple():
    obj = {"ok": True}
    assert _looks_like_data_object(obj) is False


def test_looks_like_data_object_complex_no_indicators():
    obj = {"foo": 1, "bar": 2, "baz": 3, "qux": 4, "quux": 5}
    assert _looks_like_data_object(obj) is True


def test_count_unique_responses_different_ids():
    responses = {
        "1": {"id": 1, "name": "Alice"},
        "2": {"id": 2, "name": "Bob"},
        "3": {"id": 3, "name": "Carol"},
    }
    assert _count_unique_responses(responses) == 3


def test_count_unique_responses_same_object():
    responses = {
        "1": {"id": 1, "name": "Alice"},
        "2": {"id": 1, "name": "Alice"},
        "3": {"id": 1, "name": "Alice"},
    }
    assert _count_unique_responses(responses) == 1


def test_count_unique_responses_no_id_field():
    responses = {
        "1": {"name": "Alice", "role": "admin"},
        "2": {"name": "Bob", "role": "user"},
    }
    assert _count_unique_responses(responses) == 2


def test_sensitive_fields_include_pii():
    assert "email" in SENSITIVE_FIELDS
    assert "phone" in SENSITIVE_FIELDS
    assert "password" in SENSITIVE_FIELDS
    assert "api_key" in SENSITIVE_FIELDS


def test_api_patterns_have_id_placeholder():
    for pattern, _ in API_PATTERNS:
        assert "{id}" in pattern, f"Pattern missing {{id}}: {pattern}"


def test_test_ids_are_small_numbers():
    for tid in TEST_IDS:
        assert tid.isdigit(), f"Test ID is not numeric: {tid}"
        assert int(tid) <= 1000, f"Test ID too large: {tid}"
