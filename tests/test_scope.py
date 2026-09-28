"""Tests for the scope checker — the most critical safety component."""

import pytest

from src.core.scope import ScopeChecker, ScopeEntry, require_scope


# ── Fixtures ─────────────────────────────────────────────────────────


def make_checker() -> ScopeChecker:
    """Build a checker with a realistic scope setup."""
    in_scope = [
        ScopeEntry("*.example.com", "URL", eligible_for_bounty=True, eligible_for_submission=True),
        ScopeEntry("api.example.com", "URL", eligible_for_bounty=True, eligible_for_submission=True),
        ScopeEntry("https://app.target.io/", "URL", eligible_for_bounty=True, eligible_for_submission=True),
        ScopeEntry("10.0.0.0/24", "CIDR", eligible_for_bounty=True, eligible_for_submission=True),
        ScopeEntry("192.168.1.100", "IP", eligible_for_bounty=True, eligible_for_submission=True),
        ScopeEntry("target.io", "Domain", eligible_for_bounty=True, eligible_for_submission=True),
    ]
    out_of_scope = [
        ScopeEntry("support.example.com", "URL", eligible_for_submission=False),
        ScopeEntry("staging.example.com", "URL", eligible_for_submission=False),
    ]
    return ScopeChecker("test-program", in_scope, out_of_scope)


# ── Exact match ──────────────────────────────────────────────────────


def test_exact_domain_match():
    checker = make_checker()
    assert checker.check("api.example.com").allowed is True


def test_exact_domain_case_insensitive():
    checker = make_checker()
    assert checker.check("API.Example.COM").allowed is True


# ── Wildcard matching ────────────────────────────────────────────────


def test_wildcard_matches_subdomain():
    checker = make_checker()
    assert checker.check("www.example.com").allowed is True
    assert checker.check("mail.example.com").allowed is True


def test_wildcard_matches_deep_subdomain():
    checker = make_checker()
    assert checker.check("a.b.c.example.com").allowed is True


def test_wildcard_does_not_match_base_domain():
    """*.example.com should NOT match example.com itself."""
    in_scope = [
        ScopeEntry("*.example.com", "URL", eligible_for_submission=True),
    ]
    checker = ScopeChecker("test", in_scope)
    assert checker.check("example.com").allowed is False


# ── URL normalization ────────────────────────────────────────────────


def test_url_target_normalized_to_hostname():
    checker = make_checker()
    assert checker.check("https://api.example.com/v1/users").allowed is True


def test_url_scope_entry_normalized():
    checker = make_checker()
    assert checker.check("app.target.io").allowed is True
    assert checker.check("https://app.target.io/foo").allowed is True


# ── Domain type subdomain matching ───────────────────────────────────


def test_subdomain_of_domain_scope():
    checker = make_checker()
    # target.io is in scope as Domain, so sub.target.io should match
    assert checker.check("sub.target.io").allowed is True


# ── Out-of-scope exclusions ─────────────────────────────────────────


def test_out_of_scope_overrides_wildcard():
    """Exclusions must win over wildcard matches."""
    checker = make_checker()
    result = checker.check("support.example.com")
    assert result.allowed is False
    assert "out-of-scope" in result.reason.lower()


def test_out_of_scope_staging():
    checker = make_checker()
    assert checker.check("staging.example.com").allowed is False


# ── IP and CIDR matching ────────────────────────────────────────────


def test_ip_in_cidr():
    checker = make_checker()
    assert checker.check("10.0.0.50").allowed is True
    assert checker.check("10.0.0.1").allowed is True


def test_ip_outside_cidr():
    checker = make_checker()
    assert checker.check("10.0.1.1").allowed is False


def test_exact_ip_match():
    checker = make_checker()
    assert checker.check("192.168.1.100").allowed is True


def test_ip_no_match():
    checker = make_checker()
    assert checker.check("8.8.8.8").allowed is False


# ── Default deny ─────────────────────────────────────────────────────


def test_unknown_domain_denied():
    checker = make_checker()
    result = checker.check("evil.com")
    assert result.allowed is False
    assert "default deny" in result.reason.lower()


def test_empty_scope_denies_everything():
    checker = ScopeChecker("empty", [])
    assert checker.check("anything.com").allowed is False


# ── require_scope gate ───────────────────────────────────────────────


def test_require_scope_passes():
    checker = make_checker()
    result = require_scope(checker, "api.example.com")
    assert result.allowed is True


def test_require_scope_raises_on_deny():
    checker = make_checker()
    with pytest.raises(PermissionError, match="SCOPE DENIED"):
        require_scope(checker, "evil.com")


# ── Batch operations ────────────────────────────────────────────────


def test_check_many():
    checker = make_checker()
    results = checker.check_many(["api.example.com", "evil.com", "10.0.0.5"])
    assert results["api.example.com"].allowed is True
    assert results["evil.com"].allowed is False
    assert results["10.0.0.5"].allowed is True


def test_filter_allowed():
    checker = make_checker()
    allowed = checker.filter_allowed(
        ["api.example.com", "evil.com", "support.example.com", "10.0.0.5"]
    )
    assert allowed == ["api.example.com", "10.0.0.5"]


# ── Audit log ────────────────────────────────────────────────────────


def test_audit_log_records_checks():
    checker = make_checker()
    checker.check("api.example.com")
    checker.check("evil.com")
    log = checker.audit_log
    assert len(log) == 2
    assert log[0].target == "api.example.com"
    assert log[0].allowed is True
    assert log[1].target == "evil.com"
    assert log[1].allowed is False


# ── Edge cases ───────────────────────────────────────────────────────


def test_trailing_dot_fqdn():
    checker = make_checker()
    assert checker.check("api.example.com.").allowed is True


def test_whitespace_stripped():
    checker = make_checker()
    assert checker.check("  api.example.com  ").allowed is True


def test_from_parsed_scope():
    parsed = {
        "in_scope": [
            {
                "id": "1",
                "asset_identifier": "*.test.com",
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
        "out_of_scope": [
            {
                "id": "2",
                "asset_identifier": "admin.test.com",
                "asset_type": "URL",
                "eligible_for_bounty": False,
                "eligible_for_submission": False,
            }
        ],
    }
    checker = ScopeChecker.from_parsed_scope("test", parsed)
    assert checker.check("www.test.com").allowed is True
    assert checker.check("admin.test.com").allowed is False
