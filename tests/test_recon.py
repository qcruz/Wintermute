"""Tests for recon modules — subdomain enumeration parsing."""

from unittest.mock import MagicMock, patch

from src.recon.subdomain import (
    SubdomainResult,
    _query_crtsh,
    _query_hackertarget,
    _query_otx,
    enumerate_subdomains,
)


# ── HackerTarget parsing ────────────────────────────────────────────


def test_hackertarget_parses_csv_lines():
    """HackerTarget returns CSV lines: hostname,ip."""
    response = MagicMock()
    response.status_code = 200
    response.text = "sub1.example.com,1.2.3.4\nsub2.example.com,5.6.7.8\n"

    with patch("src.recon.subdomain.httpx.get", return_value=response):
        result = _query_hackertarget("example.com")

    assert result == {"sub1.example.com", "sub2.example.com"}


def test_hackertarget_filters_unrelated_domains():
    """Only subdomains of the target domain are included."""
    response = MagicMock()
    response.status_code = 200
    response.text = "sub.example.com,1.2.3.4\nevil.com,9.9.9.9\n"

    with patch("src.recon.subdomain.httpx.get", return_value=response):
        result = _query_hackertarget("example.com")

    assert "evil.com" not in result
    assert "sub.example.com" in result


def test_hackertarget_handles_error_response():
    """HackerTarget returns 'error ...' text on rate limit or invalid query."""
    response = MagicMock()
    response.status_code = 200
    response.text = "error check your search parameter"

    with patch("src.recon.subdomain.httpx.get", return_value=response):
        result = _query_hackertarget("example.com")

    assert result == set()


def test_hackertarget_handles_http_error():
    """Non-200 status code returns empty set."""
    response = MagicMock()
    response.status_code = 503

    with patch("src.recon.subdomain.httpx.get", return_value=response):
        result = _query_hackertarget("example.com")

    assert result == set()


# ── OTX parsing ──────────────────────────────────────────────────────


def test_otx_parses_passive_dns():
    """OTX returns JSON with passive_dns array."""
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "passive_dns": [
            {"hostname": "api.example.com", "address": "1.2.3.4"},
            {"hostname": "cdn.example.com", "address": "5.6.7.8"},
            {"hostname": "other.net", "address": "9.9.9.9"},
        ]
    }

    with patch("src.recon.subdomain.httpx.get", return_value=response):
        result = _query_otx("example.com")

    assert result == {"api.example.com", "cdn.example.com"}
    assert "other.net" not in result


def test_otx_handles_empty_response():
    """OTX returns empty passive_dns array."""
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"passive_dns": []}

    with patch("src.recon.subdomain.httpx.get", return_value=response):
        result = _query_otx("example.com")

    assert result == set()


def test_otx_handles_http_error():
    response = MagicMock()
    response.status_code = 429

    with patch("src.recon.subdomain.httpx.get", return_value=response):
        result = _query_otx("example.com")

    assert result == set()


# ── enumerate_subdomains integration ─────────────────────────────────


def test_enumerate_merges_sources():
    """enumerate_subdomains deduplicates across all sources."""
    crt_response = MagicMock()
    crt_response.status_code = 200
    crt_response.json.return_value = [
        {"name_value": "shared.example.com"},
        {"name_value": "crt-only.example.com"},
    ]
    # raise_for_status should not raise
    crt_response.raise_for_status = MagicMock()

    ht_response = MagicMock()
    ht_response.status_code = 200
    ht_response.text = "shared.example.com,1.2.3.4\nht-only.example.com,5.6.7.8\n"

    otx_response = MagicMock()
    otx_response.status_code = 200
    otx_response.json.return_value = {
        "passive_dns": [
            {"hostname": "shared.example.com", "address": "1.2.3.4"},
            {"hostname": "otx-only.example.com", "address": "9.9.9.9"},
        ]
    }

    def mock_get(url, **kwargs):
        if "crt.sh" in url:
            return crt_response
        elif "hackertarget" in url:
            return ht_response
        elif "alienvault" in url:
            return otx_response
        raise ValueError(f"Unexpected URL: {url}")

    with patch("src.recon.subdomain.httpx.get", side_effect=mock_get), \
         patch("src.recon.subdomain._resolve_hostname", return_value=(["1.2.3.4"], True)):
        results = enumerate_subdomains("example.com")

    hostnames = {r.hostname for r in results}
    assert "shared.example.com" in hostnames
    assert "crt-only.example.com" in hostnames
    assert "ht-only.example.com" in hostnames
    assert "otx-only.example.com" in hostnames
    assert len(hostnames) == 4  # no duplicates
