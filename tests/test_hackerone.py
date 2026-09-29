"""Tests for HackerOne API client."""

from src.platforms.hackerone import parse_scope


def test_parse_scope_separates_eligible():
    raw = [
        {
            "id": "1",
            "attributes": {
                "asset_identifier": "*.example.com",
                "asset_type": "Domain",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": "",
            },
        },
        {
            "id": "2",
            "attributes": {
                "asset_identifier": "internal.example.com",
                "asset_type": "Domain",
                "eligible_for_bounty": False,
                "eligible_for_submission": False,
                "instruction": "Do not test",
            },
        },
    ]
    result = parse_scope(raw)
    assert len(result["in_scope"]) == 1
    assert len(result["out_of_scope"]) == 1
    assert result["in_scope"][0]["asset_identifier"] == "*.example.com"
    assert result["out_of_scope"][0]["asset_identifier"] == "internal.example.com"


def test_parse_scope_empty():
    assert parse_scope([]) == {"in_scope": [], "out_of_scope": []}
