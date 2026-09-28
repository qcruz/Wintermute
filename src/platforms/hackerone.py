"""HackerOne API client for the Hacker endpoint."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.core.config import get_hackerone_credentials

logger = logging.getLogger(__name__)

BASE_URL = "https://api.hackerone.com/v1"
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


class HackerOneClient:
    """Client for HackerOne's hacker-facing API (v1)."""

    def __init__(self) -> None:
        username, token = get_hackerone_credentials()
        self._auth = (username, token)
        self._client = httpx.Client(
            base_url=BASE_URL,
            auth=self._auth,
            timeout=30.0,
            headers={"Accept": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HackerOneClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ── Core request method ──────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> dict:
        """Make a GET request and return the JSON response."""
        response = self._client.get(path, params=params or {})
        response.raise_for_status()
        return response.json()

    def _paginate(self, path: str, params: dict | None = None) -> list[dict]:
        """Fetch all pages for a paginated endpoint."""
        params = dict(params or {})
        params.setdefault("page[size]", DEFAULT_PAGE_SIZE)

        all_items: list[dict] = []
        page = 1

        while True:
            params["page[number]"] = page
            data = self._get(path, params)

            items = data.get("data", [])
            if not items:
                break

            all_items.extend(items)

            # Check if there are more pages
            links = data.get("links", {})
            if not links.get("next"):
                break

            page += 1

        return all_items

    # ── Programs ─────────────────────────────────────────────────────

    def list_programs(self, page_size: int = DEFAULT_PAGE_SIZE) -> list[dict]:
        """List all accessible bug bounty programs."""
        return self._paginate(
            "/hackers/programs",
            params={"page[size]": min(page_size, MAX_PAGE_SIZE)},
        )

    def get_program(self, handle: str) -> dict:
        """Get details for a specific program by its handle."""
        data = self._get(f"/hackers/programs/{handle}")
        return data.get("data", data)

    # ── Scope ────────────────────────────────────────────────────────

    def get_structured_scopes(self, handle: str) -> list[dict]:
        """Get the in-scope and out-of-scope assets for a program."""
        return self._paginate(f"/hackers/programs/{handle}/structured_scopes")

    def get_weaknesses(self, handle: str) -> list[dict]:
        """Get accepted weakness types (CWEs) for a program."""
        return self._paginate(f"/hackers/programs/{handle}/weaknesses")

    # ── Reports ──────────────────────────────────────────────────────

    def list_my_reports(self) -> list[dict]:
        """List all reports submitted by the authenticated user."""
        return self._paginate("/hackers/me/reports")

    def get_report(self, report_id: int) -> dict:
        """Get details of a specific report."""
        data = self._get(f"/hackers/reports/{report_id}")
        return data.get("data", data)

    def submit_report(
        self,
        team_handle: str,
        title: str,
        vulnerability_information: str,
        impact: str,
        severity_rating: str = "medium",
        weakness_id: int | None = None,
        structured_scope_id: int | None = None,
    ) -> dict:
        """Submit a vulnerability report to a program.

        Args:
            team_handle: The program's handle (e.g. 'security')
            title: Report title
            vulnerability_information: Detailed description with reproduction steps
            impact: Description of the security impact
            severity_rating: One of 'none', 'low', 'medium', 'high', 'critical'
            weakness_id: Optional CWE weakness ID from the program's accepted list
            structured_scope_id: Optional scope asset ID this vuln applies to
        """
        payload: dict[str, Any] = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": team_handle,
                    "title": title,
                    "vulnerability_information": vulnerability_information,
                    "impact": impact,
                    "severity_rating": severity_rating,
                },
            }
        }

        if weakness_id is not None:
            payload["data"]["relationships"] = payload["data"].get("relationships", {})
            payload["data"]["relationships"]["weakness"] = {
                "data": {"type": "weakness", "id": weakness_id}
            }

        if structured_scope_id is not None:
            payload["data"]["relationships"] = payload["data"].get("relationships", {})
            payload["data"]["relationships"]["structured_scope"] = {
                "data": {"type": "structured-scope", "id": structured_scope_id}
            }

        response = self._client.post(
            "/hackers/reports",
            json=payload,
        )
        response.raise_for_status()
        return response.json()


# ── Convenience helpers ──────────────────────────────────────────────


def parse_scope(raw_scopes: list[dict]) -> dict[str, list[dict]]:
    """Parse structured scopes into in-scope and out-of-scope lists.

    Returns:
        {"in_scope": [...], "out_of_scope": [...]}
        Each item has: asset_identifier, asset_type, eligible_for_bounty,
                       eligible_for_submission, instruction
    """
    result: dict[str, list[dict]] = {"in_scope": [], "out_of_scope": []}

    for scope in raw_scopes:
        attrs = scope.get("attributes", {})
        entry = {
            "id": scope.get("id"),
            "asset_identifier": attrs.get("asset_identifier", ""),
            "asset_type": attrs.get("asset_type", ""),
            "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
            "eligible_for_submission": attrs.get("eligible_for_submission", False),
            "instruction": attrs.get("instruction", ""),
        }

        if attrs.get("eligible_for_submission", False):
            result["in_scope"].append(entry)
        else:
            result["out_of_scope"].append(entry)

    return result
