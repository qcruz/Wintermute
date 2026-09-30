"""Shared HTTP client with optional authentication support.

Provides a configured httpx client that all scanner modules can use.
When auth is configured for a program, cookies and headers are automatically
injected into every request.

Auth config is loaded from `.auth/<program_handle>.json` files:
{
    "cookies": {"session_id": "abc123", "csrf_token": "xyz"},
    "headers": {"Authorization": "Bearer token123"}
}

These files are gitignored and never committed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

AUTH_DIR = Path(__file__).resolve().parent.parent.parent / ".auth"
USER_AGENT = "Wintermute/0.1 (Security Research)"


@dataclass
class AuthConfig:
    """Authentication configuration for a program."""

    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_configured(self) -> bool:
        return bool(self.cookies or self.headers)


def load_auth(program_handle: str) -> AuthConfig:
    """Load auth config for a program from .auth/<handle>.json.

    Returns an empty AuthConfig if no config file exists.
    """
    auth_file = AUTH_DIR / f"{program_handle}.json"
    if not auth_file.exists():
        return AuthConfig()

    try:
        data = json.loads(auth_file.read_text())
        config = AuthConfig(
            cookies=data.get("cookies", {}),
            headers=data.get("headers", {}),
        )
        if config.is_configured:
            logger.info(
                "Loaded auth config for %s (%d cookies, %d headers)",
                program_handle,
                len(config.cookies),
                len(config.headers),
            )
        return config
    except Exception as e:
        logger.warning("Failed to load auth config for %s: %s", program_handle, e)
        return AuthConfig()


def make_client(
    auth: AuthConfig | None = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
) -> httpx.Client:
    """Create an httpx Client with Wintermute defaults and optional auth.

    The returned client should be used as a context manager:
        with make_client(auth) as client:
            resp = client.get(url)
    """
    headers = {"User-Agent": USER_AGENT}
    cookies = {}

    if auth and auth.is_configured:
        headers.update(auth.headers)
        cookies.update(auth.cookies)

    return httpx.Client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers=headers,
        cookies=cookies,
    )


def get(
    url: str,
    auth: AuthConfig | None = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Make a GET request with Wintermute defaults and optional auth.

    Convenience function for one-off requests. For multiple requests to the
    same host, prefer make_client() to reuse the connection.
    """
    request_headers = {"User-Agent": USER_AGENT}
    if auth and auth.headers:
        request_headers.update(auth.headers)
    if headers:
        request_headers.update(headers)

    cookies = {}
    if auth and auth.cookies:
        cookies.update(auth.cookies)

    return httpx.get(
        url,
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers=request_headers,
        cookies=cookies,
    )
