"""Scope checker — hard gate for all scanning operations.

No target may be scanned, probed, or interacted with unless it passes
a scope check against the program's published structured scopes.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ScopeEntry:
    """A single in-scope or out-of-scope asset."""

    asset_identifier: str
    asset_type: str  # URL, CIDR, Domain, IP, OTHER, etc.
    eligible_for_bounty: bool = False
    eligible_for_submission: bool = False
    instruction: str = ""
    scope_id: str = ""


@dataclass
class ScopeCheckResult:
    """Result of a scope check with audit trail."""

    target: str
    allowed: bool
    matched_entry: ScopeEntry | None = None
    reason: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __bool__(self) -> bool:
        return self.allowed


class ScopeChecker:
    """Validates targets against a program's structured scope.

    This is a HARD GATE. If a target does not explicitly match an
    in-scope entry, it is denied. Ambiguity is always resolved as
    out-of-scope.
    """

    def __init__(
        self,
        program_handle: str,
        in_scope: list[ScopeEntry],
        out_of_scope: list[ScopeEntry] | None = None,
    ) -> None:
        self.program_handle = program_handle
        self.in_scope = in_scope
        self.out_of_scope = out_of_scope or []
        self._check_log: list[ScopeCheckResult] = []

    @classmethod
    def from_parsed_scope(cls, program_handle: str, parsed: dict) -> ScopeChecker:
        """Create a ScopeChecker from the output of hackerone.parse_scope()."""
        in_scope = [
            ScopeEntry(
                asset_identifier=s["asset_identifier"],
                asset_type=s["asset_type"],
                eligible_for_bounty=s["eligible_for_bounty"],
                eligible_for_submission=s["eligible_for_submission"],
                instruction=s.get("instruction", ""),
                scope_id=s.get("id", ""),
            )
            for s in parsed.get("in_scope", [])
        ]
        out_of_scope = [
            ScopeEntry(
                asset_identifier=s["asset_identifier"],
                asset_type=s["asset_type"],
                eligible_for_bounty=s["eligible_for_bounty"],
                eligible_for_submission=s["eligible_for_submission"],
                instruction=s.get("instruction", ""),
                scope_id=s.get("id", ""),
            )
            for s in parsed.get("out_of_scope", [])
        ]
        return cls(program_handle, in_scope, out_of_scope)

    def check(self, target: str) -> ScopeCheckResult:
        """Check if a target is in scope.

        Args:
            target: A domain, URL, or IP address to check.

        Returns:
            ScopeCheckResult with allowed=True only if the target
            explicitly matches an in-scope entry and does NOT match
            any out-of-scope entry.
        """
        normalized = self._normalize_target(target)

        # Step 1: Check out-of-scope FIRST — exclusions always win
        for entry in self.out_of_scope:
            if self._matches(normalized, entry):
                result = ScopeCheckResult(
                    target=target,
                    allowed=False,
                    matched_entry=entry,
                    reason=f"Explicitly out-of-scope: {entry.asset_identifier}",
                )
                self._log_check(result)
                return result

        # Step 2: Check in-scope entries
        for entry in self.in_scope:
            if self._matches(normalized, entry):
                result = ScopeCheckResult(
                    target=target,
                    allowed=True,
                    matched_entry=entry,
                    reason=f"Matches in-scope: {entry.asset_identifier}",
                )
                self._log_check(result)
                return result

        # Step 3: No match — denied (default deny)
        result = ScopeCheckResult(
            target=target,
            allowed=False,
            reason="No matching in-scope entry found (default deny)",
        )
        self._log_check(result)
        return result

    def check_many(self, targets: list[str]) -> dict[str, ScopeCheckResult]:
        """Check multiple targets. Returns {target: result}."""
        return {t: self.check(t) for t in targets}

    def filter_allowed(self, targets: list[str]) -> list[str]:
        """Return only targets that pass scope check."""
        return [t for t in targets if self.check(t).allowed]

    @property
    def audit_log(self) -> list[ScopeCheckResult]:
        """Full audit log of all scope checks performed."""
        return list(self._check_log)

    # ── Internal matching logic ──────────────────────────────────────

    def _normalize_target(self, target: str) -> str:
        """Normalize a target to a comparable form."""
        target = target.strip().lower()

        # Strip protocol and path from URLs to get the hostname
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target

        # Strip trailing dots from FQDNs
        target = target.rstrip(".")

        return target

    def _normalize_asset(self, asset: str) -> str:
        """Normalize a scope asset identifier for comparison."""
        asset = asset.strip().lower()

        # Strip protocol and path
        if "://" in asset:
            parsed = urlparse(asset)
            hostname = parsed.hostname or asset
            # Preserve wildcard if it was in the hostname
            return hostname

        asset = asset.rstrip(".")
        return asset

    def _matches(self, normalized_target: str, entry: ScopeEntry) -> bool:
        """Check if a normalized target matches a scope entry."""
        asset = self._normalize_asset(entry.asset_identifier)

        # Exact match
        if normalized_target == asset:
            return True

        # Wildcard domain matching (e.g., *.example.com)
        if "*" in asset:
            return self._wildcard_match(normalized_target, asset)

        # IP / CIDR matching
        if entry.asset_type in ("CIDR", "IP"):
            return self._ip_match(normalized_target, asset)

        # Subdomain matching: target "sub.example.com" matches scope "example.com"
        # but only for URL/Domain types (not for OTHER, IP, etc.)
        if entry.asset_type in ("URL", "Domain"):
            if normalized_target.endswith("." + asset):
                return True

        return False

    def _wildcard_match(self, target: str, pattern: str) -> bool:
        """Match target against a wildcard pattern like *.example.com."""
        # Convert *.example.com to fnmatch pattern
        # But be strict: *.example.com should match sub.example.com
        # but NOT example.com itself (wildcard implies at least one label)
        if pattern.startswith("*."):
            base_domain = pattern[2:]

            # Exact base domain does NOT match wildcard
            if target == base_domain:
                return False

            # Must end with .base_domain
            if target.endswith("." + base_domain):
                return True

            return False

        # General wildcard (less common)
        return fnmatch.fnmatch(target, pattern)

    def _ip_match(self, target: str, asset: str) -> bool:
        """Check if target IP falls within a CIDR range or matches an IP."""
        try:
            target_ip = ip_address(target)
        except ValueError:
            return False

        try:
            # Try as network (CIDR)
            network = ip_network(asset, strict=False)
            return target_ip in network
        except ValueError:
            pass

        try:
            # Try as single IP
            return target_ip == ip_address(asset)
        except ValueError:
            return False

    def _log_check(self, result: ScopeCheckResult) -> None:
        """Log a scope check result."""
        self._check_log.append(result)
        level = logging.INFO if result.allowed else logging.WARNING
        logger.log(
            level,
            "Scope check [%s] target=%s allowed=%s reason=%s",
            self.program_handle,
            result.target,
            result.allowed,
            result.reason,
        )


def require_scope(checker: ScopeChecker, target: str) -> ScopeCheckResult:
    """Check scope and raise if denied. Use this as a gate before any scan."""
    result = checker.check(target)
    if not result:
        raise PermissionError(
            f"SCOPE DENIED: {target} — {result.reason} "
            f"(program: {checker.program_handle})"
        )
    return result
