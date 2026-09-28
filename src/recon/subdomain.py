"""Subdomain enumeration via passive sources.

Uses DNS resolution to validate discovered subdomains.
No active brute-forcing in v1 — passive only for safety.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import dns.resolver
import httpx

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    hostname: str
    source: str
    ip_addresses: list[str] = field(default_factory=list)
    alive: bool = False


def enumerate_subdomains(domain: str) -> list[SubdomainResult]:
    """Discover subdomains for a domain using passive sources.

    Sources:
        - crt.sh (Certificate Transparency logs)

    Each discovered subdomain is validated via DNS resolution.
    """
    discovered: dict[str, SubdomainResult] = {}

    # Source 1: Certificate Transparency via crt.sh
    crt_results = _query_crtsh(domain)
    for hostname in crt_results:
        if hostname not in discovered:
            discovered[hostname] = SubdomainResult(hostname=hostname, source="crt.sh")

    # Validate via DNS
    for result in discovered.values():
        result.ip_addresses, result.alive = _resolve_hostname(result.hostname)

    total = len(discovered)
    alive = sum(1 for r in discovered.values() if r.alive)
    logger.info("Enumerated %d subdomains for %s (%d alive)", total, domain, alive)

    return list(discovered.values())


def _query_crtsh(domain: str) -> set[str]:
    """Query crt.sh for subdomains from Certificate Transparency logs."""
    subdomains: set[str] = set()
    url = "https://crt.sh/"

    try:
        response = httpx.get(
            url,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=30.0,
        )
        response.raise_for_status()
        entries = response.json()

        for entry in entries:
            name = entry.get("name_value", "")
            # crt.sh can return multiple names separated by newlines
            for line in name.split("\n"):
                line = line.strip().lower()
                # Skip wildcards — we want actual hostnames
                if line.startswith("*"):
                    continue
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.add(line)

    except Exception as e:
        logger.warning("crt.sh query failed for %s: %s", domain, e)

    return subdomains


def _resolve_hostname(hostname: str) -> tuple[list[str], bool]:
    """Resolve a hostname to IP addresses via DNS.

    Returns:
        (ip_addresses, alive)
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    ips: list[str] = []

    for rdtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, rdtype)
            ips.extend(str(rdata) for rdata in answers)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            pass
        except Exception as e:
            logger.debug("DNS resolve failed for %s %s: %s", hostname, rdtype, e)

    return ips, len(ips) > 0
