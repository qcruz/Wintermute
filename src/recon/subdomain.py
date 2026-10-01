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
        - HackerTarget (free subdomain finder API)
        - AlienVault OTX (passive DNS)

    Each discovered subdomain is validated via DNS resolution.
    """
    discovered: dict[str, SubdomainResult] = {}

    def _add_results(hostnames: set[str], source: str) -> None:
        for hostname in hostnames:
            if hostname not in discovered:
                discovered[hostname] = SubdomainResult(hostname=hostname, source=source)

    # Source 1: Certificate Transparency via crt.sh
    _add_results(_query_crtsh(domain), "crt.sh")

    # Source 2: HackerTarget free API
    _add_results(_query_hackertarget(domain), "hackertarget")

    # Source 3: AlienVault OTX passive DNS
    _add_results(_query_otx(domain), "otx")

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
            timeout=60.0,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
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


def _query_hackertarget(domain: str) -> set[str]:
    """Query HackerTarget free API for subdomains."""
    subdomains: set[str] = set()
    url = "https://api.hackertarget.com/hostsearch/"

    try:
        response = httpx.get(
            url,
            params={"q": domain},
            timeout=30.0,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        if response.status_code != 200:
            logger.warning("HackerTarget query failed for %s: HTTP %d", domain, response.status_code)
            return subdomains

        text = response.text.strip()
        if text.startswith("error") or not text:
            logger.debug("HackerTarget returned no results for %s", domain)
            return subdomains

        for line in text.split("\n"):
            parts = line.split(",")
            if parts:
                hostname = parts[0].strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subdomains.add(hostname)

    except Exception as e:
        logger.warning("HackerTarget query failed for %s: %s", domain, e)

    logger.debug("HackerTarget found %d subdomains for %s", len(subdomains), domain)
    return subdomains


def _query_otx(domain: str) -> set[str]:
    """Query AlienVault OTX for subdomains via passive DNS."""
    subdomains: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    try:
        response = httpx.get(
            url,
            timeout=60.0,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        if response.status_code != 200:
            logger.warning("OTX query failed for %s: HTTP %d", domain, response.status_code)
            return subdomains

        data = response.json()
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").strip().lower()
            if hostname.endswith(f".{domain}") or hostname == domain:
                subdomains.add(hostname)

    except Exception as e:
        logger.warning("OTX query failed for %s: %s", domain, e)

    logger.debug("OTX found %d subdomains for %s", len(subdomains), domain)
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
