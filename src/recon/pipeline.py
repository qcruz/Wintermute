"""Recon pipeline — orchestrates enumeration with scope enforcement."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.core.db import Finding, Program, Scope, Service, Target, get_session
from src.core.scope import ScopeChecker, ScopeEntry
from src.platforms.hackerone import HackerOneClient, parse_scope
from src.recon.headers import HeaderAnalysis, analyze_headers
from src.recon.subdomain import SubdomainResult, enumerate_subdomains

logger = logging.getLogger(__name__)


@dataclass
class ReconResult:
    program_handle: str
    subdomains_found: int = 0
    subdomains_alive: int = 0
    in_scope_targets: int = 0
    out_of_scope_filtered: int = 0
    headers_analyzed: int = 0
    targets: list[SubdomainResult] = field(default_factory=list)
    header_results: list[HeaderAnalysis] = field(default_factory=list)


def run_recon(program_handle: str) -> ReconResult:
    """Run the full recon pipeline for a HackerOne program.

    Steps:
        1. Fetch program scope from HackerOne API
        2. Build scope checker
        3. Extract base domains from in-scope assets
        4. Enumerate subdomains for each base domain
        5. Filter discovered hosts through scope checker
        6. Analyze HTTP headers on alive, in-scope targets
        7. Store results in database
    """
    result = ReconResult(program_handle=program_handle)

    # Step 1-2: Fetch scope and build checker
    logger.info("Fetching scope for program: %s", program_handle)
    with HackerOneClient() as client:
        program_data = client.get_program(program_handle)
        raw_scopes = client.get_structured_scopes(program_handle)

    parsed = parse_scope(raw_scopes)
    checker = ScopeChecker.from_parsed_scope(program_handle, parsed)

    logger.info(
        "Scope loaded: %d in-scope, %d out-of-scope",
        len(parsed["in_scope"]),
        len(parsed["out_of_scope"]),
    )

    # Step 3: Extract base domains to enumerate
    base_domains = _extract_base_domains(parsed["in_scope"])
    logger.info("Base domains for enumeration: %s", base_domains)

    # Step 4: Enumerate subdomains
    all_subdomains: list[SubdomainResult] = []
    for domain in base_domains:
        subs = enumerate_subdomains(domain)
        all_subdomains.extend(subs)

    result.subdomains_found = len(all_subdomains)
    result.subdomains_alive = sum(1 for s in all_subdomains if s.alive)

    # Step 5: Filter through scope checker
    in_scope_targets: list[SubdomainResult] = []
    for sub in all_subdomains:
        check = checker.check(sub.hostname)
        if check.allowed and sub.alive:
            in_scope_targets.append(sub)
        elif not check.allowed:
            result.out_of_scope_filtered += 1

    result.in_scope_targets = len(in_scope_targets)
    result.targets = in_scope_targets

    logger.info(
        "After scope filter: %d targets (%d filtered out)",
        result.in_scope_targets,
        result.out_of_scope_filtered,
    )

    # Step 6: HTTP header analysis on alive, in-scope targets
    for target in in_scope_targets:
        analysis = analyze_headers(target.hostname)
        result.header_results.append(analysis)
        result.headers_analyzed += 1

    # Step 7: Store in database
    _store_results(program_handle, program_data, parsed, in_scope_targets, result.header_results)

    logger.info("Recon complete for %s", program_handle)
    return result


def _extract_base_domains(in_scope: list[dict]) -> set[str]:
    """Extract unique base domains from in-scope assets for subdomain enumeration."""
    domains: set[str] = set()

    for entry in in_scope:
        asset = entry.get("asset_identifier", "").strip().lower()
        asset_type = entry.get("asset_type", "")

        if asset_type not in ("URL", "Domain", "WILDCARD"):
            continue

        # Strip protocol and path
        if "://" in asset:
            from urllib.parse import urlparse
            parsed = urlparse(asset)
            asset = parsed.hostname or asset

        # Strip wildcard prefix
        if asset.startswith("*."):
            asset = asset[2:]

        # Basic validation — must have at least one dot
        if "." in asset and not asset.replace(".", "").replace("-", "").isdigit():
            domains.add(asset)

    return domains


def _store_results(
    handle: str,
    program_data: dict,
    parsed_scope: dict,
    targets: list[SubdomainResult],
    headers: list[HeaderAnalysis],
) -> None:
    """Persist recon results to the database."""
    session = get_session()

    try:
        # Upsert program
        program = session.query(Program).filter_by(handle=handle).first()
        if not program:
            attrs = program_data.get("attributes", {})
            program = Program(
                handle=handle,
                name=attrs.get("name", handle),
                platform="hackerone",
                submission_state=attrs.get("submission_state", "open"),
            )
            session.add(program)
            session.flush()
        else:
            program.last_synced = datetime.now(timezone.utc)

        # Store scopes
        session.query(Scope).filter_by(program_id=program.id).delete()
        for scope_list in (parsed_scope["in_scope"], parsed_scope["out_of_scope"]):
            for s in scope_list:
                session.add(Scope(
                    program_id=program.id,
                    asset_identifier=s["asset_identifier"],
                    asset_type=s["asset_type"],
                    eligible_for_bounty=s["eligible_for_bounty"],
                    eligible_for_submission=s["eligible_for_submission"],
                    instruction=s.get("instruction", ""),
                ))

        # Store targets
        header_map = {h.hostname: h for h in headers}
        for sub in targets:
            existing = (
                session.query(Target)
                .filter_by(program_id=program.id, hostname=sub.hostname)
                .first()
            )
            if existing:
                existing.last_seen = datetime.now(timezone.utc)
                existing.alive = sub.alive
                existing.ip_address = ", ".join(sub.ip_addresses)
            else:
                target = Target(
                    program_id=program.id,
                    hostname=sub.hostname,
                    source=sub.source,
                    ip_address=", ".join(sub.ip_addresses),
                    alive=sub.alive,
                )
                session.add(target)

        session.commit()
        logger.info("Stored results for %s: %d targets", handle, len(targets))

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
