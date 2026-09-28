#!/usr/bin/env python3
"""Run reconnaissance on a HackerOne program."""

import logging
import sys

from src.recon.pipeline import run_recon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.run_recon <program_handle>")
        print("Example: python -m scripts.run_recon security")
        sys.exit(1)

    handle = sys.argv[1]
    print(f"Starting recon for: {handle}")
    print("=" * 50)

    result = run_recon(handle)

    print()
    print("=" * 50)
    print(f"Recon Summary: {handle}")
    print(f"  Subdomains found:      {result.subdomains_found}")
    print(f"  Subdomains alive:      {result.subdomains_alive}")
    print(f"  In-scope targets:      {result.in_scope_targets}")
    print(f"  Filtered (out-of-scope): {result.out_of_scope_filtered}")
    print(f"  Headers analyzed:      {result.headers_analyzed}")

    if result.targets:
        print()
        print("In-scope alive targets:")
        for t in result.targets:
            ips = ", ".join(t.ip_addresses[:3])
            print(f"  {t.hostname:40s}  {ips}")

    if result.header_results:
        print()
        print("Technology fingerprints:")
        for h in result.header_results:
            if h.technologies:
                techs = " | ".join(h.technologies[:4])
                print(f"  {h.hostname:40s}  {techs}")
            if h.missing_security_headers:
                missing = ", ".join(h.missing_security_headers)
                print(f"    missing headers: {missing}")


if __name__ == "__main__":
    main()
