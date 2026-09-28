#!/usr/bin/env python3
"""Quick CLI to explore HackerOne programs and their scope."""

import sys

from src.platforms.hackerone import HackerOneClient, parse_scope


def list_programs(limit: int = 25) -> None:
    with HackerOneClient() as client:
        programs = client._get("/hackers/programs", {"page[size]": limit})
        for p in programs.get("data", []):
            attrs = p.get("attributes", {})
            print(f"  {attrs.get('handle', '?'):30s}  {attrs.get('name', '?')}")


def show_program(handle: str) -> None:
    with HackerOneClient() as client:
        program = client.get_program(handle)
        attrs = program.get("attributes", {})
        print(f"Program: {attrs.get('name')}")
        print(f"Handle:  {attrs.get('handle')}")
        print(f"State:   {attrs.get('submission_state', '?')}")
        print()

        raw_scopes = client.get_structured_scopes(handle)
        scopes = parse_scope(raw_scopes)

        print(f"In-scope assets ({len(scopes['in_scope'])}):")
        for s in scopes["in_scope"]:
            bounty = " [bounty]" if s["eligible_for_bounty"] else ""
            print(f"  {s['asset_type']:15s} {s['asset_identifier']}{bounty}")

        if scopes["out_of_scope"]:
            print(f"\nOut-of-scope ({len(scopes['out_of_scope'])}):")
            for s in scopes["out_of_scope"]:
                print(f"  {s['asset_type']:15s} {s['asset_identifier']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m scripts.h1_explore list [limit]")
        print("  python -m scripts.h1_explore show <handle>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "list":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 25
        list_programs(limit)
    elif cmd == "show":
        if len(sys.argv) < 3:
            print("Error: provide a program handle")
            sys.exit(1)
        show_program(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
