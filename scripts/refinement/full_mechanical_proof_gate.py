#!/usr/bin/env python3
"""
ARC full Rust-to-Coq mechanical proof gate.

This script intentionally fails unless every target in the mechanical refinement
inventory is both mechanically checked and mechanically proven.

Use this as the final gate before claiming full Rust implementation refinement.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"


def load_inventory() -> dict:
    if not INVENTORY_PATH.exists():
        raise FileNotFoundError(
            f"Missing mechanical refinement inventory: {INVENTORY_PATH}"
        )

    with INVENTORY_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def evaluate_inventory(payload: dict) -> tuple[bool, list[str]]:
    target_count = int(payload.get("target_count", 0))
    checked_count = int(payload.get("mechanically_checked_count", 0))
    proven_count = int(payload.get("mechanically_proven_count", 0))
    entries = payload.get("entries", [])

    failures: list[str] = []

    if target_count <= 0:
        failures.append("target_count must be greater than zero")

    if checked_count != target_count:
        failures.append(
            f"mechanically_checked_count is {checked_count}, expected {target_count}"
        )

    if proven_count != target_count:
        failures.append(
            f"mechanically_proven_count is {proven_count}, expected {target_count}"
        )

    for entry in entries:
        entry_id = entry.get("id", "<unknown>")
        if entry.get("mechanically_checked") is not True:
            failures.append(f"{entry_id} is not mechanically checked")
        if entry.get("mechanically_proven") is not True:
            failures.append(f"{entry_id} is not mechanically proven")

    return not failures, failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check whether ARC may claim full Rust-to-Coq mechanical proof."
    )
    parser.add_argument(
        "--allow-open",
        action="store_true",
        help="Return success while printing the open proof obligations. Use for development CI only.",
    )
    args = parser.parse_args()

    payload = load_inventory()
    passed, failures = evaluate_inventory(payload)

    print("ARC full Rust-to-Coq mechanical proof gate")
    print(f"Inventory: {INVENTORY_PATH}")
    print(f"Targets: {payload.get('target_count', 0)}")
    print(f"Mechanically checked: {payload.get('mechanically_checked_count', 0)}")
    print(f"Mechanically proven: {payload.get('mechanically_proven_count', 0)}")

    if passed:
        print("PASS: ARC may claim full Rust-to-Coq mechanical proof for the inventory.")
        return 0

    print("OPEN: ARC may not yet claim full Rust-to-Coq mechanical proof.")
    print("Open obligations:")
    for failure in failures:
        print(f"- {failure}")

    if args.allow_open:
        print("Development mode: --allow-open enabled, returning success.")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
