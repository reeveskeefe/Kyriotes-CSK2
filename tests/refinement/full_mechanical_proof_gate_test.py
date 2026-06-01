#!/usr/bin/env python3
"""
Development test for the Kyriotēs-CSK2 full mechanical proof gate.

This test confirms that the gate correctly recognizes the current proof state as
open. It should fail only if the inventory format is broken or if the project
starts claiming full mechanical proof without updating this test.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"


def main() -> int:
    payload = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    target_count = payload["target_count"]
    checked_count = payload["mechanically_checked_count"]
    proven_count = payload["mechanically_proven_count"]

    assert target_count > 0
    assert checked_count <= target_count
    assert proven_count <= target_count
    assert checked_count == 0
    assert proven_count == 0

    for entry in payload["entries"]:
        assert entry["mechanically_checked"] is False
        assert entry["mechanically_proven"] is False

    print("Full mechanical proof gate correctly remains open.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
