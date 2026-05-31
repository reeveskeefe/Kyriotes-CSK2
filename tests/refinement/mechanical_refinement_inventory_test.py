#!/usr/bin/env python3
"""
Repository-local mechanical refinement inventory test.

This test intentionally checks the harness inventory, not full Rust behavioral
equivalence. It should pass only when the mechanical-refinement inventory exists,
is well formed, and preserves the explicit boundary that mechanically proven
count remains zero until a real verifier pipeline is attached.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"


def main() -> int:
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.rust_mechanical_refinement_inventory.v1"
    assert payload["target_count"] >= 10
    assert payload["source_present_count"] == payload["target_count"]
    assert payload["mechanically_checked_count"] == 0
    assert payload["mechanically_proven_count"] == 0

    entries = payload["entries"]
    assert isinstance(entries, list)
    assert len(entries) == payload["target_count"]

    for entry in entries:
        assert entry["source_present"] is True
        assert entry["harness_level"] == "MechanicallyHarnessed"
        assert entry["mechanically_checked"] is False
        assert entry["mechanically_proven"] is False
        assert "not a proof" in entry["boundary"]

    print("Mechanical refinement inventory test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
