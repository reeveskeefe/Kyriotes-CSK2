#!/usr/bin/env python3
"""
Checks that the first Rust-to-Coq mechanical target is marked checked and not
yet marked proven.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"


def main() -> int:
    payload = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    assert payload["target_count"] > 0
    assert payload["mechanically_checked_count"] >= 1
    assert payload["mechanically_proven_count"] == 0

    context_entries = [
        entry for entry in payload["entries"]
        if entry["id"] == "model.context_hash"
    ]

    assert len(context_entries) == 1
    context_entry = context_entries[0]

    assert context_entry["mechanically_checked"] is True
    assert context_entry["mechanically_proven"] is False
    assert "not yet a full semantic proof" in context_entry["boundary"]

    print("First mechanical target test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
