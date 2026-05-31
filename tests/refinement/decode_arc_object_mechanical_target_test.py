#!/usr/bin/env python3
"""
Checks that decode_arc_object is marked mechanically checked and not mechanically proven.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"


def main() -> int:
    payload = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    assert payload["mechanically_checked_count"] >= 2
    assert payload["mechanically_proven_count"] == 0

    matches = [
        entry for entry in payload["entries"]
        if entry["id"] == "codec.decode_arc_object"
    ]

    assert len(matches) == 1

    entry = matches[0]
    assert entry["mechanically_checked"] is True
    assert entry["mechanically_proven"] is False
    assert "parser-refinement" in entry["boundary"]

    print("decode_arc_object mechanical target test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
