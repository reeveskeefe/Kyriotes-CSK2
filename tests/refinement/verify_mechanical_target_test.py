#!/usr/bin/env python3
"""
Checks that engine.verify is marked mechanically checked and not mechanically proven.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"


def main() -> int:
    payload = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    assert payload["mechanically_checked_count"] >= 4
    assert payload["mechanically_proven_count"] == 0

    matches = [
        item for item in payload["entries"]
        if item["id"] == "engine.verify"
    ]

    assert len(matches) == 1

    item = matches[0]
    assert item["mechanically_checked"] is True
    assert item["mechanically_proven"] is False
    assert "verification-gate refinement track" in item["boundary"]

    print("verify mechanical target test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
