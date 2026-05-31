#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "rotate_epoch_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.rotate_epoch.refinement_vectors.v1"
    assert payload["target"] == "src/arc/engine.rs::rotate_epoch"
    assert payload["vector_count"] >= 10

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-previous-authority-state-rejection",
        "missing-next-authority-state-rejection",
        "missing-previous-epoch-rejection",
        "missing-next-epoch-rejection",
        "epoch-regression-rejection",
        "same-epoch-rotation-rejection",
        "strict-epoch-advance-required",
        "authority-root-continuity-required",
        "chain-hash-linkage-required",
        "rotate-verify-roundtrip-reserved",
    }

    assert required_categories.issubset(categories)

    ids = set()

    for item in vectors:
        assert item["id"] not in ids
        ids.add(item["id"])

        assert item["expected_result"] in {"reject", "reserved"}
        assert item["deterministic"] is True
        assert isinstance(item["gate_name"], str)
        assert item["gate_name"]

    print("rotate_epoch vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
