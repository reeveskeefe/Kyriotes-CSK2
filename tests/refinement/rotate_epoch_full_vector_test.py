#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "rotate_epoch_full_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.rotate_epoch_full.refinement_vectors.v1"
    assert payload["target"] == "src/arc/engine.rs::rotate_epoch_full"
    assert payload["vector_count"] >= 12

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-transparency-log-rejection",
        "missing-previous-authority-state-rejection",
        "missing-next-authority-state-rejection",
        "missing-previous-epoch-rejection",
        "missing-next-epoch-rejection",
        "epoch-regression-rejection",
        "same-epoch-rotation-rejection",
        "authority-root-continuity-required",
        "state-root-consistency-required",
        "chain-hash-linkage-required",
        "transparency-commit-linkage-required",
        "full-rotation-verify-roundtrip-reserved",
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

    print("rotate_epoch_full vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
