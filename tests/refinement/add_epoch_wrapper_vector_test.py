#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "add_epoch_wrapper_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.add_epoch_wrapper.refinement_vectors.v1"
    assert payload["target"] == "src/arc/engine.rs::add_epoch_wrapper"
    assert payload["vector_count"] >= 11

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-recipient-secret-key-rejection",
        "missing-recipient-public-key-rejection",
        "missing-object-rejection",
        "missing-capability-rejection",
        "missing-capability-proof-rejection",
        "missing-previous-authority-state-rejection",
        "missing-next-authority-state-rejection",
        "missing-transparency-proof-rejection",
        "epoch-regression-rejection",
        "wrapper-binding-preservation-reserved",
        "rewrap-roundtrip-reserved",
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

    print("add_epoch_wrapper vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
