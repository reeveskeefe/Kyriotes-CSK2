#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "transparency_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.transparency.refinement_vectors.v1"
    assert payload["target"] == "src/kyriotes_csk2/transparency.rs"
    assert payload["vector_count"] >= 12

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-log-rejection",
        "missing-entry-rejection",
        "missing-epoch-rejection",
        "missing-state-root-rejection",
        "missing-commitment-rejection",
        "conflicting-epoch-rejection",
        "duplicate-conflicting-entry-rejection",
        "append-only-regression-rejection",
        "lookup-missing-entry-rejection",
        "state-root-binding-reserved",
        "valid-append-reserved",
        "valid-lookup-reserved",
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

    print("transparency vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
