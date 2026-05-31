#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "capability_tree_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.capability_tree.refinement_vectors.v1"
    assert payload["target"] == "src/arc/capability_tree.rs"
    assert payload["vector_count"] >= 11

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-capability-proof-rejection",
        "missing-membership-proof-rejection",
        "missing-nonrevocation-witness-rejection",
        "root-mismatch-rejection",
        "tampered-leaf-rejection",
        "tampered-sibling-rejection",
        "sibling-order-mismatch-rejection",
        "empty-proof-rejection",
        "revoked-capability-rejection",
        "valid-membership-proof-reserved",
        "valid-nonrevocation-proof-reserved",
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

    print("capability_tree vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
