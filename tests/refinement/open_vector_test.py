#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "open_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.open.refinement_vectors.v1"
    assert payload["target"] == "src/arc/engine.rs::open"
    assert payload["vector_count"] >= 10

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-recipient-secret-key-rejection",
        "missing-object-rejection",
        "missing-capability-rejection",
        "missing-capability-proof-rejection",
        "missing-authority-state-rejection",
        "revoked-capability-rejection",
        "temporal-policy-mismatch-rejection",
        "wrapper-binding-mismatch-rejection",
        "decrypt-failure-rejection",
        "seal-verify-open-roundtrip-reserved",
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

    print("open vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
