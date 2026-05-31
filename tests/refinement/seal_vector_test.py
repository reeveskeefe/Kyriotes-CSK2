#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "seal_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.seal.refinement_vectors.v1"
    assert payload["target"] == "src/arc/engine.rs::seal"
    assert payload["vector_count"] >= 10

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-recipient-key-rejection",
        "missing-message-rejection",
        "missing-capability-rejection",
        "missing-capability-proof-rejection",
        "missing-authority-state-rejection",
        "missing-transparency-proof-rejection",
        "temporal-policy-required",
        "lifecycle-seal-transition",
        "seal-verify-roundtrip-reserved",
        "seal-open-roundtrip-reserved",
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

    print("seal vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
