#!/usr/bin/env python3
"""
Verification-gate vector test for engine::verify.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "verify_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.verify.refinement_vectors.v1"
    assert payload["target"] == "src/arc/engine.rs::verify"
    assert payload["vector_count"] >= 10

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {item["category"] for item in vectors}
    required_categories = {
        "missing-object-rejection",
        "missing-capability-rejection",
        "missing-capability-proof-rejection",
        "missing-authority-state-rejection",
        "missing-transparency-proof-rejection",
        "revoked-capability-rejection",
        "temporal-policy-mismatch-rejection",
        "transcript-binding-mismatch-rejection",
        "wrapper-binding-mismatch-rejection",
        "valid-verification-reserved",
    }

    assert required_categories.issubset(categories)

    ids = set()
    gates = set()

    for item in vectors:
        assert item["id"] not in ids
        ids.add(item["id"])

        assert item["expected_result"] in {"reject", "reserved"}
        assert item["deterministic"] is True
        assert isinstance(item["gate_name"], str)
        assert item["gate_name"]
        gates.add(item["gate_name"])

    assert "all_gates" in gates
    assert len(gates) >= 10

    print("verify vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
