#!/usr/bin/env python3
"""
Parser-refinement vector test for decode_arc_object.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "decode_arc_object_vectors.json"


def require_hex(value: str) -> None:
    assert isinstance(value, str)
    assert len(value) % 2 == 0
    if value:
        int(value, 16)


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.decode_arc_object.refinement_vectors.v1"
    assert payload["target"] == "src/encoding/wire.rs::decode_arc_object"
    assert payload["vector_count"] >= 10

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    categories = {vector["category"] for vector in vectors}

    required_categories = {
        "empty-input-rejection",
        "tiny-input-rejection",
        "malformed-input-rejection",
        "truncation-rejection",
        "limit-rejection",
        "roundtrip-reserved",
    }

    assert required_categories.issubset(categories)

    ids = set()

    for vector in vectors:
        assert vector["id"] not in ids
        ids.add(vector["id"])

        assert vector["expected_result"] in {"reject", "reserved"}
        assert isinstance(vector["max_allowed_millis"], int)
        assert vector["max_allowed_millis"] >= 0
        require_hex(vector["input_hex"])

        if vector["expected_result"] == "reject":
            assert vector["category"] != "roundtrip-reserved"
            assert vector["max_allowed_millis"] > 0

    print("decode_arc_object vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
