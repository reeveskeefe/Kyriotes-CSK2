#!/usr/bin/env python3
"""
Round-trip refinement-track vector test for encode_arc_object.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "encode_arc_object_vectors.json"


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.encode_arc_object.refinement_vectors.v1"
    assert payload["target"] == "src/encoding/codec.rs::encode_arc_object"
    assert payload["paired_decoder"] == "src/encoding/codec.rs::decode_arc_object"
    assert payload["vector_count"] >= 5

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    ids = set()

    for vector in vectors:
        assert vector["id"] not in ids
        ids.add(vector["id"])

        assert vector["category"] == "roundtrip-valid-object-reserved"
        assert vector["expected_result"] == "reserved"
        assert vector["canonical_required"] is True
        assert vector["decode_pairing_required"] is True
        assert isinstance(vector["object_fixture_id"], str)
        assert vector["object_fixture_id"]

    print("encode_arc_object vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
