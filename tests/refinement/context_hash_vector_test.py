#!/usr/bin/env python3
"""
Mechanical refinement vector test for ARC context_hash.

This checks the deterministic context_hash vector artifact. It confirms schema,
target identity, vector count, 32-byte hash shape, and mutation sensitivity.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = PROJECT_ROOT / "tests" / "refinement" / "context_hash_vectors.json"


def require_hex_32(value: str) -> None:
    assert isinstance(value, str)
    assert len(value) == 64
    int(value, 16)


def main() -> int:
    payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.context_hash.refinement_vectors.v1"
    assert payload["target"] == "src/arc/model.rs::context_hash"
    assert payload["hash_size_bytes"] == 32
    assert payload["vector_count"] >= 4

    vectors = payload["vectors"]
    assert len(vectors) == payload["vector_count"]

    ids = set()
    hashes = set()

    for vector in vectors:
        assert vector["id"] not in ids
        ids.add(vector["id"])

        assert isinstance(vector["object_id"], str)
        assert isinstance(vector["required_rights"], int)
        assert isinstance(vector["epoch"], int)
        assert isinstance(vector["temporal_start"], int)
        assert isinstance(vector["temporal_end"], int)

        require_hex_32(vector["policy_hash_hex"])
        require_hex_32(vector["authority_root_hex"])
        require_hex_32(vector["expected_hash_hex"])

        hashes.add(vector["expected_hash_hex"])

    assert len(hashes) == len(vectors)

    print("Context hash vector test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
