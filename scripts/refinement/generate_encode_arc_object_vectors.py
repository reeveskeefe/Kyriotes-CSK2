#!/usr/bin/env python3
"""
Generate deterministic encode_arc_object refinement-track vectors.

This generator establishes the encode/decode round-trip evidence schema. It does
not fabricate valid ARC objects. Valid-object round-trip fixtures are explicitly
reserved until they can be generated from the real Rust constructors/encoder.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "encode_arc_object_vectors.json"


@dataclass(frozen=True)
class EncodeArcObjectVector:
    id: str
    category: str
    object_fixture_id: str
    expected_result: str
    canonical_required: bool
    decode_pairing_required: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def build_vectors() -> list[EncodeArcObjectVector]:
    seeds = [
        "minimal-valid-object-reserved",
        "multi-wrapper-valid-object-reserved",
        "temporal-policy-valid-object-reserved",
        "revocation-proof-valid-object-reserved",
        "transparency-bound-valid-object-reserved",
    ]

    return [
        EncodeArcObjectVector(
            id=f"encode.{stable_id(seed)}",
            category="roundtrip-valid-object-reserved",
            object_fixture_id=seed,
            expected_result="reserved",
            canonical_required=True,
            decode_pairing_required=True,
            notes="Reserved until generated from real Rust ARC object constructors and encode_arc_object.",
        )
        for seed in seeds
    ]


def main() -> int:
    vectors = build_vectors()

    payload = {
        "schema": "arc.encode_arc_object.refinement_vectors.v1",
        "target": "src/encoding/codec.rs::encode_arc_object",
        "paired_decoder": "src/encoding/codec.rs::decode_arc_object",
        "claim_boundary": "Round-trip refinement track established; valid-object fixtures are reserved until generated from real Rust objects.",
        "vector_count": len(vectors),
        "vectors": [asdict(vector) for vector in vectors],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Wrote {OUTPUT_PATH}")
    print(f"Vectors: {payload['vector_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
