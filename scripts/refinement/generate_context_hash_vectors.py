#!/usr/bin/env python3
"""
Generate deterministic Kyriotēs-CSK2 context_hash refinement vectors.

This generator intentionally avoids importing Kyriotēs-CSK2 internals. It creates stable
model-side vectors that define the expected refinement evidence shape for the
context_hash target. The Rust test/harness layer is responsible for connecting
actual Rust behavior to these cases.

The vectors are deterministic and suitable for version control.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "context_hash_vectors.json"


@dataclass(frozen=True)
class ContextHashVector:
    id: str
    object_id: str
    required_rights: int
    policy_hash_hex: str
    authority_root_hex: str
    epoch: int
    temporal_start: int
    temporal_end: int
    expected_hash_hex: str


def hex32(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def expected_hash(
    object_id: str,
    required_rights: int,
    policy_hash_hex: str,
    authority_root_hex: str,
    epoch: int,
    temporal_start: int,
    temporal_end: int,
) -> str:
    payload = "|".join(
        [
            "KYRIOTES_CSK2_CONTEXT_HASH_REFINEMENT_V1",
            object_id,
            str(required_rights),
            policy_hash_hex,
            authority_root_hex,
            str(epoch),
            str(temporal_start),
            str(temporal_end),
        ]
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def build_vectors() -> list[ContextHashVector]:
    raw_cases = [
        {
            "id": "context.empty-read-epoch0",
            "object_id": "",
            "required_rights": 1,
            "policy_hash_hex": hex32("policy.empty.read"),
            "authority_root_hex": hex32("authority.root.0"),
            "epoch": 0,
            "temporal_start": 0,
            "temporal_end": 0,
        },
        {
            "id": "context.object-alpha-read-write",
            "object_id": "object-alpha",
            "required_rights": 3,
            "policy_hash_hex": hex32("policy.alpha.rw"),
            "authority_root_hex": hex32("authority.root.alpha"),
            "epoch": 1,
            "temporal_start": 1,
            "temporal_end": 100,
        },
        {
            "id": "context.object-beta-admin",
            "object_id": "object-beta",
            "required_rights": 7,
            "policy_hash_hex": hex32("policy.beta.admin"),
            "authority_root_hex": hex32("authority.root.beta"),
            "epoch": 42,
            "temporal_start": 40,
            "temporal_end": 50,
        },
        {
            "id": "context.long-object-id",
            "object_id": "kyriotes-csk2-object-" + "x" * 128,
            "required_rights": 15,
            "policy_hash_hex": hex32("policy.long.object"),
            "authority_root_hex": hex32("authority.root.long"),
            "epoch": 18446744073709551615,
            "temporal_start": 0,
            "temporal_end": 18446744073709551615,
        },
    ]

    vectors: list[ContextHashVector] = []

    for case in raw_cases:
        vectors.append(
            ContextHashVector(
                id=case["id"],
                object_id=case["object_id"],
                required_rights=case["required_rights"],
                policy_hash_hex=case["policy_hash_hex"],
                authority_root_hex=case["authority_root_hex"],
                epoch=case["epoch"],
                temporal_start=case["temporal_start"],
                temporal_end=case["temporal_end"],
                expected_hash_hex=expected_hash(
                    object_id=case["object_id"],
                    required_rights=case["required_rights"],
                    policy_hash_hex=case["policy_hash_hex"],
                    authority_root_hex=case["authority_root_hex"],
                    epoch=case["epoch"],
                    temporal_start=case["temporal_start"],
                    temporal_end=case["temporal_end"],
                ),
            )
        )

    return vectors


def main() -> int:
    vectors = build_vectors()

    payload = {
        "schema": "kyriotes_csk2.context_hash.refinement_vectors.v1",
        "target": "src/kyriotes_csk2/model.rs::context_hash",
        "claim_boundary": "Deterministic mechanical check vectors; not full Coq/Rust semantic equivalence.",
        "vector_count": len(vectors),
        "hash_size_bytes": 32,
        "vectors": [asdict(vector) for vector in vectors],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Wrote {OUTPUT_PATH}")
    print(f"Vectors: {payload['vector_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
