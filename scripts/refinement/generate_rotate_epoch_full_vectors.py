#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "rotate_epoch_full_vectors.json"


@dataclass(frozen=True)
class RotateEpochFullVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> RotateEpochFullVector:
    return RotateEpochFullVector(
        id=f"rotate_epoch_full.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[RotateEpochFullVector]:
    return [
        vector(
            "missing-transparency-log-rejection",
            "reject",
            "transparency_log",
            "rotate_epoch_full must require a transparency log surface.",
        ),
        vector(
            "missing-previous-authority-state-rejection",
            "reject",
            "previous_authority_state",
            "rotate_epoch_full must require the previous authority state.",
        ),
        vector(
            "missing-next-authority-state-rejection",
            "reject",
            "next_authority_state",
            "rotate_epoch_full must require the next authority state.",
        ),
        vector(
            "missing-previous-epoch-rejection",
            "reject",
            "previous_epoch",
            "rotate_epoch_full must require the previous epoch.",
        ),
        vector(
            "missing-next-epoch-rejection",
            "reject",
            "next_epoch",
            "rotate_epoch_full must require the next epoch.",
        ),
        vector(
            "epoch-regression-rejection",
            "reject",
            "epoch_regression",
            "rotate_epoch_full must reject transitions where the next epoch is less than the previous epoch.",
        ),
        vector(
            "same-epoch-rotation-rejection",
            "reject",
            "same_epoch_rotation",
            "rotate_epoch_full must reject rotation that does not strictly advance the epoch.",
        ),
        vector(
            "authority-root-continuity-required",
            "reserved",
            "authority_root_continuity",
            "Reserved for future authority-root continuity fixture.",
        ),
        vector(
            "state-root-consistency-required",
            "reserved",
            "state_root_consistency",
            "Reserved for future state-root consistency fixture.",
        ),
        vector(
            "chain-hash-linkage-required",
            "reserved",
            "chain_hash_linkage",
            "Reserved for future chain-hash linkage fixture.",
        ),
        vector(
            "transparency-commit-linkage-required",
            "reserved",
            "transparency_commit_linkage",
            "Reserved for future transparency commit linkage fixture.",
        ),
        vector(
            "full-rotation-verify-roundtrip-reserved",
            "reserved",
            "full_rotation_verify_roundtrip",
            "Reserved for future rotate_epoch_full then verify fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()
    payload = {
        "schema": "arc.rotate_epoch_full.refinement_vectors.v1",
        "target": "src/arc/engine.rs::rotate_epoch_full",
        "claim_boundary": "Full authority epoch-rotation refinement track; not full Coq/Rust semantic equivalence.",
        "vector_count": len(vectors),
        "vectors": [asdict(item) for item in vectors],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Wrote {OUTPUT_PATH}")
    print(f"Vectors: {payload['vector_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
