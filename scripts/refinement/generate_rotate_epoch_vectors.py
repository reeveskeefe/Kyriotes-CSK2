#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "rotate_epoch_vectors.json"


@dataclass(frozen=True)
class RotateEpochVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> RotateEpochVector:
    return RotateEpochVector(
        id=f"rotate_epoch.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[RotateEpochVector]:
    return [
        vector(
            "missing-previous-authority-state-rejection",
            "reject",
            "previous_authority_state",
            "rotate_epoch must require the previous authority state.",
        ),
        vector(
            "missing-next-authority-state-rejection",
            "reject",
            "next_authority_state",
            "rotate_epoch must require the next authority state.",
        ),
        vector(
            "missing-previous-epoch-rejection",
            "reject",
            "previous_epoch",
            "rotate_epoch must require the previous epoch.",
        ),
        vector(
            "missing-next-epoch-rejection",
            "reject",
            "next_epoch",
            "rotate_epoch must require the next epoch.",
        ),
        vector(
            "epoch-regression-rejection",
            "reject",
            "epoch_regression",
            "rotate_epoch must reject transitions where the next epoch is less than the previous epoch.",
        ),
        vector(
            "same-epoch-rotation-rejection",
            "reject",
            "same_epoch_rotation",
            "rotate_epoch must reject rotation that does not strictly advance the epoch.",
        ),
        vector(
            "strict-epoch-advance-required",
            "reserved",
            "strict_epoch_advance",
            "Reserved for future valid previous epoch to next epoch fixture.",
        ),
        vector(
            "authority-root-continuity-required",
            "reserved",
            "authority_root_continuity",
            "Reserved for future valid authority-root continuity fixture.",
        ),
        vector(
            "chain-hash-linkage-required",
            "reserved",
            "chain_hash_linkage",
            "Reserved for future valid chain-hash linkage fixture.",
        ),
        vector(
            "rotate-verify-roundtrip-reserved",
            "reserved",
            "rotate_verify_roundtrip",
            "Reserved for future rotate then verify fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()
    payload = {
        "schema": "kyriotes_csk2.rotate_epoch.refinement_vectors.v1",
        "target": "src/kyriotes_csk2/engine.rs::rotate_epoch",
        "claim_boundary": "Authority epoch-rotation refinement track; not full Coq/Rust semantic equivalence.",
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
