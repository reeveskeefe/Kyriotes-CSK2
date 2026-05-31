#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "add_epoch_wrapper_vectors.json"


@dataclass(frozen=True)
class AddEpochWrapperVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> AddEpochWrapperVector:
    return AddEpochWrapperVector(
        id=f"add_epoch_wrapper.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[AddEpochWrapperVector]:
    return [
        vector(
            "missing-recipient-secret-key-rejection",
            "reject",
            "recipient_secret_key",
            "add_epoch_wrapper must require recipient secret key material.",
        ),
        vector(
            "missing-recipient-public-key-rejection",
            "reject",
            "recipient_public_key",
            "add_epoch_wrapper must require recipient public key material.",
        ),
        vector(
            "missing-object-rejection",
            "reject",
            "arc_object",
            "add_epoch_wrapper must require a mutable ARC object.",
        ),
        vector(
            "missing-capability-rejection",
            "reject",
            "capability",
            "add_epoch_wrapper must require a valid capability.",
        ),
        vector(
            "missing-capability-proof-rejection",
            "reject",
            "capability_proof",
            "add_epoch_wrapper must require capability proof evidence.",
        ),
        vector(
            "missing-previous-authority-state-rejection",
            "reject",
            "previous_authority_state",
            "add_epoch_wrapper must require the previous authority state.",
        ),
        vector(
            "missing-next-authority-state-rejection",
            "reject",
            "next_authority_state",
            "add_epoch_wrapper must require the next authority state.",
        ),
        vector(
            "missing-transparency-proof-rejection",
            "reject",
            "transparency_proof",
            "add_epoch_wrapper must require transparency proof evidence.",
        ),
        vector(
            "epoch-regression-rejection",
            "reject",
            "epoch_monotonicity",
            "add_epoch_wrapper must reject wrapper transitions that regress epoch state.",
        ),
        vector(
            "wrapper-binding-preservation-reserved",
            "reserved",
            "wrapper_binding",
            "Reserved for future concrete wrapper binding preservation fixture.",
        ),
        vector(
            "rewrap-roundtrip-reserved",
            "reserved",
            "rewrap_roundtrip",
            "Reserved for future seal -> verify -> add_epoch_wrapper -> open fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()
    payload = {
        "schema": "arc.add_epoch_wrapper.refinement_vectors.v1",
        "target": "src/arc/engine.rs::add_epoch_wrapper",
        "claim_boundary": "Epoch-wrapper refinement track; not full Coq/Rust semantic equivalence.",
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
