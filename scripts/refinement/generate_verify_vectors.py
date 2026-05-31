#!/usr/bin/env python3
"""
Generate deterministic verification-gate refinement vectors for engine::verify.

These vectors describe the verification gate categories that must be checked
before verify can be promoted from surface-level mechanical check to deeper
semantic refinement.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "verify_vectors.json"


@dataclass(frozen=True)
class VerifyVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> VerifyVector:
    return VerifyVector(
        id=f"verify.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[VerifyVector]:
    return [
        vector(
            "missing-object-rejection",
            "reject",
            "arc_object",
            "verify must reject when no valid ARC object is available.",
        ),
        vector(
            "missing-capability-rejection",
            "reject",
            "capability",
            "verify must reject when capability evidence is missing or malformed.",
        ),
        vector(
            "missing-capability-proof-rejection",
            "reject",
            "capability_proof",
            "verify must reject when capability proof evidence is missing or invalid.",
        ),
        vector(
            "missing-authority-state-rejection",
            "reject",
            "authority_state",
            "verify must reject when authority state is absent or mismatched.",
        ),
        vector(
            "missing-transparency-proof-rejection",
            "reject",
            "transparency_proof",
            "verify must reject when transparency proof evidence is missing or mismatched.",
        ),
        vector(
            "revoked-capability-rejection",
            "reject",
            "nonrevocation",
            "verify must reject revoked capabilities.",
        ),
        vector(
            "temporal-policy-mismatch-rejection",
            "reject",
            "temporal_policy",
            "verify must reject temporal policy mismatches.",
        ),
        vector(
            "transcript-binding-mismatch-rejection",
            "reject",
            "transcript_binding",
            "verify must reject transcript or context binding mismatches.",
        ),
        vector(
            "wrapper-binding-mismatch-rejection",
            "reject",
            "wrapper_binding",
            "verify must reject wrapper binding mismatches.",
        ),
        vector(
            "valid-verification-reserved",
            "reserved",
            "all_gates",
            "Reserved for future valid object/capability/proof/state/transparency fixtures.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()

    payload = {
        "schema": "arc.verify.refinement_vectors.v1",
        "target": "src/arc/engine.rs::verify",
        "claim_boundary": "Verification-gate refinement track; not full Coq/Rust semantic equivalence.",
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
