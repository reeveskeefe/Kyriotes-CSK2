#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "capability_tree_vectors.json"


@dataclass(frozen=True)
class CapabilityTreeVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> CapabilityTreeVector:
    return CapabilityTreeVector(
        id=f"capability_tree.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[CapabilityTreeVector]:
    return [
        vector(
            "missing-capability-proof-rejection",
            "reject",
            "capability_proof",
            "capability_tree must reject missing capability proof material.",
        ),
        vector(
            "missing-membership-proof-rejection",
            "reject",
            "membership_proof",
            "capability_tree must reject missing membership proof material.",
        ),
        vector(
            "missing-nonrevocation-witness-rejection",
            "reject",
            "nonrevocation_witness",
            "capability_tree must reject missing non-revocation witness material.",
        ),
        vector(
            "root-mismatch-rejection",
            "reject",
            "root_binding",
            "capability_tree must reject proofs whose computed root does not match the expected root.",
        ),
        vector(
            "tampered-leaf-rejection",
            "reject",
            "leaf_binding",
            "capability_tree must reject tampered proof leaf material.",
        ),
        vector(
            "tampered-sibling-rejection",
            "reject",
            "sibling_binding",
            "capability_tree must reject tampered sibling material.",
        ),
        vector(
            "sibling-order-mismatch-rejection",
            "reject",
            "sibling_order",
            "capability_tree must reject sibling ordering mismatches.",
        ),
        vector(
            "empty-proof-rejection",
            "reject",
            "empty_proof",
            "capability_tree must reject invalid empty proof material.",
        ),
        vector(
            "revoked-capability-rejection",
            "reject",
            "revocation_witness",
            "capability_tree must reject revoked capability evidence.",
        ),
        vector(
            "valid-membership-proof-reserved",
            "reserved",
            "valid_membership_proof",
            "Reserved for future concrete valid capability membership proof fixture.",
        ),
        vector(
            "valid-nonrevocation-proof-reserved",
            "reserved",
            "valid_nonrevocation_proof",
            "Reserved for future concrete valid non-revocation proof fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()
    payload = {
        "schema": "kyriotes_csk2.capability_tree.refinement_vectors.v1",
        "target": "src/kyriotes_csk2/capability_tree.rs",
        "claim_boundary": "Capability-tree proof refinement track; not full Coq/Rust semantic equivalence.",
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
