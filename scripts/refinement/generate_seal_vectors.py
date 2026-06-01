#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "seal_vectors.json"


@dataclass(frozen=True)
class SealVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> SealVector:
    return SealVector(
        id=f"seal.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[SealVector]:
    return [
        vector(
            "missing-recipient-key-rejection",
            "reject",
            "recipient_public_key",
            "seal must require a recipient public key.",
        ),
        vector(
            "missing-message-rejection",
            "reject",
            "message",
            "seal must require message input.",
        ),
        vector(
            "missing-capability-rejection",
            "reject",
            "capability",
            "seal must require a valid capability.",
        ),
        vector(
            "missing-capability-proof-rejection",
            "reject",
            "capability_proof",
            "seal must require capability proof evidence.",
        ),
        vector(
            "missing-authority-state-rejection",
            "reject",
            "authority_state",
            "seal must require authority state.",
        ),
        vector(
            "missing-transparency-proof-rejection",
            "reject",
            "transparency_proof",
            "seal must require transparency proof linkage.",
        ),
        vector(
            "temporal-policy-required",
            "reject",
            "temporal_policy",
            "seal must carry temporal policy context.",
        ),
        vector(
            "lifecycle-seal-transition",
            "reserved",
            "lifecycle_seal",
            "Reserved for future concrete valid seal fixture.",
        ),
        vector(
            "seal-verify-roundtrip-reserved",
            "reserved",
            "seal_verify_roundtrip",
            "Reserved for future seal followed by verify fixture.",
        ),
        vector(
            "seal-open-roundtrip-reserved",
            "reserved",
            "seal_open_roundtrip",
            "Reserved for future seal followed by open fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()
    payload = {
        "schema": "kyriotes_csk2.seal.refinement_vectors.v1",
        "target": "src/kyriotes_csk2/engine.rs::seal",
        "claim_boundary": "Seal lifecycle refinement track; not full Coq/Rust semantic equivalence.",
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
