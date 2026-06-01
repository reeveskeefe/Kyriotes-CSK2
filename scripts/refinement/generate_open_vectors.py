#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "open_vectors.json"


@dataclass(frozen=True)
class OpenVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> OpenVector:
    return OpenVector(
        id=f"open.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[OpenVector]:
    return [
        vector(
            "missing-recipient-secret-key-rejection",
            "reject",
            "recipient_secret_key",
            "open must require recipient secret key material.",
        ),
        vector(
            "missing-object-rejection",
            "reject",
            "kyriotes_csk2_object",
            "open must require an Kyriotēs-CSK2 object.",
        ),
        vector(
            "missing-capability-rejection",
            "reject",
            "capability",
            "open must require a valid capability.",
        ),
        vector(
            "missing-capability-proof-rejection",
            "reject",
            "capability_proof",
            "open must require capability proof evidence.",
        ),
        vector(
            "missing-authority-state-rejection",
            "reject",
            "authority_state",
            "open must require authority state.",
        ),
        vector(
            "revoked-capability-rejection",
            "reject",
            "nonrevocation",
            "open must reject revoked capabilities.",
        ),
        vector(
            "temporal-policy-mismatch-rejection",
            "reject",
            "temporal_policy",
            "open must reject temporal policy mismatches.",
        ),
        vector(
            "wrapper-binding-mismatch-rejection",
            "reject",
            "wrapper_binding",
            "open must reject wrapper binding mismatches.",
        ),
        vector(
            "decrypt-failure-rejection",
            "reject",
            "cryptographic_open",
            "open must reject cryptographic unwrap/decrypt failure.",
        ),
        vector(
            "seal-verify-open-roundtrip-reserved",
            "reserved",
            "seal_verify_open_roundtrip",
            "Reserved for future concrete valid seal -> verify -> open fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()
    payload = {
        "schema": "kyriotes_csk2.open.refinement_vectors.v1",
        "target": "src/kyriotes_csk2/engine.rs::open",
        "claim_boundary": "Open authorization refinement track; not full Coq/Rust semantic equivalence.",
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
