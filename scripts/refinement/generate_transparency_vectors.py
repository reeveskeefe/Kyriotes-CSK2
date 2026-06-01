#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "transparency_vectors.json"


@dataclass(frozen=True)
class TransparencyVector:
    id: str
    category: str
    expected_result: str
    gate_name: str
    deterministic: bool
    notes: str


def stable_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def vector(category: str, expected_result: str, gate_name: str, notes: str) -> TransparencyVector:
    return TransparencyVector(
        id=f"transparency.{stable_id(category + ':' + gate_name)}",
        category=category,
        expected_result=expected_result,
        gate_name=gate_name,
        deterministic=True,
        notes=notes,
    )


def build_vectors() -> list[TransparencyVector]:
    return [
        vector(
            "missing-log-rejection",
            "reject",
            "transparency_log",
            "transparency operations must require a log surface.",
        ),
        vector(
            "missing-entry-rejection",
            "reject",
            "transparency_entry",
            "transparency append must require an entry.",
        ),
        vector(
            "missing-epoch-rejection",
            "reject",
            "epoch",
            "transparency entries must bind an epoch.",
        ),
        vector(
            "missing-state-root-rejection",
            "reject",
            "state_root",
            "transparency entries must bind a state root.",
        ),
        vector(
            "missing-commitment-rejection",
            "reject",
            "commitment",
            "transparency entries must bind a commitment or equivalent root.",
        ),
        vector(
            "conflicting-epoch-rejection",
            "reject",
            "conflicting_epoch",
            "transparency must reject conflicting epoch entries.",
        ),
        vector(
            "duplicate-conflicting-entry-rejection",
            "reject",
            "duplicate_conflict",
            "transparency must reject duplicate entries that conflict with existing state.",
        ),
        vector(
            "append-only-regression-rejection",
            "reject",
            "append_only",
            "transparency must reject log regressions or non-append mutations.",
        ),
        vector(
            "lookup-missing-entry-rejection",
            "reject",
            "lookup",
            "transparency lookup should reject or miss absent entries deterministically.",
        ),
        vector(
            "state-root-binding-reserved",
            "reserved",
            "state_root_binding",
            "Reserved for future concrete state-root binding fixture.",
        ),
        vector(
            "valid-append-reserved",
            "reserved",
            "valid_append",
            "Reserved for future concrete valid append fixture.",
        ),
        vector(
            "valid-lookup-reserved",
            "reserved",
            "valid_lookup",
            "Reserved for future concrete valid lookup fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()
    payload = {
        "schema": "kyriotes_csk2.transparency.refinement_vectors.v1",
        "target": "src/kyriotes_csk2/transparency.rs",
        "claim_boundary": "Transparency append/lookup/conflict refinement track; not full Coq/Rust semantic equivalence.",
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
