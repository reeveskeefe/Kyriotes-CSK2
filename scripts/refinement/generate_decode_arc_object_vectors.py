#!/usr/bin/env python3
"""
Generate deterministic parser-refinement vectors for decode_arc_object.

These vectors classify byte inputs by parser-refinement category. Most current
vectors are invalid-input rejection cases. Round-trip vectors are represented as
a reserved category until canonical valid ARC object fixtures are generated from
the Rust encoder.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "decode_arc_object_vectors.json"


@dataclass(frozen=True)
class DecodeArcObjectVector:
    id: str
    category: str
    input_hex: str
    expected_result: str
    max_allowed_millis: int
    notes: str


def hex_bytes(data: bytes) -> str:
    return data.hex()


def repeated(seed: str, length: int) -> bytes:
    out = bytearray()
    counter = 0

    while len(out) < length:
        out.extend(hashlib.sha256(f"{seed}:{counter}".encode("utf-8")).digest())
        counter += 1

    return bytes(out[:length])


def build_vectors() -> list[DecodeArcObjectVector]:
    return [
        DecodeArcObjectVector(
            id="decode.empty",
            category="empty-input-rejection",
            input_hex="",
            expected_result="reject",
            max_allowed_millis=50,
            notes="Empty input must not decode as a valid ARC object.",
        ),
        DecodeArcObjectVector(
            id="decode.single-zero",
            category="tiny-input-rejection",
            input_hex="00",
            expected_result="reject",
            max_allowed_millis=50,
            notes="Single byte input must be rejected safely.",
        ),
        DecodeArcObjectVector(
            id="decode.single-ff",
            category="tiny-input-rejection",
            input_hex="ff",
            expected_result="reject",
            max_allowed_millis=50,
            notes="Single 0xff byte must be rejected safely.",
        ),
        DecodeArcObjectVector(
            id="decode.short-garbage-8",
            category="malformed-input-rejection",
            input_hex=hex_bytes(repeated("short-garbage", 8)),
            expected_result="reject",
            max_allowed_millis=50,
            notes="Short deterministic garbage must be rejected.",
        ),
        DecodeArcObjectVector(
            id="decode.truncated-32",
            category="truncation-rejection",
            input_hex=hex_bytes(repeated("truncated", 32)),
            expected_result="reject",
            max_allowed_millis=50,
            notes="Truncated object-shaped data must be rejected.",
        ),
        DecodeArcObjectVector(
            id="decode.truncated-127",
            category="truncation-rejection",
            input_hex=hex_bytes(repeated("truncated", 127)),
            expected_result="reject",
            max_allowed_millis=50,
            notes="Odd-size truncated data must be rejected.",
        ),
        DecodeArcObjectVector(
            id="decode.repeated-zero-512",
            category="malformed-input-rejection",
            input_hex=hex_bytes(bytes([0]) * 512),
            expected_result="reject",
            max_allowed_millis=100,
            notes="Large zero-filled malformed input must be rejected.",
        ),
        DecodeArcObjectVector(
            id="decode.repeated-ff-512",
            category="malformed-input-rejection",
            input_hex=hex_bytes(bytes([255]) * 512),
            expected_result="reject",
            max_allowed_millis=100,
            notes="Large 0xff-filled malformed input must be rejected.",
        ),
        DecodeArcObjectVector(
            id="decode.deterministic-garbage-4096",
            category="limit-rejection",
            input_hex=hex_bytes(repeated("limit-garbage", 4096)),
            expected_result="reject",
            max_allowed_millis=250,
            notes="Large deterministic garbage must be rejected without parser instability.",
        ),
        DecodeArcObjectVector(
            id="decode.roundtrip-valid-object-reserved",
            category="roundtrip-reserved",
            input_hex="",
            expected_result="reserved",
            max_allowed_millis=0,
            notes="Reserved for future encode_arc_object followed by decode_arc_object canonical round-trip fixture.",
        ),
    ]


def main() -> int:
    vectors = build_vectors()

    payload = {
        "schema": "arc.decode_arc_object.refinement_vectors.v1",
        "target": "src/encoding/codec.rs::decode_arc_object",
        "claim_boundary": "Parser-refinement vectors and rejection checks; not full byte-level Coq/Rust equivalence.",
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
