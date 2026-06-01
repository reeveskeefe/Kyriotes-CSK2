#!/usr/bin/env python3
"""
Check the encode/decode wire-format refinement surface.

This is a repository-local mechanical surface check. It verifies that the
encoding source surface exists and that the expected encode/decode symbols are
discoverable somewhere in the Rust source tree.

It does not prove byte-level semantic equivalence.
"""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUST_SOURCE_ROOTS = [
    PROJECT_ROOT / "src",
]


def read_all_rust() -> str:
    chunks: list[str] = []

    for root in RUST_SOURCE_ROOTS:
        if not root.exists():
            continue

        for path in sorted(root.rglob("*.rs")):
            chunks.append(path.read_text(encoding="utf-8"))

    return "\n".join(chunks)


def main() -> int:
    codec_path = PROJECT_ROOT / "src" / "encoding" / "codec.rs"
    source = read_all_rust()

    assert codec_path.exists(), "src/encoding/codec.rs must exist"
    assert "decode_kyriotes_csk2_object" in source, "decode_kyriotes_csk2_object symbol must be discoverable"
    assert "encode_kyriotes_csk2_object" in source, "encode_kyriotes_csk2_object symbol must be discoverable"

    print("Encode/decode refinement surface check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
