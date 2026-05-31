#!/usr/bin/env python3
"""
Check the Rust verify refinement surface.

This checks source-level structure without pretending to prove semantic
equivalence. It verifies that engine.rs contains verify and that the source
mentions the expected verification inputs.
"""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = PROJECT_ROOT / "src" / "arc" / "engine.rs"


def main() -> int:
    assert ENGINE_PATH.exists(), "src/arc/engine.rs must exist"

    source = ENGINE_PATH.read_text(encoding="utf-8")

    assert "fn verify" in source or "pub fn verify" in source, "verify function must exist in engine.rs"

    required_terms = [
        "ArcObject",
        "Capability",
        "CapabilityProof",
        "AuthorityState",
        "TransparencyProof",
    ]

    for term in required_terms:
        assert term in source, f"verify surface must mention {term}"

    assert "Result" in source, "verify should expose Result-style fallible behavior"
    assert "ArcError" in source, "verify should use ARC error surface"

    print("verify surface check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
