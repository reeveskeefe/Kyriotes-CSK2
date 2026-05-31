#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = PROJECT_ROOT / "src" / "arc" / "engine.rs"


def main() -> int:
    assert ENGINE_PATH.exists(), "src/arc/engine.rs must exist"

    source = ENGINE_PATH.read_text(encoding="utf-8")

    assert "fn seal" in source or "pub fn seal" in source, "seal function must exist in engine.rs"

    required_terms = [
        "RecipientPublicKey",
        "Capability",
        "CapabilityProof",
        "AuthorityState",
        "TransparencyProof",
        "TemporalPolicy",
        "ArcObject",
    ]

    for term in required_terms:
        assert term in source, f"seal surface must mention {term}"

    assert "Result" in source, "seal should expose Result-style fallible behavior"
    assert "ArcError" in source, "seal should use ARC error surface"

    print("seal surface check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
