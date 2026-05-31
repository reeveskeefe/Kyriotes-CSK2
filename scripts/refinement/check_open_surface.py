#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = PROJECT_ROOT / "src" / "arc" / "engine.rs"


def main() -> int:
    assert ENGINE_PATH.exists(), "src/arc/engine.rs must exist"

    source = ENGINE_PATH.read_text(encoding="utf-8")

    assert "fn open" in source or "pub fn open" in source, "open function must exist in engine.rs"

    required_terms = [
        "RecipientSecretKey",
        "ArcObject",
        "Capability",
        "CapabilityProof",
        "AuthorityState",
    ]

    for term in required_terms:
        assert term in source, f"open surface must mention {term}"

    assert "Result" in source, "open should expose Result-style fallible behavior"
    assert "ArcError" in source, "open should use ARC error surface"

    print("open surface check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
