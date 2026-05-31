#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = PROJECT_ROOT / "src" / "arc" / "engine.rs"


def main() -> int:
    assert ENGINE_PATH.exists(), "src/arc/engine.rs must exist"

    source = ENGINE_PATH.read_text(encoding="utf-8")

    assert "add_epoch_wrapper" in source, "add_epoch_wrapper function must exist in engine.rs"

    required_terms = [
        "RecipientSecretKey",
        "RecipientPublicKey",
        "ArcObject",
        "Capability",
        "CapabilityProof",
        "AuthorityState",
        "TransparencyProof",
    ]

    for term in required_terms:
        assert term in source, f"add_epoch_wrapper surface must mention {term}"

    assert "Result" in source, "add_epoch_wrapper should expose Result-style fallible behavior"
    assert "ArcError" in source, "add_epoch_wrapper should use ARC error surface"

    print("add_epoch_wrapper surface check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
