#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = PROJECT_ROOT / "src" / "kyriotes-csk2" / "engine.rs"


def main() -> int:
    assert ENGINE_PATH.exists(), "src/kyriotes_csk2/engine.rs must exist"

    source = ENGINE_PATH.read_text(encoding="utf-8")

    assert "rotate_epoch" in source, "rotate_epoch function must exist in engine.rs"

    required_terms = [
        "AuthorityState",
        "epoch",
        "chain",
        "Result",
        "KyriotesCsk2Error",
    ]

    for term in required_terms:
        assert term in source, f"rotate_epoch surface must mention {term}"

    print("rotate_epoch surface check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
