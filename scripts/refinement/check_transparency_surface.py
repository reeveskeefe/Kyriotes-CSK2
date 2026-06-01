#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TRANSPARENCY_PATH = PROJECT_ROOT / "src" / "kyriotes-csk2" / "transparency.rs"


def main() -> int:
    assert TRANSPARENCY_PATH.exists(), "src/kyriotes_csk2/transparency.rs must exist"

    source = TRANSPARENCY_PATH.read_text(encoding="utf-8")
    lowered = source.lower()

    required_terms = [
        "transparency",
        "epoch",
        "root",
    ]

    for term in required_terms:
        assert term in lowered, f"transparency surface must mention {term}"

    flexible_terms = [
        "append",
        "commit",
        "proof",
        "lookup",
        "state",
        "log",
        "entry",
        "conflict",
        "verify",
        "hash",
    ]

    present = [term for term in flexible_terms if term in lowered]
    assert len(present) >= 5, "transparency should expose several log/proof/commit-related terms"

    print("transparency surface check passed.")
    print("Detected transparency terms: " + ", ".join(sorted(present)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
