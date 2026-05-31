#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAPABILITY_TREE_PATH = PROJECT_ROOT / "src" / "arc" / "capability_tree.rs"


def main() -> int:
    assert CAPABILITY_TREE_PATH.exists(), "src/arc/capability_tree.rs must exist"

    source = CAPABILITY_TREE_PATH.read_text(encoding="utf-8")
    lowered = source.lower()

    required_terms = [
        "proof",
        "capability",
        "root",
    ]

    for term in required_terms:
        assert term in lowered, f"capability_tree surface must mention {term}"

    flexible_terms = [
        "sibling",
        "path",
        "witness",
        "revocation",
        "member",
        "leaf",
        "hash",
        "verify",
    ]

    present = [term for term in flexible_terms if term in lowered]
    assert len(present) >= 4, "capability_tree should expose several Merkle/proof-related terms"

    print("capability_tree surface check passed.")
    print("Detected proof terms: " + ", ".join(sorted(present)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
