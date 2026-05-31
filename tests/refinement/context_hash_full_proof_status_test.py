#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATUS_PATH = PROJECT_ROOT / "tests" / "refinement" / "context_hash_full_proof_status.json"


def main() -> int:
    payload = json.loads(STATUS_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] == "arc.context_hash.full_mechanical_proof_status.v1"
    assert payload["target"] == "src/arc/model.rs::context_hash"
    assert payload["mechanically_checked"] is True
    assert payload["proof_tool"] == "kani"
    assert isinstance(payload["mechanically_proven"], bool)

    if payload["mechanically_proven"] is True:
        assert payload["proof_succeeded"] is True
    else:
        assert payload["proof_succeeded"] is False

    print("context_hash full proof status test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
