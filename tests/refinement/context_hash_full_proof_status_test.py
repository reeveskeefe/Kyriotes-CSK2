#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATUS_PATH = PROJECT_ROOT / "tests" / "refinement" / "context_hash_full_proof_status.json"


def main() -> int:
    payload = json.loads(STATUS_PATH.read_text(encoding="utf-8"))

    assert payload["schema"] in {
        "arc.context_hash.full_mechanical_proof_status.v1",
        "arc.context_hash.full_mechanical_proof_status.v2",
    }
    assert payload["target"] == "src/arc/model.rs::context_hash"
    assert payload["mechanically_checked"] is True
    assert payload["proof_tool"] == "kani"
    assert isinstance(payload["mechanically_proven"], bool)

    if payload["schema"] == "arc.context_hash.full_mechanical_proof_status.v2":
        assert payload["required_harness_count"] == 4
        assert len(payload["required_harnesses"]) == 4
        assert isinstance(payload["harness_results"], list)
        assert payload["passed_harness_count"] <= payload["required_harness_count"]

        if payload["mechanically_proven"] is True:
            assert payload["proof_succeeded"] is True
            assert payload["passed_harness_count"] == payload["required_harness_count"]
            assert all(item["succeeded"] is True for item in payload["harness_results"])
        else:
            assert payload["proof_succeeded"] is False
    else:
        if payload["mechanically_proven"] is True:
            assert payload["proof_succeeded"] is True
        else:
            assert payload["proof_succeeded"] is False

    print("context_hash full proof status test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
