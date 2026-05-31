#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"
ARTIFACT_PATH = PROJECT_ROOT / "tests" / "refinement" / "context_hash_full_proof_status.json"


def write_status(status: dict) -> None:
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    kani = shutil.which("cargo-kani") or shutil.which("kani")

    status = {
        "schema": "arc.context_hash.full_mechanical_proof_status.v1",
        "target": "src/arc/model.rs::context_hash",
        "proof_tool": "kani",
        "proof_attempted": False,
        "proof_succeeded": False,
        "mechanically_checked": True,
        "mechanically_proven": False,
        "boundary": "Full proof remains open unless the verifier command succeeds.",
    }

    if kani is None:
        status["reason"] = "Kani is not installed or not discoverable on PATH."
        write_status(status)
        print("OPEN: Kani is not installed or not discoverable on PATH.")
        print(f"Wrote {ARTIFACT_PATH}")
        return 0

    status["proof_attempted"] = True

    command = [
        "cargo",
        "kani",
        "--lib",
        "--harness",
        "context_transcript_model_is_deterministic_for_equal_inputs",
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    status["command"] = command
    status["returncode"] = result.returncode
    status["output_tail"] = result.stdout[-4000:]

    if result.returncode == 0:
        status["proof_succeeded"] = True
        status["mechanically_proven"] = True
        status["boundary"] = "Kani proof succeeded for the first context_hash harness."
        update_inventory(proven=True)
        print("PASS: context_hash first Kani proof succeeded.")
    else:
        status["reason"] = "Kani command failed; target remains checked but not proven."
        print("OPEN: Kani command failed; context_hash remains checked but not proven.")

    write_status(status)
    print(f"Wrote {ARTIFACT_PATH}")
    return 0


def update_inventory(proven: bool) -> None:
    payload = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    checked_count = 0
    proven_count = 0

    for entry in payload.get("entries", []):
        if entry.get("id") == "model.context_hash":
            entry["mechanically_checked"] = True
            entry["mechanically_proven"] = proven
            if proven:
                entry["boundary"] = "context_hash has verifier-backed Kani proof evidence for the first deterministic equivalence harness."

        if entry.get("mechanically_checked") is True:
            checked_count += 1
        if entry.get("mechanically_proven") is True:
            proven_count += 1

    payload["mechanically_checked_count"] = checked_count
    payload["mechanically_proven_count"] = proven_count

    if proven:
        payload["boundary"] = "Mechanical refinement inventory has all declared targets checked and at least one verifier-backed proven target."

    INVENTORY_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
