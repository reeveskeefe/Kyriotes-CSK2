#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"
ARTIFACT_PATH = PROJECT_ROOT / "tests" / "refinement" / "context_hash_full_proof_status.json"

HARNESSES = [
    "context_transcript_model_is_deterministic_for_equal_inputs",
    "context_transcript_model_binds_policy_hash",
    "context_transcript_model_binds_epoch",
    "context_transcript_model_binds_capability_stamp",
]


def write_status(status: dict) -> None:
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_harness(harness: str) -> dict:
    command = [
        "cargo",
        "kani",
        "--lib",
        "--harness",
        harness,
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    return {
        "harness": harness,
        "command": command,
        "returncode": result.returncode,
        "succeeded": result.returncode == 0,
        "output_tail": result.stdout[-4000:],
    }


def update_inventory(proven: bool) -> None:
    payload = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    checked_count = 0
    proven_count = 0

    for entry in payload.get("entries", []):
        if entry.get("id") == "model.context_hash":
            entry["mechanically_checked"] = True
            entry["mechanically_proven"] = proven
            if proven:
                entry["boundary"] = (
                    "context_hash has verifier-backed Kani proof evidence for all four "
                    "context transcript model harnesses: determinism, policy-hash binding, "
                    "epoch binding, and capability-stamp binding."
                )
            else:
                entry["boundary"] = (
                    "context_hash has mechanical check evidence, but full verifier-backed "
                    "proof remains open until all required Kani transcript harnesses pass."
                )

        if entry.get("mechanically_checked") is True:
            checked_count += 1
        if entry.get("mechanically_proven") is True:
            proven_count += 1

    payload["mechanically_checked_count"] = checked_count
    payload["mechanically_proven_count"] = proven_count

    if proven:
        payload["boundary"] = (
            "Mechanical refinement inventory has all declared targets checked and "
            "context_hash verifier-backed transcript-model proof complete."
        )
    else:
        payload["boundary"] = (
            "Mechanical refinement inventory has all declared targets checked; full proof "
            "remains open until required verifier-backed harnesses pass."
        )

    INVENTORY_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    kani = shutil.which("cargo-kani") or shutil.which("kani")

    status = {
        "schema": "kyriotes_csk2.context_hash.full_mechanical_proof_status.v2",
        "target": "src/kyriotes_csk2/model.rs::context_hash",
        "proof_tool": "kani",
        "required_harness_count": len(HARNESSES),
        "required_harnesses": HARNESSES,
        "proof_attempted": False,
        "proof_succeeded": False,
        "mechanically_checked": True,
        "mechanically_proven": False,
        "harness_results": [],
        "boundary": (
            "Full context_hash proof requires all four Kani transcript-model harnesses "
            "to pass. This proves the verifier-friendly transcript binding model, not "
            "the full SHA-256 implementation internals."
        ),
    }

    if kani is None:
        status["reason"] = "Kani is not installed or not discoverable on PATH."
        write_status(status)
        update_inventory(proven=False)
        print("OPEN: Kani is not installed or not discoverable on PATH.")
        print(f"Wrote {ARTIFACT_PATH}")
        return 0

    status["proof_attempted"] = True

    all_passed = True

    for harness in HARNESSES:
        print(f"Running Kani harness: {harness}")
        result = run_harness(harness)
        status["harness_results"].append(result)

        if result["succeeded"]:
            print(f"PASS: {harness}")
        else:
            print(f"FAIL: {harness}")
            all_passed = False
            break

    status["proof_succeeded"] = all_passed
    status["mechanically_proven"] = all_passed
    status["passed_harness_count"] = sum(1 for item in status["harness_results"] if item["succeeded"])

    if all_passed:
        status["boundary"] = (
            "All four Kani transcript-model harnesses passed. context_hash is marked "
            "mechanically proven for the transcript binding model, while full SHA-256 "
            "implementation equivalence remains outside this narrow proof claim."
        )
        update_inventory(proven=True)
        print("PASS: all context_hash Kani transcript harnesses succeeded.")
    else:
        status["reason"] = "At least one required Kani harness failed; target remains checked but not proven."
        update_inventory(proven=False)
        print("OPEN: at least one context_hash Kani harness failed; target remains checked but not proven.")

    write_status(status)
    print(f"Wrote {ARTIFACT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
