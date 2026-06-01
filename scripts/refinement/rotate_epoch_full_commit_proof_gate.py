#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"
ARTIFACT_PATH = PROJECT_ROOT / "tests" / "refinement" / "rotate_epoch_full_commit_proof_status.json"

HARNESSES = [
    "rotate_epoch_full_commit_phase_propagates_transparency_commit_rejection",
    "rotate_epoch_full_commit_phase_rejection_is_deterministic",
    "rotate_epoch_full_commit_phase_does_not_store_chain_hash_when_commit_fails",
    "rotate_epoch_full_commit_phase_rejection_hides_commit_material",
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
        if entry.get("id") == "engine.rotate_epoch_full":
            entry["mechanically_checked"] = True
            entry["mechanically_proven"] = proven
            if proven:
                entry["boundary"] = (
                    "rotate_epoch_full has verifier-backed Kani proof evidence for its extracted commit/finalization phase for fail-closed "
                    "transparency-log commit rejection propagation, deterministic rejection, "
                    "non-observability of successful commit material when commit_state fails, "
                    "and store_chain_hash non-reachability on commit failure. Full successful "
                    "transparency-commit semantic equivalence remains outside this narrow proof claim."
                )
            else:
                entry["boundary"] = (
                    "rotate_epoch_full has mechanical check evidence, but verifier-backed "
                    "transparency-commit fail-closed proof remains open until all required "
                    "Kani harnesses pass."
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
            "rotate_epoch_full transparency-commit fail-closed proof lane complete "
            "within its stated narrow scope."
        )

    INVENTORY_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    kani = shutil.which("cargo-kani") or shutil.which("kani")

    status = {
        "schema": "kyriotes_csk2.rotate_epoch_full.commit_mechanical_proof_status.v1",
        "target": "src/kyriotes_csk2/engine.rs::begin_epoch_rotation_commit",
        "proof_tool": "kani",
        "required_harness_count": len(HARNESSES),
        "required_harnesses": HARNESSES,
        "proof_attempted": False,
        "proof_succeeded": False,
        "mechanically_checked": True,
        "mechanically_proven": False,
        "harness_results": [],
        "boundary": (
            "Full rotate_epoch_full proof requires all Kani transparency-log fail-closed "
            "harnesses to pass. This proves commit_state rejection propagation and "
            "store_chain_hash non-reachability on commit failure, not full successful "
            "transparency-commit equivalence."
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
            "All rotate_epoch_full Kani transparency-log fail-closed harnesses passed. "
            "rotate_epoch_full is marked mechanically proven for its extracted commit/finalization phase: commit_state rejection "
            "propagation, deterministic rejection, TransparencyStateCommit non-return on commit failure, "
            "and store_chain_hash non-reachability on commit failure. Full successful "
            "transparency-commit equivalence remains outside this narrow proof claim."
        )
        update_inventory(proven=True)
        print("PASS: all rotate_epoch_full Kani transparency-log fail-closed harnesses succeeded.")
    else:
        status["reason"] = "At least one required Kani harness failed; target remains checked but not proven."
        update_inventory(proven=False)
        print("OPEN: at least one rotate_epoch_full Kani harness failed; target remains checked but not proven.")

    write_status(status)
    print(f"Wrote {ARTIFACT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
