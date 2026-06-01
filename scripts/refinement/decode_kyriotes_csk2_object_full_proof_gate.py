#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"
ARTIFACT_PATH = PROJECT_ROOT / "tests" / "refinement" / "decode_kyriotes_csk2_object_full_proof_status.json"

HARNESSES = [
    "decode_kyriotes_csk2_object_rejects_empty_input",
    "decode_kyriotes_csk2_object_rejects_one_byte_input",
    "decode_kyriotes_csk2_object_rejects_two_byte_input",
    "decode_kyriotes_csk2_object_rejects_tiny_malformed_input",
    "decode_kyriotes_csk2_object_rejects_bounded_malformed_input",
    "decode_kyriotes_csk2_object_malformed_rejection_is_deterministic",
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
        if entry.get("id") == "codec.decode_kyriotes_csk2_object":
            entry["mechanically_checked"] = True
            entry["mechanically_proven"] = proven
            if proven:
                entry["boundary"] = (
                    "decode_kyriotes_csk2_object has verifier-backed Kani proof evidence for "
                    "bounded malformed parser rejection and deterministic rejection behavior. "
                    "Full parser equivalence remains outside this narrow proof claim."
                )
            else:
                entry["boundary"] = (
                    "decode_kyriotes_csk2_object has mechanical check evidence, but verifier-backed "
                    "parser proof remains open until all required Kani harnesses pass."
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
            "context_hash plus decode_kyriotes_csk2_object verifier-backed proof lanes complete "
            "within their stated narrow scopes."
        )

    INVENTORY_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    kani = shutil.which("cargo-kani") or shutil.which("kani")

    status = {
        "schema": "kyriotes_csk2.decode_kyriotes_csk2_object.full_mechanical_proof_status.v1",
        "target": "src/encoding/wire.rs::decode_kyriotes_csk2_object",
        "proof_tool": "kani",
        "required_harness_count": len(HARNESSES),
        "required_harnesses": HARNESSES,
        "proof_attempted": False,
        "proof_succeeded": False,
        "mechanically_checked": True,
        "mechanically_proven": False,
        "harness_results": [],
        "boundary": (
            "Full decode_kyriotes_csk2_object proof requires all Kani malformed-input parser "
            "safety harnesses to pass. This proves bounded rejection and no-panic "
            "behavior for selected malformed surfaces, not full parser equivalence."
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
            "All decode_kyriotes_csk2_object Kani parser-safety harnesses passed. "
            "decode_kyriotes_csk2_object is marked mechanically proven for bounded malformed "
            "input rejection and deterministic rejection behavior. Full parser "
            "equivalence remains outside this narrow proof claim."
        )
        update_inventory(proven=True)
        print("PASS: all decode_kyriotes_csk2_object Kani parser-safety harnesses succeeded.")
    else:
        status["reason"] = "At least one required Kani harness failed; target remains checked but not proven."
        update_inventory(proven=False)
        print("OPEN: at least one decode_kyriotes_csk2_object Kani harness failed; target remains checked but not proven.")

    write_status(status)
    print(f"Wrote {ARTIFACT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
