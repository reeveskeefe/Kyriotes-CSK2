#!/usr/bin/env python3
"""
Generate ARC Rust mechanical-refinement inventory.

This script creates a deterministic inventory of Rust surfaces that are intended
to become mechanically refined against the Coq model.

It is intentionally conservative:
- It records source and symbol presence.
- It records whether a target is mechanically harnessed.
- It does not claim a target is mechanically proven.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_mechanical_refinement_inventory.json"


@dataclass(frozen=True)
class MechanicalTarget:
    id: str
    rust_file: str
    rust_symbol: str
    coq_model: str
    obligation: str
    harness_level: str
    mechanically_checked: bool
    mechanically_proven: bool


@dataclass(frozen=True)
class MechanicalInventoryEntry:
    id: str
    rust_file: str
    rust_symbol: str
    coq_model: str
    obligation: str
    harness_level: str
    source_present: bool
    symbol_present: bool
    mechanically_checked: bool
    mechanically_proven: bool
    boundary: str


TARGETS: tuple[MechanicalTarget, ...] = (
    MechanicalTarget(
        id="codec.decode_arc_object",
        rust_file="src/encoding/codec.rs",
        rust_symbol="decode_arc_object",
        coq_model="ArcEncodingProofs",
        obligation="Rust decoder must reject malformed and over-limit ARC objects consistently with Coq encoding safety assumptions.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="codec.encode_arc_object",
        rust_file="src/encoding/codec.rs",
        rust_symbol="encode_arc_object",
        coq_model="ArcEncodingProofs",
        obligation="Rust encoder must produce canonical ARC object encodings compatible with the Coq encoding model.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="model.context_hash",
        rust_file="src/arc/model.rs",
        rust_symbol="context_hash",
        coq_model="ArcTranscriptProofs",
        obligation="Rust context_hash must bind object, rights, policy, authority, and temporal context as modeled in Coq.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="engine.verify",
        rust_file="src/arc/engine.rs",
        rust_symbol="verify",
        coq_model="ArcVerify",
        obligation="Rust verify must accept only when capability, revocation, temporal, authority, wrapper, and transparency gates hold.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="engine.open",
        rust_file="src/arc/engine.rs",
        rust_symbol="open",
        coq_model="ArcMasterInvariantProofs",
        obligation="Rust open must refine the Coq master open invariant and reject missing authorization gates.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="engine.seal",
        rust_file="src/arc/engine.rs",
        rust_symbol="seal",
        coq_model="ArcLifecycleProofs",
        obligation="Rust seal must refine the Coq lifecycle seal transition.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="engine.add_epoch_wrapper",
        rust_file="src/arc/engine.rs",
        rust_symbol="add_epoch_wrapper",
        coq_model="ArcStateMachineCompleteness",
        obligation="Rust add_epoch_wrapper must refine rewrap and epoch-wrapper state-machine rules.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="engine.rotate_epoch",
        rust_file="src/arc/engine.rs",
        rust_symbol="rotate_epoch",
        coq_model="ArcStateMachineCompleteness",
        obligation="Rust rotate_epoch must strictly advance epoch state.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="engine.rotate_epoch_full",
        rust_file="src/arc/engine.rs",
        rust_symbol="rotate_epoch_full",
        coq_model="ArcStateMachineCompleteness",
        obligation="Rust rotate_epoch_full must preserve authority transition and transparency linkage obligations.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="capability_tree.proofs",
        rust_file="src/arc/capability_tree.rs",
        rust_symbol="proof",
        coq_model="ArcMerkleTransparencyCompleteness",
        obligation="Rust capability tree proof logic must refine Coq Merkle membership and revocation models.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
    MechanicalTarget(
        id="transparency.append",
        rust_file="src/arc/transparency.rs",
        rust_symbol="append",
        coq_model="ArcTransparencyAppendOnly",
        obligation="Rust transparency append or equivalent log extension logic must refine Coq append-only behavior.",
        harness_level="MechanicallyHarnessed",
        mechanically_checked=False,
        mechanically_proven=False,
    ),
)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def symbol_present(source: str, symbol: str) -> bool:
    if not source:
        return False

    candidates = (
        symbol,
        f"fn {symbol}",
        f"pub fn {symbol}",
        f"struct {symbol}",
        f"pub struct {symbol}",
        f"enum {symbol}",
        f"pub enum {symbol}",
        f"type {symbol}",
        f"pub type {symbol}",
        f"trait {symbol}",
        f"pub trait {symbol}",
    )

    return any(candidate in source for candidate in candidates)


def build_inventory(targets: Iterable[MechanicalTarget]) -> list[MechanicalInventoryEntry]:
    entries: list[MechanicalInventoryEntry] = []

    for target in targets:
        source_path = PROJECT_ROOT / target.rust_file
        source = read_text(source_path)

        entries.append(
            MechanicalInventoryEntry(
                id=target.id,
                rust_file=target.rust_file,
                rust_symbol=target.rust_symbol,
                coq_model=target.coq_model,
                obligation=target.obligation,
                harness_level=target.harness_level,
                source_present=source_path.exists(),
                symbol_present=symbol_present(source, target.rust_symbol),
                mechanically_checked=target.mechanically_checked,
                mechanically_proven=target.mechanically_proven,
                boundary="Harnessed inventory only; not a proof of Rust behavioral equivalence.",
            )
        )

    return entries


def main() -> int:
    entries = build_inventory(TARGETS)

    payload = {
        "schema": "arc.rust_mechanical_refinement_inventory.v1",
        "generated_by": "scripts/refinement/generate_mechanical_refinement_inventory.py",
        "boundary": "Mechanical refinement harness inventory; mechanically_checked and mechanically_proven remain false until a verifier or proof-producing pipeline is attached.",
        "target_count": len(entries),
        "source_present_count": sum(1 for entry in entries if entry.source_present),
        "symbol_present_count": sum(1 for entry in entries if entry.symbol_present),
        "mechanically_checked_count": sum(1 for entry in entries if entry.mechanically_checked),
        "mechanically_proven_count": sum(1 for entry in entries if entry.mechanically_proven),
        "entries": [asdict(entry) for entry in entries],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Wrote {OUTPUT_PATH}")
    print(f"Targets: {payload['target_count']}")
    print(f"Sources present: {payload['source_present_count']}")
    print(f"Symbols present: {payload['symbol_present_count']}")
    print(f"Mechanically checked: {payload['mechanically_checked_count']}")
    print(f"Mechanically proven: {payload['mechanically_proven_count']}")

    missing = [entry for entry in entries if not entry.symbol_present]
    if missing:
        print("Missing or weakly detected symbols:")
        for entry in missing:
            print(f"- {entry.id}: {entry.rust_file}::{entry.rust_symbol}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
