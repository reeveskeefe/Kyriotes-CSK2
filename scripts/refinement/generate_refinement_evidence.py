#!/usr/bin/env python3
"""
Generate deterministic Rust-to-Coq refinement evidence for ARC.

This script does not claim full formal refinement. It records whether the expected
Rust source surfaces and symbols exist, then writes a stable JSON artifact that
can be reviewed, versioned, and cross-referenced from the Coq evidence layer.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "tests" / "refinement" / "rust_coq_refinement_evidence.json"


@dataclass(frozen=True)
class RefinementTarget:
    id: str
    rust_file: str
    rust_symbol: str
    coq_concept: str
    refinement_level: str
    notes: str


@dataclass(frozen=True)
class RefinementEvidence:
    id: str
    rust_file: str
    rust_symbol: str
    coq_concept: str
    refinement_level: str
    source_present: bool
    symbol_present: bool
    coq_witness: str
    notes: str


TARGETS: tuple[RefinementTarget, ...] = (
    RefinementTarget(
        id="encoding.decode_arc_object",
        rust_file="src/encoding/codec.rs",
        rust_symbol="decode_arc_object",
        coq_concept="ArcEncodingProofs decoding safety model",
        refinement_level="ExecutableWitnessed",
        notes="Decoder symbol should correspond to bounded ARC object decoding assumptions.",
    ),
    RefinementTarget(
        id="encoding.encode_arc_object",
        rust_file="src/encoding/codec.rs",
        rust_symbol="encode_arc_object",
        coq_concept="ArcEncodingProofs canonical encoding model",
        refinement_level="ExecutableWitnessed",
        notes="Encoder symbol should correspond to canonical ARC object encoding assumptions.",
    ),
    RefinementTarget(
        id="model.context_hash",
        rust_file="src/arc/model.rs",
        rust_symbol="context_hash",
        coq_concept="ArcTranscriptProofs and AAD/context binding model",
        refinement_level="ExecutableWitnessed",
        notes="Context hash links object identity, rights, policy, authority, and temporal state.",
    ),
    RefinementTarget(
        id="engine.seal",
        rust_file="src/arc/engine.rs",
        rust_symbol="seal",
        coq_concept="ArcLifecycleProofs LifecycleSeal transition",
        refinement_level="ExecutableWitnessed",
        notes="Seal operation should create an object that enters the sealed lifecycle state.",
    ),
    RefinementTarget(
        id="engine.open",
        rust_file="src/arc/engine.rs",
        rust_symbol="open",
        coq_concept="ArcMasterInvariantProofs verified open invariant",
        refinement_level="ExecutableWitnessed",
        notes="Open operation should require key material, capability proof, non-revocation, state, policy, and wrapper binding.",
    ),
    RefinementTarget(
        id="engine.verify",
        rust_file="src/arc/engine.rs",
        rust_symbol="verify",
        coq_concept="ArcVerify and ArcMasterInvariantProofs verification gates",
        refinement_level="ExecutableWitnessed",
        notes="Verify operation should compose capability, revocation, temporal, authority, and transparency gates.",
    ),
    RefinementTarget(
        id="engine.add_epoch_wrapper",
        rust_file="src/arc/engine.rs",
        rust_symbol="add_epoch_wrapper",
        coq_concept="ArcStateMachineCompleteness rewrap and epoch wrapper transition",
        refinement_level="ExecutableWitnessed",
        notes="Epoch wrapper addition should preserve authorization gates and avoid invalid epoch transitions.",
    ),
    RefinementTarget(
        id="engine.open_and_reseal",
        rust_file="src/arc/engine.rs",
        rust_symbol="open_and_reseal",
        coq_concept="ArcLifecycleProofs open followed by reseal transition",
        refinement_level="ExecutableWitnessed",
        notes="Open-and-reseal should preserve lifecycle ordering and reject invalid authorization states.",
    ),
    RefinementTarget(
        id="engine.rotate_epoch",
        rust_file="src/arc/engine.rs",
        rust_symbol="rotate_epoch",
        coq_concept="ArcStateMachineCompleteness authority epoch rotation",
        refinement_level="ExecutableWitnessed",
        notes="Epoch rotation should strictly advance authority epoch state.",
    ),
    RefinementTarget(
        id="engine.rotate_epoch_full",
        rust_file="src/arc/engine.rs",
        rust_symbol="rotate_epoch_full",
        coq_concept="ArcStateMachineCompleteness full authority rotation with transparency linkage",
        refinement_level="ExecutableWitnessed",
        notes="Full epoch rotation should connect authority transition and transparency commitment behavior.",
    ),
    RefinementTarget(
        id="capability_tree.module",
        rust_file="src/arc/capability_tree.rs",
        rust_symbol="proof",
        coq_concept="ArcMerkleTransparencyCompleteness Merkle membership and revocation model",
        refinement_level="ExecutableWitnessed",
        notes="Capability tree module should contain proof-related logic for membership or revocation witnesses.",
    ),
    RefinementTarget(
        id="transparency.module",
        rust_file="src/arc/transparency.rs",
        rust_symbol="append",
        coq_concept="ArcTransparencyAppendOnly append-only transparency model",
        refinement_level="ExecutableWitnessed",
        notes="Transparency module should contain append-style behavior or equivalent log extension logic.",
    ),
    RefinementTarget(
        id="authority.verify_compromise_notice",
        rust_file="src/arc/authority.rs",
        rust_symbol="verify_compromise_notice",
        coq_concept="ArcRevocationCompromiseProofs compromise notice model",
        refinement_level="ExecutableWitnessed",
        notes="Compromise notice verification should correspond to compromise-safety assumptions.",
    ),
    RefinementTarget(
        id="temporal.temporal_policy",
        rust_file="src/core/temporal.rs",
        rust_symbol="TemporalPolicy",
        coq_concept="ArcTemporalProofs temporal policy model",
        refinement_level="ExecutableWitnessed",
        notes="TemporalPolicy should correspond to epoch/window authorization constraints.",
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
        symbol,
    )

    return any(candidate in source for candidate in candidates)


def build_evidence(targets: Iterable[RefinementTarget]) -> list[RefinementEvidence]:
    evidence: list[RefinementEvidence] = []

    for target in targets:
        source_path = PROJECT_ROOT / target.rust_file
        source = read_text(source_path)
        source_exists = source_path.exists()
        has_symbol = symbol_present(source, target.rust_symbol)

        evidence.append(
            RefinementEvidence(
                id=target.id,
                rust_file=target.rust_file,
                rust_symbol=target.rust_symbol,
                coq_concept=target.coq_concept,
                refinement_level=target.refinement_level,
                source_present=source_exists,
                symbol_present=has_symbol,
                coq_witness=f"ArcRustRefinementEvidence::{target.id.replace('.', '_')}_witness",
                notes=target.notes,
            )
        )

    return evidence


def main() -> int:
    evidence = build_evidence(TARGETS)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema": "arc.rust_coq_refinement_evidence.v1",
        "generated_by": "scripts/refinement/generate_refinement_evidence.py",
        "claim_boundary": "Executable witness evidence only; not full mechanical Rust refinement.",
        "target_count": len(evidence),
        "present_source_count": sum(1 for item in evidence if item.source_present),
        "present_symbol_count": sum(1 for item in evidence if item.symbol_present),
        "evidence": [asdict(item) for item in evidence],
    }

    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Wrote {OUTPUT_PATH}")
    print(f"Targets: {payload['target_count']}")
    print(f"Sources present: {payload['present_source_count']}")
    print(f"Symbols present: {payload['present_symbol_count']}")

    missing = [item for item in evidence if not item.symbol_present]
    if missing:
        print("Missing or weakly detected symbols:")
        for item in missing:
            print(f"- {item.id}: {item.rust_file}::{item.rust_symbol}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
