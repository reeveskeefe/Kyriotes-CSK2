# ARC Rust-to-Coq Refinement Evidence Plan

ARC now has machine-checked Coq closure for the current abstract protocol, design-model, state-machine, Merkle/transparency, and symbolic crypto-reduction checklists.

This document defines the next verification layer: Rust-to-Coq refinement evidence.

## Purpose

The Coq model proves ARC's protocol rules at the abstract design level. Rust-to-Coq refinement evidence tracks how the actual Rust implementation relates to those Coq concepts.

This is not the same as full implementation-level formal verification.

The goal of this layer is to make each Rust implementation surface explicit, map it to the Coq model, and attach executable evidence that the Rust behavior matches the intended model behavior for deterministic witness cases.

## Refinement Levels

### ConceptMapped

The Rust symbol has a documented conceptual relationship to a Coq model concept.

Example:

    src/arc/engine.rs::open
    maps to
    Coq lifecycle open and master invariant gates

### ExecutableWitnessed

There is deterministic evidence generated from the repository that the Rust symbol exists, is tracked, and is covered by a refinement witness record.

This includes generated JSON evidence under:

    tests/refinement/rust_coq_refinement_evidence.json

### PropertyTested

The Rust symbol is covered by fuzz, property tests, or deterministic test vectors that exercise valid and invalid cases.

This is stronger than executable witness evidence, but still not a full proof.

### MechanicallyRefined

The Rust symbol is mechanically proven to refine the Coq model through a verification toolchain, extraction bridge, verified subset, or proof-carrying artifact.

This is the target state for full implementation-level verification.

## Current Boundary

ARC currently claims:

    Rust-to-Coq refinement evidence exists.

ARC does not yet claim:

    The Rust implementation is mechanically proven equivalent to the Coq model.

## Initial Refinement Targets

| Rust file | Rust symbol | Coq concept |
|---|---|---|
| src/encoding/codec.rs | decode_arc_object | encoding safety and object decoding model |
| src/encoding/codec.rs | encode_arc_object | canonical object encoding model |
| src/arc/model.rs | context_hash | context/AAD/transcript binding |
| src/arc/engine.rs | seal | lifecycle seal transition |
| src/arc/engine.rs | open | lifecycle open transition and master invariant |
| src/arc/engine.rs | verify | verification gate composition |
| src/arc/engine.rs | add_epoch_wrapper | rewrap/epoch wrapper transition |
| src/arc/engine.rs | open_and_reseal | open followed by reseal lifecycle transition |
| src/arc/engine.rs | rotate_epoch | authority epoch transition |
| src/arc/engine.rs | rotate_epoch_full | authority epoch transition with transparency state |
| src/arc/capability_tree.rs | capability tree verification | Merkle membership/revocation model |
| src/arc/transparency.rs | transparency append/lookup | append-only transparency model |
| src/arc/authority.rs | verify_compromise_notice | compromise notice validation model |
| src/core/temporal.rs | TemporalPolicy | temporal policy acceptance model |

## Evidence JSON

The refinement scanner writes:

    tests/refinement/rust_coq_refinement_evidence.json

Each entry contains:

    id
    rust_file
    rust_symbol
    coq_concept
    refinement_level
    source_present
    symbol_present
    coq_witness
    notes

## Coq Evidence Layer

The Coq evidence layer is:

    proofs/coq/ArcRustRefinementEvidence.v

It defines a checklist for the refinement evidence surface and proves that the current evidence layer is closed at the executable-witness level.

## CI Recommendation

A complete verification CI job should run:

    cargo test
    cargo +nightly fuzz build fuzz_decode_arc_object
    ./scripts/refinement/generate_refinement_evidence.py
    ./proofs/coq/check.sh

The evidence layer should be considered stale if Rust symbols change without updating the refinement evidence map.
