# ARC Rust Full Mechanical Proof Gate

ARC currently has:

    Abstract protocol invariant closure
    Coq design model closure
    State-machine closure
    Merkle/transparency model closure
    Symbolic crypto-reduction closure
    Rust-to-Coq executable evidence closure
    Rust mechanical refinement harness closure

This document defines the remaining gate:

    Rust-to-Coq full mechanical proof

## What Full Mechanical Proof Means

Full mechanical proof means the actual Rust implementation is checked against the Coq model or an equivalent formal specification by a repeatable proof-producing or verifier-backed pipeline.

This is stronger than:

    concept mapping
    executable witness evidence
    source symbol detection
    property testing
    fuzzing
    checklist closure

## Minimum Requirements

ARC cannot honestly mark full Rust-to-Coq mechanical proof complete until all of these are true:

    every required Rust refinement target has a mechanically checked result
    every required Rust refinement target has a mechanically proven or verifier-backed obligation
    the proof inventory reports mechanically_checked_count equal to target_count
    the proof inventory reports mechanically_proven_count equal to target_count
    the Coq full mechanical proof status file marks the proof list complete
    CI runs the proof gate and fails if the inventory is incomplete

## Acceptable Toolchains

Any of these may be used for the actual proof-producing layer:

    Kani
    Creusot
    Prusti
    Verus
    Rust extraction from a verified model
    proof-carrying generated Rust
    a custom Coq/Rust refinement artifact generator

## Current Status

The full mechanical proof gate is intentionally open.

That is the honest current status:

    Rust-to-Coq full mechanical proof: open

The gate exists so ARC cannot accidentally overclaim implementation-level verification.
