# ARC Full Mechanical Proof Equivalence Plan

ARC has completed the checked-target phase for all declared Rust-to-Coq refinement targets.

The next phase is full mechanical proof equivalence.

## Current State

    Mechanically checked targets: 11 / 11
    Mechanically proven targets: 0 / 11

## Meaning of Full Mechanical Proof Equivalence

A target becomes mechanically proven only when actual Rust behavior is checked against a formal obligation by a repeatable verifier-backed or proof-producing path.

This is stronger than:

    source-symbol detection
    vector schema checking
    deterministic witness generation
    parser rejection tests
    Coq checklist closure
    mechanical refinement harness closure

## First Target

The first target is:

    src/arc/model.rs::context_hash

Reason:

    it is deterministic
    it is side-effect free
    it is security-critical
    it binds ARC context material
    it is simpler than verify, seal, open, or transparency behavior

## Proof Strategy

The first proof path should establish:

    context_hash always returns 32 bytes
    equal inputs produce equal outputs
    changed object identity changes the modeled transcript input
    changed rights changes the modeled transcript input
    changed policy hash changes the modeled transcript input
    changed authority root changes the modeled transcript input
    changed epoch changes the modeled transcript input
    changed temporal policy changes the modeled transcript input

The first verifier-backed lane is Kani-oriented.

If Kani is installed, the proof script should run the Kani harness.

If Kani is not installed, the gate must remain open and must not mark the target proven.

## Boundary

This phase may mark a target as mechanically proven only when:

    the verifier command succeeds
    the proof artifact is recorded
    the inventory marks the target mechanically_proven = true
    the Coq full-proof status imports that result

Until that happens, the full proof equivalence gate remains open.
