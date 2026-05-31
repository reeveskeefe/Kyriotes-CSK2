# ARC seal Mechanical Refinement

This document records the fifth Rust-to-Coq mechanical refinement target:

    src/arc/engine.rs::seal

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why seal matters

seal is the lifecycle operation that creates a protected ARC object. It is the natural next target after verify because open should not be checked before the object creation side of the lifecycle has its own refinement track.

## Seal refinement categories

The seal refinement track covers:

    recipient public key requirement
    message input requirement
    capability requirement
    capability proof requirement
    authority state requirement
    transparency proof requirement
    temporal policy requirement
    fallible Result behavior
    lifecycle seal transition
    future round-trip path into verify and open

## Current mechanical check

This pass checks:

    seal source surface
    seal symbol presence
    seal API surface terms
    seal lifecycle vector schema
    deterministic gate category inventory
    Coq status connection
    mechanical inventory checked status

## Boundary

This pass does not yet prove that Rust seal is semantically equivalent to the Coq lifecycle seal model.

A future proof-producing pass should connect:

    Rust seal
    Coq ArcLifecycleProofs
    Coq ArcMasterInvariantProofs
    actual ArcObject construction
    actual wrapper/context/transcript binding
    actual seal -> verify -> open round trip
