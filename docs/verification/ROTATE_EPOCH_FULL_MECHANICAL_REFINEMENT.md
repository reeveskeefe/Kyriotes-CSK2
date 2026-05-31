# ARC rotate_epoch_full Mechanical Refinement

This document records the ninth Rust-to-Coq mechanical refinement target:

    src/arc/engine.rs::rotate_epoch_full

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why rotate_epoch_full matters

rotate_epoch_full is the heavier authority rotation boundary. It should connect epoch rotation, authority state continuity, chain hash linkage, state root consistency, and transparency log behavior.

This target follows rotate_epoch because it extends the basic authority epoch transition into the full rotation path.

## rotate_epoch_full refinement categories

The refinement track covers:

    transparency log requirement
    previous authority state requirement
    next authority state requirement
    previous epoch requirement
    next epoch requirement
    strict epoch advance requirement
    epoch regression rejection
    same epoch rotation rejection
    authority root continuity requirement
    state root consistency requirement
    chain hash linkage requirement
    transparency commit linkage requirement
    future full rotation verify fixture

## Current mechanical check

This pass checks:

    rotate_epoch_full source surface
    rotate_epoch_full symbol presence
    expected API surface terms
    full epoch-rotation vector schema
    deterministic gate category inventory
    Coq status connection
    mechanical inventory checked status

## Boundary

This pass does not yet prove that Rust rotate_epoch_full is semantically equivalent to the Coq full authority rotation model.

A future proof-producing pass should connect:

    Rust rotate_epoch_full
    Coq ArcStateMachineCompleteness
    Coq ArcTransparencyAppendOnly
    Coq ArcMerkleTransparencyCompleteness
    concrete transparency log append
    previous AuthorityState
    next AuthorityState
    strict epoch advance
    authority root continuity
    state root consistency
    chain hash linkage
