# ARC rotate_epoch Mechanical Refinement

This document records the eighth Rust-to-Coq mechanical refinement target:

    src/arc/engine.rs::rotate_epoch

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why rotate_epoch matters

rotate_epoch is the basic authority epoch transition boundary. It is security-sensitive because ARC authority state must move forward, never backward, and epoch transitions must preserve the chain of trust used by verification, sealing, opening, and rewrapping.

This target comes after add_epoch_wrapper because wrapper addition depends on valid authority epoch movement.

## rotate_epoch refinement categories

The refinement track covers:

    previous authority state requirement
    next authority state requirement
    previous epoch requirement
    next epoch requirement
    epoch strict-advance requirement
    epoch regression rejection
    same-epoch rotation rejection
    authority root continuity requirement
    chain hash linkage requirement
    future rotate to verify fixture

## Current mechanical check

This pass checks:

    rotate_epoch source surface
    rotate_epoch symbol presence
    expected API surface terms
    epoch-rotation vector schema
    deterministic gate category inventory
    Coq status connection
    mechanical inventory checked status

## Boundary

This pass does not yet prove that Rust rotate_epoch is semantically equivalent to the Coq authority state-machine model.

A future proof-producing pass should connect:

    Rust rotate_epoch
    Coq ArcStateMachineCompleteness
    Coq ArcAuthority
    previous AuthorityState
    next AuthorityState
    strict epoch advance
    authority root continuity
    chain hash linkage
