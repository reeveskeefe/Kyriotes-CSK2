# ARC add_epoch_wrapper Mechanical Refinement

This document records the seventh Rust-to-Coq mechanical refinement target:

    src/arc/engine.rs::add_epoch_wrapper

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why add_epoch_wrapper matters

add_epoch_wrapper is the rewrap/epoch-wrapper boundary. It is security-sensitive because an ARC object may gain an additional epoch wrapper only when the previous authorization state, next authorization state, capability proof, transparency proof, and recipient key material line up correctly.

This target comes after seal and open because wrapper addition depends on the sealed object lifecycle and the authorization model.

## add_epoch_wrapper refinement categories

The refinement track covers:

    recipient secret key requirement
    recipient public key requirement
    mutable ARC object requirement
    capability requirement
    capability proof requirement
    previous authority state requirement
    next authority state requirement
    transparency proof requirement
    epoch regression rejection
    wrapper binding preservation
    future rewrap round-trip fixture

## Current mechanical check

This pass checks:

    add_epoch_wrapper source surface
    add_epoch_wrapper symbol presence
    expected API surface terms
    epoch-wrapper vector schema
    deterministic gate category inventory
    Coq status connection
    mechanical inventory checked status

## Boundary

This pass does not yet prove that Rust add_epoch_wrapper is semantically equivalent to the Coq rewrap/epoch-wrapper model.

A future proof-producing pass should connect:

    Rust add_epoch_wrapper
    Coq ArcStateMachineCompleteness
    Coq ArcLifecycleProofs
    concrete old authority state
    concrete new authority state
    concrete wrapper addition
    no epoch regression
    wrapper binding preservation
