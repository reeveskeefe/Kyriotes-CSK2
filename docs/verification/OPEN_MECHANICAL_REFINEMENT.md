# ARC open Mechanical Refinement

This document records the sixth Rust-to-Coq mechanical refinement target:

    src/arc/engine.rs::open

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why open matters

open is the central authorization boundary for ARC. It is where key material, capability proof, authority state, non-revocation, temporal policy, wrapper binding, and object state must all line up before protected content can be opened.

This target comes after context_hash, decode_arc_object, encode_arc_object, verify, and seal because open depends on those earlier surfaces.

## Open refinement categories

The open refinement track covers:

    recipient secret key requirement
    ARC object requirement
    capability requirement
    capability proof requirement
    authority state requirement
    wrapper binding requirement
    temporal validity requirement
    non-revocation requirement
    fallible Result behavior
    no open without prior verification boundary
    future seal verify open round trip

## Current mechanical check

This pass checks:

    open source surface
    open symbol presence
    open API surface terms
    open authorization vector schema
    deterministic gate category inventory
    Coq status connection
    mechanical inventory checked status

## Boundary

This pass does not yet prove that Rust open is semantically equivalent to the Coq open/master invariant model.

A future proof-producing pass should connect:

    Rust open
    Coq ArcMasterInvariantProofs
    Coq ArcLifecycleProofs
    actual RecipientSecretKey behavior
    actual AEAD/KEM unwrap behavior
    actual wrapper selection
    actual seal -> verify -> open round trip
