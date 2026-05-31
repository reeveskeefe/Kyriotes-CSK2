# ARC verify Mechanical Refinement

This document records the fourth Rust-to-Coq mechanical refinement target:

    src/arc/engine.rs::verify

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why verify matters

verify is the first implementation boundary that connects ARC's Rust behavior to the authorization gate model proven in Coq.

It sits between parsing/encoding and open/decryption behavior.

Before open can be treated as mechanically checked, verify should have its own refinement track.

## Verification-gate categories

The verify refinement track covers these intended gate categories:

    valid object requirement
    valid capability requirement
    valid capability proof requirement
    valid authority state requirement
    valid transparency proof requirement
    non-revocation requirement
    temporal policy requirement
    transcript and wrapper binding requirement
    deterministic rejection behavior
    no-open-before-verify boundary

## Current mechanical check

This pass checks:

    verify source surface
    verify symbol presence
    expected five-argument API shape
    verification gate vector schema
    deterministic gate category inventory
    Coq status connection
    mechanical inventory checked status

## Boundary

This pass does not yet prove that Rust verify is semantically equivalent to the Coq verify model.

A future proof-producing pass should connect:

    Rust verify
    Coq ArcVerify
    Coq ArcMasterInvariantProofs
    actual Capability, CapabilityProof, AuthorityState, and TransparencyProof values
    valid acceptance and invalid rejection equivalence
