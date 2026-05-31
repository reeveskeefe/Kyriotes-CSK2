# ARC Rust Mechanical Refinement Plan

ARC has a closed Coq model layer and an executable Rust-to-Coq evidence layer.

This document defines the next track: Rust-to-Coq mechanical refinement.

## Boundary

Mechanical refinement means an actual Rust implementation surface is checked against a formal model obligation by a repeatable tool or proof harness.

This is stronger than executable witness evidence.

Executable witness evidence says:

    The Rust symbol exists and is mapped to the Coq concept.

Mechanical refinement says:

    The Rust behavior is checked against a formal or executable refinement obligation.

## Current Mechanical Refinement Status

The current repository state introduces the mechanical-refinement harness and obligation inventory.

It does not yet claim that all Rust functions are mechanically proven equivalent to the Coq model.

## Mechanical Refinement Levels

ConceptMapped:

    A Rust symbol is mapped to a Coq concept.

ExecutableWitnessed:

    The Rust symbol is detected and recorded in deterministic evidence.

MechanicallyHarnessed:

    The Rust symbol is included in a repeatable mechanical-refinement harness.

MechanicallyChecked:

    The Rust symbol has an actual tool-checked refinement result.

MechanicallyProven:

    The Rust symbol is proven equivalent to the Coq model by a formal verification pipeline.

## Initial Toolchain Strategy

ARC should support a layered approach:

    Coq/Rocq for protocol model proofs
    Rust source scanner for symbol and obligation inventory
    Rust tests for deterministic refinement witnesses
    Property tests for input/output behavior
    Kani, Creusot, Prusti, or another Rust verifier for deeper function-level proofs
    CI scripts that fail when the refinement inventory becomes stale

## First Mechanical Targets

The first practical mechanical targets are:

    src/encoding/codec.rs::decode_arc_object
    src/encoding/codec.rs::encode_arc_object
    src/arc/model.rs::context_hash
    src/arc/engine.rs::verify
    src/arc/engine.rs::open
    src/arc/engine.rs::seal
    src/arc/engine.rs::add_epoch_wrapper
    src/arc/engine.rs::rotate_epoch
    src/arc/engine.rs::rotate_epoch_full
    src/arc/capability_tree.rs proof-related membership/revocation logic
    src/arc/transparency.rs append/lookup/conflict logic

## Completion Meaning

When this harness is complete, ARC may claim:

    Rust-to-Coq mechanical refinement harness: complete.

ARC may not yet claim:

    Rust implementation is fully mechanically proven equivalent to the Coq model.

That final claim requires function-level verifier results or a proof-producing extraction/refinement pipeline.
