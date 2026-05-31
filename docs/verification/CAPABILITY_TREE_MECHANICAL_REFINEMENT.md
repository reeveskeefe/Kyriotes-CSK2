# ARC capability_tree Mechanical Refinement

This document records the tenth Rust-to-Coq mechanical refinement target:

    src/arc/capability_tree.rs

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why capability_tree matters

The capability tree is the Merkle-style authorization proof boundary for ARC. It is security-sensitive because membership, revocation, non-revocation, sibling ordering, root binding, and proof tampering directly affect whether a capability is accepted or rejected.

This target comes after the engine lifecycle and epoch-rotation targets because capability-tree proof behavior is one of the remaining low-level authorization proof surfaces.

## capability_tree refinement categories

The refinement track covers:

    capability proof surface
    membership proof surface
    revocation witness surface
    non-revocation witness surface
    Merkle sibling/path terminology
    root mismatch rejection track
    tampered proof rejection track
    sibling ordering track
    empty proof rejection track
    valid proof fixture reserved

## Current mechanical check

This pass checks:

    capability_tree source surface
    capability_tree proof terminology
    Merkle/path/root/sibling surface terms
    capability tree vector schema
    deterministic gate category inventory
    Coq status connection
    mechanical inventory checked status

## Boundary

This pass does not yet prove that Rust capability_tree behavior is semantically equivalent to the Coq concrete Merkle/capability model.

A future proof-producing pass should connect:

    Rust capability_tree proof verification
    Coq ArcConcreteMerkleProofs
    Coq ArcMerkleConcreteTree
    Coq ArcMerkleTransparencyCompleteness
    concrete membership proofs
    concrete non-revocation witnesses
    root mismatch rejection
    sibling-order preservation
