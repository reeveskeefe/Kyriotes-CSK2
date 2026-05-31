# ARC Context Hash Mechanical Refinement

This document records the first Rust-to-Coq mechanical refinement target:

    src/arc/model.rs::context_hash

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why context_hash first

The context hash is deterministic, security-critical, and side-effect free. It binds ARC context material into a stable commitment surface used by the broader authorization and transcript model.

This makes it the right first implementation-level verification target.

## What is checked

The mechanical check layer verifies that:

    the Rust source file exists
    the context_hash Rust symbol exists
    deterministic refinement vectors are generated
    the vector schema is stable
    the vector count is non-zero
    every vector records a 32-byte hash expectation
    the Coq layer records the target as mechanically checked
    the Coq layer does not claim it is fully mechanically proven

## Boundary

This is stronger than symbol-only evidence.

It is still not a full Coq proof that the Rust implementation is definitionally equivalent to the Coq model.

That final step requires a proof-producing bridge, verifier-backed proof, extraction path, or a formalized Rust semantics path.
