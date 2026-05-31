# ARC Context Hash Mechanical Refinement

## Status

    Tracked proof lane: complete
    Mechanically checked: yes
    Verifier-backed Kani proof evidence: yes

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

## Target

    src/arc/model.rs::context_hash

## Completed Proof Boundary

context_hash has verifier-backed Kani proof evidence for the transcript-model binding lane: determinism for equal inputs, epoch binding, policy-hash binding, and capability-stamp binding.

This is an implementation-level refinement lane within a narrowed model boundary. It is not a full proof of SHA preimage/collision properties or full protocol-level context semantic equivalence.
