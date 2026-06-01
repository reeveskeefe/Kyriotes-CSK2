# Kyriotēs-CSK2 open Mechanical Refinement

## Status

    Tracked proof lane: complete
    Mechanically checked: yes
    Verifier-backed Kani proof evidence: yes

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

## Target

    src/kyriotes_csk2/engine.rs::open_with_verifier

## Completed Proof Boundary

open_with_verifier has verifier-backed Kani proof evidence for fail-closed authority-verifier behavior: authority rejection propagation, deterministic rejection, rejection before capability validation can succeed, and invalid authority surface rejection without panic.

This lane proves selected implementation-level rejection behavior. Full recipient-key unwrap behavior, full AEAD/KEM cryptographic semantics, full wrapper-selection semantics, and full seal/verify/open round-trip equivalence remain outside this narrow proof claim.
