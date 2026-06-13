# Kyriotēs-CSK2 Context Hash Mechanical Refinement

## Status

    Tracked proof lane: complete
    Mechanically checked: yes
    Verifier-backed Kani proof evidence: yes

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

## Target

    src/kyriotes_csk2/model.rs::context_hash

## Completed Proof Boundary

context_hash has verifier-backed Kani proof evidence for the transcript-model binding lane: determinism for equal inputs, epoch binding, policy-hash binding, authority-root binding, capability-stamp binding, and fixed 32-byte output size.

The production-function harnesses in `src/kani/kani_context_hash_production_equivalence.rs` call `context_hash` directly:

- `context_hash_is_deterministic_for_equal_inputs` — equal inputs produce equal output
- `context_hash_distinguishes_policy_hash_inputs` — differing policy_hash bytes produce distinct hashes
- `context_hash_distinguishes_epoch_inputs` — differing epoch values produce distinct hashes
- `context_hash_distinguishes_authority_root_inputs` — differing authority_root bytes produce distinct hashes
- `context_hash_distinguishes_capability_stamp_inputs` — differing cap_stamp bytes produce distinct hashes
- `context_hash_output_is_always_32_bytes` — output length is always 32

These harnesses back the `rust_context_hash_binding_holds` axiom in `KyriotesCsk2RustCoqFormalCorrespondence.v`.

This is an implementation-level refinement lane within a narrowed model boundary. It is not a full proof of SHA preimage/collision properties or full protocol-level context semantic equivalence.
