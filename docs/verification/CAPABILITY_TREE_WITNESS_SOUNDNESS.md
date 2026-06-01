# Capability Tree Witness Soundness

## Status

    Verification expansion lane: active
    Coq model artifact: added and wired
    Kani model harnesses: added and wired
    Production API impact: none
    Tracked Rust mechanical inventory impact: none

ARC's tracked Rust mechanical refinement inventory remains complete at 11 / 11 verifier-backed proof lanes. This document records a deeper expansion lane for capability-tree non-empty witness and binding soundness.

## Claim

If ARC accepts a modeled capability proof and non-revocation witness against an authority root and revocation root, then the accepted witness binds the claimed subject, rights, policy hash, capability leaf, authority root, and non-revoked state.

## Boundary

This is a deterministic model lane for ARC-owned witness binding logic. It does not prove SHA-256, production Merkle collision resistance, or full production capability-tree semantic equivalence.

The lane strengthens the previous capability-tree inventory item, which covered selected empty-set non-revocation behavior. It does not change the 11 / 11 Rust mechanical inventory count.

## Coq Artifact

    proofs/coq/rust_refinement/ArcCapabilityTreeWitnessSoundness.v

The Coq model defines:

    CapabilityClaim
    Capability
    ModelMerklePath
    CapabilityWitness
    capability_leaf_hash
    compute_root
    revocation_root_for
    accepts_capability_witness

The main theorem is:

    capability_tree_witness_soundness

It proves that acceptance implies non-empty witness structure, claim-field binding, non-revocation, capability leaf binding, authority-root binding, and revocation-root binding.

The file also proves named rejection/acceptance cases for:

    valid non-revoked witness acceptance
    empty witness rejection
    wrong subject rejection
    wrong rights rejection
    wrong policy-hash rejection
    wrong authority-root rejection
    revoked capability rejection
    tampered leaf rejection
    deterministic rejection for equal invalid inputs

## Kani Artifact

    src/kani/kani_capability_tree_witness_soundness.rs

The Kani harness mirrors the Coq model with fixed-size symbolic data and deterministic bounded paths. It proves:

    capability_tree_witness_soundness_acceptance_implies_claim_binding
    capability_tree_valid_non_revoked_witness_accepts
    capability_tree_empty_witness_rejects
    capability_tree_wrong_subject_rejects
    capability_tree_wrong_rights_rejects
    capability_tree_wrong_policy_hash_rejects
    capability_tree_wrong_authority_root_rejects
    capability_tree_revoked_capability_rejects
    capability_tree_rejection_is_deterministic_for_equal_invalid_inputs

## Wiring

The Coq file is listed in:

    proofs/coq/_CoqProject
    proofs/coq/check.sh

The Kani file is registered in:

    src/kani/mod.rs

## Next Work

The next strengthening step is to connect this deterministic model to extracted production helper surfaces from `src/arc/capability_tree.rs`, then separately discharge the SHA/Merkle primitive boundary with external primitive assumptions or audited references.
