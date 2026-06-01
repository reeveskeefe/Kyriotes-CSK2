# Kyriotēs-CSK2 capability_tree Mechanical Refinement

## Status

    Tracked proof lane: complete
    Mechanically checked: yes
    Verifier-backed Kani proof evidence: yes

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

## Target

    src/kyriotes_csk2/capability_tree.rs::verify_non_revocation

## Completed Proof Boundary

capability_tree.proofs has verifier-backed Kani proof evidence for verify_non_revocation empty-set witness behavior: empty revocation set acceptance under zero root, rejection under non-zero root, rejection when witness.total_revoked disagrees with the authenticated revocation_count, and deterministic acceptance/rejection for equal inputs.

Full Merkle path soundness, non-empty boundary witnesses, issuance-signature verification, and full capability-tree semantic equivalence remain outside this narrow proof claim.
