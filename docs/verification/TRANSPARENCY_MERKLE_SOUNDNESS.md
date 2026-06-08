# Transparency/Merkle Soundness

## Status

    Verification expansion lane: added
    Coq artifact: added and wired
    Rust production helper bridge: added
    Kani helper evidence: added and wired
    Tracked Rust mechanical inventory impact: none

Kyriotēs-CSK2's tracked Rust mechanical refinement inventory remains complete at 11 / 11 verifier-backed proof lanes. This is a deeper expansion lane for transparency append behavior and Merkle-path soundness.

## Claim

Under the external SHA-256 ordered-node hash contract, this lane covers:

    ordered indexed Merkle-path verification
    generated proof/root agreement for every leaf in tested production tree sizes
    odd leaf handling through LONE_NODE_SENTINEL
    leaf, sibling, index, and root tamper rejection
    idempotent identical commits
    conflicting same-authority/same-epoch commit rejection
    historical proof regeneration after later appends
    append-only preservation of existing entries

## Boundary

This is not an internal proof of SHA-256 collision resistance, second-preimage resistance, or the `sha2` crate. Coq models the primitive boundary with an ordered injective node-hash contract. Rust tests and Kani verify Kyriotēs-CSK2-owned ordering, index progression, sentinel handling, commit behavior, and proof-generation/proof-verification agreement.

The computational false-inclusion and append-history forgery games are defined in [SECURITY_MODEL.md](SECURITY_MODEL.md). A completed computational reduction must construct a SHA-256 collision or second-preimage adversary from a successful Merkle forgery and record its advantage loss.

## Evidence

Coq:

    proofs/coq/merkle_transparency/KyriotesCsk2FullTransparencyMerkleSoundness.v

Production Rust:

    src/kyriotes_csk2/transparency.rs

Kani:

    src/kani/kani_transparency_merkle_soundness.rs

The production helper bridge covers `merkle_sibling_is_right`, `next_merkle_index`, `merkle_proof_for_index`, `merkle_root_from_proof`, and `verify_transparency_proof`.

The Coq artifact proves accepted-path root binding, left/right ordering, swapped-child rejection under the hash contract, append prefix preservation, append length growth, historical lookup preservation, conflicting commit rejection, and production evidence completeness.

Production regression tests exercise all leaf positions for tree sizes 1 through 9, odd-node sentinel use, tamper rejection, historical proof regeneration, idempotent commits, and conflicting commit rejection.

## Result

Kyriotēs-CSK2 now has a full owned-composition transparency/Merkle soundness lane under explicit SHA-256 primitive assumptions. SHA-256 and the `sha2` implementation remain external assumptions recorded in `PRIMITIVE_BOUNDARY.md`.
