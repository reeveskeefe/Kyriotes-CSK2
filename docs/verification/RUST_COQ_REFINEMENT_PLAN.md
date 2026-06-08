# Kyriotēs-CSK2 Rust-to-Coq Refinement Evidence Plan

Kyriotēs-CSK2 now has machine-checked Coq closure for the current abstract protocol, design-model, state-machine, Merkle/transparency, and symbolic crypto-reduction checklists.

Kyriotēs-CSK2's tracked Rust mechanical refinement inventory is complete at 11 / 11 verifier-backed proof lanes, with each lane scoped and recorded by explicit proof-boundary language.

## Purpose

The Coq model proves Kyriotēs-CSK2's protocol rules at the abstract design level. Rust-to-Coq refinement evidence tracks how the actual Rust implementation relates to those Coq concepts.

Computational security claims are defined separately by [SECURITY_MODEL.md](SECURITY_MODEL.md). Refinement evidence establishes that implementation surfaces follow their models; it does not replace game-based reductions to primitive assumptions.

The tracked Rust mechanical refinement inventory is now complete. All 11 declared targets have mechanical check coverage and verifier-backed Kani proof evidence within their recorded proof boundaries. These proof lanes cover bounded parser rejection, encoding surface stability, context transcript binding, fail-closed engine behavior, epoch transition structure, transparency commit failure boundaries, transparency-root state binding, and selected capability-tree non-revocation behavior.

This milestone should not be read as full end-to-end cryptographic verification of Kyriotēs-CSK2. Several completed lanes intentionally prove narrowed implementation properties rather than full protocol semantics. Transparency/Merkle owned-composition soundness is now complete under explicit SHA-256 assumptions; SHA-256 itself is not internally proven. Full capability-tree non-empty witness soundness, exhaustive encode/decode canonical equivalence over arbitrary bytes and the unbounded object space, and full seal/open cryptographic semantic equivalence remain future verification-expansion targets.

## Refinement Levels

### ConceptMapped

The Rust symbol has a documented conceptual relationship to a Coq model concept.

Example:

    src/kyriotes_csk2/engine.rs::open
    maps to
    Coq lifecycle open and master invariant gates

### ExecutableWitnessed

There is deterministic evidence generated from the repository that the Rust symbol exists, is tracked, and is covered by a refinement witness record.

This includes generated JSON evidence under:

    tests/refinement/rust_coq_refinement_evidence.json

### PropertyTested

The Rust symbol is covered by fuzz, property tests, or deterministic test vectors that exercise valid and invalid cases.

This is stronger than executable witness evidence, but still not a full proof.

### MechanicallyRefined

The Rust symbol is mechanically checked by a repeatable verifier-backed or proof-producing path within a stated proof boundary.

For the current tracked Rust mechanical refinement inventory:

    Mechanically checked targets: 11 / 11
    Verifier-backed proven targets: 11 / 11

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

## Tracked Mechanical Targets

| Rust surface | Completed lane |
|---|---|
| src/encoding/codec.rs::decode_kyriotes_csk2_object | bounded malformed-input parser rejection |
| src/encoding/codec.rs::encode_kyriotes_csk2_object | selected encoding surface stability |
| src/kyriotes_csk2/model.rs::context_hash | transcript-model binding checks |
| src/kyriotes_csk2/engine.rs::verify_with_verifier | fail-closed authority rejection behavior |
| src/kyriotes_csk2/engine.rs::seal_with_verifier | fail-closed authority rejection behavior |
| src/kyriotes_csk2/engine.rs::open_with_verifier | fail-closed authority rejection behavior |
| src/kyriotes_csk2/engine.rs::add_epoch_wrapper_with_verifier | fail-closed wrapper rejection behavior |
| src/kyriotes_csk2/engine.rs::rotated_authority_state | extracted epoch transition structure |
| src/kyriotes_csk2/engine.rs::begin_epoch_rotation_commit | extracted rotate_epoch_full commit/finalization boundary |
| src/kyriotes_csk2/capability_tree.rs::verify_non_revocation | selected empty-set non-revocation behavior |
| src/kyriotes_csk2/transparency.rs::bind_transparency_root_to_state | extracted transparency-root state binding |

## Coq Evidence Layer

The Coq evidence layer is:

    proofs/coq/rust_refinement/KyriotesCsk2RustRefinementEvidence.v

It defines the refinement evidence surface and records the current executable evidence layer. The Rust mechanical refinement inventory closure is tracked separately by the generated refinement inventory and the Kani proof-status artifacts.

## CI Recommendation

A verification CI job should run:

    cargo test
    cargo +nightly fuzz build fuzz_decode_kyriotes_csk2_object
    ./scripts/refinement/generate_refinement_evidence.py
    ./proofs/coq/check.sh

The repository CI now includes a dedicated `Coq proof check` job for `./proofs/coq/check.sh` and uploads the `coq-proof-check-evidence` artifact containing the proof-check log and summary.

The evidence layer should be considered stale if Rust symbols change without updating the refinement evidence map.

## Next Verification Expansion Targets

1. Formalize the two-gate opening security game and reduction hybrids.
2. Complete the Merkle false-inclusion reduction to collision/second-preimage resistance.
3. Extend capability-tree witness refinement into a computational binding reduction.
4. Add concrete advantage accounting to seal/open composition claims.
5. Preserve all proof and verifier evidence per release.
