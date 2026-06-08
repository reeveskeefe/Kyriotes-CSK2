# Tracked Rust Mechanical Proof Inventory: Complete

Kyriotēs-CSK2's tracked Rust mechanical refinement inventory is complete at 11 / 11 verifier-backed proof lanes, with each lane scoped and recorded by explicit proof-boundary language.

The tracked Rust mechanical refinement inventory is now complete. All 11 declared targets have mechanical check coverage and verifier-backed Kani proof evidence within their recorded proof boundaries. These proof lanes cover bounded parser rejection, encoding surface stability, context transcript binding, fail-closed engine behavior, epoch transition structure, transparency commit failure boundaries, transparency-root state binding, and selected capability-tree non-revocation behavior.

This milestone should not be read as full end-to-end cryptographic verification of Kyriotēs-CSK2. Several completed lanes intentionally prove narrowed implementation properties rather than full protocol semantics. Transparency/Merkle owned-composition soundness is now complete under explicit SHA-256 assumptions; SHA-256 itself is not internally proven. Full capability-tree non-empty witness soundness, exhaustive encode/decode canonical equivalence over arbitrary bytes and the unbounded object space, and full seal/open cryptographic semantic equivalence remain future verification-expansion targets.

## Inventory Status

    Tracked targets: 11 / 11
    Mechanically checked: 11 / 11
    Verifier-backed proven: 11 / 11

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

The computational adversary model and reduction roadmap are maintained in [SECURITY_MODEL.md](SECURITY_MODEL.md). The 11 / 11 inventory concerns implementation-level refinement and must not be interpreted as completion of those computational reductions.

## What Complete Means

Mechanical refinement means an actual Rust implementation surface is checked against a formal or executable model obligation by a repeatable tool or proof harness.

For the current inventory, complete means every target currently listed in the Rust mechanical refinement inventory is:

    mechanically checked
    backed by Kani verifier evidence
    recorded with an explicit proof boundary

This does not mean Kyriotēs-CSK2 has full cryptographic semantic equivalence across the entire protocol. The completed milestone proves the tracked implementation-level refinement lanes within their stated scopes.

## Completed Proof Lanes

The completed tracked lanes are:

    decode_kyriotes_csk2_object bounded malformed-input rejection
    encode_kyriotes_csk2_object output stability and binding checks
    context_hash transcript-model binding checks
    verify_with_verifier fail-closed authority rejection behavior
    seal_with_verifier fail-closed authority rejection behavior
    open_with_verifier fail-closed authority rejection behavior
    add_epoch_wrapper_with_verifier fail-closed wrapper rejection behavior
    rotate_epoch extracted authority-state transition structure
    rotate_epoch_full extracted commit/finalization failure boundary
    bind_transparency_root_to_state structural state binding
    verify_non_revocation selected empty-set capability-tree behavior

## Next Verification Expansion Targets

1. Formalize the two-gate opening security game and reduction hybrids.
2. Complete the Merkle false-inclusion reduction to collision/second-preimage resistance.
3. Extend capability-tree witness refinement into a computational binding reduction.
4. Add concrete advantage accounting to seal/open composition claims.
5. Preserve all proof and verifier evidence per release.
