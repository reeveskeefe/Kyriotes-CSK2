# Seal/Open Encode/Decode Round-Trip Expansion

## Status

    Verification expansion lane: complete for recorded scope
    Constructive Coq structured codec: complete
    Coq Rust-evidence bridge: added and wired
    Kani bounded round-trip harnesses: added
    Production wire tests: added / reused
    Tracked Rust mechanical inventory impact: none

Kyriotēs-CSK2's tracked Rust mechanical refinement inventory remains complete at 11 / 11 verifier-backed proof lanes. This file records a deeper proof-expansion lane that closes the serialization gap for seal/open within the stated scope.

## Claim

For objects produced by `seal`, encoding the object with the production wire encoder and then decoding those bytes with the production wire decoder preserves the same semantic object.

In scoped form:

    decode_kyriotes_csk2_object(encode_kyriotes_csk2_object(seal(...))) = seal(...)

for the recorded seal/open object shapes and bounded Kani semantic-object fixtures.

## Evidence

The production Rust tests include:

    tests/kyriotes_csk2_wire.rs::sealed_object_encode_decode_roundtrip_preserves_semantic_object_for_temporal_policies
    tests/kyriotes_csk2_multi_wrapper.rs::wire_roundtrip_preserves_multi_wrapper_object

These cover seal-produced objects across all temporal policy shapes and a seal-produced object that has been rewrapped into a multi-wrapper object.

The Kani expansion harnesses use a bounded semantic wire model aligned to the object fields preserved by the production codec:

    src/kani/kani_encode_decode_roundtrip_equivalence.rs::encode_decode_roundtrip_preserves_minimal_semantic_object
    src/kani/kani_encode_decode_roundtrip_equivalence.rs::encode_decode_roundtrip_preserves_wrapper_semantic_object
    src/kani/kani_encode_decode_roundtrip_equivalence.rs::encode_decode_roundtrip_preserves_window_policy_semantic_object
    src/kani/kani_encode_decode_roundtrip_equivalence.rs::encode_decode_roundtrip_is_canonical_for_bounded_semantic_object

The Coq evidence bridge is:

    proofs/coq/rust_refinement/KyriotesCsk2EncodeDecodeRoundTripRustRefinement.v

It records the Rust/Kani evidence and proves:

    seal_open_serialization_gap_closed_for_current_scope

The constructive structured codec is:

    proofs/coq/lifecycle/KyriotesCsk2EncodingProofs.v

Its canonical encoder and bounded decoder are executable Coq definitions. The previous `Parameter` declarations and the three canonical-codec `Axiom` declarations have been removed. The file now proves:

    canonical_decode_correct
    canonical_decode_rejects_invalid_shape
    canonical_decode_rejects_noncanonical_shape
    canonical_encode_decode_roundtrip
    accepted_decode_implies_shape_valid_and_canonical
    accepted_decode_reencodes_exactly

## Boundary

This lane proves encode/decode preservation for recorded seal-produced objects using the production encoder and decoder, records bounded Kani semantic-wire preservation for the same object-field surface, and constructively proves canonicality for the structured Coq codec.

The Coq codec uses a symbolic structured magic tag and structured field metadata; the production literal `KCS2` bytes and byte-level layout remain covered by Rust tests and Kani evidence. This lane does not prove full arbitrary-byte Rust-to-Coq grammar equivalence, full parser completeness, or exhaustive canonicality over the unbounded production byte space. Malformed byte rejection and selected encode/decode surfaces remain covered by the narrower tracked mechanical lanes:

    DECODE_KYRIOTES_CSK2_OBJECT_MECHANICAL_REFINEMENT.md
    ENCODE_KYRIOTES_CSK2_OBJECT_MECHANICAL_REFINEMENT.md

This lane closes the serialization gap needed by the current seal/open semantic-equivalence story, without changing the 11 / 11 tracked Rust mechanical inventory count.
