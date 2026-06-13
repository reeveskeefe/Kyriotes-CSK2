# Kyriotēs-CSK2 encode_kyriotes_csk2_object Mechanical Refinement

## Status

    Tracked proof lane: complete
    Mechanically checked: yes
    Verifier-backed Kani proof evidence: yes

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

## Target

    src/encoding/codec.rs::encode_kyriotes_csk2_object

## Completed Proof Boundary

encode_kyriotes_csk2_object has verifier-backed Kani proof evidence for selected encoding surface stability: determinism for equal input, non-empty output, Kyriotēs-CSK2 magic prefix stability, version-one layout stability, and object-id binding.

The production-function round-trip harnesses in `src/kani/kani_encode_kyriotes_csk2_object_equivalence.rs` call both `encode_kyriotes_csk2_object` and `decode_kyriotes_csk2_object` directly:

- `encode_decode_roundtrip_preserves_semantic_fields` — all semantic fields survive a round-trip unchanged
- `encode_decode_roundtrip_is_idempotent` — re-encoding a decoded object produces identical bytes
- `encode_decode_roundtrip_binds_rights` — required_rights bits survive a round-trip
- `encode_decode_roundtrip_binds_seal_epoch` — seal_epoch value survives a round-trip
- `encode_decode_roundtrip_binds_policy_hash` — policy_hash bytes survive a round-trip

These harnesses back the `rust_encode_decode_roundtrip_holds` axiom in `KyriotesCsk2RustCoqFormalCorrespondence.v`.

The separate seal/open serialization expansion now records scoped evidence that objects produced by seal encode and decode back to the same semantic object. See [SEAL_OPEN_ENCODE_DECODE_ROUNDTRIP.md](SEAL_OPEN_ENCODE_DECODE_ROUNDTRIP.md). Full arbitrary-byte grammar equivalence and exhaustive canonicality over the unbounded object space remain outside both narrow claims.
