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

This tracked lane does not prove full canonical encode/decode round-trip equivalence or byte-level semantic equivalence with the Coq encoding model.

The separate seal/open serialization expansion now records scoped evidence that objects produced by seal encode and decode back to the same semantic object. See [SEAL_OPEN_ENCODE_DECODE_ROUNDTRIP.md](SEAL_OPEN_ENCODE_DECODE_ROUNDTRIP.md). Full arbitrary-byte grammar equivalence and exhaustive canonicality over the unbounded object space remain outside both narrow claims.
