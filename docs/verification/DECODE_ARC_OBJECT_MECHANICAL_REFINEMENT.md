# ARC decode_arc_object Mechanical Refinement

## Status

    Tracked proof lane: complete
    Mechanically checked: yes
    Verifier-backed Kani proof evidence: yes

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

## Target

    src/encoding/codec.rs::decode_arc_object

## Completed Proof Boundary

decode_arc_object has verifier-backed Kani proof evidence for bounded malformed-input rejection: empty input rejection, one-byte rejection, two-byte rejection, tiny malformed rejection, bounded malformed rejection, and deterministic rejection for equal malformed input.

This lane proves parser-safety behavior for selected bounded invalid surfaces. Full byte-level parser equivalence, full decode grammar coverage, and canonical encode/decode round-trip equivalence remain outside this narrow proof claim.
