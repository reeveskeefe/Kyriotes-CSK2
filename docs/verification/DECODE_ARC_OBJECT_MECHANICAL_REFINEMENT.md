# ARC decode_arc_object Mechanical Refinement

This document records the second Rust-to-Coq mechanical refinement target:

    src/encoding/codec.rs::decode_arc_object

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why decode_arc_object matters

decode_arc_object is a parser boundary. Parser boundaries are security-critical because malformed, truncated, oversized, or ambiguous inputs must be rejected safely.

This target is treated differently from a simple deterministic function such as context_hash.

## Parser-refinement categories

The refinement evidence covers these parser categories:

    malformed input rejection
    empty input rejection
    tiny input rejection
    truncation rejection
    oversized input rejection
    repeated garbage rejection
    deterministic rejection behavior
    round-trip category reserved for future valid-object vectors

## Current boundary

This pass checks parser-refinement evidence and rejection behavior.

It does not yet prove byte-level equivalence between the Rust parser and the Coq encoding model.

A future proof-producing pass should connect:

    Rust decode_arc_object
    Coq ArcEncodingProofs
    concrete byte grammar
    decode limits
    canonical encode/decode round trip
