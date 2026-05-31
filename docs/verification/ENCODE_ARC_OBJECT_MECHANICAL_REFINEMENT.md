# ARC encode_arc_object Mechanical Refinement

This document records the third Rust-to-Coq mechanical refinement target:

    src/encoding/codec.rs::encode_arc_object

## Status

    Mechanically checked: yes
    Mechanically proven equivalent to Coq: not yet

## Why encode_arc_object matters

encode_arc_object is the natural companion to decode_arc_object. Together they define the ARC wire-format boundary.

For security, the encoder must eventually support a canonical round-trip refinement claim:

    decode_arc_object(encode_arc_object(object)) = object

for every valid ARC object covered by the formal model.

## Current mechanical check

This pass checks the encode target as a mechanical refinement surface and establishes the round-trip refinement track.

The current evidence covers:

    encoder source surface
    encoder symbol surface
    canonical-output obligation
    decode-pairing obligation
    round-trip fixture schema
    reserved valid-object fixture track
    Coq status connection
    inventory checked status

## Boundary

This pass does not yet prove byte-level encode/decode equivalence.

The next deeper pass should generate real valid ARC objects, encode them through Rust, decode them through Rust, and compare structural equality.

That future pass should then update the round-trip fixture category from reserved to active.
