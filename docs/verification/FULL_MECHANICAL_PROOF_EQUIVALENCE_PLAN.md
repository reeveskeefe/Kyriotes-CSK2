# Tracked Rust Mechanical Proof Inventory: Complete

Kyriotēs-CSK2's tracked Rust mechanical refinement inventory is complete at 11 / 11 verifier-backed proof lanes, with each lane scoped and recorded by explicit proof-boundary language.

The tracked Rust mechanical refinement inventory is now complete. All 11 declared targets have mechanical check coverage and verifier-backed Kani proof evidence within their recorded proof boundaries. These proof lanes cover bounded parser rejection, encoding surface stability, context transcript binding, fail-closed engine behavior, epoch transition structure, transparency commit failure boundaries, transparency-root state binding, and selected capability-tree non-revocation behavior.

This milestone should not be read as full end-to-end cryptographic verification of Kyriotēs-CSK2. Several completed lanes intentionally prove narrowed implementation properties rather than full protocol semantics. Transparency/Merkle owned-composition soundness is complete under explicit SHA-256 assumptions; SHA-256 itself is not internally proven. Capability-tree non-empty witness soundness is mechanically refined within a scoped proof boundary. Encode/decode canonical round-trip equivalence is now evidenced by production-function Kani harnesses and the Coq axiom-backed correspondence layer in `KyriotesCsk2RustCoqFormalCorrespondence.v`. Seal/open cryptographic semantic equivalence has been mechanically formalized in that file via model contracts, mechanically proven implications, and Kani-backed axioms. Remaining future targets are extending capability-tree witness refinement into a computational binding reduction and adding concrete advantage accounting to the seal/open composition claims.

## Completed Inventory Meaning

All tracked Rust mechanical refinement targets are verifier-backed proven within their stated narrow proof boundaries.

This is stronger than:

    source-symbol detection
    vector schema checking
    deterministic witness generation
    parser rejection tests
    Coq checklist closure
    mechanical refinement harness closure

It is still narrower than full cryptographic semantic equivalence across the entire Kyriotēs-CSK2 protocol.

## Next Verification Expansion Targets

1. (Complete) Transparency append and Merkle owned-composition soundness: complete under explicit SHA-256 assumptions; preserve CI evidence per release.
2. (Complete within scoped boundary) Capability-tree non-empty witness refinement complete; extending into full Merkle-path computational soundness remains open.
3. (Complete) Seal/open encode/decode round-trip preservation for recorded seal-produced objects: complete within the scoped expansion lane.
4. Exhaustive encode/decode canonical equivalence over arbitrary bytes and the unbounded object space.
5. (Complete — formalized) Seal/open crypto semantic contracts over explicit AEAD/KEM/HKDF/SHA assumptions are formalized in `KyriotesCsk2RustCoqFormalCorrespondence.v` via model contracts and Kani-backed axioms; the two-gate hybrid reduction is formalized in `KyriotesCsk2TwoGateHybridReduction.v`. Concrete advantage accounting and full production end-to-end proof remain open.
