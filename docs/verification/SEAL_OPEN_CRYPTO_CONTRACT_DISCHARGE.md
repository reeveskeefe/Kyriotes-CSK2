# Seal/Open Crypto Contract Discharge

## Status

    Verification expansion lane: active sub-lane
    Concrete Rust evidence: added
    Coq discharge evidence: recorded
    Production API impact: none
    Tracked Rust mechanical inventory impact: none

This lane records concrete implementation evidence for the remaining seal/open crypto semantic contracts after the AEAD + AAD discharge. Kyriotēs-CSK2's tracked Rust mechanical refinement inventory remains unchanged at 11 / 11 verifier-backed proof lanes.

## Concrete Evidence

The implementation evidence is split across:

    src/kyriotes_csk2/engine.rs
    src/kani/kani_seal_open_helper_surface_equivalence.rs
    tests/kyriotes_csk2_seal_open_crypto_semantic.rs

CI records this evidence in the `Seal/open concrete Rust evidence` job. The job uploads the `seal-open-rust-evidence` artifact containing:

    crypto-contract-discharge-tests.log
    kyriotes-csk2-seal-open-crypto-semantic.log
    seal-open-rust-summary.md

The private engine tests cover:

    classical X25519 encapsulation/decapsulation agreement
    wrong classical recipient secret changing the recovered shared secret
    hybrid PQ KEM encapsulation/decapsulation agreement
    PQ KEM ciphertext tamper changing the recovered PQ shared secret
    hybrid secret determinism
    classical-only versus hybrid domain separation
    HKDF determinism
    HKDF separation by context hash, authority digest, and policy hash
    context_hash binding for object id, rights, policy hash, epoch, authority root, revocation root, transparency root, capability stamp, authority id, and temporal policy

The production composed tests cover:

    seal/open round trip returns the original message
    payload ciphertext tamper rejects
    wrapped DEK tamper rejects
    policy hash tamper rejects
    context hash tamper rejects
    classical KEM ciphertext tamper rejects
    PQ KEM ciphertext tamper rejects
    wrapper swapped from another object rejects
    missing epoch wrapper rejects
    wrong epoch wrapper rejects
    swapped capability proof rejects
    swapped authority state rejects
    stale transparency root rejects
    altered temporal policy rejects
    well-formed decoded object with policy tamper rejects
    well-formed decoded object with temporal-policy tamper rejects

The Kani helper-surface model records extracted boundary evidence for Kyriotēs-CSK2-owned composition helpers without relying on production crypto internals. It covers:

    context hash binding for transcript fields and capability stamp
    classical KEM agreement, wrong-secret rejection, and ciphertext-tamper rejection
    hybrid shared-secret binding to both classical and PQ shares
    HKDF/KEK determinism
    HKDF/KEK binding to context hash and authority digest
    authority AAD binding to context hash, classical KEM ciphertext, and PQ KEM ciphertext
    payload AAD binding to object identity, rights, policy hash, and seal epoch
    context-hash versus KEK domain separation

The seal/open serialization gap is covered by the separate scoped expansion lane:

    docs/verification/SEAL_OPEN_ENCODE_DECODE_ROUNDTRIP.md

That lane records production and Kani evidence that recorded seal-produced objects encode and decode back to the same semantic object.

## Coq Evidence Record

The discharge status is recorded in:

    proofs/coq/rust_refinement/KyriotesCsk2SealOpenCryptoSemanticContracts.v

CI compiles the Coq proof tree in the `Coq proof check` job by running:

    ./proofs/coq/check.sh

The job uploads the `coq-proof-check-evidence` artifact containing:

    coq-check.log
    coq-summary.md

The key evidence record is:

    SealOpenConcreteDischargeEvidence
    SealOpenKaniCompositionEvidence
    SealOpenHelperSurfaceEvidence

The evidence record now has a separate `concrete_production_extended_tamper_rejection_tests` flag for the wrapper/state/proof/temporal/well-formed-decode tamper cases.

The Coq bridge also links Kani composition evidence to explicit lemmas for Kyriotēs-CSK2-owned logic:

    owned_composition_evidence_implies_boundary_extraction
    owned_composition_evidence_implies_aad_binding_evidence
    owned_composition_evidence_implies_wrapper_selection_evidence
    owned_composition_evidence_implies_composed_roundtrip_and_tamper_evidence

These lemmas make the composition bridge less assumption-shaped by deriving local binding, wrapper-selection, round-trip, and tamper-rejection claims from recorded Rust/Kani evidence. Primitive security contracts remain external assumptions.

The helper-surface bridge adds:

    current_helper_surface_evidence_complete
    helper_surface_evidence_implies_kem_hkdf_context_boundaries
    current_helper_surface_evidence_implies_kem_hkdf_context_boundaries

These lemmas record the extracted Kani helper-model evidence for KEM agreement/rejection, HKDF/context binding, authority AAD binding, payload AAD binding, and helper-level domain separation.

The key theorem is:

    current_kem_hkdf_context_and_production_contracts_discharged
    current_owned_composition_evidence_complete

The bridge definitions for `crypto_contract_seal` and `crypto_contract_open` are constructive aliases over the model seal/open functions. The semantic round-trip theorem now depends on the model theorem directly instead of an abstract Coq axiom, and the tamper theorem is discharged by explicit case analysis over model-backed tamper cases.

## Boundary

This is concrete implementation evidence for Kyriotēs-CSK2's use of the primitives and binding surfaces. It does not prove X25519, ML-KEM, ChaCha20Poly1305, HKDF, or SHA as cryptographic primitives. It also does not replace external primitive analysis or third-party implementation audits.

For the explicit primitive assumptions and standards references used by this lane, see [PRIMITIVE_BOUNDARY.md](PRIMITIVE_BOUNDARY.md).

## Remaining Work

The remaining steps for a stronger full seal/open story are:

1. Exhaustive encode/decode canonical equivalence over arbitrary bytes and the unbounded object space.
2. Long-term retention or release attachment of CI evidence artifacts for audit packages.
3. Periodic review of [PRIMITIVE_BOUNDARY.md](PRIMITIVE_BOUNDARY.md) when primitive crates or standards references change.
