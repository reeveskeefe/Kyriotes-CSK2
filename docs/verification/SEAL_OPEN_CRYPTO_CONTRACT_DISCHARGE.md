# Seal/Open Crypto Contract Discharge

## Status

    Verification expansion lane: active sub-lane
    Concrete Rust evidence: added
    Coq discharge evidence: recorded
    Production API impact: none
    Tracked Rust mechanical inventory impact: none

This lane records concrete implementation evidence for the remaining seal/open crypto semantic contracts after the AEAD + AAD discharge. ARC's tracked Rust mechanical refinement inventory remains unchanged at 11 / 11 verifier-backed proof lanes.

## Concrete Evidence

The implementation evidence is split across:

    src/arc/engine.rs
    tests/arc_seal_open_crypto_semantic.rs

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

## Coq Evidence Record

The discharge status is recorded in:

    proofs/coq/rust_refinement/ArcSealOpenCryptoSemanticContracts.v

The key evidence record is:

    SealOpenConcreteDischargeEvidence

The key theorem is:

    current_kem_hkdf_context_and_production_contracts_discharged

## Boundary

This is concrete implementation evidence for ARC's use of the primitives and binding surfaces. It does not prove X25519, ML-KEM, ChaCha20Poly1305, HKDF, or SHA as cryptographic primitives. It also does not replace external primitive analysis or third-party implementation audits.

## Remaining Work

The remaining step for a stronger full seal/open story is to connect these concrete tests to stronger proof automation or external primitive proofs:

1. Kani-friendly extracted models for the concrete KEM/HKDF/context helper surfaces.
2. External primitive-security references for X25519, ML-KEM, ChaCha20Poly1305, HKDF, and SHA.
3. CI recording of the concrete discharge tests as named verification evidence.
