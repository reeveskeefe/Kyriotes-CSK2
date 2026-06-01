# Seal/Open AEAD + AAD Contract Discharge

## Status

    Verification expansion lane: active sub-lane
    Concrete Rust evidence: added
    Coq discharge evidence: recorded
    Production API impact: none
    Tracked Rust mechanical inventory impact: none

This lane discharges the AEAD and AAD-binding portion of the seal/open crypto semantic contract story. Kyriotēs-CSK2's tracked Rust mechanical refinement inventory remains unchanged at 11 / 11 verifier-backed proof lanes.

## Concrete Evidence

The concrete evidence lives in the private test module inside:

    src/kyriotes_csk2/engine.rs

The tests exercise the actual production helper functions:

    payload_encrypt
    payload_decrypt
    wrap_dek
    unwrap_dek
    payload_aad
    authority_aad

The tests check:

    payload AEAD encrypt/decrypt round trip
    payload AEAD rejection for ciphertext tamper
    payload AEAD rejection for wrong DEK, nonce, and AAD
    wrapped-DEK AEAD encrypt/decrypt round trip
    wrapped-DEK AEAD rejection for ciphertext tamper
    wrapped-DEK AEAD rejection for wrong KEK, nonce, and AAD
    payload AAD binding for object id, rights, policy hash, and seal epoch
    authority AAD binding for object id, policy hash, temporal policy, authority root, revocation root, transparency root, context hash, classical KEM ciphertext, and PQ KEM ciphertext

## Coq Evidence Record

The discharge status is recorded in:

    proofs/coq/rust_refinement/KyriotesCsk2SealOpenCryptoSemanticContracts.v

The key evidence record is:

    SealOpenAeadAadDischargeEvidence

The key theorem is:

    current_aead_roundtrip_and_aad_tamper_contracts_discharged

## Boundary

This does not prove ChaCha20Poly1305 itself. It discharges Kyriotēs-CSK2's concrete use of the AEAD API and AAD construction for the bounded contract cases above. The primitive's cryptographic security remains inherited from the primitive and its implementation, not proven in this repository.

## Remaining Seal/Open Contract Work

The remaining undischarged expansion targets are:

1. Concrete KEM encapsulation/decapsulation agreement evidence.
2. Concrete HKDF determinism and context separation evidence.
3. SHA/context-hash field-inclusion expansion beyond the existing transcript model.
4. Production-level composed seal/open harnesses covering real valid inputs and defined tampering cases.
