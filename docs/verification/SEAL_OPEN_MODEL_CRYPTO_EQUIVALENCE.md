# Seal/Open Model-Crypto Equivalence Expansion

## Status

    Verification expansion lane: active
    Coq proof artifact: added and wired
    Verifier-backed Kani proof evidence: yes
    Tracked Rust mechanical inventory impact: none

ARC's tracked Rust mechanical refinement inventory remains complete at 11 / 11 verifier-backed proof lanes. This document records the first deeper verification-expansion lane beyond that tracked inventory.

## Proof Claim

Under the deterministic model crypto backend assumptions, sealing a message and opening the resulting object with matching recipient, capability binding, proof binding, and authority-state binding returns the original message. Defined tampering cases fail before plaintext recovery.

This is a model-crypto equivalence proof. It is not a proof of X25519, ML-KEM, ChaCha20Poly1305, HKDF, SHA, or concrete Merkle security.

## Coq Artifact

    proofs/coq/rust_refinement/ArcSealOpenModelCryptoEquivalence.v

The Coq lane models seal/open monolithically over deterministic symbolic operations:

    model_seal
    model_open
    model_encrypt_payload
    model_decrypt_payload
    model_wrap_dek
    model_unwrap_dek

The shared symbolic binding covers object id, rights, policy hash, epoch, authority root, revocation root, transparency root, capability stamp, and temporal policy.

The central theorem is:

    model_open_after_model_seal_returns_message

The negative theorems cover wrong recipient secret, altered object id, altered policy hash, altered capability stamp, altered authority root, altered payload ciphertext, altered wrapper binding, and wrong epoch/wrapper selection.

## Kani Artifact

    src/kani/kani_seal_open_model_crypto_equivalence.rs

The Kani lane mirrors the Coq model with fixed-size deterministic model key material, structured model ciphertexts, explicit binding digests, and deterministic rejection on mismatch. It is independent of ARC's production crypto primitives.

Representative harnesses:

    model_crypto_seal_open_roundtrip_returns_message
    model_crypto_open_rejects_altered_context

Additional tamper harnesses cover the same rejection boundaries as the Coq negative theorems.

## Boundary

This expansion lane proves model-level seal/open semantic equivalence for one deterministic symbolic backend. It does not prove concrete cryptographic primitive security, production randomness behavior, side-channel resistance, real KEM encapsulation/decapsulation security, AEAD misuse resistance, HKDF soundness, SHA collision resistance, or full protocol-level cryptographic semantic equivalence.

The tracked Rust mechanical refinement inventory remains unchanged: 11 / 11 checked and 11 / 11 verifier-backed proven within the recorded narrow proof boundaries.
