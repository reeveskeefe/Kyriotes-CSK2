# ARC: Authenticated Routing Chain


<p align="center"><em>Capability routed Encryption</em></p>

<p align="center">

  <img src="ARCLogoRectangular.png" alt="The ARC logo">

</p>

ARC is an encryption scheme where opening ciphertext requires these two things to be true in order to safely decrypt:

**a)** correct key material  
**b)** valid, non-revoked authority capability proof

>This is currently an experiment. It still requires some public audit and verification. It is becomming something ready to be showcased and audited for the future. The issue is it needs to be proven before it can be sent off and battletested and reviewed. Until then, I do not reccomend using it in production environments. 


ARC seals bytes to an authority state (root, policy, rights, object, epoch, revocation), so decryption succeeds only when key possession and current authority are both cryptographically true.

## Core property

Traditional encryption works by decrypting if the key is valid. Whereas ARC in the core of the encryption mechanism will only decrypt if the key is valid AND capability proof is valid for this exact authority context


## Current architecture 

ARC uses a two-layer encryption design. The payload itself is encrypted with a fresh random 256-bit data encryption key, or DEK, using AEAD. That produces the encrypted payload. Separately, ARC binds access to the current authority state by deriving a key-encryption key, or KEK, from the recipient shared secret and the authority context for a specific epoch. That KEK is then used to wrap the DEK together with authority-associated data.

This means the ciphertext is not opened by key possession alone. A recipient must have both the right key material and a valid authority context for the object, policy, rights, epoch, and revocation state. Because only the small DEK wrapper is tied to the authority epoch, ARC can rewrap access for new epochs without re-encrypting the full payload.

## Threat-model honesty

ARC is designed for cases where possession of a key should not be enough on its own. The scheme is meant to reject key-only access when the matching authority proof is missing or no longer valid, reject authority-only access when the recipient does not have the right key material, prevent a capability for one object from being reused against another object, and block stale capability replay when the current-authority policy requires fresh authority state.

ARC is not a complete endpoint security system. It does not claim to protect against a recipient secret being compromised together with a valid capability, an already-authorized decryptor choosing to exfiltrate plaintext, compromise of the full threshold authority, or compromise of the machine after decryption
has succeeded.

## Status

ARC is a draft cryptographic construction and security model with ongoing hardening work. The implementation is built from standard primitives and patterns, including AEAD encryption, KDFs, Merkle commitments, signatures, KEM and hybrid KEM flows, transparency proofs, and threshold signatures.

## Rust development status

This repository includes the Rust package ARCencryption, which exposes the library crate arc_core in Rust code. Crate metadata and release checks are maintained for manual publishing by the maintainer. The implementation currently focuses on validating capabilities, checking authority state, enforcing temporal policy, encrypting payloads with fresh DEKs, wrapping those DEKs with HKDF-derived authority-bound KEKs, supporting epoch rewraps for current-authority opening, framing canonical transcripts and associated data, and exposing pluggable authority verifier interfaces.

The crate is organized around a small set of core modules. The ARC data model
and context hashing live in src/arc/model.rs, while src/arc/engine.rs contains the seal, open, and rewrap pipeline. Authority verification traits
and verifier implementations live in src/arc/verify.rs. Canonical encoding helpers are under src/encoding/codec.rs, and the common temporal policy, rights, and error types live under src/core/. The public crate surface is
collected through src/lib.rs.

## Local development commands

Use cargo test to run the test suite, cargo fmt to format the code, and
cargo clippy --all-targets --all-features -- -D warnings to run the strict
lint configuration used by CI.

## Test organization

The integration tests are grouped by behavior. Seal, open, and rewrap flows
are covered in tests/arc_flow.rs, while rejection and tamper scenarios are
covered in tests/arc_guards.rs. 

Shared test setup lives under
tests/helpers/, including authority-state fixtures, capability and prooffixtures, request builders, policy-hash helpers, and small scenario buildersfor composing expressive end-to-end cases.

