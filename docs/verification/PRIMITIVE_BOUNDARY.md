# Primitive Boundary

Kyriotēs-CSK2 proves composition and binding around cryptographic primitives. It does not prove the primitive algorithms internally.

This file records the primitive contracts assumed by the seal/open crypto semantic contract lane. These assumptions are external inputs to Kyriotēs-CSK2's proof story, not internally proven theorems.

## Implementation Surface

The current Rust implementation uses the following primitive crates:

- `x25519-dalek` for X25519.
- `ml-kem` for ML-KEM.
- `chacha20poly1305` for ChaCha20Poly1305 AEAD.
- `hkdf` with SHA-256 for HKDF-SHA256.
- `sha2` for SHA-256 transcript and tree hashing.

The verification lanes check Kyriotēs-CSK2's use of these APIs: agreement composition, context construction, associated-data construction, deterministic binding, and defined tamper rejection. They do not audit crate internals, prove constant-time behavior, prove randomness quality, or prove cryptanalytic hardness.

## Assumed Primitive Contracts

### X25519

Reference: [RFC 7748, Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748).

Kyriotēs-CSK2 assumes:

- X25519 scalar multiplication is implemented according to RFC 7748.
- For a matching recipient keypair and sender ephemeral key, both sides derive the same shared secret.
- Non-matching private/public key material does not satisfy the matching-key agreement contract used by seal/open.
- The implementation handles invalid or low-order public-key behavior according to its documented API contract.

Kyriotēs-CSK2 proves only that the resulting shared secret is consumed in the expected transcript-bound composition.

### ML-KEM

Reference: [NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final).

Kyriotēs-CSK2 assumes:

- ML-KEM key generation, encapsulation, and decapsulation are implemented according to FIPS 203.
- Encapsulation to a valid public encapsulation key and decapsulation with the matching decapsulation key produce the same shared secret except for the negligible decapsulation-failure behavior specified by ML-KEM.
- Invalid, mismatched, or tampered ciphertexts follow the implementation's specified rejection or implicit-failure behavior and do not satisfy the matching-ciphertext agreement contract.
- The shared secret has the intended length and distribution promised by the primitive contract.

Kyriotēs-CSK2 proves only that the ML-KEM output is combined with the classical component and context-bound derivation path in the intended way.

### HKDF-SHA256

Reference: [RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/rfc/rfc5869).

Kyriotēs-CSK2 assumes:

- HKDF extract and expand are implemented according to RFC 5869 with SHA-256 as the hash function.
- Equal input keying material, salt, and info produce equal output key material.
- Distinct domain/context inputs are computationally separated under the HKDF pseudorandomness assumption.
- Requested output lengths within the implementation's fixed bounds are produced correctly or rejected according to the API contract.

Kyriotēs-CSK2 proves only that the salt/info inputs include the intended seal/open context material and that context changes alter the derived binding surface.

### ChaCha20Poly1305

Reference: [RFC 8439, ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439).

Kyriotēs-CSK2 assumes:

- ChaCha20Poly1305 encryption and decryption are implemented according to RFC 8439's AEAD construction.
- Decryption with the same key, nonce, ciphertext, and associated data returns the encrypted plaintext.
- Changing ciphertext, authentication tag, key, nonce, or associated data causes authentication failure except with the primitive's stated forgery probability.
- Nonce uniqueness requirements are respected by the production seal/open construction.

Kyriotēs-CSK2 proves only that payload and DEK-wrapper AEAD calls receive the intended keys, nonces, ciphertexts, and associated data, and that defined tamper cases reject before plaintext recovery.

### SHA-256

Reference: [NIST FIPS 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

Kyriotēs-CSK2 assumes:

- SHA-256 is implemented according to FIPS 180-4.
- Equal byte transcripts hash to equal digests.
- Distinct transcripts are computationally collision-resistant under the SHA-256 collision-resistance assumption.
- Preimage and second-preimage resistance hold at the security level expected of SHA-256.

Kyriotēs-CSK2 proves only that transcript fields are included in the intended order and that selected context changes alter the hashed transcript surface. It does not prove SHA-256 collision resistance.

## Resulting Claim Boundary

Under the primitive contracts above, Kyriotēs-CSK2's seal/open proof lane supports the following scoped claim:

    seal/open cryptographic semantic equivalence holds under stated primitive contracts and recorded implementation-boundary evidence.

It does not support the following stronger claims:

    Kyriotēs-CSK2 proves X25519, ML-KEM, ChaCha20Poly1305, HKDF, or SHA-256 internally.
    Kyriotēs-CSK2 proves end-to-end cryptographic security without external primitive assumptions.
    Kyriotēs-CSK2 proves side-channel resistance or implementation audit results for dependency crates.

These assumptions support Kyriotēs-CSK2's seal/open crypto semantic contract lane. They are not claims that Kyriotēs-CSK2 independently verifies the primitive cryptographic algorithms.
