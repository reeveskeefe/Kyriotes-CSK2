# Primitive Boundary

ARC proves composition and binding around the following primitives. It does not prove the primitive algorithms internally.

- **X25519**: key agreement correctness and security are inherited from the implementation and external specification.
- **ML-KEM**: encapsulation and decapsulation correctness and security are inherited from the implementation and external specification.
- **ChaCha20Poly1305**: AEAD confidentiality, integrity, round-trip behavior, and associated-data rejection are inherited from the implementation and external specification.
- **HKDF-SHA256**: KDF correctness, determinism, and domain separation are inherited from the implementation and external specification.
- **SHA-256**: hash correctness and preimage/collision-resistance assumptions are inherited from the implementation and external specification.

These assumptions support ARC's seal/open crypto semantic contract lane. They are not claims that ARC independently verifies the primitive cryptographic algorithms.
