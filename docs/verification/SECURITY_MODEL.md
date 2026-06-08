# Kyriotēs-CSK2 Security Model

## Purpose

This document defines the computational security claims targeted by Kyriotēs-CSK2. It separates properties proved internally about Kyriotēs-CSK2-owned logic from cryptographic properties inherited through explicit primitive assumptions.

The intended claim structure is:

> Kyriotēs-CSK2 proves owned implementation/refinement and composition properties internally, while cryptographic security is stated as reduction-style claims under explicit primitive assumptions.

This document is a security-model specification and reduction roadmap. It does not by itself constitute completed machine-checked reductions.

## Adversary Model

The cryptographic games quantify over probabilistic polynomial-time adversaries. A game may give the adversary:

- Public parameters, authority public keys, recipient public keys, published authority states, transparency roots, and public capabilities.
- Chosen-message seal access where required by the security notion.
- Chosen-ciphertext or open-oracle access subject to the challenge restrictions of the game.
- Valid and invalid capability, wrapper, state, and transparency inputs.
- Control over transport, storage, replay, substitution, reordering, and malformed serialization.
- Compromise of selected recipient, epoch, or authority keys where the game explicitly permits it.

The model does not assume the adversary can break the primitive assumptions listed in [PRIMITIVE_BOUNDARY.md](PRIMITIVE_BOUNDARY.md). Side channels, implementation supply-chain compromise, randomness failure, denial of service, and unsafe host integration require separate models.

## Security Games

### Two-Gate Opening Security

The challenger seals a message for a recipient and an authorized capability context.

The adversary wins if it recovers the challenge plaintext, or produces an accepted equivalent opening, without satisfying both:

1. possession of the required recipient secret material; and
2. possession of an accepted capability and authority/transparency proof context.

Separate cases cover key-only and capability-only adversaries. The intended reduction target is a break of the hybrid KEM, HKDF/context separation, AEAD confidentiality or integrity, signature authenticity, capability soundness, or transparency binding.

### Capability Binding

The adversary wins if a capability accepted for one object, subject, rights set, policy hash, authority state, or epoch is accepted for a different bound context without authorization.

The reduction target is a signature forgery, hash collision or second preimage, Merkle binding failure, or a violation of the proved Kyriotēs-CSK2 transcript and verifier invariants.

### Revocation And Epoch Security

The adversary wins if a revoked capability, stale authority state, invalid epoch wrapper, or capability outside its epoch window is accepted.

The reduction target is a transparency/Merkle binding failure, authority-signature forgery, capability-tree soundness failure, or a violation of the proved epoch and temporal-policy checks.

### Ciphertext And Wrapper Non-Malleability

The adversary wins if it modifies or substitutes payload ciphertext, wrapped DEK material, KEM ciphertext, object identifiers, policy data, temporal policy, authority roots, or wrapper context and obtains accepted plaintext outside an authorized context.

The reduction target is AEAD integrity failure, KEM/HKDF context-separation failure, hash-binding failure, or a violation of the proved AAD and transcript construction.

### Rewrap Security

The adversary wins if rewrapping exposes plaintext or DEK material, grants access to an unauthorized recipient or epoch, weakens the original policy, or produces a wrapper accepted under a context not authorized by the rewrap transition.

The reduction target is AEAD/KEM/HKDF failure or a violation of the proved wrapper-selection, epoch-transition, policy, and context-binding invariants.

### Transparency And Merkle Soundness

The adversary wins if it produces an accepted inclusion or non-revocation proof for a leaf or state not committed by the authenticated root, or if it changes an earlier log entry while preserving an accepted append-only history.

Under collision and second-preimage resistance of the domain-separated SHA-256 node construction, the intended reduction maps such a forgery to a hash collision/second preimage or to a violation of the internally proved ordered-path and append-only composition logic.

## Primitive Assumptions

The security reductions may rely on:

- X25519 agreement and the selected computational hardness assumptions.
- ML-KEM correctness and IND-CCA security under the assumptions underlying FIPS 203.
- Security of the classical/post-quantum hybrid combiner used by Kyriotēs-CSK2.
- HKDF-SHA256 extraction, expansion, pseudorandomness, and context separation.
- ChaCha20Poly1305 AEAD confidentiality and ciphertext integrity.
- Ed25519 EUF-CMA signature security.
- SHA-256 collision resistance, second-preimage resistance, and preimage resistance.
- Random-oracle modeling only for the specific reductions that explicitly declare it.

The project must not silently mix random-oracle and standard-model claims. Each completed reduction must state its model and advantage bound.

## Reduction Obligations

A completed reduction should identify:

1. The exact Kyriotēs-CSK2 game and winning event.
2. The constructed primitive adversary.
3. Oracle simulation and challenge embedding.
4. Abort conditions and probability loss.
5. Hybrid transitions between the real and ideal games.
6. The resulting concrete or asymptotic advantage bound.
7. Every external assumption and whether the proof uses the standard model or random-oracle model.

The target theorem shape is:

    Adv_Kyriotes(A)
      <= Adv_AEAD(B1)
       + Adv_KEM(B2)
       + Adv_KDF(B3)
       + Adv_SIG(B4)
       + Adv_HASH(B5)
       + implementation/refinement failure probability

The exact terms depend on the game. They must not be included when irrelevant, and concrete multiplicative factors from oracle queries or hybrid steps must be recorded.

## Verification Layers

### Internal Proof Layer

Coq proves protocol invariants, constructive models, encoding and transcript properties, state transitions, Merkle composition, and reduction scaffolding.

Kani proves bounded Rust implementation helper contracts and selected refinement obligations.

Rust tests and fuzzing provide integration, tamper, parser, and state-machine evidence.

### Computational Proof Layer

Game-based proofs establish that winning a Kyriotēs-CSK2 security game yields an adversary against an assumed primitive. EasyCrypt is the preferred candidate for mechanized game hopping and advantage accounting; Coq remains suitable when the reduction infrastructure is developed there.

### External Assurance Layer

Primitive standards, dependency audits, cryptographic review, side-channel analysis, randomness review, and release evidence retention remain external assurance inputs.

## Claim Discipline

Acceptable:

> Under the stated primitive assumptions, Kyriotēs-CSK2's owned composition and binding logic satisfies the specified security game, subject to the recorded reduction and implementation-refinement boundaries.

Not acceptable:

> Kyriotēs-CSK2 is unconditionally secure.

Not acceptable:

> Kyriotēs-CSK2 internally proves SHA-256, X25519, ML-KEM, Ed25519, HKDF, or ChaCha20Poly1305 secure.

Not acceptable until the corresponding reduction is complete:

> Kyriotēs-CSK2 has a complete machine-checked end-to-end computational security proof.

## Next Formal Work

1. Formalize the two-gate opening game and its challenge restrictions.
2. Define the hybrid KEM and AEAD advantage interfaces.
3. Prove the Merkle binding reduction from an accepted false path to a node-hash collision or second preimage.
4. Formalize capability/object/policy/epoch binding as a game.
5. Add concrete advantage accounting and reduction status to each security claim.
6. Preserve Coq, Kani, test, and future game-proof artifacts per release.
