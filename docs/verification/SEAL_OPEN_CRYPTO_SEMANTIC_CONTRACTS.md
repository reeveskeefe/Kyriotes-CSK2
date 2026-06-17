# Seal/Open Crypto Semantic Contract Expansion

## Status

    Verification expansion lane: active
    Coq contract artifact: added and wired
    Kani boundary harnesses: added
    Production API impact: none
    Tracked Rust mechanical inventory impact: none

Kyriotēs-CSK2's tracked Rust mechanical refinement inventory remains complete at 11 / 11 verifier-backed proof lanes. This file records the next seal/open expansion stage after the deterministic model-crypto lane.

## Claim Shape

The target semantic claim is:

    open(sk_recipient, seal(pk_recipient, state, cap, message)) = message

under explicit assumptions:

    matching recipient keypair
    valid authority state
    valid capability proof
    valid non-revocation proof
    matching transparency proof
    selected epoch wrapper exists
    seal/open context bindings match
    AEAD, KEM, HKDF, and SHA/context-binding contracts hold

Defined tampering cases should reject before plaintext recovery.

## Boundary

This is a crypto-contract lane, not a primitive-security proof. It assumes contract behavior for AEAD round trip and tamper rejection, KEM encapsulation/decapsulation agreement for matching keys, HKDF determinism, and SHA/context binding.

It does not prove X25519, ML-KEM, ChaCha20Poly1305, Ed25519, HKDF, or SHA security internally. Those properties remain explicit assumptions discharged only through standards, external analysis, and completed reduction arguments.

For a detailed list of primitive assumptions, see [PRIMITIVE_BOUNDARY.md](PRIMITIVE_BOUNDARY.md).
The adversary model, target security games, and reduction obligations are defined in [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Coq Artifact

    proofs/coq/rust_refinement/KyriotesCsk2SealOpenCryptoSemanticContracts.v

The Coq layer records the primitive contract assumptions, the Rust helper-boundary evidence, and the composed semantic theorems:

    seal_open_crypto_semantic_equivalence_under_primitive_contracts
    seal_open_defined_tamper_rejects_under_primitive_contracts

The Coq bridge now uses constructive definitions for `crypto_contract_seal` and `crypto_contract_open` over the model-crypto seal/open functions, rather than abstract `Parameter` declarations. The round-trip theorem is proved by applying the model theorem directly, and the defined tamper theorem is proved by case analysis over explicit model-backed tamper scenarios.

The primitive-contract records still state the external cryptographic assumptions. They no longer stand in for the Coq seal/open transition itself.

## Kani Artifact

    src/kani/kani_seal_open_crypto_boundary_equivalence.rs

CI records representative Kani evidence in the `Seal/open Kani evidence` job. The job uploads the `seal-open-kani-evidence` artifact containing `cargo kani list` output and logs for the model-crypto and crypto-contract round-trip and tamper harnesses.

The Kani boundary harnesses check the executable contract model for:

    payload AAD policy binding
    authority AAD KEM-ciphertext binding
    wrapper selection for required epoch
    missing-wrapper rejection
    AEAD round trip
    AEAD AAD tamper rejection
    DEK wrap round trip
    KEM/HKDF determinism
    composed seal/open contract round trip
    payload ciphertext tamper rejection

## Discharged Concrete Sub-Lanes

The AEAD + AAD binding portion now has concrete Rust evidence recorded in:

    docs/verification/SEAL_OPEN_AEAD_AAD_CONTRACT_DISCHARGE.md

This discharges Kyriotēs-CSK2's concrete use of `payload_encrypt`, `payload_decrypt`, `wrap_dek`, `unwrap_dek`, `payload_aad`, and `authority_aad` for round-trip and defined tamper-rejection behavior. It does not prove ChaCha20Poly1305 as a primitive.

The KEM agreement, HKDF/context separation, deeper context-hash binding, and production composed seal/open tamper behavior now have concrete Rust evidence recorded in:

    docs/verification/SEAL_OPEN_CRYPTO_CONTRACT_DISCHARGE.md

This discharges the remaining implementation-level contract evidence for Kyriotēs-CSK2's current seal/open composition, while preserving the boundary that primitive cryptographic security is inherited rather than proven here.

The seal/open serialization gap now has scoped encode/decode round-trip evidence recorded in:

    docs/verification/SEAL_OPEN_ENCODE_DECODE_ROUNDTRIP.md

This proves that recorded seal-produced objects and bounded semantic-object fixtures encode and decode back to the same semantic object under the production wire codec. Full arbitrary-byte grammar equivalence and exhaustive canonicality over the unbounded object space remain outside that narrow claim.

The Coq proof tree is compiled in CI by the `Coq proof check` job, which runs `./proofs/coq/check.sh` and uploads the `coq-proof-check-evidence` artifact.

## Production Helper Boundaries

The open path now has explicit helper boundaries for wrapper selection and open-request construction. This does not change public API behavior; it gives the proof lane named implementation surfaces for the real seal/open semantic expansion.

## Remaining Work

1. (Complete) Two-gate opening game and reduction hybrids: formalized in `KyriotesCsk2TwoGateOpeningGame.v` and `KyriotesCsk2TwoGateHybridReduction.v`.
2. Add explicit advantage bounds for AEAD, KEM, KDF, signature, and hash failure events.
3. Retain or attach CI and game-proof evidence artifacts to releases.
4. Review [PRIMITIVE_BOUNDARY.md](PRIMITIVE_BOUNDARY.md) whenever primitive crates or standards references change.
