<h1 align="center">Kyriotēs-CSK2</h1>


<p align="center"><em>Capability-Sealed Keyed Encryption with Two-Gate Opening</em></p>

<p align="center">

  <img src="Kyriotes-CSK2LogoRectangular.png" alt="The Kyriotēs-CSK2 logo">

</p>

Kyriotēs-CSK2 is an encryption scheme where opening ciphertext requires these two things to be true in order to safely decrypt:

**a)** correct key material  
**b)** valid, non-revoked authority capability proof


Kyriotēs-CSK2 seals bytes to an authority state (root, policy, rights, object, epoch, revocation), so decryption succeeds only when key possession and current authority are both cryptographically true.


## Security Status & Disclaimer

**Kyriotēs-CSK2 is an experimental construction.** It is **not yet recommended for production use** or handling sensitive data.

### Current Security Posture
- I have invested heavily in formal verification, including:
- 11/11 mechanical refinement lanes in Rust (backed by Kani)
- Substantial Coq/Rocq modeling of the protocol, invariants, and Merkle soundness
- Ongoing EasyCrypt development for computational security reductions (KEM + AEAD core, capability binding, Merkle soundness)
- The security model, two-gate opening semantics, and reduction roadmap are formally defined.
- However, the work is still **partial**. Full end-to-end computational reductions, external review, and independent security auditing are not yet complete.

**I am actively seeking funding** for a professional security audit (Trail of Bits, NCC Group, or equivalent) and further formal verification work.

Until an independent audit is completed and the reductions are fully published and reviewed, I strongly advise against using Kyriotēs-CSK2 in any high-stakes or production environment.

So far the computations I have personally completed have shown the design and evidence are promising, but **cryptography is hard** and novel constructions require rigorous external scrutiny before they can be trusted with real secrets.


## Core property

Traditional encryption works by decrypting if the key is valid. Whereas Kyriotēs-CSK2 in the core of the encryption mechanism will only decrypt if the key is valid AND capability proof is valid for this exact authority context


## Current architecture 

Kyriotēs-CSK2 uses a two-layer encryption design. The payload itself is encrypted with a fresh random 256-bit data encryption key, or DEK, using AEAD. That produces the encrypted payload. Separately, Kyriotēs-CSK2 binds access to the current authority state by deriving a key-encryption key, or KEK, from the recipient shared secret and the authority context for a specific epoch. That KEK is then used to wrap the DEK together with authority-associated data.

This means the ciphertext is not opened by key possession alone. A recipient must have both the right key material and a valid authority context for the object, policy, rights, epoch, and revocation state. Because only the small DEK wrapper is tied to the authority epoch, Kyriotēs-CSK2 can rewrap access for new epochs without re-encrypting the full payload.

## Threat-model honesty

Kyriotēs-CSK2 is designed for cases where possession of a key should not be enough on its own. The scheme is meant to reject key-only access when the matching authority proof is missing or no longer valid, reject authority-only access when the recipient does not have the right key material, prevent a capability for one object from being reused against another object, and block stale capability replay when the current-authority policy requires fresh authority state.

Kyriotēs-CSK2 is not a complete endpoint security system. It does not claim to protect against a recipient secret being compromised together with a valid capability, an already-authorized decryptor choosing to exfiltrate plaintext, compromise of the full threshold authority, or compromise of the machine after decryption
has succeeded.

## Status

Kyriotēs-CSK2 is a draft cryptographic construction and security model with ongoing hardening work. The implementation is built from standard primitives and patterns, including AEAD encryption, KDFs, Merkle commitments, signatures, KEM and hybrid KEM flows, transparency proofs, and threshold signatures.

## Rust development status

Kyriotēs-CSK2 encryption exposes the library crate `kyriotes_csk2` in Rust code. The crate is published on crates.io, and release checks now run in CI with a manual publish workflow. The implementation currently focuses on validating capabilities, checking authority state, enforcing temporal policy, encrypting payloads with fresh DEKs, wrapping those DEKs with HKDF-derived authority-bound KEKs, supporting epoch rewraps for current-authority opening, framing canonical transcripts and associated data, and exposing pluggable authority verifier interfaces.

The crate is organized around a small set of core modules. The Kyriotēs-CSK2 data model
and context hashing live in `src/kyriotes_csk2/model.rs`, while `src/kyriotes_csk2/engine.rs` contains the seal, open, and rewrap pipeline. Authority verification traits
and verifier implementations live in `src/kyriotes_csk2/verify.rs`. Canonical encoding helpers are under `src/encoding/codec.rs`, and the common temporal policy, rights, and error types live under `src/core/`. The public crate surface is
collected through src/lib.rs.

## Local development commands

Use cargo test to run the test suite, `cargo fmt` to format the code, and `cargo clippy --all-targets --all-features -- -D warnings` to run the strict lint configuration used by CI.

## Verification evidence

CI records the current verification evidence in named jobs:

- `Coq proof check` runs `./proofs/coq/check.sh` and uploads `coq-proof-check-evidence`.
- `Seal/open concrete Rust evidence` runs the concrete seal/open crypto discharge tests and uploads `seal-open-rust-evidence`.
- `Seal/open Kani evidence` runs representative model-crypto and crypto-contract Kani harnesses and uploads `seal-open-kani-evidence`.

These artifacts support the scoped seal/open semantic-equivalence expansion lanes. They do not prove the underlying cryptographic primitives themselves.

The computational adversary model, target security games, and reduction roadmap are documented in [SECURITY_MODEL.md](docs/verification/SECURITY_MODEL.md). External primitive assumptions and standards references are documented in [PRIMITIVE_BOUNDARY.md](docs/verification/PRIMITIVE_BOUNDARY.md).

## Publishing

Publishing is automated with the GitHub Actions workflow in `.github/workflows/publish.yml`.

- Run the `Publish` workflow manually from the Actions tab.
- The workflow packages and publishes using the repository secret `CARGO_REGISTRY_TOKEN`.

For local preflight checks, run `cargo publish --dry-run --locked`.

## Test organization

The integration tests are grouped by behavior. Seal, open, and rewrap flows
are covered in `tests/kyriotes_csk2_flow.rs`, while rejection and tamper scenarios are
covered in `tests/kyriotes_csk2_guards.rs`.

Shared test setup lives under
tests/helpers/, including authority-state fixtures, capability and prooffixtures, request builders, policy-hash helpers, and small scenario buildersfor composing expressive end-to-end cases.


## Project Status

- [Changelog](CHANGELOG.md)
- [Verification documentation](docs/verification/)
