# Changelog

## 0.1.2 - Authority Verification Boundary Hardening

### Security

- Reworked the authority verification boundary so production security decisions no longer rely on user-supplied validity booleans.
- Removed the trust model where raw `AuthorityState` could carry self-reported verification flags such as `epoch_signature_valid`, `epoch_key_cert_valid`, and `transparency_inclusion_valid`.
- Introduced a type-state verification model where raw authority data must be verified before it can be used by security-sensitive engine paths.
- Added the `VerifiedAuthorityState` boundary to represent authority state that has been produced by verifier code rather than caller-controlled input.
- Added an `AuthorityVerificationEvidence` path for signatures, certificates, transparency proofs, revocation evidence, and related authority proof material.
- Updated the authority verifier flow so `AuthorityVerifier::verify_state` returns a verifier-issued `VerifiedAuthorityState` token instead of only returning `Ok(())`.
- Ensured production engine paths derive verification results internally rather than accepting final gate results or pre-verified booleans from input.
- Prevented the “input 1” class of misuse by making the final authority validity result verifier-computed, not caller-supplied.

### API

- Added strict verified-state entrypoints for authority-sensitive operations.
- Preserved dual API ergonomics by keeping raw-state entrypoints that verify internally before reaching the verified engine path.
- Updated `seal`, `open`, `verify`, `add_epoch_wrapper`, and related verifier-based paths so security decisions are made only after authority state has crossed the verified boundary.
- Added or prepared lower-level `*_verified` style APIs for call sites that already hold a `VerifiedAuthorityState`.

### Verifier Changes

- Reworked `CryptoAuthorityVerifier` to issue `VerifiedAuthorityState` only after authority evidence checks succeed.
- Kept cryptographic authority verification as the production path.
- Renamed the old boolean-trusting verifier concept to `StubAuthorityVerifier`.
- Gated the stub verifier behind a non-default feature so it is only available for tests, Kani harnesses, examples, or explicitly insecure/demo usage.
- Removed `BasicAuthorityVerifier` as a default production boundary.
- Made stub verification opt-in instead of silently available in normal builds.

### Model Changes

- Split raw authority data from verified authority state.
- Kept `AuthorityState` as raw authority state data.
- Added `VerifiedAuthorityState` as a verifier-produced authority token.
- Added read-only accessors for verified authority state so callers can inspect verified state without constructing it.
- Removed public validity flags from raw authority state so they cannot be deserialized, fixture-injected, or caller-set as trusted proof.

### Engine Changes

- Updated authority-sensitive engine call sites to consume verified authority state after verifier execution.
- Updated `seal_with_verifier`, `open_with_verifier`, `verify_with_verifier`, and wrapper-related verifier paths to verify raw state before using it.
- Added strict internal or public verified entrypoints where appropriate.
- Ensured capability validation, wrapper selection, temporal checks, and cryptographic operations are reached only after the authority verification boundary has succeeded.
- Preserved compatibility through the dual API design while strengthening the internal security boundary.

### Tests

- Updated authority-state fixtures to remove direct construction of self-reported validity booleans.
- Updated test helpers such as state and scenario builders to work with the new raw-state plus verified-state model.
- Migrated non-cryptographic behavior tests to explicitly use the feature-gated `StubAuthorityVerifier` where appropriate.
- Added production verification tests using `CryptoAuthorityVerifier` and real authority evidence.
- Added regression coverage for the core boundary property: raw authority state cannot self-report validity and bypass authority verification.

### Kani / Mechanical Verification

- Updated impacted Kani harnesses for the new authority verification boundary.
- Migrated fail-closed engine harnesses to the new verifier-issued `VerifiedAuthorityState` model.
- Added or prepared explicit Kani coverage for the verified-state boundary.
- Preserved the existing tracked proof inventory while tightening the authority trust model.
- Updated proof-boundary language so the inventory reflects that production security paths no longer trust caller-supplied validity flags.

### Documentation

- Updated README and usage documentation to describe the `VerifiedAuthorityState` boundary.
- Clarified that authority validity is verifier-computed, not caller-supplied.
- Documented that `StubAuthorityVerifier` is test/demo-only and gated behind a non-default feature.
- Updated verification documentation to explain the distinction between raw authority data, authority evidence, verifier execution, and verified authority state.

### Notes

This release hardens the Kyriotēs-CSK2 authority boundary. The previous design allowed raw authority state to carry validity booleans that could be treated as already-verified facts by stub-style verification paths. Version 0.1.2 replaces that model with a verifier-issued token boundary: authority state is raw data until cryptographic evidence verifies it and produces `VerifiedAuthorityState`.

This does not change the mathematical Kyriotēs-CSK2 opening rule. It strengthens the implementation so the rule is enforced correctly: the final gate value is derived internally from verification, not accepted from user input.