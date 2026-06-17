# Software Design Document

**Document ID:** SWDD-KYRIOTES-CSK2-001
**Project Title:** Kyriotēs-CSK2: Authenticated Routing Chain
**Document Type:** Software Design Document  
**Author:** Keefe Reeves  
**Date:** May 31, 2026  
**Repository Path:** `docs/design/SWDD.md`  

---

# Table of Contents

1. [Introduction](#10-introduction)  
   1. [Purpose](#11-purpose)  
   2. [Scope](#12-scope)  
   3. [Overview](#13-overview)  
   4. [Reference Material](#14-reference-material)  
   5. [Definitions and Acronyms](#15-definitions-and-acronyms)  

2. [System Overview](#20-system-overview)  

3. [System Architecture](#30-system-architecture)  
   1. [Architectural Design](#31-architectural-design)  
   2. [Decomposition Description](#32-decomposition-description)  
   3. [Design Rationale](#33-design-rationale)  

4. [Data Design](#40-data-design)  
   1. [Data Description](#41-data-description)  
   2. [Data Dictionary](#42-data-dictionary)  

5. [Component Design](#50-component-design)  

6. [Human Interface Design](#60-human-interface-design)  
   1. [Overview of User Interface](#61-overview-of-user-interface)  
   2. [Screen Images](#62-screen-images)  
   3. [Screen Objects and Actions](#63-screen-objects-and-actions)  

7. [Requirements Matrix](#70-requirements-matrix)  

8. [Appendices](#80-appendices)  

---

# 1.0 Introduction

## 1.1 Purpose

This Software Design Document describes the architecture and system design of Kyriotēs-CSK2, the Authenticated Routing Chain encryption library.

The purpose of this document is to explain how Kyriotēs-CSK2 is structured, how its major components work together, and how the design satisfies the project’s security and functionality goals.

This document is intended for developers, security reviewers, maintainers, formal-methods contributors, and future auditors who need to understand the internal structure of Kyriotēs-CSK2 before implementing, reviewing, testing, or extending the system.

## 1.2 Scope

Kyriotēs-CSK2 is a Rust cryptography library designed around capability-routed encryption. Opening ciphertext in Kyriotēs-CSK2 requires more than possession of secret key material. A valid open operation depends on both correct cryptographic key material and a valid, non-revoked authority capability proof bound to the correct authority context.

The scope of Kyriotēs-CSK2 includes hybrid classical and post-quantum key encapsulation, authority-root binding, epoch-based state, revocation tracking, transparency commitments, rewrapping across epochs, delegation limits, canonical encoding, fuzz testing, and formal proof scaffolding in Coq.

The project is currently experimental and should be treated as an early-stage cryptographic construction. Its design goal is to explore a stronger authorization-bound encryption model where decryption is tied to authority state, capability rights, revocation status, epoch validity, and authenticated transcript binding.

The main benefits of the project are:

- Strong separation between key possession and authorization.
- Capability-based access control built into the cryptographic opening path.
- Revocation and transparency state bound into verification.
- Hybrid key encapsulation using classical and post-quantum primitives.
- Formal proof layers for authorization safety, temporal safety, delegation safety, transcript binding, revocation monotonicity, compromise notice safety, and reduction-shape reasoning.

## 1.3 Overview

This document follows the general structure of a Software Design Document.

Section 1 introduces the purpose, scope, references, and definitions. Section 2 gives a general system overview. Section 3 describes the architecture, decomposition, and rationale. Section 4 explains the data model and data dictionary. Section 5 describes the component behavior and core algorithms. Section 6 describes the human interface. Section 7 maps requirements to design components. Section 8 provides appendices and supporting notes.

## 1.4 Reference Material

The following materials were used as design references:

- Kyriotēs-CSK2 source code and repository documentation.
- Kyriotēs-CSK2 Coq proof files under `proofs/coq`.
- Rust cryptography crate documentation for ChaCha20Poly1305, HKDF-SHA256, Ed25519, ML-KEM, and X25519.
- General Merkle tree literature for inclusion and non-revocation proof design.
- General authenticated encryption and key encapsulation design practices.
- IEEE-style Software Design Document structure from the supplied SWDD template.

## 1.5 Definitions and Acronyms

**AAD:** Additional Authenticated Data. Data authenticated by AEAD encryption but not encrypted.

**AEAD:** Authenticated Encryption with Associated Data.

**Kyriotēs-CSK2:** Authenticated Routing Chain.

**Capability:** A cryptographic authorization object that grants rights over a specific object, subject to epoch, delegation, and revocation constraints.

**Coq:** A proof assistant used to machine-check formal definitions and theorems.

**DEK:** Data Encryption Key.

**Epoch:** A discrete authority period used for key rotation, temporal policies, and state transitions.

**HKDF:** HMAC-based Key Derivation Function.

**KEM:** Key Encapsulation Mechanism.

**KEK:** Key Encryption Key.

**ML-KEM:** Module-Lattice-Based Key Encapsulation Mechanism, used as the post-quantum KEM component.

**PQ:** Post-Quantum.

**Rewrap:** The process of adding or updating an authority wrapper for a new epoch without fully re-encrypting the underlying object payload.

**Revocation Root:** A Merkle root representing revoked capability stamps.

**Transparency Root:** A root commitment representing auditable authority state.

---

# 2.0 System Overview

Kyriotēs-CSK2 is a Rust library for capability-routed encryption. Its core security model is that ciphertext should only open when the recipient has the correct key material and the presented capability is valid for the object, rights, epoch, revocation state, authority root, and transparency context.

In a conventional encryption library, possession of the correct private key is usually enough to decrypt. Kyriotēs-CSK2 adds an authority layer around that process. A sealed object is bound to an authority state, a revocation state, an epoch, required rights, and a transcript/context hash. This means the open path must verify authorization context before or alongside cryptographic opening.

Kyriotēs-CSK2 supports capability issuance, capability delegation, revocation, epoch rotation, transparency commitments, resealing to a new recipient, and rewrapping across epochs.

Delegation is constrained so child capabilities cannot exceed parent rights, expand the parent epoch window, break parent-stamp linkage, or exceed the maximum delegation depth.

The system also includes a growing Coq proof suite. These proofs currently model and verify important design properties such as authorization safety, context mutation rejection, delegation safety, temporal and rewrap safety, transcript binding, revocation monotonicity, compromise notice safety, and abstract reduction-shape reasoning.

---

# 3.0 System Architecture

## 3.1 Architectural Design

Kyriotēs-CSK2 follows a layered architecture. Each layer has a clear responsibility so the system can be audited, tested, fuzzed, and formally modeled.

The major layers are described below.

## Model Layer

The model layer defines the core data structures used by Kyriotēs-CSK2. These include capabilities, authority states, sealed objects, wrappers, signatures, proofs, revocation witnesses, transcript records, and compromise notices.

## Engine Layer

The engine layer performs the main cryptographic workflows. It handles sealing, opening, issuing capabilities, delegating capabilities, revoking capabilities, rotating epochs, resealing to new recipients, and rewrapping for new epochs.

## Verification Layer

The verification layer checks whether an open operation is allowed. It verifies authority signatures, epoch certificates, capability inclusion, non-revocation, required rights, object binding, temporal policy, delegation constraints, transparency commitments, and transcript binding.

## Encoding Layer

The encoding layer handles canonical serialization and decoding. This is important because cryptographic systems require unambiguous byte representations. Kyriotēs-CSK2’s encoding layer is designed to prevent inconsistent serialization from creating hash, signature, or transcript mismatch issues.

## Proof Layer

The proof layer contains Coq files that model Kyriotēs-CSK2’s security-relevant logic. These files machine-check properties around authorization gates, delegation, transcript binding, rewrap rules, revocation monotonicity, compromise notice handling, and reduction-shape reasoning.

## Testing and Fuzzing Layer

The test and fuzzing layer validates runtime behavior. Unit and integration tests cover seal/open flows, revocation, temporal policy, delegation, PQ KEM behavior, transparency, rewraps, compromise notices, and wire decoding. Fuzz targets stress parser and decoder behavior with malformed input.

The high-level flow is:

1. A capability is issued and committed to an authority root.
2. A caller seals an object to a recipient under a required-rights policy.
3. Kyriotēs-CSK2 derives cryptographic wrapping material using hybrid KEM and HKDF.
4. Kyriotēs-CSK2 binds authority state, revocation state, transparency state, epoch, object ID, and required rights into the object context.
5. A recipient attempts to open the object.
6. Kyriotēs-CSK2 verifies the capability, revocation status, authority state, transcript binding, and temporal policy.
7. Kyriotēs-CSK2 only decrypts when the cryptographic and authorization gates both succeed.

## 3.2 Decomposition Description

Kyriotēs-CSK2 can be decomposed into the following subsystems.

## Capability Management Subsystem

This subsystem creates, validates, delegates, and revokes capabilities. It is responsible for enforcing rights constraints, object binding, epoch windows, delegation depth, parent-stamp linkage, and capability stamps.

Core responsibilities:

- Create direct capabilities.
- Create delegated capabilities.
- Prevent rights escalation.
- Prevent epoch-window expansion.
- Prevent invalid delegation depth.
- Provide capability inclusion data for authority roots.
- Provide revocation stamps for revoked capabilities.

## Authority State Subsystem

This subsystem manages the authority roots and epoch state used to verify sealed objects.

Core responsibilities:

- Maintain the current authority root.
- Maintain the current revocation root.
- Maintain the current transparency root.
- Track epoch numbers.
- Track epoch public keys.
- Support epoch rotation.
- Produce or verify epoch certificates and signatures.

## Sealing Subsystem

This subsystem transforms plaintext into a Kyriotēs-CSK2 sealed object.

Core responsibilities:

- Validate the capability before sealing.
- Generate or use encryption material.
- Use hybrid KEM for recipient wrapping.
- Derive a KEK through HKDF.
- Encrypt payload data with AEAD.
- Bind required context into AAD.
- Produce a sealed object with authority wrapper data.

## Opening Subsystem

This subsystem verifies and decrypts a sealed object.

Core responsibilities:

- Decode the object safely.
- Verify authority state.
- Verify capability inclusion.
- Verify non-revocation.
- Verify rights.
- Verify epoch window.
- Verify transcript/context binding.
- Reconstruct the KEK.
- Unwrap the DEK.
- Decrypt the ciphertext only when all checks pass.

## Revocation Subsystem

This subsystem records and enforces revoked capability stamps.

Core responsibilities:

- Insert revoked stamps.
- Update revocation roots.
- Produce non-revocation witnesses.
- Block revoked capabilities.
- Preserve revocation monotonicity across later states.

## Transparency Subsystem

This subsystem commits authority states into an auditable state log.

Core responsibilities:

- Commit authority state.
- Track state roots.
- Verify transparency proofs.
- Detect conflicting epoch or state commitments.
- Support auditability of authority changes.

## Temporal and Rewrap Subsystem

This subsystem handles time-based access rules.

Core responsibilities:

- Reject same-epoch rewraps.
- Reject backward rewraps.
- Reject rewraps outside the capability epoch window.
- Ensure verified opens are inside the valid capability window.
- Allow new epoch wrappers only when temporal constraints are satisfied.

## Encoding and Wire Format Subsystem

This subsystem ensures canonical and bounded decoding.

Core responsibilities:

- Encode Kyriotēs-CSK2 objects.
- Decode Kyriotēs-CSK2 objects.
- Reject bad magic values.
- Reject truncated input.
- Reject oversized fields.
- Reject oversized wrapper counts.
- Enforce decode profiles and limits.

## Formal Proof Subsystem

This subsystem provides Coq proof files for security-relevant design properties, organized across six subdirectories under `proofs/coq/`.

- `core/`: Core abstract types, authority-state model, policy model, and verified-open gate model.
- `merkle_transparency/`: Abstract and concrete Merkle tree proofs, transparency append-only and consistency proofs, false-inclusion reduction, and soundness completeness.
- `security/`: Security game definitions, authorization theorems, delegation proofs, KEM/AEAD assumption interfaces, two-gate opening game, hybrid reduction, adversary game, and crypto reduction completeness.
- `lifecycle/`: Temporal proofs, transcript binding proofs, revocation and compromise proofs, encoding proofs, wrapper proofs, state transition proofs, protocol state machine proofs, end-to-end theorems, and predicate refinement proofs.
- `completeness/`: Master invariant proofs, abstract invariant completeness, design model completeness, and state machine completeness.
- `rust_refinement/`: Rust-to-Coq mechanical correspondence, Kani-backed axioms, seal/open crypto semantic contracts, encode/decode round-trip refinement, capability tree witness soundness, epoch wrapper and rotation refinement, and the formal correspondence layer.

The `check.sh` script at the root of `proofs/coq/` compiles all proof files in dependency order and reports success or failure.

## 3.3 Design Rationale

Kyriotēs-CSK2 is designed around the principle that encryption alone is not enough for certain systems. Some systems need cryptographic opening to be tied to authority, policy, revocation, and time. Kyriotēs-CSK2 therefore separates the idea of possessing a key from the idea of being authorized to open an object.

The architecture uses standard cryptographic building blocks where possible. ChaCha20Poly1305 provides AEAD encryption. HKDF derives keys from shared material. X25519 provides classical elliptic-curve key agreement. ML-KEM adds post-quantum key encapsulation. Ed25519 supports signatures for authority and epoch verification. Merkle trees support compact inclusion and non-revocation proofs.

The main architectural tradeoff is complexity. Kyriotēs-CSK2 is more complex than a normal public-key encryption library because it includes authority state, revocation state, temporal policy, and transparency state. This complexity is accepted because it directly supports the project’s goal: opening ciphertext should require both cryptographic key possession and valid authorization context.

Alternative architectures considered include the following.

## Simple Public-Key Encryption

This was rejected because key possession alone does not express revocation, temporal policy, capability delegation, or authority state.

## Server-Side Authorization Before Decryption

This was rejected as the core design because Kyriotēs-CSK2 is intended to cryptographically bind authorization into the object itself rather than relying entirely on a hosted policy service.

## Linear Revocation Lists

This was rejected because Merkle-based revocation is more efficient for proof-based verification and transparency.

## Classical-Only Key Encapsulation

This was rejected because Kyriotēs-CSK2 aims to explore long-term security against future quantum-capable adversaries.

---

# 4.0 Data Design

## 4.1 Data Description

Kyriotēs-CSK2’s information domain is transformed into a set of cryptographic and authorization data structures.

The most important data structures are capabilities, authority states, sealed objects, wrappers, proofs, revocation witnesses, transparency commits, transcript records, and compromise notices.

A capability represents authorization. It contains the subject, object ID, rights, epoch window, revocation stamp, parent stamp, and delegation depth.

An authority state represents the committed security context. It contains the authority root, revocation root, transparency root, epoch number, epoch public key, and root public key.

A sealed object represents encrypted content bound to an authorization context. It contains an object ID, required rights, bound authority root, bound revocation root, bound transparency root, bound epoch, AAD context hash, encrypted payload, and one or more authority wrappers.

Merkle proofs represent inclusion in an authority tree or non-inclusion/non-revocation in a revocation tree. Transparency commitments represent auditable state history.

The Coq proof model abstracts these structures into natural-number-based records and predicates so their relationships can be machine-checked.

## 4.2 Data Dictionary

## KyriotesCsk2Object

- `object_id`: Unique identifier for the sealed object.
- `required_rights`: Rights needed to open the object.
- `bound_authority_root`: Authority root bound to the object.
- `bound_revocation_root`: Revocation root bound to the object.
- `bound_transparency_root`: Transparency root bound to the object.
- `bound_epoch`: Epoch bound to the object.
- `aad_context_hash`: Hash of the transcript/context used for AAD binding.

## AuthorityState

- `authority_root`: Merkle root for issued capabilities.
- `revocation_root`: Merkle root for revoked capability stamps.
- `transparency_root`: Root commitment for transparency state.
- `epoch`: Current authority epoch.
- `authority_id`: Identifier for the authority.
- `root_pk`: Public key for the authority root (offline trust anchor).
- `revocation_count`: Authenticated count of entries in the revocation tree, bound into the authority digest so non-revocation witnesses cannot lie about tree size.
- `prev_epoch_hash`: Transparency log chain hash `Log_{e-1}` used as `prev_epoch_hash` when signing the epoch root signature.

## Capability

- `cap_subject`: Subject that holds the capability.
- `cap_object_id`: Object the capability applies to.
- `cap_rights`: Rights granted by the capability.
- `cap_epoch_start`: First valid epoch.
- `cap_epoch_end`: Last valid epoch.
- `cap_stamp`: Unique stamp used for revocation.
- `cap_parent_stamp`: Parent capability stamp for delegation.
- `cap_delegation_depth`: Delegation depth from the root capability.

## CompromiseNotice

- `compromised_epoch`: Epoch at which the key compromise occurred.
- `compromised_epoch_pk`: Epoch public key that must no longer be trusted at or after `compromised_epoch`.
- `recovery_authority_root`: Recovery authority root anchoring the declared recovery boundary.
- `signature`: Offline root signature over the notice fields (domain-separated).

## KyriotesCsk2Transcript

- `transcript_object_id`: Object ID included in the transcript.
- `transcript_required_rights`: Required rights included in the transcript.
- `transcript_authority_root`: Authority root included in the transcript.
- `transcript_revocation_root`: Revocation root included in the transcript.
- `transcript_transparency_root`: Transparency root included in the transcript.
- `transcript_epoch`: Epoch included in the transcript.
- `transcript_context_hash`: Context hash included in the transcript.

## PrimitiveBreak

- `BreakAEAD`: Abstract break of AEAD security.
- `BreakKEM`: Abstract break of KEM security.
- `BreakHKDF`: Abstract break of HKDF pseudorandomness.
- `BreakSignature`: Abstract break of signature unforgeability.
- `BreakHashBinding`: Abstract break of hash binding.
- `BreakMerkleBinding`: Abstract break of Merkle binding.
- `BreakTransparencyBinding`: Abstract break of transparency-state binding.

---

# 5.0 Component Design

This section describes the major Kyriotēs-CSK2 components in procedural design form.

## 5.1 Seal Procedure

```text
procedure SEAL(object, capability, recipient_public_key, authority_state):
    verify capability object ID matches object ID
    verify capability grants required rights
    verify capability is valid for authority_state.epoch
    verify capability is included in authority_state.authority_root
    verify capability stamp is not revoked under authority_state.revocation_root

    generate a fresh data encryption key
    perform X25519 encapsulation or agreement
    perform ML-KEM encapsulation
    combine classical and post-quantum shared material
    derive key encryption key using HKDF and domain-separated context

    build transcript containing object ID, rights, roots, epoch, and policy context
    compute AAD context hash from canonical transcript
    encrypt plaintext using ChaCha20Poly1305 with AAD
    wrap the data encryption key using the derived key encryption key

    assemble sealed object
    attach authority wrapper
    attach required proofs and context fields
    return sealed object
```

## 5.2 Open Procedure

```text
procedure OPEN(sealed_object, capability, recipient_secret_key, authority_state):
    decode sealed object using bounded canonical decoder
    verify object ID matches capability object ID
    verify capability grants required rights
    verify bound authority root matches authority_state.authority_root
    verify bound revocation root matches authority_state.revocation_root
    verify bound transparency root matches authority_state.transparency_root
    verify bound epoch matches authority_state.epoch

    verify authority signature and epoch certificate
    verify capability inclusion proof
    verify capability is not revoked
    verify temporal policy
    verify transcript and AAD context hash

    perform X25519 decapsulation or agreement
    perform ML-KEM decapsulation
    combine classical and post-quantum shared material
    derive key encryption key using HKDF and transcript context

    unwrap data encryption key
    decrypt ciphertext using ChaCha20Poly1305 and AAD
    return plaintext if all checks pass
```

## 5.3 Delegate Procedure

```text
procedure DELEGATE(parent_capability, child_subject, child_rights, child_epoch_window):
    verify parent capability has delegate right
    verify child_rights are a subset of parent rights
    verify child epoch window is inside parent epoch window
    verify parent delegation depth is below maximum
    create child capability
    set child parent stamp to parent capability stamp
    set child delegation depth to parent depth plus one
    assign unique child stamp
    commit child capability to authority tree
    return child capability
```

## 5.4 Revoke Procedure

```text
procedure REVOKE(capability_stamp, authority_state):
    insert capability_stamp into revocation set
    recompute revocation Merkle root
    update authority state
    commit updated state to transparency log
    return updated authority state
```

## 5.5 Rotate Epoch Procedure

```text
procedure ROTATE_EPOCH(authority_state, new_epoch_key):
    increment epoch number
    derive or load new epoch public key
    preserve current authority root
    preserve or update revocation root
    create epoch certificate
    sign epoch state with root authority key
    commit new state to transparency log
    return rotated authority state
```

## 5.6 Rewrap Procedure

```text
procedure REWRAP(sealed_object, capability, from_epoch, to_epoch):
    verify to_epoch is greater than from_epoch
    verify to_epoch is inside capability epoch window
    verify existing wrapper is valid for from_epoch
    create new wrapper bound to to_epoch
    preserve encrypted payload
    attach new authority wrapper
    return updated sealed object
```

## 5.7 Reseal Procedure

```text
procedure RESEAL(sealed_object, old_recipient_secret, new_recipient_public_key):
    verify old recipient can open the existing object
    decrypt or unwrap required wrapping material
    generate fresh recipient wrapping material
    bind new recipient wrapper to same authority context
    ensure old recipient cannot open resealed object unless separately authorized
    return resealed object
```

## 5.8 Verify Procedure

```text
procedure VERIFY(sealed_object, capability, authority_state):
    verify authority state is valid
    verify object is bound to authority state
    verify capability is included in authority root
    verify capability is not revoked
    verify policy accepts capability for object
    verify transcript binding
    return true only if all gates pass
```

## 5.9 Coq Proof Check Procedure

```text
procedure CHECK_COQ_PROOFS():
    invoke proofs/coq/check.sh
    script compiles all proof files across six subdirectories in dependency order
    report success only if all files compile without error
```

The proof files are organized into `core`, `merkle_transparency`, `security`, `lifecycle`, `completeness`, and `rust_refinement` subdirectories. The `check.sh` script handles the `-Q` namespace flags and compilation ordering required across all subdirectories.

---

# 6.0 Human Interface Design

## 6.1 Overview of User Interface

Kyriotēs-CSK2 is primarily a library, not a graphical application. Most users interact with Kyriotēs-CSK2 through Rust APIs, automated tests, command-line tools, or integration code.

A developer uses Kyriotēs-CSK2 by importing the library and calling operations such as capability issuance, sealing, opening, revocation, delegation, epoch rotation, rewrap, reseal, and verification.

The expected feedback is returned through structured success values and error values. In command-line workflows, feedback is displayed as terminal output. In tests and proof workflows, feedback appears through `cargo test`, fuzzing output, or Coq compiler output.

## 6.2 Screen Images

Kyriotēs-CSK2 does not currently require a graphical user interface. A command-line interface could use the following interaction style:

```text
$ kyriotes-csk2-cli seal --cap capability.json --input secret.txt --output secret.arc
Sealed object written to secret.arc
```

```text
$ kyriotes-csk2-cli open --cap capability.json --secret-key recipient.key --input secret.arc --output secret.txt
Object opened successfully.
```

```text
$ ./proofs/coq/check.sh
Kyriotēs-CSK2 Coq proofs compiled successfully.
```

```text
$ cargo test --locked --all-targets --all-features
test result: ok
```

## 6.3 Screen Objects and Actions

The main screen objects in a command-line interface are file paths, key paths, capability paths, object paths, and command names.

Expected actions include:

- Seal an object.
- Open an object.
- Issue a capability.
- Delegate a capability.
- Revoke a capability.
- Rotate an epoch.
- Rewrap an object.
- Reseal an object.
- Verify an object.
- Run tests.
- Run fuzz targets.
- Run Coq proof checks.

Errors should clearly explain whether failure came from decoding, missing rights, invalid epoch, revoked capability, authority mismatch, transcript mismatch, failed decryption, or proof-check failure.

---

# 7.0 Requirements Matrix

| Requirement ID | Requirement | Component |
|---|---|---|
| FR-1 | Seal object | Seal Engine |
| FR-2 | Open object | Open Engine |
| FR-3 | Capability binding | Verification Layer |
| FR-4 | Rights enforcement | Policy Layer |
| FR-5 | Revocation enforcement | Revocation Subsystem |
| FR-6 | Epoch enforcement | Temporal Subsystem |
| FR-7 | Capability delegation | Capability Management |
| FR-8 | Prevent rights escalation | Delegation Proof Layer |
| FR-9 | Prevent epoch expansion | Delegation Proof Layer |
| FR-10 | Rewrap across epochs | Rewrap Subsystem |
| FR-11 | Reject backward rewrap | Temporal Proof Layer |
| FR-12 | Hybrid KEM support | Cryptographic Layer |
| FR-13 | AEAD encryption | Cryptographic Layer |
| FR-14 | Canonical encoding | Encoding Layer |
| FR-15 | Bounded decoding | Encoding Layer |
| FR-16 | Transcript binding | Transcript Proof Layer |
| FR-17 | Transparency state binding | Transparency Subsystem |
| FR-18 | Coq proof checking | Formal Proof Subsystem |
| FR-19 | Fuzz testing | Testing Layer |
| FR-20 | Compromise notice handling | Compromise Subsystem |

---

# 8.0 Appendices

## Appendix A: Current Coq Proof Layers

Kyriotēs-CSK2 proof files are organized into six subdirectories under `proofs/coq/`. All files are compiled by `proofs/coq/check.sh`.

**core/** — Foundation types and gate models.
- `KyriotesCsk2Types.v`: Core abstract types and helper lemmas.
- `KyriotesCsk2Authority.v`: Abstract authority-state validity model.
- `KyriotesCsk2Policy.v`: Object, rights, and epoch policy model.
- `KyriotesCsk2Verify.v`: Verified-open gate model.

**merkle_transparency/** — Merkle and transparency log proofs.
- `KyriotesCsk2Merkle.v`: Abstract Merkle inclusion and non-revocation model.
- `KyriotesCsk2MerkleConcreteTree.v`: Concrete Merkle tree construction.
- `KyriotesCsk2ConcreteMerkleProofs.v`: Concrete Merkle path proofs.
- `KyriotesCsk2TransparencyProofs.v`: Transparency log proofs.
- `KyriotesCsk2TransparencyAppendOnly.v`: Append-only log monotonicity proof.
- `KyriotesCsk2TransparencyConsistencyProofs.v`: Log consistency proofs.
- `KyriotesCsk2FullTransparencyMerkleSoundness.v`: Full transparency/Merkle soundness under SHA-256 assumptions.
- `KyriotesCsk2MerkleFalseInclusionReduction.v`: False-inclusion to hash-collision reduction.
- `KyriotesCsk2MerkleTransparencyCompleteness.v`: Merkle/transparency completeness.

**security/** — Security games, reductions, and theorems.
- `KyriotesCsk2SecurityGame.v`: Unauthorized open game model.
- `KyriotesCsk2Theorems.v`: Main authorization safety theorems.
- `KyriotesCsk2StressProofs.v`: Mutation rejection and gate stress proofs.
- `KyriotesCsk2DelegationProofs.v`: Delegation rights, epoch, parent-stamp, and depth proofs.
- `KyriotesCsk2CryptoReduction.v`: Abstract reduction-shape proof skeleton.
- `KyriotesCsk2KemAeadAssumptions.v`: KEM and AEAD assumption interfaces.
- `KyriotesCsk2CapabilityBindingReduction.v`: Capability binding reduction.
- `KyriotesCsk2AdversaryGame.v`: Adversary game model.
- `KyriotesCsk2TwoGateOpeningGame.v`: Two-gate opening game.
- `KyriotesCsk2TwoGateHybridReduction.v`: Two-gate hybrid reduction game-hopping proof.
- `KyriotesCsk2TightSecurityGameProofs.v`: Tight security game proofs.
- `KyriotesCsk2AssumptionReductionProofs.v`: Assumption reduction proofs.
- `KyriotesCsk2CryptoReductionCompleteness.v`: Crypto reduction completeness.

**lifecycle/** — Protocol lifecycle, temporal, transcript, and encoding proofs.
- `KyriotesCsk2TemporalProofs.v`: Temporal and rewrap safety proofs.
- `KyriotesCsk2TranscriptProofs.v`: Transcript and context binding proofs.
- `KyriotesCsk2RevocationCompromiseProofs.v`: Revocation monotonicity and compromise notice proofs.
- `KyriotesCsk2EncodingProofs.v`: Encoding correctness proofs.
- `KyriotesCsk2WrapperProofs.v`: Authority wrapper proofs.
- `KyriotesCsk2StateTransitionProofs.v`: State transition proofs.
- `KyriotesCsk2ProtocolStateMachineProofs.v`: Protocol state machine proofs.
- `KyriotesCsk2InvalidTransitionProofs.v`: Invalid transition rejection proofs.
- `KyriotesCsk2LifecycleProofs.v`: Full lifecycle proofs.
- `KyriotesCsk2PredicateRefinementProofs.v`: Predicate refinement proofs.
- `KyriotesCsk2EndToEndTheorems.v`: End-to-end protocol theorems.

**completeness/** — Invariant and model completeness proofs.
- `KyriotesCsk2MasterInvariantProofs.v`: Master invariant closure proofs.
- `KyriotesCsk2AbstractInvariantCompleteness.v`: Abstract invariant completeness.
- `KyriotesCsk2DesignModelCompleteness.v`: Design model completeness.
- `KyriotesCsk2StateMachineCompleteness.v`: State machine completeness.

**rust_refinement/** — Rust-to-Coq mechanical correspondence and Kani-backed axioms.
- `KyriotesCsk2RustCoqFormalCorrespondence.v`: Formal correspondence layer between Rust and Coq, with model contracts and Kani-backed axioms.
- `KyriotesCsk2SealOpenCryptoSemanticContracts.v`: Seal/open crypto semantic contracts under AEAD/KEM/HKDF/SHA assumptions.
- `KyriotesCsk2SealOpenModelCryptoEquivalence.v`: Seal/open model/crypto equivalence.
- `KyriotesCsk2EncodeDecodeRoundTripRustRefinement.v`: Encode/decode canonical round-trip refinement.
- `KyriotesCsk2CapabilityTreeWitnessSoundness.v`: Capability tree witness soundness.
- `KyriotesCsk2FullMechanicalProofEquivalence.v`: Full mechanical proof equivalence gate.
- `KyriotesCsk2RustFullMechanicalProofGate.v`: Rust mechanical proof gate record.
- Plus individual function refinement files for `context_hash`, `decode`, `encode`, `verify`, `seal`, `open`, `add_epoch_wrapper`, `rotate_epoch`, `rotate_epoch_full`, `capability_tree`, `transparency`.

## Appendix B: Current Security Claims Supported by the Design

The current design supports the following internal safety claims:

- A verified open implies capability inclusion.
- A verified open implies non-revocation.
- A verified open implies policy acceptance.
- A verified open implies object-state binding.
- A verified open implies authority-state validity.
- A delegated capability cannot exceed parent rights.
- A delegated capability cannot expand the parent epoch window.
- A delegated capability cannot exceed the delegation depth bound.
- A same-epoch rewrap is rejected.
- A backward rewrap is rejected.
- A rewrap outside the capability window is rejected.
- Transcript field mutation blocks transcript acceptance.
- Revoked stamps remain blocked under revocation-set extension.
- Matching compromise notices block affected state opens.

## Appendix C: Future Work

Completed items are noted inline. Remaining future design and proof work includes:

- (Complete) Transparency log consistency proofs: `KyriotesCsk2TransparencyConsistencyProofs.v` and `KyriotesCsk2FullTransparencyMerkleSoundness.v`.
- (Complete) More detailed Merkle proof modeling: concrete Merkle proofs and false-inclusion reduction are in `merkle_transparency/`.
- (Complete) Concrete wire-format proof alignment with Rust encoding code: full `rust_refinement/` directory with individual function refinement files and formal correspondence layer.
- (Complete) Two-gate cryptographic game-hopping model: `KyriotesCsk2TwoGateOpeningGame.v` and `KyriotesCsk2TwoGateHybridReduction.v`.
- Exhaustive encode/decode canonical equivalence over arbitrary bytes and the unbounded object space.
- Concrete advantage accounting for seal/open composition claims.
- Extending capability-tree witness refinement into a full Merkle-path computational binding reduction.
- Property-based testing connected to formal invariants.
- External cryptographic review.
- Performance profiling of revocation and proof verification.
- Hardened CLI design for real user workflows.
- Expanded fuzz corpus for decoding, proof parsing, and wrapper parsing.
