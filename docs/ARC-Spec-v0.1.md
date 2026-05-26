# ARC Specification v0.1 (Hardened Draft)

## 1. Abstract

ARC (Authority-Rooted Cryptography) is a capability-bound encryption scheme for arbitrary byte strings.
Decryption succeeds only when both conditions hold:

- key possession is valid for the recipient
- authority proof is valid for the required object, rights, policy, and epoch context

ARC is not a new cipher primitive. ARC is an encryption construction built from standard primitives and a signed, transparent authority state.

## 2. Scheme Interface

ARC = (Setup, KeyGen, Issue, Delegate, Revoke, Seal, Open, Verify)

Message space:

M in {0,1}*

### Setup

Setup(1^lambda) -> pp

Generates public parameters: hash function H (SHA-256, 256-bit output), AEAD
suite (ChaCha20-Poly1305), classical KEM parameters (X25519), post-quantum KEM
parameters, and ed25519 signing parameters.

### KeyGen

KeyGen(pp) -> (pk_B, sk_B)

Generates a recipient keypair:

- Classical component: (pk_C, sk_C) <- KEM_C.KeyGen
- Post-quantum component: (pk_Q, sk_Q) <- KEM_Q.KeyGen
- pk_B = (pk_C, pk_Q),  sk_B = (sk_C, sk_Q)

### Issue

Issue(pp, sk_A_e, cert_e, cap, A_e) -> sigma_issue or reject

1. Compute h_cap from cap fields (§5).
2. Require h_cap in L_e (cap must be in the active capability set).
3. sigma_issue = Sign(sk_A_e, "ARC-ISSUANCE-v1" || h_cap || R_e || e_le64).
4. Return sigma_issue.

The caller distributes (cap, sigma_issue, cert_e) together as the issuance bundle.

### Delegate

Delegate is reserved for a future version.  Fields delegation_depth and
parent_stamp in cap are allocated but not enforced in v0.1.  Conformant
implementations must reject any cap with delegation_depth > 0 until Delegate
is formally specified.

### Revoke

See §16.

### Seal and Open

See §13 and §14.

### Verify

Verify(pp, ARCObject, cap, proof, A_e, req) -> {0,1}

Public verifiability check that does not require sk_B.

1. Verify epoch key certificate chain for ARCObject.seal_epoch (§7).
2. Verify epoch root signature sigma_e (§7).
3. Verify transparency inclusion proof (§8).
4. Require TemporalAccept(ARCObject.temporal_policy, e_req, ARCObject.seal_epoch) = 1.
5. Return ValidCap(cap, proof, A_e, req) (§9).

Verify confirms authority-chain integrity and capability validity without
decrypting the payload.  Full authentication of plaintext requires Open.

## 3. Domains and Sets

- Subjects S
- Objects O
- Rights R
- Policies P
- Epochs E
- Authorities A

Elements:

- s in S
- o in O
- e in E
- a in A

Rights universe example:

R = {READ, WRITE, APPEND, DELETE, DECRYPT, DELEGATE, EXPORT, EXECUTE, ROTATE, SEAL, UNSEAL}

Capability rights set: R_cap subseteq R
Required rights set: R_req subseteq R
Satisfaction predicate: R_cap superset_eq R_req

## 4. Cryptographic Primitives

ARC relies on:

- H: hash function to lambda bits
- HKDF-Extract, HKDF-Expand
- AEAD.Enc, AEAD.Dec
- SIG.KeyGen, SIG.Sign, SIG.Verify
- TSIG.Sign, TSIG.Verify for threshold root signatures
- KEM.KeyGen, KEM.Encaps, KEM.Decaps
- Merkle inclusion proofs
- Transparency log inclusion and consistency proofs

Hybrid secret:

ss_H = H("ARC-HYBRID-SECRET-v1" || ss_C || ss_Q)

## 5. Capability Object

Raw capability:

cap = (
  version,
  subject,
  object,
  rights,
  policy_hash,
  epoch_start,
  epoch_end,
  delegation_depth,
  parent_stamp,
  nonce
)

Leaf hash:

h_cap = H(
  "ARC-CAPABILITY-LEAF-v1" ||
  version || subject || object || rights || policy_hash ||
  epoch_start_le64 || epoch_end_le64 || delegation_depth_le64 || parent_stamp || nonce
)

Capability stamp at epoch e:

stamp_e = H("ARC-CAPABILITY-STAMP-v1" || h_cap || R_e || e_le64 || a)

## 6. Authority State and Roots

At epoch e:

- Active capability set L_e
- Authority root R_e = MerkleRoot(L_e)
- Revoked stamp set V_e
- Revocation root Rev_e = MerkleRoot(V_e)

Authority tuple:

A_e = (R_e, Rev_e, e, policy_hash, a)

## 7. Epoch-Scoped Authority Keys

ARC authority signing is epoch-scoped.

- Offline authority root key pair: (pk_A_off, sk_A_off)
- Epoch online key pair: (pk_A_e, sk_A_e)

Epoch key certificate:

cert_e = Sign(sk_A_off, "ARC-EPOCH-KEY-v1" || pk_A_e || e_le64 || validity_window_le64)

Epoch root signature:

sigma_e = TSIG.Sign(t-of-n, "ARC-EPOCH-ROOT-v1" || R_e || Rev_e || e_le64 || prev_epoch_hash)

Capability issuance signature:

sigma_issue = Sign(sk_A_e, "ARC-ISSUANCE-v1" || h_cap || R_e || e_le64)

The epoch online key signs each capability leaf hash against the current authority
root and epoch, binding issuance to the epoch certificate chain.  Verifying
sigma_issue requires first verifying cert_e under pk_A_off.

Note on signing message format: all signing inputs above are raw concatenated
byte strings, not pre-hashed.  The signature scheme (ed25519) applies SHA-512
internally.  Integer fields are unsigned 64-bit little-endian.

Security consequence:

Leak(sk_A_e) compromises epoch e scope, not all historical epochs.

## 8. Transparency Log

Each epoch root is committed to an append-only transparency log.

Log_e = H(Log_(e-1) || R_e || Rev_e || e_le64 || pk_A_e || sigma_e)

Each ARC object carries or references transparency material for the sealing epoch.

Open requires successful validation of:

- epoch key certificate chain to offline root
- threshold epoch root signature
- log inclusion proof (and consistency when available)

## 9. Valid Capability Predicate

ValidCap(cap, proof, A_e, req) in {0,1}

Where:

- proof = (inclusion_path, nonrev_witness, sigma_issue)
- req = (object_req, R_req, policy_hash_req, e_req)

ValidCap = 1 iff all hold:

1. Merkle inclusion verifies under R_e.
2. Non-revocation witness verifies under Rev_e.
3. Object match: object_cap = object_req.
4. Rights sufficient: R_cap superset_eq R_req.
5. Policy hash match.
6. Epoch range valid: epoch_start <= e_req <= epoch_end.
7. SIG.Verify(cert_e.pk_A_e, proof.sigma_issue, m_issue) = 1,
   where m_issue = "ARC-ISSUANCE-v1" || h_cap || R_e || e_req_le64,
   and cert_e verifies under pk_A_off (§7).

## 10. Temporal Policy

ARC objects must carry one temporal opening policy:

TemporalPolicy in {
  Historical(e_seal),
  Current,
  Window(e_start, e_end),
  ResealRequired(e_after)
}

Temporal acceptance predicate:

TemporalAccept(T, e_open, e_seal) in {0,1}

Semantics:

- Historical(e_seal): open against historical authority state at sealing epoch.
- Current: open only against current authority state at e_open.
- Window(e_start, e_end): open only when e_start <= e_open <= e_end.
- ResealRequired(e_after): old wrapper accepted until e_after, then new wrapper required.

Formal predicate:

  T = Historical(e_s):         TemporalAccept = 1 iff e_open = e_s
  T = Current:                 TemporalAccept = 1 iff A_open is the live authority state at e_open
  T = Window(e_s, e_t):        TemporalAccept = 1 iff e_s <= e_open <= e_t
  T = ResealRequired(e_after): TemporalAccept = 1 iff e_open <= e_after

  TemporalAccept = 0 otherwise.

For ResealRequired: if e_open > e_after, Open rejects and signals that Reseal
is required before the object can be opened at the later epoch (§15).

## 11. Corrected Key Hierarchy (DEK + Authority Wrapper)

ARC uses two layers:

1. Payload encryption:

DEK <- random 256-bit
C_payload = AEAD.Enc(DEK, n_payload, M, AAD_payload)

2. Authority-bound DEK wrapping:

chi_e = H(
  "ARC-CONTEXT-v1" ||
  version || suite || subject || object || required_rights || policy_hash ||
  e || R_e || Rev_e || stamp_e || a || TemporalPolicy
)

kappa_e = HKDF-Extract(salt = H("ARC-AUTHORITY-DIGEST-v1" || R_e || Rev_e || e || policy_hash || a), ikm = ss_H || chi_e)

KEK_e = HKDF-Expand(kappa_e, "ARC-KEK-v1" || chi_e, 32)

WrappedDEK_e = AEAD.Enc(KEK_e, n_wrap, DEK, AAD_authority)

This architecture preserves authority-bound decryption while allowing epoch rewraps without rewriting payload ciphertext.

## 12. ARC Object Format

ARCObject = (
  magic,
  version,
  suite,
  recipient_header,
  payload_ciphertext,
  payload_aad,
  authority_wrappers[],
  cap_commitment,
  object_id,
  required_rights,
  policy_hash,
  temporal_policy,
  seal_epoch,
  authority_root,
  revocation_root,
  epoch_signature,
  epoch_key_cert,
  transparency_proof
)

Each element in authority_wrappers[] contains at least:

- epoch
- ct_C, ct_Q
- wrapped_DEK
- authority_aad
- stamp
- wrapper_tag

## 13. Seal

Seal(pp, pk_B, M, cap, proof, A_e, req, T) -> ARCObject or reject

1. Require ValidCap(cap, proof, A_e, req) = 1.
2. Require temporal policy T is valid for sealing epoch.
3. Sample random DEK and encrypt payload: C_payload.
4. Encapsulate to recipient:
   - (ct_C, ss_C) = KEM_C.Encaps(pk_C)
   - (ct_Q, ss_Q) = KEM_Q.Encaps(pk_Q)
5. Compute ss_H and chi_e including authority context and T.
6. Derive KEK_e and produce WrappedDEK_e.
7. Attach epoch root signature, epoch key certificate, transparency proof.
8. Output ARCObject with one or more authority wrappers.

## 14. Open

Open(pp, sk_B, ARCObject, cap, proof, A_open) -> M or reject

1. Parse ARCObject and select candidate wrapper for opening epoch e_open.
2. Verify epoch key certificate chain for wrapper epoch.
3. Verify threshold epoch root signature for wrapper epoch.
4. Verify transparency inclusion proof.
5. Build req from object_id, required_rights, policy_hash, epoch.
6. Require TemporalAccept(T, e_open, e_seal) = 1.
7. Require ValidCap(cap, proof, A_open, req) = 1.
8. Decapsulate ct_C and ct_Q to recover ss_H inputs; reject on failure.
9. Recompute chi_e and derive KEK_e.
10. DEK = AEAD.Dec(KEK_e, wrapped_DEK, authority_aad); reject on failure.
11. M = AEAD.Dec(DEK, payload_ciphertext, payload_aad); reject on failure.
12. Return M.

## 15. Reseal and Rewrap

Rewrap and reseal are distinct operations:

- **Rewrap**: add a DEK wrapper for a new epoch or authority state without touching C_payload.
- **Reseal**: full regeneration — new DEK, new ciphertext, new wrappers.

Rewrap is the dominant operation.  Reseal is reserved for policy-mandated DEK rotation
(e.g. ResealRequired) or post-compromise ciphertext refresh.

### Rewrap

Rewrap(sk_B, pk_B, ARCObject, cap, proof_from, A_from, A_to, tp_to) -> ARCObject' or reject

Preconditions:

- A_to.epoch > A_from.epoch
- A_to.epoch in [cap.epoch_start, cap.epoch_end]

Algorithm:

1. Select the authority wrapper in ARCObject matching A_from.epoch.  Reject if absent.
2. Verify epoch key certificate chain for A_from (cert_e under pk_A_off).
3. Verify epoch root signature sigma_e for A_from.
4. Verify transparency inclusion proof for A_from.
5. Require ValidCap(cap, proof_from, A_from, req_from) = 1.
6. Decapsulate ct_C and ct_Q under sk_B to recover ss_H for A_from.epoch.
7. Compute chi_from and derive KEK_from.
8. DEK = AEAD.Dec(KEK_from, WrappedDEK_from, AAD_authority_from).  Reject on failure.
9. Compute chi_to using A_to and tp_to.
10. Derive KEK_to.
11. WrappedDEK_to = AEAD.Enc(KEK_to, n_wrap_to, DEK, AAD_authority_to).
12. Append the new authority wrapper to ARCObject.authority_wrappers[].
13. Output ARCObject'.

C_payload is never rewritten during Rewrap.  Only the authority wrapper set changes.

### Reseal

Reseal(sk_B, pk_B, pk_B', M, cap, proof, A_new, req, T_new) -> ARCObject' or reject

1. Require ValidCap(cap, proof, A_new, req) = 1.
2. Sample a fresh DEK <- random 256-bit.
3. C_payload' = AEAD.Enc(DEK, n_payload', M, AAD_payload').
4. Continue as Seal from step 4, using the fresh DEK, A_new, req, T_new.

Use Reseal when:

- T = ResealRequired(e_after) and e_open > e_after.
- Policy mandates fresh ciphertext after suspected payload-layer compromise.

## 16. Revocation and Recovery

Revoke(stamp, e):

1. Add stamp to V_e and recompute Rev_e.
2. Optionally remove corresponding h_cap from L_e and recompute R_e.
3. Publish revocation metadata in log for epoch e.

Compromise recovery:

1. Detect compromised epoch signer at e_bad.
2. Create recovery epoch e_recover = e_bad + 1 with fresh keyset.
3. Publish signed compromise notice from offline root:

CompromiseNotice fields:

- compromised_epoch_pk: pk_A_e_bad
- compromised_epoch: e_bad
- recovery_authority_root: R_recover
- signature: Sign(sk_A_off, "ARC-COMPROMISE-v1" || pk_A_e_bad || e_bad_le64 || R_recover)

The signing input is a raw concatenation.  Integer fields are unsigned 64-bit little-endian.

Compromise check predicate:

CheckCompromise(e, pk_A_e, notice) -> accept | reject

  Reject iff:
    notice.compromised_epoch_pk = pk_A_e
    AND e >= notice.compromised_epoch

  Accept otherwise.

Historical opens at epochs strictly before notice.compromised_epoch remain valid.
Only uses of pk_A_e_bad at or after the declared boundary epoch are rejected.

Enforcement flow (integrated into the Open predicate):

If a CompromiseNotice is available:

1. Verify notice signature: SIG.Verify(pk_A_off, notice.signature, m) = 1,
   where m = "ARC-COMPROMISE-v1" || pk_A_e_bad || e_bad_le64 || R_recover.
   Reject if verification fails.
2. Require CheckCompromise(e_open, pk_A_e, notice) = accept.  Reject if compromised.
3. Continue with normal Open predicate checks.

## 17. Correctness

For all M, if all verification predicates pass and ARCObject was honestly produced by Seal, Open returns M.

Open returns reject on any failure of:

- epoch chain/signature/log verification
- temporal policy acceptance
- capability validity
- decapsulation
- authority wrapper authentication
- payload AEAD authentication

## 18. Security Model (Split Games)

ARC security is defined by separate games.

Game 1: Confidentiality (ARC-Conf)

Adversary distinguishes Seal(M0) from Seal(M1) without recipient secret key material.

Game 2: Authority Forgery (ARC-AuthForge)

Adversary outputs (cap*, proof*, A_e*, req*) such that ValidCap = 1 but capability was not honestly issued.

Game 3: Cross-Context Misuse (ARC-XCtx)

Adversary attempts to use valid authority for one object/policy/rights context to open another context.

Required property:

If context_A != context_B then chi_A != chi_B, implying KEK_A != KEK_B except negligible probability.

Game 4: Stale Replay (ARC-Stale)

Adversary replays old capability or wrapper under later epoch contrary to TemporalPolicy.

Required property:

TemporalAccept and current authority checks reject stale openings when policy demands current validity.

Game 5: Epoch Key Compromise (ARC-Compromise)

Adversary A receives sk_A_e_bad (the epoch online signing key for epoch e_bad).
A wins if it produces a valid Open output for any object whose effective opening
epoch is >= e_bad, when a valid CompromiseNotice for e_bad has been published
and CheckCompromise enforcement is active.

Required property:

Adv_ARC_Compromise(A) <= negl(lambda)

Intuition: sk_A_e_bad enables forgery of issuance signatures for epoch e_bad.
CheckCompromise bounds the damage to that epoch boundary.  Historical objects
at epochs strictly before e_bad retain distinct chi_e contexts and are not
directly attacked.  Epochs after e_bad use fresh key material not derived
from sk_A_e_bad.

## 19. Authority-Bound Confidentiality Law

Recover(M) iff all required predicates hold:

- KeyValid
- RootValid
- TemporalAccept
- ValidCap
- DEKUnwrapValid
- PayloadAuthValid

ValidEpochRoot(R_e, Rev_e, e, pk_A_off, cert_e, sigma_e, log_proof) = 1 iff all hold:

1. SIG.Verify(pk_A_off, cert_e.sig,
     "ARC-EPOCH-KEY-v1" || cert_e.pk_A_e || e_le64 || cert_e.validity_window_le64) = 1
2. TSIG.Verify(t-of-n, cert_e.pk_A_e, sigma_e,
     "ARC-EPOCH-ROOT-v1" || R_e || Rev_e || e_le64 || prev_epoch_hash) = 1
3. MerkleVerify(log_proof, Log_e_root,
     H(R_e || Rev_e || e_le64 || cert_e.pk_A_e || sigma_e)) = 1

Expanded opening law:

Open(ARCObject) = M
iff
ValidEpochRoot(R_e, Rev_e, e, pk_A_off, cert_e, sigma_e, log_proof) = 1
and TemporalAccept(T, e_open, e_seal) = 1
and ValidCap(cap, proof, A_e, req) = 1
and KEK_e derives correctly from ss_H and chi_e
and DEK = AEAD.Dec(KEK_e, WrappedDEK_e, AAD_authority)
and M = AEAD.Dec(DEK, C_payload, AAD_payload)

## 20. Reduction Sketch

ARC advantage is bounded by terms from:

- classical KEM IND-CCA security
- PQ KEM IND-CCA security
- KDF pseudorandomness
- AEAD IND-CCA security
- signature EUF-CMA security
- threshold-signature security
- hash collision resistance
- Merkle proof soundness
- transparency log append-only and inclusion soundness
- non-revocation proof soundness

plus negligible slack.

## 21. Honest Threat Model

ARC is designed to protect against:

- key-only access without valid authority
- authority-only access without recipient keys
- cross-object and cross-policy capability misuse
- stale replay under Current and Window policy modes
- storage-provider compromise with ciphertext exfiltration

ARC does not protect against:

- recipient key compromise combined with valid capability compromise
- malicious authorized decryptor plaintext exfiltration
- full threshold authority quorum compromise
- endpoint compromise after successful decryption
- weak randomness or side-channel leakage in implementations

## 22. Claims Discipline

Correct claim:

ARC requires both cryptographic possession and valid authority for decryption, with authority bound to signed, transparent, epoch-scoped roots.

Avoid claim:

ARC remains secure against all compromise classes, including recipient key plus valid authority compromise.

## 23. Summary

ARC does not only encrypt data.

ARC encrypts payloads under random DEKs, then binds DEK access to cryptographically verified authority state.

That preserves the core novelty while making compromise handling, temporal behavior, and operational rekeying explicit and implementable.

## 24. Reference Implementation Notes (Rust, Development Stage)

This repository includes a Rust implementation that validates ARC semantics
and exercises the full capability and authority chain end to end.

Scope of current code:

- DEK plus authority-wrapper architecture (§11, §13, §14)
- Temporal policies and wrapper epoch selection (§10)
- ValidCap checks 1, 2, 3, 4, 5, 6, 7 — all implemented with real cryptography (§9)
- Rewrap path for epoch transitions — add_epoch_wrapper (§15)
- Epoch key certificate chain — issue and verify, ed25519 (§7)
- Merkle capability inclusion proofs — generate and verify (§9 check 1)
- Sorted Merkle non-revocation witnesses — generate and verify (§9 check 2)
- Capability issuance signatures — sign and verify under epoch cert chain (§9 check 7)
- Synchronous and async transparency log trait model, InMemoryTransparencyLog (§8)
- Synchronous and async capability revocation and transparency state commit (§16)
- CompromiseNotice — issue, verify, and CheckCompromise enforcement (§16)
- Canonical domain-separated signing transcripts for all operations (§25)
- Pluggable authority verifier: BasicAuthorityVerifier and CryptoAuthorityVerifier

Out of scope for current code:

- Production threshold signature stack (single-signer epoch root only; TSIG not implemented)
- Production transparency proof verifier (Merkle path not verified by default verifier)
- Finalized binary canonical encoding (format not yet stabilized)
- Delegation flow (delegation_depth and parent_stamp fields reserved; depth > 0 not enforced)
- Reseal with DEK rotation (Rewrap only; full reseal path not wired)
- Side-channel and constant-time audit

Conformance intent:

The Rust implementation is a spec-aligned prototype for testing and design
iteration, not for security-critical deployment.

## 25. Canonical Domain-Separated Signing Transcripts

This section collects every signing and hashing message format used in ARC.
Each transcript begins with a versioned ASCII domain separator that ensures
distinct inputs across operation types.  All integer fields are unsigned 64-bit
little-endian.  Signing inputs are raw concatenated byte strings; the signature
scheme (ed25519) applies SHA-512 internally — no additional pre-hash is applied.

### 25a. Capability leaf hash (§5)

h_cap = H(
  "ARC-CAPABILITY-LEAF-v1" ||
  version || subject || object || rights || policy_hash ||
  epoch_start_le64 || epoch_end_le64 ||
  delegation_depth_le64 || parent_stamp || nonce
)

### 25b. Capability stamp (§5)

stamp_e = H(
  "ARC-CAPABILITY-STAMP-v1" || h_cap || R_e || e_le64 || a
)

### 25c. Context hash (§11)

chi_e = H(
  "ARC-CONTEXT-v1" ||
  version || suite || subject || object || required_rights || policy_hash ||
  e_le64 || R_e || Rev_e || stamp_e || a || TemporalPolicy
)

### 25d. Authority digest (§11)

kappa_e = HKDF-Extract(
  salt = H("ARC-AUTHORITY-DIGEST-v1" || R_e || Rev_e || e_le64 || policy_hash || a),
  ikm  = ss_H || chi_e
)

### 25e. Epoch key certificate (§7)

m_cert_e = "ARC-EPOCH-KEY-v1" || pk_A_e || e_le64 || validity_window_le64
cert_e   = Sign(sk_A_off, m_cert_e)

### 25f. Epoch root signature (§7)

m_root_e = "ARC-EPOCH-ROOT-v1" || R_e || Rev_e || e_le64 || prev_epoch_hash
sigma_e  = TSIG.Sign(t-of-n, m_root_e)

### 25g. Capability issuance signature (§7)

m_issue     = "ARC-ISSUANCE-v1" || h_cap || R_e || e_le64
sigma_issue = Sign(sk_A_e, m_issue)

### 25h. CompromiseNotice signature (§16)

m_notice = "ARC-COMPROMISE-v1" || pk_A_e_bad || e_bad_le64 || R_recover
CompromiseNotice.signature = Sign(sk_A_off, m_notice)

### 25i. Transparency log chain (§8)

Log_e = H(Log_(e-1) || R_e || Rev_e || e_le64 || pk_A_e || sigma_e)

For the genesis epoch, Log_0 = H("ARC-LOG-GENESIS-v1" || R_0 || Rev_0 || 0_le64 || pk_A_0 || sigma_0).

### Domain separator uniqueness

All domain separators are distinct ASCII strings.  Collision between any two
transcript formats is computationally infeasible given hash collision resistance.
Adding a new operation type requires a fresh, never-previously-used separator.
