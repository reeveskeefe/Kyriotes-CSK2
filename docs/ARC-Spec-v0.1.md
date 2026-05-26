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
  epoch_start || epoch_end || delegation_depth || parent_stamp || nonce
)

Capability stamp at epoch e:

stamp_e = H("ARC-CAPABILITY-STAMP-v1" || h_cap || R_e || e || a)

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

cert_e = Sign(sk_A_off, H("ARC-EPOCH-KEY-v1" || pk_A_e || e || validity_window))

Epoch root signature:

sigma_e = TSIG.Sign(t-of-n, H("ARC-EPOCH-ROOT-v1" || R_e || Rev_e || e || prev_epoch_hash))

Security consequence:

Leak(sk_A_e) compromises epoch e scope, not all historical epochs.

## 8. Transparency Log

Each epoch root is committed to an append-only transparency log.

Log_e = H(Log_(e-1) || R_e || Rev_e || e || pk_A_e || sigma_e)

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
7. Issuance signature verifies under authority chain for epoch e_req.

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

Reseal and rewrap are explicit operations:

- Rewrap updates authority wrappers for new epoch or recipient authority state.
- Reseal may rotate DEK and regenerate payload ciphertext when policy requires.

Practical default:

- Keep C_payload unchanged.
- Replace or add WrappedDEK_(e_new) wrappers.

## 16. Revocation and Recovery

Revoke(stamp, e):

1. Add stamp to V_e and recompute Rev_e.
2. Optionally remove corresponding h_cap from L_e and recompute R_e.
3. Publish revocation metadata in log for epoch e.

Compromise recovery:

1. Detect compromised epoch signer at e_bad.
2. Create recovery epoch e_recover = e_bad + 1 with fresh keyset.
3. Publish signed compromise notice from offline root:

CompromiseNotice = Sign(sk_A_off, H("ARC-COMPROMISE-v1" || pk_A_e_bad || e_bad || R_recover))

Clients reject compromised signer roots beyond declared boundary.

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

## 19. Authority-Bound Confidentiality Law

Recover(M) iff all required predicates hold:

- KeyValid
- RootValid
- TemporalAccept
- ValidCap
- DEKUnwrapValid
- PayloadAuthValid

Expanded opening law:

Open(ARCObject) = M
iff
ValidEpochRoot(R_e, Rev_e, e) = 1
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

This repository includes a development-stage Rust implementation scaffold intended to validate ARC semantics before production hardening.

Scope of current code:

- DEK plus authority-wrapper architecture
- temporal policies and wrapper epoch selection
- capability and authority precondition checks
- rewrap path for epoch transitions
- canonical framing for hashed and AAD transcripts
- pluggable authority verifier hook for epoch-chain, cert, and transparency checks

Out of scope for current code:

- production threshold signature stack
- production transparency proof verifier
- finalized binary canonical encoding
- side-channel and constant-time audit

Conformance intent:

The Rust implementation should be treated as a spec-aligned prototype. It is for testing and design iteration, not security-critical deployment.
