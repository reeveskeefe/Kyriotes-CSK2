# ARC Rust Usage Guide

This guide shows how to use the current ARC Rust implementation end to end.

Scope of this guide:

- local development usage (crate is not published yet)
- sealing and opening data
- authority wrapper rewrap across epochs
- wire encoding and decoding
- decode limit profiles and env/CLI profile selection
- diagnosing failures and error mapping

How to read this guide:

- each section starts with plain-language intent
- code blocks are complete snippets you can adapt
- after each snippet, there is guidance on what to customize first

## Core concepts

Capability is a signed permission object that says subject X may exercise rights Y on object Z between epochs A and B. It is not a token you pass around freely. It is a cryptographic claim that must be verified against an authority root.

Authority state is a snapshot of who is authorized at a specific epoch. It contains the Merkle root of active capabilities, the revocation root, and the epoch number. Decryption is bound to this state.

Epoch is a numbered time window. Authority state advances through epochs. Whether an old object can be opened at a new epoch depends entirely on its temporal policy.

Temporal policy is the rule baked into a sealed object that says when it can be opened. Historical means only at the epoch it was sealed. Current means only under the live authority state. Window means within a bounded range (not demonstrated in code examples in this guide yet).

DEK and KEK are a two-layer model. The payload is encrypted with a random data encryption key (DEK). The DEK is wrapped by a key-encryption key (KEK) derived from authority context. Opening requires unwrapping the DEK first, then decrypting the payload. This is why rewrap is cheap. You rotate the wrapper, not the payload.

Shared secret in the current API is the caller-provided 32-byte input used to derive wrapping keys in both `seal` and `open`. In a real deployment this should come from your key establishment or key management layer (for example KEM output or a securely provisioned symmetric secret), not from a hardcoded constant.

## IMPORTANT: Development stage

This implementation is not production-ready cryptography. The authority validation booleans in examples are stubs. Before production use, plan for external cryptographic review, side-channel analysis, and real verifier integrations.

## Before you write any code

What are you trying to do?

Seal data for the first time
  -> Minimal Seal/Open example

Open data sealed by someone else
  -> Minimal Seal/Open example (open path)

Transition an object to a new epoch
  -> Rewrap for newer authority epoch

Persist or transmit an ARC object
  -> Wire format encode/decode

Handle untrusted input from the network
  -> Sections 7 or 8 (Decode limits or Decode profiles), then Section 6 (Wire format encode/decode)

## 1. Prerequisites

- Rust toolchain installed
- Clone this repository
- Run tests once to verify your environment:

```bash
cargo test
```

## 2. Add ARC in your app (local path)

Because the crate is not published, use a path dependency.

Why this matters:

- this keeps your app pinned to your local ARC workspace
- you can iterate rapidly without publishing versions
- your app will build against whatever commit you currently have checked out

```toml
# Cargo.toml
[dependencies]
arc_core = { path = "../ARC" }
```

Adjust the path for your workspace layout.

If your app and ARC live in different folders, update the path string to the relative location of this repository.

## 3. Minimal Seal/Open example (annotated)

This is the smallest realistic flow:

1. define authority state for the current epoch
2. define capability plus proof
3. define a request for object and rights
4. seal bytes into an ARC object
5. open with matching authority and capability context

When this example fails, the error usually points directly to a mismatch in object, rights, policy, or epoch.

```rust
use arc_core::{
    hash_policy, open, seal, ArcError, AuthorityState, Capability, CapabilityProof,
    OpenRequest, Rights, TemporalPolicy,
};

fn example() -> Result<Vec<u8>, ArcError> {
    // Demo placeholder secret.
    // In production derive or load this from your key management flow.
    let shared_secret = [42u8; 32];

    // hash_policy hashes a human-readable policy string into the 32-byte
    // policy_hash used throughout ARC. Use a consistent string per policy.
    let policy_hash = hash_policy("only-valid-current-capability");

    // Stage 1: Define the authority state for the current epoch.
    // In production, these roots come from your transparency log and verifier.
    // The boolean fields are production stubs. Replace with real verifier calls.
    let state = AuthorityState {
        authority_root: [1u8; 32],
        revocation_root: [2u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,        // stub: replace with real epoch signature check
        epoch_key_cert_valid: true,         // stub: replace with real cert chain check
        transparency_inclusion_valid: true, // stub: replace with real log proof check
    };

    // Stage 2: Define the capability.
    // This says subject "keefe" may READ and DECRYPT "research-notes.pdf"
    // between epochs 40 and 60, under this policy hash.
    let cap = Capability {
        subject: "keefe".to_string(),
        object_id: "research-notes.pdf".to_string(),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash,
        epoch_start: 40,
        epoch_end: 60,
        // Generate randomly per capability in production.
        nonce: [7u8; 16],
    };

    // Stage 3: Define proof that capability is currently valid.
    // In production these come from Merkle inclusion and revocation verification.
    // These booleans are stubs.
    let proof = CapabilityProof {
        inclusion_valid: true,        // stub: Merkle path check
        non_revoked: true,            // stub: revocation witness check
        issued_signature_valid: true, // stub: authority signature check
    };

    // Stage 4: Define the open request.
    // Must match capability object, required rights, policy hash, and epoch.
    let req = OpenRequest {
        object_id: "research-notes.pdf".to_string(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: 42,
    };

    // Stage 5: Seal and open.
    let object = seal(
        &shared_secret,
        b"secret bytes",
        &cap,
        &proof,
        &state,
        &req,
        // Historical(42) means opening is pinned to epoch 42 specifically.
        TemporalPolicy::Historical(42),
    )?;

    // open() does not take OpenRequest directly.
    // Request context is reconstructed from ArcObject fields.
    let plaintext = open(&shared_secret, &object, &cap, &proof, &state)?;

    // Empty plaintext is valid: Ok(vec![]) means authenticated empty content.
    // Treat Err(_) as failure and Ok(_) as successful authenticated bytes.
    Ok(plaintext)
}
```

What to customize first in real usage:

- `object_id`: set this to your actual object namespace key
- `rights`: keep minimal rights for least privilege
- `epoch_start` and `epoch_end`: bound capability lifetime tightly
- authority validation booleans: replace with production verifier integrations

## 4. Rewrap for newer authority epoch

For current-authority mode, opening at a later epoch requires a wrapper for that epoch.

When you seal with `TemporalPolicy::Current`, the DEK wrapper is bound to the authority state at sealing time. At epoch 50, that wrapper is unreadable because the authority context changed. `add_epoch_wrapper` decrypts the DEK using the old authority state and re-wraps it under the new one, without touching the payload ciphertext. The object then carries two wrappers, one for epoch 42 and one for epoch 50.

Why rewrap exists:

- payload ciphertext can remain unchanged
- only the authority-bound DEK wrapper needs updating
- this makes epoch transitions much cheaper than full reseal

```rust
use arc_core::{
    add_epoch_wrapper, open, seal, ArcError, AuthorityState, Capability,
    CapabilityProof, OpenRequest, Rights, TemporalPolicy, hash_policy,
};

fn rewrap_example() -> Result<Vec<u8>, ArcError> {
    // Demo placeholder secret.
    // In production derive or load this from your key management flow.
    let shared_secret = [9u8; 32];
    let policy_hash = hash_policy("current-only");

    // Stage 1: Authority state at sealing epoch (42).
    // Booleans are stubs. Replace with real verifier outputs.
    let state42 = AuthorityState {
        authority_root: [42u8; 32],
        revocation_root: [43u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,        // stub: real epoch signature validation
        epoch_key_cert_valid: true,         // stub: real cert-chain validation
        transparency_inclusion_valid: true, // stub: real transparency proof validation
    };

    // Stage 2: Authority state at opening epoch (50).
    // This is the target state for the new wrapper.
    let state50 = AuthorityState {
        authority_root: [50u8; 32],
        revocation_root: [51u8; 32],
        epoch: 50,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,        // stub: real epoch signature validation
        epoch_key_cert_valid: true,         // stub: real cert-chain validation
        transparency_inclusion_valid: true, // stub: real transparency proof validation
    };

    let cap = Capability {
        subject: "keefe".to_string(),
        object_id: "research-notes.pdf".to_string(),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash,
        epoch_start: 40,
        epoch_end: 60,
        // Generate randomly per capability in production.
        nonce: [1u8; 16],
    };

    // Stage 3: Capability proof values. These are stubs.
    let proof = CapabilityProof {
        inclusion_valid: true,        // stub: Merkle inclusion verification
        non_revoked: true,            // stub: revocation witness verification
        issued_signature_valid: true, // stub: authority issuance signature verification
    };

    let req42 = OpenRequest {
        object_id: "research-notes.pdf".to_string(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: 42,
    };

    // Stage 4: Seal under epoch 42 current-authority context.
    let mut object = seal(
        &shared_secret,
        b"draft-v1",
        &cap,
        &proof,
        &state42,
        &req42,
        // Current has no epoch argument because it follows live authority state.
        TemporalPolicy::Current,
    )?;

    // Stage 5: Rewrap DEK for epoch 50 without rewriting payload ciphertext.
    // Argument order: old authority state first, target epoch state second.
    add_epoch_wrapper(
        &shared_secret,
        &mut object,
        &cap,
        &proof,
        &state42,
        &state50,
    )?;

    let opened = open(&shared_secret, &object, &cap, &proof, &state50)?;
    Ok(opened)
}
```

What to customize first:

- replace `state42` and `state50` roots with your authority state provider
- replace proof booleans with your verifier integration
- ensure epoch rollover jobs call `add_epoch_wrapper` before readers at the new epoch open

## 5. Diagnosing failures

Treat these as diagnostics, not just failures. They usually map directly to one class of integration mismatch.

- `ArcError::InvalidCapability("object mismatch")`
  - request object does not match capability object
- `ArcError::InvalidCapability("policy hash mismatch")`
  - request policy hash differs from capability policy hash
- `ArcError::InvalidCapability("capability revoked")`
  - proof indicates capability is revoked
- `ArcError::TemporalRejected`
  - temporal policy does not allow opening in current epoch
- `ArcError::MissingWrapper`
  - required epoch wrapper not present
- `ArcError::AuthorityState(...)`
  - authority chain, cert, transparency, or context checks failed
- `ArcError::Parse(...)`
  - malformed wire payload or decode limit exceeded

## 6. Wire format encode/decode

Use these APIs for transport or storage.

Use cases:

- persist ARC objects in databases or object stores
- send ARC objects over message queues
- bridge ARC objects between services

```rust
use arc_core::{decode_arc_object, encode_arc_object, ArcError, ArcObject};

fn wire_roundtrip(object: &ArcObject) -> Result<ArcObject, ArcError> {
    let bytes = encode_arc_object(object);
    decode_arc_object(&bytes)
}
```

Decode defensively in service boundaries and prefer explicit limits for untrusted input.

Object and encoding notes:

- `ArcObject` is `Clone`, so cloning in memory is supported.
- `ArcObject` is not `serde` serializable by default in this implementation.
- `encode_arc_object` is deterministic for identical field values and wrapper order.

## 7. Decode limits (default and custom)

`decode_arc_object` uses strict defaults.

If you need tuning, call `decode_arc_object_with_limits`.

When to tune limits:

- your deployment has strict memory ceilings
- your payload size profile is known and bounded
- you need different limits across edge, worker, and backend tiers

```rust
use arc_core::{decode_arc_object_with_limits, DecodeLimits, ArcError, ArcObject};

fn decode_with_custom_limits(bytes: &[u8]) -> Result<ArcObject, ArcError> {
    let limits = DecodeLimits {
        max_payload_ciphertext_len: 32 * 1024 * 1024,
        max_wrapped_dek_len: 8 * 1024,
        ..DecodeLimits::default()
    };

    decode_arc_object_with_limits(bytes, limits)
}
```

Practical advice:

- start with defaults
- tighten limits where possible
- only relax a field after measuring real workloads

Defensive decode pattern in services:

```rust
use arc_core::{decode_arc_object_with_limits, ArcError, DecodeProfile};

fn decode_untrusted(bytes: &[u8]) -> Result<(), ArcError> {
    let limits = DecodeProfile::Strict.limits();

    match decode_arc_object_with_limits(bytes, limits) {
        Ok(_obj) => {
            // Continue with capability and authority validation.
            Ok(())
        }
        Err(ArcError::Parse(msg)) => {
            // Reject malformed or oversized input at the boundary.
            eprintln!("rejecting ARC payload at decode boundary: {msg}");
            Err(ArcError::Parse(msg))
        }
        Err(other) => Err(other),
    }
}
```

## 8. Decode profiles for deployments

Named profiles map to concrete limits:

| Profile | Max payload | Max wrappers | Max wrapped DEK | Intended for |
|---|---:|---:|---:|---|
| Embedded | 256 KiB | 16 | 512 B | constrained devices |
| Strict | 8 MiB | 1024 | 4 KiB | most service deployments |
| Server | 64 MiB | 8192 | 16 KiB | high-throughput backends |

Example:

```rust
use arc_core::{decode_arc_object_with_limits, DecodeProfile, ArcError, ArcObject};

fn decode_server_profile(bytes: &[u8]) -> Result<ArcObject, ArcError> {
    decode_arc_object_with_limits(bytes, DecodeProfile::Server.limits())
}
```

## 9. Env/CLI profile loading

`decode_profile_from_env` returns `Strict` when the env var is missing or invalid.

This gives you a secure fallback posture for misconfigured environments.

Recommended deployment pattern:

1. set `ARC_DECODE_PROFILE` per environment
2. log the resolved profile at process start
3. monitor parse failures and limit rejections

```rust
use arc_core::{decode_arc_object_with_limits, decode_profile_from_env, ArcError, ArcObject};

fn decode_from_env(bytes: &[u8]) -> Result<ArcObject, ArcError> {
    let profile = decode_profile_from_env("ARC_DECODE_PROFILE");
    decode_arc_object_with_limits(bytes, profile.limits())
}
```

Behavior summary:

- if `ARC_DECODE_PROFILE` is unset: `Strict`
- if it is set to an unknown value: `Strict`
- if it is set to a recognized value: parsed profile is used

Accepted values (case-insensitive, trims whitespace):

- embedded, embed
- strict, default
- server, srv

## 10. Transparency backends

ARC defines two traits for plugging in your own transparency log service:

| Trait | Use when |
|---|---|
| `TransparencyLog` | Synchronous or in-process log (e.g. `InMemoryTransparencyLog`) |
| `AsyncTransparencyLog` | Network-backed log (Rekor, Certificate Transparency, etc.) |

Both traits expose the same three operations:

```rust
async fn commit_state(&mut self, state: &AuthorityState) -> Result<TransparencyStateCommit, ArcError>;
async fn proof_for_state(&self, state: &AuthorityState) -> Result<TransparencyProof, ArcError>;
async fn current_root(&self) -> [u8; 32];
```

`InMemoryTransparencyLog` implements both out of the box, so you can run
the full seal/open flow in tests and development with no extra setup.

### Implementing a real backend

To plug in a real log service, implement `AsyncTransparencyLog` for your
client type:

```rust
use arc_core::{ArcError, AsyncTransparencyLog, AuthorityState, TransparencyProof, TransparencyStateCommit};
use async_trait::async_trait;

pub struct RekorTransparencyLog {
    base_url: String,
    // your HTTP client, auth tokens, etc.
}

#[async_trait]
impl AsyncTransparencyLog for RekorTransparencyLog {
    async fn commit_state(&mut self, state: &AuthorityState) -> Result<TransparencyStateCommit, ArcError> {
        // POST the state to your log service, get back the Merkle proof
        todo!()
    }

    async fn proof_for_state(&self, state: &AuthorityState) -> Result<TransparencyProof, ArcError> {
        // GET proof by state leaf hash from your log service
        todo!()
    }

    async fn current_root(&self) -> [u8; 32] {
        // GET the current signed tree head from your log service
        todo!()
    }
}
```

Once implemented, drop it in anywhere `InMemoryTransparencyLog` was used —
no changes to engine, verifier, or wire-format code needed.

### What `TransparencyStateCommit` contains and how it feeds the auth flow

`commit_state` returns a `TransparencyStateCommit` with two fields:

- `state` — a copy of the input state with `transparency_root` updated to the log's current Merkle root after the commit. Use this returned state (not the original) when calling `seal` or passing state to a verifier.
- `proof` — the Merkle inclusion proof for this state in the log. Pass this as the `transparency_proof` argument to `seal`.

Set `transparency_inclusion_valid: true` on any state before committing it. The `CryptoAuthorityVerifier` uses that flag as a pre-flight check, then independently recomputes and verifies the Merkle proof from `proof.sibling_hashes` — so the boolean and the cryptographic proof must both be consistent.

### Object safety

`AsyncTransparencyLog` is object-safe. You can hold it as
`Box<dyn AsyncTransparencyLog>` and swap backends at runtime:

```rust
let log: Box<dyn AsyncTransparencyLog> = if cfg!(test) {
    Box::new(InMemoryTransparencyLog::new())
} else {
    Box::new(RekorTransparencyLog { base_url: "https://rekor.example.com".into() })
};
```

## 11. Authority capability tree and real proof construction

Sections 3 and 4 use stub booleans for `CapabilityProof`.  This section shows
how to replace them with real cryptographic proofs using the four building
blocks that implement §6, §7, and §9 of the spec.

### 11a. Building authority roots with `AuthorityCapabilityTree`

The authority root and revocation root are Merkle roots over the active
capability set and the revoked stamp set respectively.  Instead of hardcoding
byte arrays, build them from the actual capability set.

```rust
use arc_core::{
    AuthorityCapabilityTree, AuthorityState, Capability, Rights, capability_stamp, hash_policy,
};

fn build_authority_state(epoch: u64) -> (AuthorityCapabilityTree, AuthorityState) {
    let policy_hash = hash_policy("read-only-research");

    let cap = Capability {
        subject: "keefe".to_string(),
        object_id: "research-notes.pdf".to_string(),
        rights: Rights::READ,
        policy_hash,
        epoch_start: 40,
        epoch_end: 60,
        nonce: [7u8; 16],
    };

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap); // returns the 32-byte leaf hash

    let authority_root = tree.authority_root();   // MerkleRoot(L_e)
    let revocation_root = tree.revocation_root(); // MerkleRoot(V_e) — [0;32] when empty

    let state = AuthorityState {
        authority_root,
        revocation_root,
        transparency_root: [0u8; 32], // populated by transparency log commit
        epoch,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
    };

    (tree, state)
}
```

To revoke a capability, add its stamp to the tree before publishing the state:

```rust
// revoking updates revocation_root; republish the state after this call
tree.revoke_capability(&cap, &state);
let new_revocation_root = tree.revocation_root();
```

### 11b. Epoch key certificate chain (§7)

The offline root keypair signs a certificate binding the epoch online keypair
to a specific epoch.  Keep `AuthorityRootKeyPair` offline.  Use
`EpochSigningKeyPair` for all per-epoch operations.

```rust
use arc_core::{AuthorityRootKeyPair, EpochSigningKeyPair, verify_epoch_cert};
use rand::rngs::OsRng;

// Offline key — generate once, store in cold storage.
let root_kp = AuthorityRootKeyPair::generate(&mut OsRng);
let root_pk = root_kp.verifying_key_bytes();

// Epoch online key — generate fresh each epoch rotation.
let epoch_kp = EpochSigningKeyPair::generate(&mut OsRng);

// Issue a certificate binding the epoch key to epoch 42 with a validity window of 10.
let cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 42, 10);

// Verifiers authenticate the epoch key against the published root public key.
verify_epoch_cert(&root_pk, &cert).expect("cert must verify");
```

Distribute `root_pk` out-of-band (pinned in client config or hardware).  Distribute
`cert` alongside every authority state or ARC object for the epoch.

### 11c. Merkle capability inclusion proof (§9 check 1)

```rust
use arc_core::{AuthorityCapabilityTree, verify_capability_inclusion};

let mut tree = AuthorityCapabilityTree::new();
tree.add_capability(&cap);
let authority_root = tree.authority_root();

// Authority side: generate the proof for this capability.
let inclusion_proof = tree.inclusion_proof(&cap)
    .expect("capability must be in the tree");

// Verifier side: check that cap is in the tree rooted at authority_root.
verify_capability_inclusion(&cap, &inclusion_proof, &authority_root)
    .expect("inclusion proof must verify");
```

The proof carries `leaf_hash`, `sibling_hashes`, and `leaf_index`.  All three must
match the tree at the time the proof was generated.  Adding new capabilities changes
the root and invalidates old proofs — regenerate proofs after each tree mutation.

### 11d. Non-revocation witness (§9 check 2)

A sorted-Merkle non-membership proof shows that a capability stamp is absent
from `V_e` by providing the adjacent sorted boundary elements.

`NonRevocationWitness` is the proof object the authority generates and the
verifier checks.  `NonRevocationBound` is one boundary element inside it — a
stamp value plus its Merkle inclusion proof in the revocation tree.  You
never construct `NonRevocationBound` by hand; it comes out of
`non_revocation_witness`.

```rust
use arc_core::{
    AuthorityCapabilityTree, NonRevocationBound, NonRevocationWitness,
    capability_stamp, verify_non_revocation,
};

let stamp = capability_stamp(&cap, &state);

// Authority side: generate the witness (fails if cap is already revoked).
// Returns NonRevocationWitness { stamp, total_revoked, left, right }
// where left/right are Option<NonRevocationBound>.
let witness: NonRevocationWitness = tree.non_revocation_witness(&stamp)
    .expect("capability must not be revoked");

// Verifier side: check stamp is absent from the revocation tree.
verify_non_revocation(&witness, &state.revocation_root)
    .expect("non-revocation witness must verify");
```

After revoking a capability, `non_revocation_witness` returns `Err` for that
stamp and `verify_non_revocation` will reject any previously-issued witness
because the revocation root changes.

### 11e. Capability issuance proof (§9 check 7)

The epoch online key signs the capability leaf hash, binding issuance to the
authority chain.  The verifier authenticates the signing key via the epoch
cert before checking the signature.

```rust
use arc_core::{
    AuthorityCapabilityTree, AuthorityRootKeyPair, CapabilityIssuanceProof,
    EpochSigningKeyPair, capability_leaf_hash, verify_capability_issuance,
};
use rand::rngs::OsRng;

let root_kp  = AuthorityRootKeyPair::generate(&mut OsRng);
let epoch_kp = EpochSigningKeyPair::generate(&mut OsRng);

let mut tree = AuthorityCapabilityTree::new();
tree.add_capability(&cap);
let authority_root = tree.authority_root();
let epoch = 42u64;

// Authority side: sign the issuance and package the cert.
let leaf_hash = capability_leaf_hash(&cap);
let sig  = epoch_kp.sign_capability_issuance(&leaf_hash, &authority_root, epoch);
let cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), epoch, 10);
let issuance_proof = CapabilityIssuanceProof { sig, epoch_cert: cert };

// Verifier side: verify cert chain then issuance signature.
verify_capability_issuance(
    &cap,
    &authority_root,
    epoch,
    &issuance_proof,
    &root_kp.verifying_key_bytes(), // trust anchor — distribute out-of-band
)
.expect("issuance proof must verify");
```

### 11f. What to replace in production

The stub booleans in `CapabilityProof` correspond directly to the three checks above:

| Stub field | Replaced by |
|---|---|
| `inclusion_valid: true` | `verify_capability_inclusion(&cap, &inclusion_proof, &state.authority_root)` |
| `non_revoked: true` | `verify_non_revocation(&witness, &state.revocation_root)` |
| `issued_signature_valid: true` | `verify_capability_issuance(&cap, &authority_root, epoch, &issuance_proof, &root_pk)` |

Run all three checks before setting `inclusion_valid`, `non_revoked`, and
`issued_signature_valid` to `true` in your `CapabilityProof`.

## 12. Before you ship

### Choosing a temporal policy

- Use `Historical` for archives and immutable records.
- Use `Current` for active collaborative data and enforce rewrap.
- Always decode with explicit limits in service contexts.
- Prefer profile-based limits for env or CLI-driven deployments.

### Production metrics to add

For production rollout, add metrics around:

- open failures by ArcError variant
- decode rejections by limit type
- rewrap backlog and latency per epoch transition

## 13. Running checks locally

For users integrating the crate:

```bash
cargo test
```

For contributors working on this repository:

```bash
cargo fmt
cargo clippy --all-targets --all-features -D warnings
```

Integration tests to inspect for examples:

- `tests/arc_flow.rs` — end-to-end seal/open flows and epoch rewrap
- `tests/arc_guards.rs` — rejection and error-condition coverage (revocation, policy mismatches, tampering)
- `tests/arc_wire.rs` — wire-format encode/decode roundtrips and decode-limit enforcement
- `tests/arc_async_transparency.rs` — transparency log trait integration and object-safety
- `tests/arc_capability_tree.rs` — authority capability tree, inclusion proofs, non-revocation witnesses, issuance proofs
- `tests/arc_crypto_verifier.rs` — full epoch cert chain verification end-to-end

Suggested daily loop for contributors:

1. make a focused change
2. run `cargo test`
3. run formatting and lint checks
4. validate one end-to-end usage path from this guide
