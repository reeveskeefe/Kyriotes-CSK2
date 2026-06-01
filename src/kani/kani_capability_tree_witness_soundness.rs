#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapabilityClaim {
    subject: u8,
    rights: u8,
    policy_hash: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Capability {
    id: u8,
    subject: u8,
    rights: u8,
    policy_hash: u8,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelMerklePath {
    leaf_hash: u64,
    siblings: [u64; 2],
    len: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapabilityWitness {
    capability: Capability,
    path: ModelMerklePath,
}

type AuthorityRoot = u64;
type RevocationRoot = u64;

fn mix(a: u64, b: u64) -> u64 {
    (a << 32) ^ b
}

fn capability_leaf_hash(capability: Capability) -> u64 {
    let revoked_bit = if capability.revoked { 1 } else { 0 };
    ((capability.id as u64) << 32)
        ^ ((capability.subject as u64) << 24)
        ^ ((capability.rights as u64) << 16)
        ^ ((capability.policy_hash as u64) << 8)
        ^ revoked_bit
}

fn revocation_root_for(capability: Capability) -> RevocationRoot {
    mix(capability.id as u64, if capability.revoked { 1 } else { 0 })
}

fn compute_root(path: ModelMerklePath) -> AuthorityRoot {
    if path.len == 0 {
        0
    } else if path.len == 1 {
        mix(path.leaf_hash, path.siblings[0])
    } else {
        mix(mix(path.leaf_hash, path.siblings[0]), path.siblings[1])
    }
}

fn accepts_capability_witness(
    authority_root: AuthorityRoot,
    revocation_root: RevocationRoot,
    claim: CapabilityClaim,
    witness: CapabilityWitness,
) -> bool {
    witness.path.len > 0
        && witness.path.len <= 2
        && witness.capability.subject == claim.subject
        && witness.capability.rights == claim.rights
        && witness.capability.policy_hash == claim.policy_hash
        && !witness.capability.revoked
        && witness.path.leaf_hash == capability_leaf_hash(witness.capability)
        && compute_root(witness.path) == authority_root
        && revocation_root_for(witness.capability) == revocation_root
}

fn valid_claim() -> CapabilityClaim {
    CapabilityClaim {
        subject: 7,
        rights: 3,
        policy_hash: 11,
    }
}

fn valid_capability() -> Capability {
    Capability {
        id: 19,
        subject: 7,
        rights: 3,
        policy_hash: 11,
        revoked: false,
    }
}

fn valid_witness() -> CapabilityWitness {
    let capability = valid_capability();
    CapabilityWitness {
        capability,
        path: ModelMerklePath {
            leaf_hash: capability_leaf_hash(capability),
            siblings: [23, 29],
            len: 2,
        },
    }
}

#[kani::proof]
fn capability_tree_witness_soundness_acceptance_implies_claim_binding() {
    let claim = CapabilityClaim {
        subject: kani::any(),
        rights: kani::any(),
        policy_hash: kani::any(),
    };
    let capability = Capability {
        id: kani::any(),
        subject: kani::any(),
        rights: kani::any(),
        policy_hash: kani::any(),
        revoked: kani::any(),
    };
    let path = ModelMerklePath {
        leaf_hash: kani::any(),
        siblings: [kani::any(), kani::any()],
        len: kani::any(),
    };
    kani::assume(path.len <= 2);

    let witness = CapabilityWitness { capability, path };
    let authority_root = kani::any();
    let revocation_root = kani::any();

    kani::assume(accepts_capability_witness(
        authority_root,
        revocation_root,
        claim,
        witness,
    ));

    kani::assert(witness.path.len > 0, "accepted witness is non-empty");
    kani::assert(
        witness.capability.subject == claim.subject,
        "accepted witness binds subject",
    );
    kani::assert(
        witness.capability.rights == claim.rights,
        "accepted witness binds rights",
    );
    kani::assert(
        witness.capability.policy_hash == claim.policy_hash,
        "accepted witness binds policy hash",
    );
    kani::assert(
        !witness.capability.revoked,
        "accepted witness is not revoked",
    );
    kani::assert(
        witness.path.leaf_hash == capability_leaf_hash(witness.capability),
        "accepted witness binds capability leaf",
    );
    kani::assert(
        compute_root(witness.path) == authority_root,
        "accepted witness binds authority root",
    );
    kani::assert(
        revocation_root_for(witness.capability) == revocation_root,
        "accepted witness binds revocation root",
    );
}

#[kani::proof]
fn capability_tree_valid_non_revoked_witness_accepts() {
    let claim = valid_claim();
    let witness = valid_witness();

    kani::assert(
        accepts_capability_witness(
            compute_root(witness.path),
            revocation_root_for(witness.capability),
            claim,
            witness,
        ),
        "valid non-revoked witness accepts",
    );
}

#[kani::proof]
fn capability_tree_empty_witness_rejects() {
    let claim = valid_claim();
    let mut witness = valid_witness();
    witness.path.len = 0;

    kani::assert(
        !accepts_capability_witness(
            compute_root(valid_witness().path),
            revocation_root_for(witness.capability),
            claim,
            witness,
        ),
        "empty witness rejects",
    );
}

#[kani::proof]
fn capability_tree_wrong_subject_rejects() {
    let claim = CapabilityClaim {
        subject: valid_claim().subject.wrapping_add(1),
        ..valid_claim()
    };
    let witness = valid_witness();

    kani::assert(
        !accepts_capability_witness(
            compute_root(witness.path),
            revocation_root_for(witness.capability),
            claim,
            witness,
        ),
        "wrong subject rejects",
    );
}

#[kani::proof]
fn capability_tree_wrong_rights_rejects() {
    let claim = CapabilityClaim {
        rights: valid_claim().rights.wrapping_add(1),
        ..valid_claim()
    };
    let witness = valid_witness();

    kani::assert(
        !accepts_capability_witness(
            compute_root(witness.path),
            revocation_root_for(witness.capability),
            claim,
            witness,
        ),
        "wrong rights rejects",
    );
}

#[kani::proof]
fn capability_tree_wrong_policy_hash_rejects() {
    let claim = CapabilityClaim {
        policy_hash: valid_claim().policy_hash.wrapping_add(1),
        ..valid_claim()
    };
    let witness = valid_witness();

    kani::assert(
        !accepts_capability_witness(
            compute_root(witness.path),
            revocation_root_for(witness.capability),
            claim,
            witness,
        ),
        "wrong policy hash rejects",
    );
}

#[kani::proof]
fn capability_tree_wrong_authority_root_rejects() {
    let claim = valid_claim();
    let witness = valid_witness();

    kani::assert(
        !accepts_capability_witness(
            compute_root(witness.path).wrapping_add(1),
            revocation_root_for(witness.capability),
            claim,
            witness,
        ),
        "wrong authority root rejects",
    );
}

#[kani::proof]
fn capability_tree_revoked_capability_rejects() {
    let claim = valid_claim();
    let mut witness = valid_witness();
    witness.capability.revoked = true;
    witness.path.leaf_hash = capability_leaf_hash(witness.capability);

    kani::assert(
        !accepts_capability_witness(
            compute_root(witness.path),
            revocation_root_for(witness.capability),
            claim,
            witness,
        ),
        "revoked capability rejects",
    );
}

#[kani::proof]
fn capability_tree_rejection_is_deterministic_for_equal_invalid_inputs() {
    let claim = valid_claim();
    let mut witness = valid_witness();
    witness.path.leaf_hash = witness.path.leaf_hash.wrapping_add(1);
    let authority_root = compute_root(valid_witness().path);
    let revocation_root = revocation_root_for(witness.capability);

    let first = accepts_capability_witness(authority_root, revocation_root, claim, witness);
    let second = accepts_capability_witness(authority_root, revocation_root, claim, witness);

    kani::assert(!first, "tampered witness rejects");
    kani::assert(
        first == second,
        "equal invalid inputs reject deterministically",
    );
}
