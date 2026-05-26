#![allow(dead_code)]

use arc_core::{
    ArcError,
    AuthorityState,
    Capability,
    CapabilityProof,
    InMemoryTransparencyLog,
    OpenRequest,
    RecipientKeyPair,
    TransparencyProof,
    TemporalPolicy,
};

use super::capability::{sample_cap, TestAuthority};
use super::request_builders::{policy_hash, sample_req};
use super::transparency::commit_state;

pub struct Scenario {
    pub keypair: RecipientKeyPair,
    pub seal_state: AuthorityState,
    pub open_state: AuthorityState,
    pub seal_transparency_proof: TransparencyProof,
    pub open_transparency_proof: TransparencyProof,
    pub cap: Capability,
    pub proof: CapabilityProof,
    pub req: OpenRequest,
    pub temporal_policy: TemporalPolicy,
    pub message: Vec<u8>,
    pub authority: TestAuthority,
    log: InMemoryTransparencyLog,
}

impl Scenario {
    pub fn baseline(policy_label: &str, epoch: u64) -> Self {
        Self::try_baseline(policy_label, epoch).expect("baseline scenario should be constructible")
    }

    pub fn try_baseline(policy_label: &str, epoch: u64) -> Result<Self, ArcError> {
        let p_hash = policy_hash(policy_label);
        let mut log = InMemoryTransparencyLog::new();

        let cap = sample_cap(40, 60, p_hash);
        let authority = TestAuthority::new_for_cap(&cap, epoch);

        let seed_state = AuthorityState {
            authority_root: authority.authority_root(),
            revocation_root: authority.revocation_root(),
            transparency_root: [0u8; 32],
            epoch,
            authority_id: "auth-main".to_string(),
            epoch_signature_valid: true,
            epoch_key_cert_valid: true,
            transparency_inclusion_valid: true,
            root_pk: authority.root_pk(),
            revocation_count: 0,
        };

        let (seal_state, seal_transparency_proof) = commit_state(&mut log, &seed_state)?;
        let (open_state, open_transparency_proof) = commit_state(&mut log, &seed_state)?;

        let proof = authority.build_proof_for_state(&cap, &seal_state);
        let req = sample_req(epoch, p_hash);

        Ok(Self {
            keypair: RecipientKeyPair::generate(&mut rand::rngs::OsRng),
            seal_state,
            open_state,
            seal_transparency_proof,
            open_transparency_proof,
            cap,
            proof,
            req,
            temporal_policy: TemporalPolicy::Historical(epoch),
            message: b"payload".to_vec(),
            authority,
            log,
        })
    }

    /// Build a new AuthorityState for the same authority at a different epoch.
    /// Preserves authority_root, revocation_root, root_pk.
    pub fn make_state_at_epoch(&self, epoch: u64) -> AuthorityState {
        AuthorityState {
            authority_root: self.authority.authority_root(),
            revocation_root: self.authority.revocation_root(),
            transparency_root: [0u8; 32],
            epoch,
            authority_id: "auth-main".to_string(),
            epoch_signature_valid: true,
            epoch_key_cert_valid: true,
            transparency_inclusion_valid: true,
            root_pk: self.authority.root_pk(),
            revocation_count: self.authority.tree.revocation_count(),
        }
    }

    /// Build a real CapabilityProof for the given state using this Scenario's authority.
    pub fn build_proof_for_state(&self, state: &AuthorityState) -> CapabilityProof {
        self.authority.build_proof_for_state(&self.cap, state)
    }

    pub fn with_open_epoch(mut self, epoch: u64) -> Self {
        let open_seed = self.make_state_at_epoch(epoch);
        let (open_state, open_proof) = commit_state(&mut self.log, &open_seed)
            .expect("open epoch state should be committable to transparency log");
        self.open_state = open_state;
        self.open_transparency_proof = open_proof;
        self
    }

    pub fn with_temporal_policy(mut self, policy: TemporalPolicy) -> Self {
        self.temporal_policy = policy;
        self
    }

    pub fn with_message(mut self, message: &[u8]) -> Self {
        self.message = message.to_vec();
        self
    }

    pub fn revoked_proof(mut self) -> Self {
        self.proof.non_revocation.stamp[0] ^= 0xFF;
        self
    }

    pub fn invalid_request_epoch(mut self, epoch: u64) -> Self {
        self.req.epoch = epoch;
        self
    }

    pub fn mismatched_policy(mut self, other_policy_label: &str) -> Self {
        self.req.policy_hash = policy_hash(other_policy_label);
        self
    }

    pub fn mismatched_object(mut self, object_id: &str) -> Self {
        self.req.object_id = object_id.to_string();
        self
    }

    pub fn invalidate_seal_epoch_signature(mut self) -> Self {
        self.seal_state.epoch_signature_valid = false;
        self
    }
}
