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

use super::capability::{sample_cap, sample_proof};
use super::request_builders::{policy_hash, sample_req};
use super::state::sample_state;
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
    log: InMemoryTransparencyLog,
}

impl Scenario {
    pub fn baseline(policy_label: &str, epoch: u64) -> Self {
        Self::try_baseline(policy_label, epoch).expect("baseline scenario should be constructible")
    }

    pub fn try_baseline(policy_label: &str, epoch: u64) -> Result<Self, ArcError> {
        let p_hash = policy_hash(policy_label);
        let mut log = InMemoryTransparencyLog::new();

        let seal_seed = sample_state(epoch);
        let (seal_state, seal_transparency_proof) = commit_state(&mut log, &seal_seed)?;

        let open_seed = sample_state(epoch);
        let (open_state, open_transparency_proof) = commit_state(&mut log, &open_seed)?;

        Ok(Self {
            keypair: RecipientKeyPair::generate(&mut rand::rngs::OsRng),
            seal_state,
            open_state,
            seal_transparency_proof,
            open_transparency_proof,
            cap: sample_cap(40, 60, p_hash),
            proof: sample_proof(),
            req: sample_req(epoch, p_hash),
            temporal_policy: TemporalPolicy::Historical(epoch),
            message: b"payload".to_vec(),
            log,
        })
    }

    pub fn with_open_epoch(mut self, epoch: u64) -> Self {
        let open_seed = sample_state(epoch);
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
        self.proof.non_revoked = false;
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
