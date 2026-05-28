use arc_core::{
    AuthorityCapabilityTree, AuthorityRootKeyPair, AuthorityState, Capability,
    CapabilityIssuanceProof, CapabilityProof, EpochSigningKeyPair, Rights, capability_leaf_hash,
    capability_stamp,
};

use super::request_builders::DEFAULT_OBJECT_ID;

pub struct TestAuthority {
    root_kp: AuthorityRootKeyPair,
    pub epoch_kp: EpochSigningKeyPair,
    pub epoch_cert: arc_core::EpochKeyCert,
    pub tree: AuthorityCapabilityTree,
}

impl TestAuthority {
    pub fn new_for_cap(cap: &Capability, epoch: u64) -> Self {
        let mut rng = rand::rngs::OsRng;
        let root_kp = AuthorityRootKeyPair::generate(&mut rng);
        let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
        let epoch_pk = epoch_kp.verifying_key_bytes();
        let epoch_cert = root_kp.issue_epoch_cert(&epoch_pk, epoch, 10);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(cap);
        Self {
            root_kp,
            epoch_kp,
            epoch_cert,
            tree,
        }
    }

    pub fn root_pk(&self) -> [u8; 32] {
        self.root_kp.verifying_key_bytes()
    }

    pub fn authority_root(&self) -> [u8; 32] {
        self.tree.authority_root()
    }

    pub fn revocation_root(&self) -> [u8; 32] {
        self.tree.revocation_root()
    }

    pub fn build_proof_for_state(
        &self,
        cap: &Capability,
        state: &AuthorityState,
    ) -> CapabilityProof {
        let inclusion = self.tree.inclusion_proof(cap).expect("cap must be in tree");
        let stamp = capability_stamp(cap, state);
        let non_revocation = self
            .tree
            .non_revocation_witness(&stamp)
            .expect("cap must not be revoked");
        let leaf_hash = capability_leaf_hash(cap);
        let sig = self.epoch_kp.sign_capability_issuance(
            &leaf_hash,
            &state.authority_root,
            self.epoch_cert.epoch,
        );
        CapabilityProof {
            inclusion,
            non_revocation,
            issuance: CapabilityIssuanceProof {
                sig,
                epoch_cert: self.epoch_cert.clone(),
            },
        }
    }
}

pub fn sample_cap(epoch_start: u64, epoch_end: u64, policy_hash: [u8; 32]) -> Capability {
    Capability {
        version: 1,
        subject: "keefe".to_string(),
        object_id: DEFAULT_OBJECT_ID.to_string(),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash,
        epoch_start,
        epoch_end,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce: [7u8; 16],
    }
}
