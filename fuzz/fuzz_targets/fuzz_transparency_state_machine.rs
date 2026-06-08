#![no_main]

use kyriotes_csk2::{
    transparency_leaf_hash, AuthorityState, InMemoryTransparencyLog, TransparencyLog,
};
use libfuzzer_sys::fuzz_target;

const MAX_STATES: usize = 16;

fn seed32(data: &[u8], offset: usize, domain: u8) -> [u8; 32] {
    let mut out = [domain; 32];
    if offset < data.len() {
        let take = (data.len() - offset).min(32);
        out[..take].copy_from_slice(&data[offset..offset + take]);
    }
    out
}

fn state_for(data: &[u8], index: usize) -> AuthorityState {
    AuthorityState {
        authority_root: seed32(data, index.wrapping_mul(7), 0x11),
        revocation_root: seed32(data, index.wrapping_mul(11), 0x22),
        transparency_root: [0u8; 32],
        epoch: index as u64,
        authority_id: format!("fuzz-authority-{}", data.first().copied().unwrap_or(0)),
        root_pk: seed32(data, index.wrapping_mul(13), 0x33),
        revocation_count: kyriotes_csk2_fuzz::bytes_to_u64(data.get(index..).unwrap_or_default())
            % 64,
        prev_epoch_hash: seed32(data, index.wrapping_mul(17), 0x44),
    }
}

fuzz_target!(|data: &[u8]| {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let state_count = (data.first().copied().unwrap_or(0) as usize % MAX_STATES) + 1;
    let mut log = InMemoryTransparencyLog::new();
    let mut committed = Vec::with_capacity(state_count);

    for index in 0..state_count {
        let state = state_for(data, index);
        let leaf = transparency_leaf_hash(&state);
        let before_root = log.current_root();
        let first = log
            .commit_state(&state)
            .expect("fresh authority/epoch pair must commit");

        assert_eq!(first.proof.leaf_hash, leaf);
        assert_eq!(first.state.transparency_root, log.current_root());
        assert_eq!(
            log.proof_for_state(&first.state)
                .expect("committed state must have a proof"),
            first.proof
        );

        let second = log
            .commit_state(&state)
            .expect("identical commit must be idempotent");
        assert_eq!(second, first);
        assert_eq!(log.current_root(), first.state.transparency_root);

        if index > 0 {
            assert_ne!(
                before_root,
                log.current_root(),
                "appending a distinct leaf should change the Merkle root"
            );
        }
        committed.push((state, first));
    }

    let conflict_index = data.get(1).copied().unwrap_or(0) as usize % committed.len();
    let (original, commit) = &committed[conflict_index];
    let proof_before_conflict = log
        .proof_for_state(&commit.state)
        .expect("committed state must have a current proof");
    let root_before_conflict = log.current_root();
    let mut conflicting = original.clone();
    conflicting.authority_root[0] ^= 1;
    assert!(
        log.commit_state(&conflicting).is_err(),
        "same authority/epoch with a different leaf must reject"
    );
    assert_eq!(
        log.proof_for_state(&commit.state)
            .expect("conflict rejection must preserve prior entry"),
        proof_before_conflict
    );
    assert_eq!(log.current_root(), root_before_conflict);

    let mut unknown = original.clone();
    unknown.epoch = unknown.epoch.wrapping_add(state_count as u64 + 1);
    assert!(
        log.proof_for_state(&unknown).is_err(),
        "uncommitted authority/epoch must not produce a proof"
    );
});
