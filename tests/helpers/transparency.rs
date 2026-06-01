use kyriotes_csk2::{AuthorityState, KyriotesCsk2Error, TransparencyLog, TransparencyProof};

pub fn commit_state<L: TransparencyLog>(
    log: &mut L,
    state: &AuthorityState,
) -> Result<(AuthorityState, TransparencyProof), KyriotesCsk2Error> {
    let commit = log.commit_state(state)?;
    Ok((commit.state, commit.proof))
}
