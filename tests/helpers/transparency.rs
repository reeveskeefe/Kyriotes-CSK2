use arc_core::{
    ArcError,
    AuthorityState,
    TransparencyLog,
    TransparencyProof,
};

pub fn commit_state<L: TransparencyLog>(
    log: &mut L,
    state: &AuthorityState,
) -> Result<(AuthorityState, TransparencyProof), ArcError> {
    let commit = log.commit_state(state)?;
    Ok((commit.state, commit.proof))
}
