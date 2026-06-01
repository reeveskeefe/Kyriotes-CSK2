From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy KyriotesCsk2Verify KyriotesCsk2SecurityGame KyriotesCsk2Theorems KyriotesCsk2StressProofs KyriotesCsk2DelegationProofs KyriotesCsk2CryptoReduction KyriotesCsk2TemporalProofs KyriotesCsk2TranscriptProofs KyriotesCsk2RevocationCompromiseProofs.

Record TransparencyCommit := {
  commit_authority_root : Hash;
  commit_revocation_root : Hash;
  commit_transparency_root : Hash;
  commit_epoch : Epoch;
  commit_previous_state_hash : Hash;
  commit_state_hash : Hash
}.

Definition transparency_commit_matches_state
  (commit : TransparencyCommit)
  (state : AuthorityState)
  : bool :=
  Nat.eqb (commit_authority_root commit) (authority_root state) &&
  Nat.eqb (commit_revocation_root commit) (revocation_root state) &&
  Nat.eqb (commit_transparency_root commit) (transparency_root state) &&
  Nat.eqb (commit_epoch commit) (epoch state).

Definition transparency_commit_matches_object
  (commit : TransparencyCommit)
  (obj : KyriotesCsk2Object)
  : bool :=
  Nat.eqb (commit_authority_root commit) (bound_authority_root obj) &&
  Nat.eqb (commit_revocation_root commit) (bound_revocation_root obj) &&
  Nat.eqb (commit_transparency_root commit) (bound_transparency_root obj) &&
  Nat.eqb (commit_epoch commit) (bound_epoch obj).

Definition same_transparency_epoch
  (left right : TransparencyCommit)
  : bool :=
  Nat.eqb (commit_epoch left) (commit_epoch right).

Definition same_transparency_state_hash
  (left right : TransparencyCommit)
  : bool :=
  Nat.eqb (commit_state_hash left) (commit_state_hash right).

Definition conflicting_transparency_commits
  (left right : TransparencyCommit)
  : bool :=
  same_transparency_epoch left right &&
  negb (same_transparency_state_hash left right).

Definition transparency_open_allowed
  (obj : KyriotesCsk2Object)
  (cap : Capability)
  (state : AuthorityState)
  (commit : TransparencyCommit)
  : bool :=
  verify_open_context obj cap state &&
  transparency_commit_matches_state commit state &&
  transparency_commit_matches_object commit obj.

Theorem transparency_commit_matches_state_implies_exact_state :
  forall commit state,
    transparency_commit_matches_state commit state = true ->
    commit_authority_root commit = authority_root state /\
    commit_revocation_root commit = revocation_root state /\
    commit_transparency_root commit = transparency_root state /\
    commit_epoch commit = epoch state.
Proof.
  intros commit state H.
  unfold transparency_commit_matches_state in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_auth H_rev] H_trans] H_epoch].
  repeat split; apply Nat.eqb_eq; assumption.
Qed.

Theorem transparency_commit_matches_object_implies_exact_object :
  forall commit obj,
    transparency_commit_matches_object commit obj = true ->
    commit_authority_root commit = bound_authority_root obj /\
    commit_revocation_root commit = bound_revocation_root obj /\
    commit_transparency_root commit = bound_transparency_root obj /\
    commit_epoch commit = bound_epoch obj.
Proof.
  intros commit obj H.
  unfold transparency_commit_matches_object in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_auth H_rev] H_trans] H_epoch].
  repeat split; apply Nat.eqb_eq; assumption.
Qed.

Theorem transparency_state_authority_root_mutation_rejected :
  forall commit state,
    commit_authority_root commit <> authority_root state ->
    transparency_commit_matches_state commit state = false.
Proof.
  intros commit state H.
  unfold transparency_commit_matches_state.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem transparency_state_revocation_root_mutation_rejected :
  forall commit state,
    commit_revocation_root commit <> revocation_root state ->
    transparency_commit_matches_state commit state = false.
Proof.
  intros commit state H.
  unfold transparency_commit_matches_state.
  destruct (Nat.eqb (commit_authority_root commit) (authority_root state)); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem transparency_state_transparency_root_mutation_rejected :
  forall commit state,
    commit_transparency_root commit <> transparency_root state ->
    transparency_commit_matches_state commit state = false.
Proof.
  intros commit state H.
  unfold transparency_commit_matches_state.
  destruct (Nat.eqb (commit_authority_root commit) (authority_root state)); simpl.
  - destruct (Nat.eqb (commit_revocation_root commit) (revocation_root state)); simpl.
    + apply Nat.eqb_neq in H.
      rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transparency_state_epoch_mutation_rejected :
  forall commit state,
    commit_epoch commit <> epoch state ->
    transparency_commit_matches_state commit state = false.
Proof.
  intros commit state H.
  unfold transparency_commit_matches_state.
  destruct (Nat.eqb (commit_authority_root commit) (authority_root state)); simpl.
  - destruct (Nat.eqb (commit_revocation_root commit) (revocation_root state)); simpl.
    + destruct (Nat.eqb (commit_transparency_root commit) (transparency_root state)); simpl.
      * apply Nat.eqb_neq in H.
        rewrite H.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transparency_object_authority_root_mutation_rejected :
  forall commit obj,
    commit_authority_root commit <> bound_authority_root obj ->
    transparency_commit_matches_object commit obj = false.
Proof.
  intros commit obj H.
  unfold transparency_commit_matches_object.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem transparency_object_revocation_root_mutation_rejected :
  forall commit obj,
    commit_revocation_root commit <> bound_revocation_root obj ->
    transparency_commit_matches_object commit obj = false.
Proof.
  intros commit obj H.
  unfold transparency_commit_matches_object.
  destruct (Nat.eqb (commit_authority_root commit) (bound_authority_root obj)); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem transparency_object_transparency_root_mutation_rejected :
  forall commit obj,
    commit_transparency_root commit <> bound_transparency_root obj ->
    transparency_commit_matches_object commit obj = false.
Proof.
  intros commit obj H.
  unfold transparency_commit_matches_object.
  destruct (Nat.eqb (commit_authority_root commit) (bound_authority_root obj)); simpl.
  - destruct (Nat.eqb (commit_revocation_root commit) (bound_revocation_root obj)); simpl.
    + apply Nat.eqb_neq in H.
      rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transparency_object_epoch_mutation_rejected :
  forall commit obj,
    commit_epoch commit <> bound_epoch obj ->
    transparency_commit_matches_object commit obj = false.
Proof.
  intros commit obj H.
  unfold transparency_commit_matches_object.
  destruct (Nat.eqb (commit_authority_root commit) (bound_authority_root obj)); simpl.
  - destruct (Nat.eqb (commit_revocation_root commit) (bound_revocation_root obj)); simpl.
    + destruct (Nat.eqb (commit_transparency_root commit) (bound_transparency_root obj)); simpl.
      * apply Nat.eqb_neq in H.
        rewrite H.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transparency_state_mismatch_blocks_open :
  forall obj cap state commit,
    transparency_commit_matches_state commit state = false ->
    transparency_open_allowed obj cap state commit = false.
Proof.
  intros obj cap state commit H.
  unfold transparency_open_allowed.
  destruct (verify_open_context obj cap state); simpl.
  - rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem transparency_object_mismatch_blocks_open :
  forall obj cap state commit,
    transparency_commit_matches_object commit obj = false ->
    transparency_open_allowed obj cap state commit = false.
Proof.
  intros obj cap state commit H.
  unfold transparency_open_allowed.
  destruct (verify_open_context obj cap state); simpl.
  - destruct (transparency_commit_matches_state commit state); simpl.
    + exact H.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transparency_open_implies_verified_open :
  forall obj cap state commit,
    transparency_open_allowed obj cap state commit = true ->
    verify_open_context obj cap state = true.
Proof.
  intros obj cap state commit H.
  unfold transparency_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_open H_state] H_object].
  exact H_open.
Qed.

Theorem transparency_open_implies_state_commit_match :
  forall obj cap state commit,
    transparency_open_allowed obj cap state commit = true ->
    transparency_commit_matches_state commit state = true.
Proof.
  intros obj cap state commit H.
  unfold transparency_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_open H_state] H_object].
  exact H_state.
Qed.

Theorem transparency_open_implies_object_commit_match :
  forall obj cap state commit,
    transparency_open_allowed obj cap state commit = true ->
    transparency_commit_matches_object commit obj = true.
Proof.
  intros obj cap state commit H.
  unfold transparency_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_open H_state] H_object].
  exact H_object.
Qed.

Theorem transparency_open_implies_exact_cross_binding :
  forall obj cap state commit,
    transparency_open_allowed obj cap state commit = true ->
    bound_authority_root obj = authority_root state /\
    bound_revocation_root obj = revocation_root state /\
    bound_transparency_root obj = transparency_root state /\
    bound_epoch obj = epoch state.
Proof.
  intros obj cap state commit H.
  pose proof (transparency_open_implies_verified_open obj cap state commit H) as H_open.
  apply kyriotes_csk2_verified_open_implies_exact_authority_binding with (cap := cap).
  exact H_open.
Qed.

Theorem conflicting_commits_imply_distinct_state_hashes :
  forall left right,
    conflicting_transparency_commits left right = true ->
    commit_epoch left = commit_epoch right /\
    commit_state_hash left <> commit_state_hash right.
Proof.
  intros left right H.
  unfold conflicting_transparency_commits in H.
  apply andb_true_iff in H.
  destruct H as [H_epoch H_hash].
  unfold same_transparency_epoch in H_epoch.
  unfold same_transparency_state_hash in H_hash.
  apply Nat.eqb_eq in H_epoch.
  apply negb_true_iff in H_hash.
  apply Nat.eqb_neq in H_hash.
  split; assumption.
Qed.

Theorem identical_state_hash_not_conflicting :
  forall left right,
    commit_state_hash left = commit_state_hash right ->
    conflicting_transparency_commits left right = false.
Proof.
  intros left right H.
  unfold conflicting_transparency_commits.
  unfold same_transparency_state_hash.
  rewrite H.
  rewrite Nat.eqb_refl.
  simpl.
  destruct (same_transparency_epoch left right); reflexivity.
Qed.

Theorem transparency_any_state_mutation_blocks_open :
  forall obj cap state commit,
    commit_authority_root commit <> authority_root state \/
    commit_revocation_root commit <> revocation_root state \/
    commit_transparency_root commit <> transparency_root state \/
    commit_epoch commit <> epoch state ->
    transparency_open_allowed obj cap state commit = false.
Proof.
  intros obj cap state commit H.
  apply transparency_state_mismatch_blocks_open.
  destruct H as [H_auth | [H_rev | [H_trans | H_epoch]]].
  - apply transparency_state_authority_root_mutation_rejected. exact H_auth.
  - apply transparency_state_revocation_root_mutation_rejected. exact H_rev.
  - apply transparency_state_transparency_root_mutation_rejected. exact H_trans.
  - apply transparency_state_epoch_mutation_rejected. exact H_epoch.
Qed.

Theorem transparency_any_object_mutation_blocks_open :
  forall obj cap state commit,
    commit_authority_root commit <> bound_authority_root obj \/
    commit_revocation_root commit <> bound_revocation_root obj \/
    commit_transparency_root commit <> bound_transparency_root obj \/
    commit_epoch commit <> bound_epoch obj ->
    transparency_open_allowed obj cap state commit = false.
Proof.
  intros obj cap state commit H.
  apply transparency_object_mismatch_blocks_open.
  destruct H as [H_auth | [H_rev | [H_trans | H_epoch]]].
  - apply transparency_object_authority_root_mutation_rejected. exact H_auth.
  - apply transparency_object_revocation_root_mutation_rejected. exact H_rev.
  - apply transparency_object_transparency_root_mutation_rejected. exact H_trans.
  - apply transparency_object_epoch_mutation_rejected. exact H_epoch.
Qed.
