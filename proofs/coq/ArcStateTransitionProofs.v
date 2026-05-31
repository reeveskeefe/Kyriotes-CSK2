From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

Require Import ArcTypes.
Require Import ArcMerkle.
Require Import ArcAuthority.
Require Import ArcPolicy.
Require Import ArcVerify.
Require Import ArcSecurityGame.
Require Import ArcTheorems.
Require Import ArcStressProofs.
Require Import ArcDelegationProofs.
Require Import ArcCryptoReduction.
Require Import ArcTemporalProofs.
Require Import ArcTranscriptProofs.
Require Import ArcRevocationCompromiseProofs.
Require Import ArcTransparencyProofs.
Require Import ArcEncodingProofs.
Require Import ArcWrapperProofs.
Require Import ArcKemAeadAssumptions.
Require Import ArcEndToEndTheorems.

Record AuthorityStateTransition := {
  transition_from_state : AuthorityState;
  transition_to_state : AuthorityState;
  transition_previous_state_hash : Hash;
  transition_next_state_hash : Hash;
  transition_reason : nat
}.

Definition transition_epoch_advances
  (transition : AuthorityStateTransition)
  : bool :=
  Nat.ltb
    (epoch (transition_from_state transition))
    (epoch (transition_to_state transition)).

Definition transition_epoch_same_or_advances
  (transition : AuthorityStateTransition)
  : bool :=
  Nat.leb
    (epoch (transition_from_state transition))
    (epoch (transition_to_state transition)).

Definition transition_authority_root_preserved
  (transition : AuthorityStateTransition)
  : bool :=
  Nat.eqb
    (authority_root (transition_from_state transition))
    (authority_root (transition_to_state transition)).

Definition transition_revocation_root_preserved
  (transition : AuthorityStateTransition)
  : bool :=
  Nat.eqb
    (revocation_root (transition_from_state transition))
    (revocation_root (transition_to_state transition)).

Definition transition_transparency_root_changes
  (transition : AuthorityStateTransition)
  : bool :=
  negb
    (Nat.eqb
      (transparency_root (transition_from_state transition))
      (transparency_root (transition_to_state transition))).

Definition transition_state_hash_changes
  (transition : AuthorityStateTransition)
  : bool :=
  negb
    (Nat.eqb
      (transition_previous_state_hash transition)
      (transition_next_state_hash transition)).

Definition transition_valid_rotation
  (transition : AuthorityStateTransition)
  : bool :=
  authority_state_valid (transition_from_state transition) &&
  authority_state_valid (transition_to_state transition) &&
  transition_epoch_advances transition &&
  transition_state_hash_changes transition.

Definition transition_valid_rewrap
  (transition : AuthorityStateTransition)
  : bool :=
  authority_state_valid (transition_from_state transition) &&
  authority_state_valid (transition_to_state transition) &&
  transition_epoch_advances transition.

Definition transition_valid_revocation_update
  (transition : AuthorityStateTransition)
  : bool :=
  authority_state_valid (transition_from_state transition) &&
  authority_state_valid (transition_to_state transition) &&
  transition_epoch_same_or_advances transition &&
  transition_state_hash_changes transition.

Definition object_bound_to_transition_to_state
  (obj : ArcObject)
  (transition : AuthorityStateTransition)
  : bool :=
  object_bound_to_state obj (transition_to_state transition).

Definition object_bound_to_transition_from_state
  (obj : ArcObject)
  (transition : AuthorityStateTransition)
  : bool :=
  object_bound_to_state obj (transition_from_state transition).

Definition transition_open_allowed
  (obj : ArcObject)
  (cap : Capability)
  (transition : AuthorityStateTransition)
  : bool :=
  transition_valid_rotation transition &&
  verify_open_context obj cap (transition_to_state transition).

Theorem transition_valid_rotation_implies_from_state_valid :
  forall transition,
    transition_valid_rotation transition = true ->
    authority_state_valid (transition_from_state transition) = true.
Proof.
  intros transition H.
  unfold transition_valid_rotation in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_from H_to] H_epoch] H_hash].
  exact H_from.
Qed.

Theorem transition_valid_rotation_implies_to_state_valid :
  forall transition,
    transition_valid_rotation transition = true ->
    authority_state_valid (transition_to_state transition) = true.
Proof.
  intros transition H.
  unfold transition_valid_rotation in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_from H_to] H_epoch] H_hash].
  exact H_to.
Qed.

Theorem transition_valid_rotation_implies_epoch_advance :
  forall transition,
    transition_valid_rotation transition = true ->
    epoch (transition_from_state transition) <
    epoch (transition_to_state transition).
Proof.
  intros transition H.
  unfold transition_valid_rotation in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_from H_to] H_epoch] H_hash].
  unfold transition_epoch_advances in H_epoch.
  apply Nat.ltb_lt.
  exact H_epoch.
Qed.

Theorem transition_valid_rotation_implies_state_hash_changes :
  forall transition,
    transition_valid_rotation transition = true ->
    transition_previous_state_hash transition <>
    transition_next_state_hash transition.
Proof.
  intros transition H.
  unfold transition_valid_rotation in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_from H_to] H_epoch] H_hash].
  unfold transition_state_hash_changes in H_hash.
  apply negb_true_iff in H_hash.
  apply Nat.eqb_neq.
  exact H_hash.
Qed.

Theorem transition_epoch_regression_not_valid_rotation :
  forall transition,
    epoch (transition_to_state transition) <=
    epoch (transition_from_state transition) ->
    transition_valid_rotation transition = false.
Proof.
  intros transition H.
  unfold transition_valid_rotation.
  unfold transition_epoch_advances.
  assert (
    Nat.ltb
      (epoch (transition_from_state transition))
      (epoch (transition_to_state transition)) = false
  ) as H_no_advance.
  {
    apply Nat.ltb_ge.
    exact H.
  }
  rewrite H_no_advance.
  destruct (authority_state_valid (transition_from_state transition)); simpl.
  - destruct (authority_state_valid (transition_to_state transition)); reflexivity.
  - reflexivity.
Qed.

Theorem transition_same_epoch_not_valid_rotation :
  forall transition,
    epoch (transition_from_state transition) =
    epoch (transition_to_state transition) ->
    transition_valid_rotation transition = false.
Proof.
  intros transition H.
  apply transition_epoch_regression_not_valid_rotation.
  rewrite H.
  lia.
Qed.

Theorem transition_valid_rewrap_implies_from_state_valid :
  forall transition,
    transition_valid_rewrap transition = true ->
    authority_state_valid (transition_from_state transition) = true.
Proof.
  intros transition H.
  unfold transition_valid_rewrap in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_from H_to] H_epoch].
  exact H_from.
Qed.

Theorem transition_valid_rewrap_implies_to_state_valid :
  forall transition,
    transition_valid_rewrap transition = true ->
    authority_state_valid (transition_to_state transition) = true.
Proof.
  intros transition H.
  unfold transition_valid_rewrap in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_from H_to] H_epoch].
  exact H_to.
Qed.

Theorem transition_valid_rewrap_implies_epoch_advance :
  forall transition,
    transition_valid_rewrap transition = true ->
    epoch (transition_from_state transition) <
    epoch (transition_to_state transition).
Proof.
  intros transition H.
  unfold transition_valid_rewrap in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_from H_to] H_epoch].
  unfold transition_epoch_advances in H_epoch.
  apply Nat.ltb_lt.
  exact H_epoch.
Qed.

Theorem transition_rewrap_rejects_backward_epoch :
  forall transition,
    epoch (transition_to_state transition) <=
    epoch (transition_from_state transition) ->
    transition_valid_rewrap transition = false.
Proof.
  intros transition H.
  unfold transition_valid_rewrap.
  unfold transition_epoch_advances.
  assert (
    Nat.ltb
      (epoch (transition_from_state transition))
      (epoch (transition_to_state transition)) = false
  ) as H_no_advance.
  {
    apply Nat.ltb_ge.
    exact H.
  }
  rewrite H_no_advance.
  destruct (authority_state_valid (transition_from_state transition)); simpl.
  - destruct (authority_state_valid (transition_to_state transition)); reflexivity.
  - reflexivity.
Qed.

Theorem transition_valid_revocation_update_implies_states_valid :
  forall transition,
    transition_valid_revocation_update transition = true ->
    authority_state_valid (transition_from_state transition) = true /\
    authority_state_valid (transition_to_state transition) = true.
Proof.
  intros transition H.
  unfold transition_valid_revocation_update in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_from H_to] H_epoch] H_hash].
  split; assumption.
Qed.

Theorem transition_valid_revocation_update_implies_no_epoch_regression :
  forall transition,
    transition_valid_revocation_update transition = true ->
    epoch (transition_from_state transition) <=
    epoch (transition_to_state transition).
Proof.
  intros transition H.
  unfold transition_valid_revocation_update in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_from H_to] H_epoch] H_hash].
  unfold transition_epoch_same_or_advances in H_epoch.
  apply Nat.leb_le.
  exact H_epoch.
Qed.

Theorem transition_valid_revocation_update_implies_hash_changes :
  forall transition,
    transition_valid_revocation_update transition = true ->
    transition_previous_state_hash transition <>
    transition_next_state_hash transition.
Proof.
  intros transition H.
  unfold transition_valid_revocation_update in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_from H_to] H_epoch] H_hash].
  unfold transition_state_hash_changes in H_hash.
  apply negb_true_iff in H_hash.
  apply Nat.eqb_neq.
  exact H_hash.
Qed.

Theorem transition_open_allowed_implies_verified_open_on_to_state :
  forall obj cap transition,
    transition_open_allowed obj cap transition = true ->
    verify_open_context obj cap (transition_to_state transition) = true.
Proof.
  intros obj cap transition H.
  unfold transition_open_allowed in H.
  apply andb_true_iff in H.
  destruct H as [H_transition H_open].
  exact H_open.
Qed.

Theorem transition_open_allowed_implies_to_state_valid :
  forall obj cap transition,
    transition_open_allowed obj cap transition = true ->
    authority_state_valid (transition_to_state transition) = true.
Proof.
  intros obj cap transition H.
  unfold transition_open_allowed in H.
  apply andb_true_iff in H.
  destruct H as [H_transition H_open].
  apply transition_valid_rotation_implies_to_state_valid.
  exact H_transition.
Qed.

Theorem transition_open_allowed_implies_object_bound_to_to_state :
  forall obj cap transition,
    transition_open_allowed obj cap transition = true ->
    object_bound_to_transition_to_state obj transition = true.
Proof.
  intros obj cap transition H.
  unfold object_bound_to_transition_to_state.
  apply verify_open_context_implies_object_bound with (cap := cap).
  apply transition_open_allowed_implies_verified_open_on_to_state.
  exact H.
Qed.

Theorem stale_from_state_binding_does_not_imply_to_state_binding :
  forall obj transition,
    object_bound_to_transition_from_state obj transition = true ->
    object_bound_to_transition_to_state obj transition = false ->
    object_bound_to_transition_from_state obj transition = true /\
    object_bound_to_transition_to_state obj transition = false.
Proof.
  intros obj transition H_from H_to.
  split; assumption.
Qed.

Theorem transition_open_rejects_if_to_state_binding_fails :
  forall obj cap transition,
    object_bound_to_transition_to_state obj transition = false ->
    transition_open_allowed obj cap transition = false.
Proof.
  intros obj cap transition H_bound.
  unfold transition_open_allowed.
  destruct (transition_valid_rotation transition) eqn:H_transition; simpl.
  - destruct (verify_open_context obj cap (transition_to_state transition)) eqn:H_open.
    + pose proof (verify_open_context_implies_object_bound obj cap (transition_to_state transition) H_open) as H_bound_true.
      unfold object_bound_to_transition_to_state in H_bound.
      rewrite H_bound_true in H_bound.
      discriminate.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transition_rotation_preserves_current_authorization_shape :
  forall obj cap transition,
    transition_open_allowed obj cap transition = true ->
    capability_in_authority_root cap (transition_to_state transition) = true /\
    capability_not_revoked cap (transition_to_state transition) = true /\
    policy_accepts cap obj = true /\
    object_bound_to_state obj (transition_to_state transition) = true /\
    authority_state_valid (transition_to_state transition) = true.
Proof.
  intros obj cap transition H.
  apply arc_verified_open_safety.
  apply transition_open_allowed_implies_verified_open_on_to_state.
  exact H.
Qed.
