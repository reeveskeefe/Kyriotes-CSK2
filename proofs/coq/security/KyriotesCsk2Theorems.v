From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy KyriotesCsk2Verify KyriotesCsk2SecurityGame.

Theorem kyriotes_csk2_verified_open_safety :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    capability_in_authority_root cap state = true /\
    capability_not_revoked cap state = true /\
    policy_accepts cap obj = true /\
    object_bound_to_state obj state = true /\
    authority_state_valid state = true.
Proof.
  intros obj cap state H.
  repeat split.
  - apply verify_open_context_implies_capability_in_authority with (obj := obj). exact H.
  - apply verify_open_context_implies_not_revoked with (obj := obj). exact H.
  - apply verify_open_context_implies_policy_accepts with (state := state). exact H.
  - apply verify_open_context_implies_object_bound with (cap := cap). exact H.
  - apply verify_open_context_implies_authority_valid with (obj := obj) (cap := cap). exact H.
Qed.

Theorem kyriotes_csk2_verified_open_implies_exact_authority_binding :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    bound_authority_root obj = authority_root state /\
    bound_revocation_root obj = revocation_root state /\
    bound_transparency_root obj = transparency_root state /\
    bound_epoch obj = epoch state.
Proof.
  intros obj cap state H.
  apply object_bound_to_state_implies_roots_and_epoch.
  apply verify_open_context_implies_object_bound with (cap := cap).
  exact H.
Qed.

Theorem kyriotes_csk2_verified_open_implies_object_authorization :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    cap_object_id cap = object_id obj /\
    Nat.land (cap_rights cap) (required_rights obj) = required_rights obj /\
    cap_epoch_start cap <= bound_epoch obj /\
    bound_epoch obj <= cap_epoch_end cap.
Proof.
  intros obj cap state H.
  pose proof (verify_open_context_implies_policy_accepts obj cap state H) as H_policy.
  repeat split.
  - apply policy_accepts_implies_object_match. exact H_policy.
  - apply policy_accepts_implies_required_rights. exact H_policy.
  - destruct (policy_accepts_implies_epoch_window cap obj H_policy) as [H_start _]. exact H_start.
  - destruct (policy_accepts_implies_epoch_window cap obj H_policy) as [_ H_end]. exact H_end.
Qed.

Theorem kyriotes_csk2_verified_open_excludes_revocation_leaf :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    included_in_merkle_root (hash_revocation_stamp (cap_stamp cap)) (revocation_root state) = false.
Proof.
  intros obj cap state H.
  apply non_revocation_excludes_revocation_leaf.
  apply verify_open_context_implies_not_revoked with (obj := obj).
  exact H.
Qed.
