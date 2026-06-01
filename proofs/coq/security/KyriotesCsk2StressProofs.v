From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy KyriotesCsk2Verify KyriotesCsk2SecurityGame KyriotesCsk2Theorems.

Theorem stress_authority_root_mutation_rejected :
  forall obj state,
    bound_authority_root obj <> authority_root state ->
    object_bound_to_state obj state = false.
Proof.
  intros obj state H.
  unfold object_bound_to_state.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem stress_revocation_root_mutation_rejected :
  forall obj state,
    bound_revocation_root obj <> revocation_root state ->
    object_bound_to_state obj state = false.
Proof.
  intros obj state H.
  unfold object_bound_to_state.
  destruct (Nat.eqb (bound_authority_root obj) (authority_root state)); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem stress_transparency_root_mutation_rejected :
  forall obj state,
    bound_transparency_root obj <> transparency_root state ->
    object_bound_to_state obj state = false.
Proof.
  intros obj state H.
  unfold object_bound_to_state.
  destruct (Nat.eqb (bound_authority_root obj) (authority_root state)); simpl.
  - destruct (Nat.eqb (bound_revocation_root obj) (revocation_root state)); simpl.
    + apply Nat.eqb_neq in H.
      rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem stress_epoch_mutation_rejected :
  forall obj state,
    bound_epoch obj <> epoch state ->
    object_bound_to_state obj state = false.
Proof.
  intros obj state H.
  unfold object_bound_to_state.
  destruct (Nat.eqb (bound_authority_root obj) (authority_root state)); simpl.
  - destruct (Nat.eqb (bound_revocation_root obj) (revocation_root state)); simpl.
    + destruct (Nat.eqb (bound_transparency_root obj) (transparency_root state)); simpl.
      * apply Nat.eqb_neq in H.
        rewrite H.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem stress_object_binding_mutation_blocks_open :
  forall obj cap state,
    object_bound_to_state obj state = false ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  unfold verify_open_context.
  destruct (authority_state_valid state); simpl.
  - rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem stress_authority_root_mutation_blocks_open :
  forall obj cap state,
    bound_authority_root obj <> authority_root state ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_object_binding_mutation_blocks_open.
  apply stress_authority_root_mutation_rejected.
  exact H.
Qed.

Theorem stress_revocation_root_mutation_blocks_open :
  forall obj cap state,
    bound_revocation_root obj <> revocation_root state ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_object_binding_mutation_blocks_open.
  apply stress_revocation_root_mutation_rejected.
  exact H.
Qed.

Theorem stress_transparency_root_mutation_blocks_open :
  forall obj cap state,
    bound_transparency_root obj <> transparency_root state ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_object_binding_mutation_blocks_open.
  apply stress_transparency_root_mutation_rejected.
  exact H.
Qed.

Theorem stress_epoch_mutation_blocks_open :
  forall obj cap state,
    bound_epoch obj <> epoch state ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_object_binding_mutation_blocks_open.
  apply stress_epoch_mutation_rejected.
  exact H.
Qed.

Theorem stress_invalid_authority_state_blocks_open :
  forall obj cap state,
    authority_state_valid state = false ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  unfold verify_open_context.
  rewrite H.
  reflexivity.
Qed.

Theorem stress_missing_authority_inclusion_blocks_open :
  forall obj cap state,
    capability_in_authority_root cap state = false ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  unfold verify_open_context.
  destruct (authority_state_valid state); simpl.
  - destruct (object_bound_to_state obj state); simpl.
    + rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem stress_revoked_capability_blocks_open :
  forall obj cap state,
    capability_not_revoked cap state = false ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  unfold verify_open_context.
  destruct (authority_state_valid state); simpl.
  - destruct (object_bound_to_state obj state); simpl.
    + destruct (capability_in_authority_root cap state); simpl.
      * rewrite H.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem stress_policy_rejection_blocks_open :
  forall obj cap state,
    policy_accepts cap obj = false ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  unfold verify_open_context.
  destruct (authority_state_valid state); simpl.
  - destruct (object_bound_to_state obj state); simpl.
    + destruct (capability_in_authority_root cap state); simpl.
      * destruct (capability_not_revoked cap state); simpl.
        -- exact H.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem stress_object_id_mismatch_rejects_policy :
  forall obj cap,
    cap_object_id cap <> object_id obj ->
    policy_accepts cap obj = false.
Proof.
  intros obj cap H.
  unfold policy_accepts.
  unfold capability_matches_object.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem stress_rights_mismatch_rejects_policy :
  forall obj cap,
    Nat.land (cap_rights cap) (required_rights obj) <> required_rights obj ->
    policy_accepts cap obj = false.
Proof.
  intros obj cap H.
  unfold policy_accepts.
  unfold capability_has_required_rights.
  unfold has_rights.
  destruct (capability_matches_object cap obj); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem stress_epoch_before_window_rejects_policy :
  forall obj cap,
    bound_epoch obj < cap_epoch_start cap ->
    policy_accepts cap obj = false.
Proof.
  intros obj cap H.
  unfold policy_accepts.
  destruct (capability_matches_object cap obj); simpl.
  - destruct (capability_has_required_rights cap obj); simpl.
    + unfold capability_valid_for_object_epoch.
      unfold epoch_in_window.
      assert (Nat.leb (cap_epoch_start cap) (bound_epoch obj) = false) as H_before.
      { apply Nat.leb_gt. exact H. }
      rewrite H_before.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem stress_epoch_after_window_rejects_policy :
  forall obj cap,
    cap_epoch_end cap < bound_epoch obj ->
    policy_accepts cap obj = false.
Proof.
  intros obj cap H.
  unfold policy_accepts.
  destruct (capability_matches_object cap obj); simpl.
  - destruct (capability_has_required_rights cap obj); simpl.
    + unfold capability_valid_for_object_epoch.
      unfold epoch_in_window.
      destruct (Nat.leb (cap_epoch_start cap) (bound_epoch obj)); simpl.
      * assert (Nat.leb (bound_epoch obj) (cap_epoch_end cap) = false) as H_after.
        { apply Nat.leb_gt. exact H. }
        rewrite H_after.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem stress_object_id_mismatch_blocks_open :
  forall obj cap state,
    cap_object_id cap <> object_id obj ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_policy_rejection_blocks_open.
  apply stress_object_id_mismatch_rejects_policy.
  exact H.
Qed.

Theorem stress_rights_mismatch_blocks_open :
  forall obj cap state,
    Nat.land (cap_rights cap) (required_rights obj) <> required_rights obj ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_policy_rejection_blocks_open.
  apply stress_rights_mismatch_rejects_policy.
  exact H.
Qed.

Theorem stress_epoch_before_window_blocks_open :
  forall obj cap state,
    bound_epoch obj < cap_epoch_start cap ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_policy_rejection_blocks_open.
  apply stress_epoch_before_window_rejects_policy.
  exact H.
Qed.

Theorem stress_epoch_after_window_blocks_open :
  forall obj cap state,
    cap_epoch_end cap < bound_epoch obj ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  apply stress_policy_rejection_blocks_open.
  apply stress_epoch_after_window_rejects_policy.
  exact H.
Qed.

Theorem stress_verified_open_forces_all_gates_true :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    authority_state_valid state = true /\
    object_bound_to_state obj state = true /\
    capability_in_authority_root cap state = true /\
    capability_not_revoked cap state = true /\
    policy_accepts cap obj = true.
Proof.
  intros obj cap state H.
  unfold verify_open_context in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_authority H_binding] H_inclusion] H_not_revoked] H_policy].
  repeat split; assumption.
Qed.

Theorem stress_verified_open_cannot_have_invalid_authority :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    authority_state_valid state = false ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (stress_verified_open_forces_all_gates_true obj cap state H_open) as [H_authority _].
  rewrite H_authority in H_bad.
  discriminate.
Qed.

Theorem stress_verified_open_cannot_have_unbound_object :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    object_bound_to_state obj state = false ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (stress_verified_open_forces_all_gates_true obj cap state H_open) as [_ [H_binding _]].
  rewrite H_binding in H_bad.
  discriminate.
Qed.

Theorem stress_verified_open_cannot_have_missing_inclusion :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    capability_in_authority_root cap state = false ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (stress_verified_open_forces_all_gates_true obj cap state H_open) as [_ [_ [H_inclusion _]]].
  rewrite H_inclusion in H_bad.
  discriminate.
Qed.

Theorem stress_verified_open_cannot_have_revoked_capability :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    capability_not_revoked cap state = false ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (stress_verified_open_forces_all_gates_true obj cap state H_open) as [_ [_ [_ [H_not_revoked _]]]].
  rewrite H_not_revoked in H_bad.
  discriminate.
Qed.

Theorem stress_verified_open_cannot_have_policy_rejection :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    policy_accepts cap obj = false ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (stress_verified_open_forces_all_gates_true obj cap state H_open) as [_ [_ [_ [_ H_policy]]]].
  rewrite H_policy in H_bad.
  discriminate.
Qed.

Theorem stress_verified_open_cannot_have_authority_root_mismatch :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    bound_authority_root obj <> authority_root state ->
    False.
Proof.
  intros obj cap state H_open H_mismatch.
  pose proof (kyriotes_csk2_verified_open_implies_exact_authority_binding obj cap state H_open) as [H_equal _].
  contradiction.
Qed.

Theorem stress_verified_open_cannot_have_revocation_root_mismatch :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    bound_revocation_root obj <> revocation_root state ->
    False.
Proof.
  intros obj cap state H_open H_mismatch.
  pose proof (kyriotes_csk2_verified_open_implies_exact_authority_binding obj cap state H_open) as [_ [H_equal _]].
  contradiction.
Qed.

Theorem stress_verified_open_cannot_have_transparency_root_mismatch :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    bound_transparency_root obj <> transparency_root state ->
    False.
Proof.
  intros obj cap state H_open H_mismatch.
  pose proof (kyriotes_csk2_verified_open_implies_exact_authority_binding obj cap state H_open) as [_ [_ [H_equal _]]].
  contradiction.
Qed.

Theorem stress_verified_open_cannot_have_epoch_mismatch :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    bound_epoch obj <> epoch state ->
    False.
Proof.
  intros obj cap state H_open H_mismatch.
  pose proof (kyriotes_csk2_verified_open_implies_exact_authority_binding obj cap state H_open) as [_ [_ [_ H_equal]]].
  contradiction.
Qed.

Theorem stress_verified_open_cannot_have_object_id_mismatch :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    cap_object_id cap <> object_id obj ->
    False.
Proof.
  intros obj cap state H_open H_mismatch.
  pose proof (kyriotes_csk2_verified_open_implies_object_authorization obj cap state H_open) as [H_equal _].
  contradiction.
Qed.

Theorem stress_verified_open_cannot_lack_required_rights :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    Nat.land (cap_rights cap) (required_rights obj) <> required_rights obj ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (kyriotes_csk2_verified_open_implies_object_authorization obj cap state H_open) as [_ [H_equal _]].
  contradiction.
Qed.

Theorem stress_verified_open_cannot_be_before_capability_window :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    bound_epoch obj < cap_epoch_start cap ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (kyriotes_csk2_verified_open_implies_object_authorization obj cap state H_open) as [_ [_ [H_start _]]].
  lia.
Qed.

Theorem stress_verified_open_cannot_be_after_capability_window :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    cap_epoch_end cap < bound_epoch obj ->
    False.
Proof.
  intros obj cap state H_open H_bad.
  pose proof (kyriotes_csk2_verified_open_implies_object_authorization obj cap state H_open) as [_ [_ [_ H_end]]].
  lia.
Qed.

Theorem stress_single_gate_failure_blocks_open :
  forall obj cap state,
    authority_state_valid state = true ->
    object_bound_to_state obj state = true ->
    capability_in_authority_root cap state = true ->
    capability_not_revoked cap state = true ->
    policy_accepts cap obj = false ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H_authority H_binding H_inclusion H_not_revoked H_policy.
  unfold verify_open_context.
  rewrite H_authority.
  rewrite H_binding.
  rewrite H_inclusion.
  rewrite H_not_revoked.
  rewrite H_policy.
  reflexivity.
Qed.

Theorem stress_all_gates_true_implies_verified_open :
  forall obj cap state,
    authority_state_valid state = true ->
    object_bound_to_state obj state = true ->
    capability_in_authority_root cap state = true ->
    capability_not_revoked cap state = true ->
    policy_accepts cap obj = true ->
    verify_open_context obj cap state = true.
Proof.
  intros obj cap state H_authority H_binding H_inclusion H_not_revoked H_policy.
  unfold verify_open_context.
  rewrite H_authority.
  rewrite H_binding.
  rewrite H_inclusion.
  rewrite H_not_revoked.
  rewrite H_policy.
  reflexivity.
Qed.

Theorem stress_verified_open_iff_all_gates_true :
  forall obj cap state,
    verify_open_context obj cap state = true <->
    authority_state_valid state = true /\
    object_bound_to_state obj state = true /\
    capability_in_authority_root cap state = true /\
    capability_not_revoked cap state = true /\
    policy_accepts cap obj = true.
Proof.
  intros obj cap state.
  split.
  - apply stress_verified_open_forces_all_gates_true.
  - intros [H_authority [H_binding [H_inclusion [H_not_revoked H_policy]]]].
    apply stress_all_gates_true_implies_verified_open; assumption.
Qed.

Theorem stress_any_authority_context_mutation_blocks_open :
  forall obj cap state,
    bound_authority_root obj <> authority_root state \/
    bound_revocation_root obj <> revocation_root state \/
    bound_transparency_root obj <> transparency_root state \/
    bound_epoch obj <> epoch state ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  destruct H as [H_auth | [H_rev | [H_trans | H_epoch]]].
  - apply stress_authority_root_mutation_blocks_open. exact H_auth.
  - apply stress_revocation_root_mutation_blocks_open. exact H_rev.
  - apply stress_transparency_root_mutation_blocks_open. exact H_trans.
  - apply stress_epoch_mutation_blocks_open. exact H_epoch.
Qed.

Theorem stress_any_policy_mutation_blocks_open :
  forall obj cap state,
    cap_object_id cap <> object_id obj \/
    Nat.land (cap_rights cap) (required_rights obj) <> required_rights obj \/
    bound_epoch obj < cap_epoch_start cap \/
    cap_epoch_end cap < bound_epoch obj ->
    verify_open_context obj cap state = false.
Proof.
  intros obj cap state H.
  destruct H as [H_obj | [H_rights | [H_before | H_after]]].
  - apply stress_object_id_mismatch_blocks_open. exact H_obj.
  - apply stress_rights_mismatch_blocks_open. exact H_rights.
  - apply stress_epoch_before_window_blocks_open. exact H_before.
  - apply stress_epoch_after_window_blocks_open. exact H_after.
Qed.
