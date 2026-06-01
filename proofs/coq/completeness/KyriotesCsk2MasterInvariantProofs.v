From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Merkle.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Authority.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Policy.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Verify.
From KyriotesCsk2Proofs Require Import KyriotesCsk2SecurityGame.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Theorems.
From KyriotesCsk2Proofs Require Import KyriotesCsk2StressProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2DelegationProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2CryptoReduction.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TemporalProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TranscriptProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RevocationCompromiseProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2EncodingProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2WrapperProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2KemAeadAssumptions.
From KyriotesCsk2Proofs Require Import KyriotesCsk2EndToEndTheorems.
From KyriotesCsk2Proofs Require Import KyriotesCsk2StateTransitionProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ConcreteMerkleProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyConsistencyProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ProtocolStateMachineProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2InvalidTransitionProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TightSecurityGameProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2AssumptionReductionProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementMap.

Record KyriotesCsk2AbstractInvariantBundle := {
  bundle_key_gate : bool;
  bundle_capability_gate : bool;
  bundle_nonrevocation_gate : bool;
  bundle_authority_state_gate : bool;
  bundle_temporal_gate : bool;
  bundle_object_binding_gate : bool;
  bundle_wrapper_gate : bool;
  bundle_transparency_gate : bool;
  bundle_transition_gate : bool;
  bundle_invalid_transition_rejection_gate : bool;
  bundle_refinement_map_gate : bool
}.

Definition kyriotes_csk2_abstract_invariants_hold
  (bundle : KyriotesCsk2AbstractInvariantBundle)
  : bool :=
  bundle_key_gate bundle &&
  bundle_capability_gate bundle &&
  bundle_nonrevocation_gate bundle &&
  bundle_authority_state_gate bundle &&
  bundle_temporal_gate bundle &&
  bundle_object_binding_gate bundle &&
  bundle_wrapper_gate bundle &&
  bundle_transparency_gate bundle &&
  bundle_transition_gate bundle &&
  bundle_invalid_transition_rejection_gate bundle &&
  bundle_refinement_map_gate bundle.

Definition bundle_from_verified_open
  (obj : KyriotesCsk2Object)
  (cap : Capability)
  (state : AuthorityState)
  (transition : AuthorityStateTransition)
  (wrapper : AuthorityWrapper)
  (step : KyriotesCsk2MachineStep)
  (entries : list RustRefinementEntry)
  : KyriotesCsk2AbstractInvariantBundle :=
  {|
    bundle_key_gate := true;
    bundle_capability_gate := capability_in_authority_root cap state;
    bundle_nonrevocation_gate := capability_not_revoked cap state;
    bundle_authority_state_gate := authority_state_valid state;
    bundle_temporal_gate := policy_accepts cap obj;
    bundle_object_binding_gate := object_bound_to_state obj state;
    bundle_wrapper_gate := wrapper_open_allowed obj cap state wrapper;
    bundle_transparency_gate := object_bound_to_transition_to_state obj transition;
    bundle_transition_gate := transition_valid_rotation transition;
    bundle_invalid_transition_rejection_gate := negb (invalid_machine_step step);
    bundle_refinement_map_gate := kyriotes_csk2_refinement_map_has_core_coverage entries
  |}.

Definition kyriotes_csk2_master_open_invariant
  (obj : KyriotesCsk2Object)
  (cap : Capability)
  (state : AuthorityState)
  (transition : AuthorityStateTransition)
  (wrapper : AuthorityWrapper)
  (step : KyriotesCsk2MachineStep)
  (entries : list RustRefinementEntry)
  : bool :=
  verify_open_context obj cap state &&
  wrapper_open_allowed obj cap state wrapper &&
  transition_open_allowed obj cap transition &&
  machine_step_valid step &&
  negb (invalid_machine_step step) &&
  kyriotes_csk2_refinement_map_has_core_coverage entries.

Theorem abstract_invariants_hold_implies_key_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_key_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[H_key _] _] _] _] _] _] _] _] _] _].
  exact H_key.
Qed.

Theorem abstract_invariants_hold_implies_capability_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_capability_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ H_cap] _] _] _] _] _] _] _] _] _].
  exact H_cap.
Qed.

Theorem abstract_invariants_hold_implies_nonrevocation_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_nonrevocation_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] H_nonrev] _] _] _] _] _] _] _] _].
  exact H_nonrev.
Qed.

Theorem abstract_invariants_hold_implies_authority_state_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_authority_state_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] H_state] _] _] _] _] _] _] _].
  exact H_state.
Qed.

Theorem abstract_invariants_hold_implies_temporal_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_temporal_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] _] H_temporal] _] _] _] _] _] _].
  exact H_temporal.
Qed.

Theorem abstract_invariants_hold_implies_object_binding_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_object_binding_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] _] _] H_object] _] _] _] _] _].
  exact H_object.
Qed.

Theorem abstract_invariants_hold_implies_wrapper_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_wrapper_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] _] _] _] H_wrapper] _] _] _] _].
  exact H_wrapper.
Qed.

Theorem abstract_invariants_hold_implies_transparency_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_transparency_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] _] _] _] _] H_transparency] _] _] _].
  exact H_transparency.
Qed.

Theorem abstract_invariants_hold_implies_transition_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_transition_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] _] _] _] _] _] H_transition] _] _].
  exact H_transition.
Qed.

Theorem abstract_invariants_hold_implies_invalid_transition_rejection_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_invalid_transition_rejection_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] _] _] _] _] _] _] H_invalid] _].
  exact H_invalid.
Qed.

Theorem abstract_invariants_hold_implies_refinement_map_gate :
  forall bundle,
    kyriotes_csk2_abstract_invariants_hold bundle = true ->
    bundle_refinement_map_gate bundle = true.
Proof.
  intros bundle H.
  unfold kyriotes_csk2_abstract_invariants_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[_ _] _] _] _] _] _] _] _] _] H_refinement].
  exact H_refinement.
Qed.

Theorem verified_open_builds_core_safety_bundle :
  forall obj cap state transition wrapper step entries,
    verify_open_context obj cap state = true ->
    wrapper_open_allowed obj cap state wrapper = true ->
    transition_open_allowed obj cap transition = true ->
    machine_step_valid step = true ->
    invalid_machine_step step = false ->
    kyriotes_csk2_refinement_map_has_core_coverage entries = true ->
    kyriotes_csk2_abstract_invariants_hold
      (bundle_from_verified_open obj cap state transition wrapper step entries) = true.
Proof.
  intros obj cap state transition wrapper step entries
    H_open H_wrapper H_transition H_step H_invalid H_refinement.

  unfold kyriotes_csk2_abstract_invariants_hold.
  unfold bundle_from_verified_open.
  simpl.

  pose proof (kyriotes_csk2_verified_open_safety obj cap state H_open)
    as [H_cap [H_nonrev [H_policy [H_object H_state]]]].

  rewrite H_cap.
  rewrite H_nonrev.
  rewrite H_state.
  rewrite H_policy.
  rewrite H_object.
  rewrite H_wrapper.

  pose proof (transition_open_allowed_implies_object_bound_to_to_state obj cap transition H_transition)
    as H_transition_object.
  rewrite H_transition_object.

  unfold transition_open_allowed in H_transition.
  apply andb_true_iff in H_transition.
  destruct H_transition as [H_transition_valid H_transition_open].
  rewrite H_transition_valid.

  rewrite H_invalid.
  simpl.
  exact H_refinement.
Qed.

Theorem master_open_invariant_implies_verified_open :
  forall obj cap state transition wrapper step entries,
    kyriotes_csk2_master_open_invariant obj cap state transition wrapper step entries = true ->
    verify_open_context obj cap state = true.
Proof.
  intros obj cap state transition wrapper step entries H.
  unfold kyriotes_csk2_master_open_invariant in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[H_open _] _] _] _] _].
  exact H_open.
Qed.

Theorem master_open_invariant_implies_wrapper_open :
  forall obj cap state transition wrapper step entries,
    kyriotes_csk2_master_open_invariant obj cap state transition wrapper step entries = true ->
    wrapper_open_allowed obj cap state wrapper = true.
Proof.
  intros obj cap state transition wrapper step entries H.
  unfold kyriotes_csk2_master_open_invariant in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[_ H_wrapper] _] _] _] _].
  exact H_wrapper.
Qed.

Theorem master_open_invariant_implies_transition_open :
  forall obj cap state transition wrapper step entries,
    kyriotes_csk2_master_open_invariant obj cap state transition wrapper step entries = true ->
    transition_open_allowed obj cap transition = true.
Proof.
  intros obj cap state transition wrapper step entries H.
  unfold kyriotes_csk2_master_open_invariant in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[_ _] H_transition] _] _] _].
  exact H_transition.
Qed.

Theorem master_open_invariant_implies_no_invalid_transition :
  forall obj cap state transition wrapper step entries,
    kyriotes_csk2_master_open_invariant obj cap state transition wrapper step entries = true ->
    invalid_machine_step step = false.
Proof.
  intros obj cap state transition wrapper step entries H.
  unfold kyriotes_csk2_master_open_invariant in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[_ _] _] H_step] H_not_invalid] _].
  apply negb_true_iff in H_not_invalid.
  exact H_not_invalid.
Qed.

Theorem master_open_invariant_implies_refinement_coverage :
  forall obj cap state transition wrapper step entries,
    kyriotes_csk2_master_open_invariant obj cap state transition wrapper step entries = true ->
    kyriotes_csk2_refinement_map_has_core_coverage entries = true.
Proof.
  intros obj cap state transition wrapper step entries H.
  unfold kyriotes_csk2_master_open_invariant in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[_ _] _] _] _] H_refinement].
  exact H_refinement.
Qed.

Theorem master_open_invariant_builds_abstract_invariants :
  forall obj cap state transition wrapper step entries,
    kyriotes_csk2_master_open_invariant obj cap state transition wrapper step entries = true ->
    kyriotes_csk2_abstract_invariants_hold
      (bundle_from_verified_open obj cap state transition wrapper step entries) = true.
Proof.
  intros obj cap state transition wrapper step entries H_master.

  apply verified_open_builds_core_safety_bundle.
  - apply master_open_invariant_implies_verified_open with
      (transition := transition) (wrapper := wrapper) (step := step) (entries := entries).
    exact H_master.
  - apply master_open_invariant_implies_wrapper_open with
      (transition := transition) (step := step) (entries := entries).
    exact H_master.
  - apply master_open_invariant_implies_transition_open with
      (state := state) (wrapper := wrapper) (step := step) (entries := entries).
    exact H_master.
  - unfold kyriotes_csk2_master_open_invariant in H_master.
    repeat rewrite andb_true_iff in H_master.
    destruct H_master as [[[[[_ _] _] H_step] _] _].
    exact H_step.
  - apply master_open_invariant_implies_no_invalid_transition with
      (obj := obj) (cap := cap) (state := state) (transition := transition)
      (wrapper := wrapper) (entries := entries).
    exact H_master.
  - apply master_open_invariant_implies_refinement_coverage with
      (obj := obj) (cap := cap) (state := state) (transition := transition)
      (wrapper := wrapper) (step := step).
    exact H_master.
Qed.

Theorem kyriotes_csk2_abstract_protocol_reaches_high_invariant_coverage :
  forall obj cap state transition wrapper step,
    kyriotes_csk2_master_open_invariant
      obj cap state transition wrapper step kyriotes_csk2_reference_refinement_map = true ->
    kyriotes_csk2_abstract_invariants_hold
      (bundle_from_verified_open
        obj cap state transition wrapper step kyriotes_csk2_reference_refinement_map) = true /\
    kyriotes_csk2_refinement_map_has_core_coverage kyriotes_csk2_reference_refinement_map = true.
Proof.
  intros obj cap state transition wrapper step H_master.
  split.
  - apply master_open_invariant_builds_abstract_invariants.
    exact H_master.
  - apply reference_refinement_map_core_coverage.
Qed.
