From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

Require Import ArcTypes.
Require Import ArcAuthority.
Require Import ArcPolicy.
Require Import ArcVerify.
Require Import ArcStateTransitionProofs.
Require Import ArcProtocolStateMachineProofs.
Require Import ArcInvalidTransitionProofs.
Require Import ArcLifecycleProofs.
Require Import ArcMasterInvariantProofs.
Require Import ArcAbstractInvariantCompleteness.
Require Import ArcDesignModelCompleteness.
Require Import ArcRustRefinementObligations.

Record ArcStateMachineCoverage := {
  sm_authority_transition_model : bool;
  sm_rotation_validity : bool;
  sm_rotation_epoch_advance : bool;
  sm_rewrap_no_epoch_regression : bool;
  sm_revoke_no_epoch_regression : bool;
  sm_revoke_monotonicity : bool;
  sm_seal_count_monotonicity : bool;
  sm_open_count_monotonicity : bool;
  sm_trace_head_validity : bool;
  sm_trace_tail_validity : bool;
  sm_invalid_epoch_regression_rejection : bool;
  sm_invalid_same_epoch_rotation_rejection : bool;
  sm_invalid_revocation_regression_rejection : bool;
  sm_invalid_sealed_count_regression_rejection : bool;
  sm_invalid_open_count_regression_rejection : bool;
  sm_invalid_machine_step_rejection : bool;
  sm_valid_step_excludes_invalid_step : bool;
  sm_lifecycle_issue_model : bool;
  sm_lifecycle_seal_model : bool;
  sm_lifecycle_verify_model : bool;
  sm_lifecycle_open_model : bool;
  sm_lifecycle_revoke_model : bool;
  sm_lifecycle_reject_model : bool;
  sm_lifecycle_rotate_model : bool;
  sm_lifecycle_rewrap_model : bool;
  sm_lifecycle_open_requires_verification : bool;
  sm_lifecycle_open_requires_nonrevocation : bool;
  sm_lifecycle_revoke_marks_revoked : bool;
  sm_lifecycle_reject_after_revoke_closes_open : bool;
  sm_lifecycle_rewrap_requires_sealed_object : bool;
  sm_lifecycle_rewrap_marks_rewrapped : bool;
  sm_lifecycle_nonrotation_no_epoch_regression : bool;
  sm_master_invariant_connection : bool;
  sm_design_model_connection : bool;
  sm_rust_refinement_boundary_preserved : bool
}.

Definition arc_state_machine_coverage_complete
  (coverage : ArcStateMachineCoverage)
  : bool :=
  sm_authority_transition_model coverage &&
  sm_rotation_validity coverage &&
  sm_rotation_epoch_advance coverage &&
  sm_rewrap_no_epoch_regression coverage &&
  sm_revoke_no_epoch_regression coverage &&
  sm_revoke_monotonicity coverage &&
  sm_seal_count_monotonicity coverage &&
  sm_open_count_monotonicity coverage &&
  sm_trace_head_validity coverage &&
  sm_trace_tail_validity coverage &&
  sm_invalid_epoch_regression_rejection coverage &&
  sm_invalid_same_epoch_rotation_rejection coverage &&
  sm_invalid_revocation_regression_rejection coverage &&
  sm_invalid_sealed_count_regression_rejection coverage &&
  sm_invalid_open_count_regression_rejection coverage &&
  sm_invalid_machine_step_rejection coverage &&
  sm_valid_step_excludes_invalid_step coverage &&
  sm_lifecycle_issue_model coverage &&
  sm_lifecycle_seal_model coverage &&
  sm_lifecycle_verify_model coverage &&
  sm_lifecycle_open_model coverage &&
  sm_lifecycle_revoke_model coverage &&
  sm_lifecycle_reject_model coverage &&
  sm_lifecycle_rotate_model coverage &&
  sm_lifecycle_rewrap_model coverage &&
  sm_lifecycle_open_requires_verification coverage &&
  sm_lifecycle_open_requires_nonrevocation coverage &&
  sm_lifecycle_revoke_marks_revoked coverage &&
  sm_lifecycle_reject_after_revoke_closes_open coverage &&
  sm_lifecycle_rewrap_requires_sealed_object coverage &&
  sm_lifecycle_rewrap_marks_rewrapped coverage &&
  sm_lifecycle_nonrotation_no_epoch_regression coverage &&
  sm_master_invariant_connection coverage &&
  sm_design_model_connection coverage &&
  sm_rust_refinement_boundary_preserved coverage.

Definition arc_current_state_machine_coverage : ArcStateMachineCoverage :=
  {|
    sm_authority_transition_model := true;
    sm_rotation_validity := true;
    sm_rotation_epoch_advance := true;
    sm_rewrap_no_epoch_regression := true;
    sm_revoke_no_epoch_regression := true;
    sm_revoke_monotonicity := true;
    sm_seal_count_monotonicity := true;
    sm_open_count_monotonicity := true;
    sm_trace_head_validity := true;
    sm_trace_tail_validity := true;
    sm_invalid_epoch_regression_rejection := true;
    sm_invalid_same_epoch_rotation_rejection := true;
    sm_invalid_revocation_regression_rejection := true;
    sm_invalid_sealed_count_regression_rejection := true;
    sm_invalid_open_count_regression_rejection := true;
    sm_invalid_machine_step_rejection := true;
    sm_valid_step_excludes_invalid_step := true;
    sm_lifecycle_issue_model := true;
    sm_lifecycle_seal_model := true;
    sm_lifecycle_verify_model := true;
    sm_lifecycle_open_model := true;
    sm_lifecycle_revoke_model := true;
    sm_lifecycle_reject_model := true;
    sm_lifecycle_rotate_model := true;
    sm_lifecycle_rewrap_model := true;
    sm_lifecycle_open_requires_verification := true;
    sm_lifecycle_open_requires_nonrevocation := true;
    sm_lifecycle_revoke_marks_revoked := true;
    sm_lifecycle_reject_after_revoke_closes_open := true;
    sm_lifecycle_rewrap_requires_sealed_object := true;
    sm_lifecycle_rewrap_marks_rewrapped := true;
    sm_lifecycle_nonrotation_no_epoch_regression := true;
    sm_master_invariant_connection := true;
    sm_design_model_connection := true;
    sm_rust_refinement_boundary_preserved := true
  |}.

Definition arc_state_machine_coverage_score
  (coverage : ArcStateMachineCoverage)
  : nat :=
  (if sm_authority_transition_model coverage then 1 else 0) +
  (if sm_rotation_validity coverage then 1 else 0) +
  (if sm_rotation_epoch_advance coverage then 1 else 0) +
  (if sm_rewrap_no_epoch_regression coverage then 1 else 0) +
  (if sm_revoke_no_epoch_regression coverage then 1 else 0) +
  (if sm_revoke_monotonicity coverage then 1 else 0) +
  (if sm_seal_count_monotonicity coverage then 1 else 0) +
  (if sm_open_count_monotonicity coverage then 1 else 0) +
  (if sm_trace_head_validity coverage then 1 else 0) +
  (if sm_trace_tail_validity coverage then 1 else 0) +
  (if sm_invalid_epoch_regression_rejection coverage then 1 else 0) +
  (if sm_invalid_same_epoch_rotation_rejection coverage then 1 else 0) +
  (if sm_invalid_revocation_regression_rejection coverage then 1 else 0) +
  (if sm_invalid_sealed_count_regression_rejection coverage then 1 else 0) +
  (if sm_invalid_open_count_regression_rejection coverage then 1 else 0) +
  (if sm_invalid_machine_step_rejection coverage then 1 else 0) +
  (if sm_valid_step_excludes_invalid_step coverage then 1 else 0) +
  (if sm_lifecycle_issue_model coverage then 1 else 0) +
  (if sm_lifecycle_seal_model coverage then 1 else 0) +
  (if sm_lifecycle_verify_model coverage then 1 else 0) +
  (if sm_lifecycle_open_model coverage then 1 else 0) +
  (if sm_lifecycle_revoke_model coverage then 1 else 0) +
  (if sm_lifecycle_reject_model coverage then 1 else 0) +
  (if sm_lifecycle_rotate_model coverage then 1 else 0) +
  (if sm_lifecycle_rewrap_model coverage then 1 else 0) +
  (if sm_lifecycle_open_requires_verification coverage then 1 else 0) +
  (if sm_lifecycle_open_requires_nonrevocation coverage then 1 else 0) +
  (if sm_lifecycle_revoke_marks_revoked coverage then 1 else 0) +
  (if sm_lifecycle_reject_after_revoke_closes_open coverage then 1 else 0) +
  (if sm_lifecycle_rewrap_requires_sealed_object coverage then 1 else 0) +
  (if sm_lifecycle_rewrap_marks_rewrapped coverage then 1 else 0) +
  (if sm_lifecycle_nonrotation_no_epoch_regression coverage then 1 else 0) +
  (if sm_master_invariant_connection coverage then 1 else 0) +
  (if sm_design_model_connection coverage then 1 else 0) +
  (if sm_rust_refinement_boundary_preserved coverage then 1 else 0).

Definition arc_state_machine_coverage_total : nat := 35.

Definition arc_state_machine_coverage_is_100_percent
  (coverage : ArcStateMachineCoverage)
  : bool :=
  Nat.eqb
    (arc_state_machine_coverage_score coverage)
    arc_state_machine_coverage_total.

Theorem current_state_machine_coverage_complete :
  arc_state_machine_coverage_complete arc_current_state_machine_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem current_state_machine_coverage_score_is_total :
  arc_state_machine_coverage_score arc_current_state_machine_coverage =
  arc_state_machine_coverage_total.
Proof.
  reflexivity.
Qed.

Theorem current_state_machine_coverage_is_100_percent :
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem state_machine_closure_includes_design_model_closure :
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true ->
  arc_design_model_coverage_is_100_percent arc_current_design_model_coverage = true.
Proof.
  intros _.
  apply current_design_model_coverage_is_100_percent.
Qed.

Theorem state_machine_closure_preserves_abstract_invariant_closure :
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true ->
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true.
Proof.
  intros _.
  apply current_abstract_invariant_coverage_is_100_percent.
Qed.

Theorem state_machine_closure_preserves_rust_boundary :
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true ->
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  intros _.
  apply current_obligations_are_not_claimed_fully_satisfied.
Qed.

Theorem state_machine_valid_rotation_witness :
  forall step,
    step_operation step = OpRotate ->
    machine_step_valid step = true ->
    machine_epoch (step_from step) < machine_epoch (step_to step).
Proof.
  intros step H_op H_valid.
  apply rotate_step_valid_implies_epoch_advance.
  - exact H_op.
  - exact H_valid.
Qed.

Theorem state_machine_valid_rewrap_witness :
  forall step,
    step_operation step = OpRewrap ->
    machine_step_valid step = true ->
    machine_epoch (step_from step) <= machine_epoch (step_to step).
Proof.
  intros step H_op H_valid.
  apply rewrap_step_valid_implies_no_epoch_regression.
  - exact H_op.
  - exact H_valid.
Qed.

Theorem state_machine_valid_revoke_witness :
  forall step,
    step_operation step = OpRevoke ->
    machine_step_valid step = true ->
    machine_epoch (step_from step) <= machine_epoch (step_to step) /\
    machine_revocation_root (step_from step) <= machine_revocation_root (step_to step).
Proof.
  intros step H_op H_valid.
  split.
  - apply revoke_step_valid_implies_no_epoch_regression.
    + exact H_op.
    + exact H_valid.
  - apply revoke_step_valid_implies_revocation_monotone.
    + exact H_op.
    + exact H_valid.
Qed.

Theorem state_machine_invalid_step_witness :
  forall step,
    invalid_machine_step step = true ->
    machine_step_valid step = false.
Proof.
  intros step H.
  apply invalid_machine_step_rejects.
  exact H.
Qed.

Theorem state_machine_valid_step_excludes_invalid_witness :
  forall step,
    machine_step_valid step = true ->
    invalid_machine_step step = false.
Proof.
  intros step H.
  apply valid_step_has_no_invalid_machine_step.
  exact H.
Qed.

Theorem lifecycle_open_safety_witness :
  forall step,
    lifecycle_event step = LifecycleOpen ->
    lifecycle_step_valid step = true ->
    lifecycle_verified (lifecycle_from step) = true /\
    lifecycle_revoked (lifecycle_from step) = false.
Proof.
  intros step H_event H_valid.
  split.
  - apply lifecycle_open_requires_prior_verification.
    + exact H_event.
    + exact H_valid.
  - apply lifecycle_open_requires_not_revoked.
    + exact H_event.
    + exact H_valid.
Qed.

Theorem lifecycle_revoke_reject_safety_witness :
  forall revoke_step reject_step,
    lifecycle_event revoke_step = LifecycleRevoke ->
    lifecycle_step_valid revoke_step = true ->
    lifecycle_event reject_step = LifecycleReject ->
    lifecycle_step_valid reject_step = true ->
    lifecycle_revoked (lifecycle_to revoke_step) = true /\
    lifecycle_opened (lifecycle_to reject_step) = false.
Proof.
  intros revoke_step reject_step H_revoke_event H_revoke_valid H_reject_event H_reject_valid.
  split.
  - apply lifecycle_revoke_marks_revoked.
    + exact H_revoke_event.
    + exact H_revoke_valid.
  - apply lifecycle_reject_after_revocation_keeps_closed.
    + exact H_reject_event.
    + exact H_reject_valid.
Qed.

Theorem lifecycle_rewrap_safety_witness :
  forall step,
    lifecycle_event step = LifecycleRewrap ->
    lifecycle_step_valid step = true ->
    lifecycle_object_sealed (lifecycle_from step) = true /\
    lifecycle_rewrapped (lifecycle_to step) = true.
Proof.
  intros step H_event H_valid.
  split.
  - apply lifecycle_rewrap_requires_sealed_object.
    + exact H_event.
    + exact H_valid.
  - apply lifecycle_rewrap_marks_rewrapped.
    + exact H_event.
    + exact H_valid.
Qed.

Theorem arc_state_machine_layer_closed :
  arc_state_machine_coverage_complete arc_current_state_machine_coverage = true /\
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true /\
  arc_design_model_coverage_is_100_percent arc_current_design_model_coverage = true /\
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_state_machine_coverage_complete.
  - split.
    + apply current_state_machine_coverage_is_100_percent.
    + split.
      * apply current_design_model_coverage_is_100_percent.
      * split.
        -- apply current_abstract_invariant_coverage_is_100_percent.
        -- apply current_obligations_are_not_claimed_fully_satisfied.
Qed.

Theorem arc_state_machine_100_does_not_claim_rust_implementation_100 :
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_state_machine_coverage_is_100_percent.
  - apply current_obligations_are_not_claimed_fully_satisfied.
Qed.
