From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Verify.
From KyriotesCsk2Proofs Require Import KyriotesCsk2WrapperProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2StateTransitionProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ProtocolStateMachineProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2InvalidTransitionProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2MasterInvariantProofs.

Inductive KyriotesCsk2LifecycleEvent :=
| LifecycleIssue
| LifecycleSeal
| LifecycleVerify
| LifecycleOpen
| LifecycleRevoke
| LifecycleReject
| LifecycleRotate
| LifecycleRewrap.

Record KyriotesCsk2LifecycleState := {
  lifecycle_epoch : Epoch;
  lifecycle_cap_issued : bool;
  lifecycle_object_sealed : bool;
  lifecycle_verified : bool;
  lifecycle_opened : bool;
  lifecycle_revoked : bool;
  lifecycle_rewrapped : bool
}.

Record KyriotesCsk2LifecycleStep := {
  lifecycle_event : KyriotesCsk2LifecycleEvent;
  lifecycle_from : KyriotesCsk2LifecycleState;
  lifecycle_to : KyriotesCsk2LifecycleState
}.

Definition lifecycle_epoch_no_regression (step : KyriotesCsk2LifecycleStep) : bool :=
  Nat.leb (lifecycle_epoch (lifecycle_from step)) (lifecycle_epoch (lifecycle_to step)).

Definition lifecycle_issue_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  negb (lifecycle_cap_issued (lifecycle_from step)) &&
  lifecycle_cap_issued (lifecycle_to step) &&
  lifecycle_epoch_no_regression step.

Definition lifecycle_seal_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  lifecycle_cap_issued (lifecycle_from step) &&
  lifecycle_object_sealed (lifecycle_to step) &&
  lifecycle_epoch_no_regression step.

Definition lifecycle_verify_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  lifecycle_object_sealed (lifecycle_from step) &&
  lifecycle_verified (lifecycle_to step) &&
  lifecycle_epoch_no_regression step.

Definition lifecycle_open_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  lifecycle_verified (lifecycle_from step) &&
  negb (lifecycle_revoked (lifecycle_from step)) &&
  lifecycle_opened (lifecycle_to step) &&
  lifecycle_epoch_no_regression step.

Definition lifecycle_revoke_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  lifecycle_cap_issued (lifecycle_from step) &&
  lifecycle_revoked (lifecycle_to step) &&
  lifecycle_epoch_no_regression step.

Definition lifecycle_reject_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  lifecycle_revoked (lifecycle_from step) &&
  negb (lifecycle_opened (lifecycle_to step)) &&
  lifecycle_epoch_no_regression step.

Definition lifecycle_rotate_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  Nat.ltb (lifecycle_epoch (lifecycle_from step)) (lifecycle_epoch (lifecycle_to step)).

Definition lifecycle_rewrap_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  lifecycle_object_sealed (lifecycle_from step) &&
  lifecycle_rewrapped (lifecycle_to step) &&
  lifecycle_epoch_no_regression step.

Definition lifecycle_step_valid (step : KyriotesCsk2LifecycleStep) : bool :=
  match lifecycle_event step with
  | LifecycleIssue => lifecycle_issue_valid step
  | LifecycleSeal => lifecycle_seal_valid step
  | LifecycleVerify => lifecycle_verify_valid step
  | LifecycleOpen => lifecycle_open_valid step
  | LifecycleRevoke => lifecycle_revoke_valid step
  | LifecycleReject => lifecycle_reject_valid step
  | LifecycleRotate => lifecycle_rotate_valid step
  | LifecycleRewrap => lifecycle_rewrap_valid step
  end.

Fixpoint lifecycle_trace_valid (trace : list KyriotesCsk2LifecycleStep) : bool :=
  match trace with
  | [] => true
  | head :: tail => lifecycle_step_valid head && lifecycle_trace_valid tail
  end.

Theorem lifecycle_valid_trace_head :
  forall head tail,
    lifecycle_trace_valid (head :: tail) = true ->
    lifecycle_step_valid head = true.
Proof.
  intros head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  exact H_head.
Qed.

Theorem lifecycle_valid_trace_tail :
  forall head tail,
    lifecycle_trace_valid (head :: tail) = true ->
    lifecycle_trace_valid tail = true.
Proof.
  intros head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  exact H_tail.
Qed.

Theorem lifecycle_open_requires_prior_verification :
  forall step,
    lifecycle_event step = LifecycleOpen ->
    lifecycle_step_valid step = true ->
    lifecycle_verified (lifecycle_from step) = true.
Proof.
  intros step H_event H_valid.
  unfold lifecycle_step_valid in H_valid.
  rewrite H_event in H_valid.
  unfold lifecycle_open_valid in H_valid.
  repeat rewrite andb_true_iff in H_valid.
  destruct H_valid as [[[H_verified H_not_revoked] H_opened] H_epoch].
  exact H_verified.
Qed.

Theorem lifecycle_open_requires_not_revoked :
  forall step,
    lifecycle_event step = LifecycleOpen ->
    lifecycle_step_valid step = true ->
    lifecycle_revoked (lifecycle_from step) = false.
Proof.
  intros step H_event H_valid.
  unfold lifecycle_step_valid in H_valid.
  rewrite H_event in H_valid.
  unfold lifecycle_open_valid in H_valid.
  repeat rewrite andb_true_iff in H_valid.
  destruct H_valid as [[[H_verified H_not_revoked] H_opened] H_epoch].
  apply negb_true_iff in H_not_revoked.
  exact H_not_revoked.
Qed.

Theorem lifecycle_revoke_marks_revoked :
  forall step,
    lifecycle_event step = LifecycleRevoke ->
    lifecycle_step_valid step = true ->
    lifecycle_revoked (lifecycle_to step) = true.
Proof.
  intros step H_event H_valid.
  unfold lifecycle_step_valid in H_valid.
  rewrite H_event in H_valid.
  unfold lifecycle_revoke_valid in H_valid.
  repeat rewrite andb_true_iff in H_valid.
  destruct H_valid as [[H_issued H_revoked] H_epoch].
  exact H_revoked.
Qed.

Theorem lifecycle_reject_after_revocation_keeps_closed :
  forall step,
    lifecycle_event step = LifecycleReject ->
    lifecycle_step_valid step = true ->
    lifecycle_opened (lifecycle_to step) = false.
Proof.
  intros step H_event H_valid.
  unfold lifecycle_step_valid in H_valid.
  rewrite H_event in H_valid.
  unfold lifecycle_reject_valid in H_valid.
  repeat rewrite andb_true_iff in H_valid.
  destruct H_valid as [[H_revoked H_not_opened] H_epoch].
  apply negb_true_iff in H_not_opened.
  exact H_not_opened.
Qed.

Theorem lifecycle_rotate_strictly_advances_epoch :
  forall step,
    lifecycle_event step = LifecycleRotate ->
    lifecycle_step_valid step = true ->
    lifecycle_epoch (lifecycle_from step) < lifecycle_epoch (lifecycle_to step).
Proof.
  intros step H_event H_valid.
  unfold lifecycle_step_valid in H_valid.
  rewrite H_event in H_valid.
  unfold lifecycle_rotate_valid in H_valid.
  apply Nat.ltb_lt.
  exact H_valid.
Qed.

Theorem lifecycle_rewrap_requires_sealed_object :
  forall step,
    lifecycle_event step = LifecycleRewrap ->
    lifecycle_step_valid step = true ->
    lifecycle_object_sealed (lifecycle_from step) = true.
Proof.
  intros step H_event H_valid.
  unfold lifecycle_step_valid in H_valid.
  rewrite H_event in H_valid.
  unfold lifecycle_rewrap_valid in H_valid.
  repeat rewrite andb_true_iff in H_valid.
  destruct H_valid as [[H_sealed H_rewrapped] H_epoch].
  exact H_sealed.
Qed.

Theorem lifecycle_rewrap_marks_rewrapped :
  forall step,
    lifecycle_event step = LifecycleRewrap ->
    lifecycle_step_valid step = true ->
    lifecycle_rewrapped (lifecycle_to step) = true.
Proof.
  intros step H_event H_valid.
  unfold lifecycle_step_valid in H_valid.
  rewrite H_event in H_valid.
  unfold lifecycle_rewrap_valid in H_valid.
  repeat rewrite andb_true_iff in H_valid.
  destruct H_valid as [[H_sealed H_rewrapped] H_epoch].
  exact H_rewrapped.
Qed.

Theorem lifecycle_valid_step_no_epoch_regression_except_strict_rotation :
  forall step,
    lifecycle_step_valid step = true ->
    lifecycle_event step <> LifecycleRotate ->
    lifecycle_epoch (lifecycle_from step) <= lifecycle_epoch (lifecycle_to step).
Proof.
  intros step H_valid H_not_rotate.
  unfold lifecycle_step_valid in H_valid.
  destruct (lifecycle_event step) eqn:H_event.
  - unfold lifecycle_issue_valid in H_valid; repeat rewrite andb_true_iff in H_valid; destruct H_valid as [[_ _] H_epoch]; unfold lifecycle_epoch_no_regression in H_epoch; apply Nat.leb_le; exact H_epoch.
  - unfold lifecycle_seal_valid in H_valid; repeat rewrite andb_true_iff in H_valid; destruct H_valid as [[_ _] H_epoch]; unfold lifecycle_epoch_no_regression in H_epoch; apply Nat.leb_le; exact H_epoch.
  - unfold lifecycle_verify_valid in H_valid; repeat rewrite andb_true_iff in H_valid; destruct H_valid as [[_ _] H_epoch]; unfold lifecycle_epoch_no_regression in H_epoch; apply Nat.leb_le; exact H_epoch.
  - unfold lifecycle_open_valid in H_valid; repeat rewrite andb_true_iff in H_valid; destruct H_valid as [[[_ _] _] H_epoch]; unfold lifecycle_epoch_no_regression in H_epoch; apply Nat.leb_le; exact H_epoch.
  - unfold lifecycle_revoke_valid in H_valid; repeat rewrite andb_true_iff in H_valid; destruct H_valid as [[_ _] H_epoch]; unfold lifecycle_epoch_no_regression in H_epoch; apply Nat.leb_le; exact H_epoch.
  - unfold lifecycle_reject_valid in H_valid; repeat rewrite andb_true_iff in H_valid; destruct H_valid as [[_ _] H_epoch]; unfold lifecycle_epoch_no_regression in H_epoch; apply Nat.leb_le; exact H_epoch.
  - contradiction H_not_rotate. reflexivity.
  - unfold lifecycle_rewrap_valid in H_valid; repeat rewrite andb_true_iff in H_valid; destruct H_valid as [[_ _] H_epoch]; unfold lifecycle_epoch_no_regression in H_epoch; apply Nat.leb_le; exact H_epoch.
Qed.
