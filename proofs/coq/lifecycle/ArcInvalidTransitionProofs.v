From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcMerkle.
From ArcProofs Require Import ArcAuthority.
From ArcProofs Require Import ArcPolicy.
From ArcProofs Require Import ArcVerify.
From ArcProofs Require Import ArcSecurityGame.
From ArcProofs Require Import ArcTheorems.
From ArcProofs Require Import ArcStressProofs.
From ArcProofs Require Import ArcDelegationProofs.
From ArcProofs Require Import ArcCryptoReduction.
From ArcProofs Require Import ArcTemporalProofs.
From ArcProofs Require Import ArcTranscriptProofs.
From ArcProofs Require Import ArcRevocationCompromiseProofs.
From ArcProofs Require Import ArcTransparencyProofs.
From ArcProofs Require Import ArcEncodingProofs.
From ArcProofs Require Import ArcWrapperProofs.
From ArcProofs Require Import ArcKemAeadAssumptions.
From ArcProofs Require Import ArcEndToEndTheorems.
From ArcProofs Require Import ArcStateTransitionProofs.
From ArcProofs Require Import ArcConcreteMerkleProofs.
From ArcProofs Require Import ArcTransparencyConsistencyProofs.
From ArcProofs Require Import ArcProtocolStateMachineProofs.

Definition invalid_epoch_regression (step : ArcMachineStep) : bool :=
  Nat.ltb (machine_epoch (step_to step)) (machine_epoch (step_from step)).

Definition invalid_same_epoch_rotation (step : ArcMachineStep) : bool :=
  match step_operation step with
  | OpRotate => Nat.eqb (machine_epoch (step_from step)) (machine_epoch (step_to step))
  | _ => false
  end.

Definition invalid_revocation_root_regression (step : ArcMachineStep) : bool :=
  match step_operation step with
  | OpRevoke => Nat.ltb (machine_revocation_root (step_to step)) (machine_revocation_root (step_from step))
  | _ => false
  end.

Definition invalid_sealed_count_regression (step : ArcMachineStep) : bool :=
  match step_operation step with
  | OpSeal => Nat.ltb (machine_sealed_count (step_to step)) (machine_sealed_count (step_from step))
  | _ => false
  end.

Definition invalid_open_count_regression (step : ArcMachineStep) : bool :=
  match step_operation step with
  | OpOpen => Nat.ltb (machine_open_count (step_to step)) (machine_open_count (step_from step))
  | _ => false
  end.

Definition invalid_machine_step (step : ArcMachineStep) : bool :=
  invalid_epoch_regression step ||
  invalid_same_epoch_rotation step ||
  invalid_revocation_root_regression step ||
  invalid_sealed_count_regression step ||
  invalid_open_count_regression step.

Theorem invalid_epoch_regression_rejects_step :
  forall step,
    invalid_epoch_regression step = true ->
    machine_step_valid step = false.
Proof.
  intros step H.
  unfold invalid_epoch_regression in H.
  apply Nat.ltb_lt in H.

  assert (H_same_or_advances_false :
    machine_epoch_same_or_advances step = false).
  {
    unfold machine_epoch_same_or_advances.
    apply Nat.leb_gt.
    exact H.
  }

  assert (H_strict_advance_false :
    machine_epoch_strictly_advances step = false).
  {
    unfold machine_epoch_strictly_advances.
    apply Nat.ltb_ge.
    lia.
  }

  unfold machine_step_valid.
  destruct (step_operation step) eqn:H_op.
  - exact H_same_or_advances_false.
  - rewrite H_same_or_advances_false. reflexivity.
  - exact H_same_or_advances_false.
  - rewrite H_same_or_advances_false. reflexivity.
  - exact H_same_or_advances_false.
  - rewrite H_same_or_advances_false. reflexivity.
  - exact H_same_or_advances_false.
  - exact H_same_or_advances_false.
  - exact H_strict_advance_false.
Qed.

Theorem invalid_same_epoch_rotation_rejects_step :
  forall step,
    invalid_same_epoch_rotation step = true ->
    machine_step_valid step = false.
Proof.
  intros step H.
  unfold invalid_same_epoch_rotation in H.
  destruct (step_operation step) eqn:H_op; try discriminate.
  unfold machine_step_valid.
  rewrite H_op.
  unfold machine_epoch_strictly_advances.
  apply Nat.eqb_eq in H.
  rewrite H.
  rewrite Nat.ltb_irrefl.
  reflexivity.
Qed.

Theorem invalid_revocation_root_regression_rejects_step :
  forall step,
    invalid_revocation_root_regression step = true ->
    machine_step_valid step = false.
Proof.
  intros step H.
  unfold invalid_revocation_root_regression in H.
  destruct (step_operation step) eqn:H_op; try discriminate.
  apply Nat.ltb_lt in H.
  unfold machine_step_valid.
  rewrite H_op.
  unfold machine_epoch_same_or_advances.
  unfold machine_revocation_monotone_hint.
  apply Nat.leb_gt in H.
  rewrite H.
  destruct (machine_epoch (step_from step) <=? machine_epoch (step_to step)); reflexivity.
Qed.

Theorem invalid_sealed_count_regression_rejects_step :
  forall step,
    invalid_sealed_count_regression step = true ->
    machine_step_valid step = false.
Proof.
  intros step H.
  unfold invalid_sealed_count_regression in H.
  destruct (step_operation step) eqn:H_op; try discriminate.
  apply Nat.ltb_lt in H.
  unfold machine_step_valid.
  rewrite H_op.
  unfold machine_epoch_same_or_advances.
  unfold machine_sealed_count_monotone.
  apply Nat.leb_gt in H.
  rewrite H.
  destruct (machine_epoch (step_from step) <=? machine_epoch (step_to step)); reflexivity.
Qed.

Theorem invalid_open_count_regression_rejects_step :
  forall step,
    invalid_open_count_regression step = true ->
    machine_step_valid step = false.
Proof.
  intros step H.
  unfold invalid_open_count_regression in H.
  destruct (step_operation step) eqn:H_op; try discriminate.
  apply Nat.ltb_lt in H.
  unfold machine_step_valid.
  rewrite H_op.
  unfold machine_epoch_same_or_advances.
  unfold machine_open_count_monotone.
  apply Nat.leb_gt in H.
  rewrite H.
  destruct (machine_epoch (step_from step) <=? machine_epoch (step_to step)); reflexivity.
Qed.

Theorem invalid_machine_step_rejects :
  forall step,
    invalid_machine_step step = true ->
    machine_step_valid step = false.
Proof.
  intros step H.
  unfold invalid_machine_step in H.

  destruct (invalid_epoch_regression step) eqn:H_epoch.
  - apply invalid_epoch_regression_rejects_step.
    exact H_epoch.
  - simpl in H.
    destruct (invalid_same_epoch_rotation step) eqn:H_same.
    + apply invalid_same_epoch_rotation_rejects_step.
      exact H_same.
    + simpl in H.
      destruct (invalid_revocation_root_regression step) eqn:H_rev.
      * apply invalid_revocation_root_regression_rejects_step.
        exact H_rev.
      * simpl in H.
        destruct (invalid_sealed_count_regression step) eqn:H_seal.
        -- apply invalid_sealed_count_regression_rejects_step.
           exact H_seal.
        -- simpl in H.
           destruct (invalid_open_count_regression step) eqn:H_open.
           ++ apply invalid_open_count_regression_rejects_step.
              exact H_open.
           ++ discriminate.
Qed.

Theorem valid_step_has_no_invalid_machine_step :
  forall step,
    machine_step_valid step = true ->
    invalid_machine_step step = false.
Proof.
  intros step H_valid.
  destruct (invalid_machine_step step) eqn:H_invalid.
  - pose proof (invalid_machine_step_rejects step H_invalid) as H_reject.
    rewrite H_valid in H_reject.
    discriminate.
  - reflexivity.
Qed.
