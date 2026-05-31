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
Require Import ArcStateTransitionProofs.
Require Import ArcConcreteMerkleProofs.
Require Import ArcTransparencyConsistencyProofs.

Inductive ArcOperation :=
| OpIssue
| OpRevoke
| OpDelegate
| OpSeal
| OpVerify
| OpOpen
| OpRewrap
| OpReseal
| OpRotate.

Record ArcMachineState := {
  machine_epoch : Epoch;
  machine_authority_root : Hash;
  machine_revocation_root : Hash;
  machine_transparency_root : Hash;
  machine_sealed_count : nat;
  machine_open_count : nat
}.

Record ArcMachineStep := {
  step_operation : ArcOperation;
  step_from : ArcMachineState;
  step_to : ArcMachineState
}.

Definition machine_epoch_same_or_advances (step : ArcMachineStep) : bool :=
  Nat.leb (machine_epoch (step_from step)) (machine_epoch (step_to step)).

Definition machine_epoch_strictly_advances (step : ArcMachineStep) : bool :=
  Nat.ltb (machine_epoch (step_from step)) (machine_epoch (step_to step)).

Definition machine_revocation_monotone_hint (step : ArcMachineStep) : bool :=
  Nat.leb (machine_revocation_root (step_from step)) (machine_revocation_root (step_to step)).

Definition machine_sealed_count_monotone (step : ArcMachineStep) : bool :=
  Nat.leb (machine_sealed_count (step_from step)) (machine_sealed_count (step_to step)).

Definition machine_open_count_monotone (step : ArcMachineStep) : bool :=
  Nat.leb (machine_open_count (step_from step)) (machine_open_count (step_to step)).

Definition machine_step_valid (step : ArcMachineStep) : bool :=
  match step_operation step with
  | OpRotate => machine_epoch_strictly_advances step
  | OpRewrap => machine_epoch_same_or_advances step
  | OpRevoke => machine_epoch_same_or_advances step && machine_revocation_monotone_hint step
  | OpSeal => machine_epoch_same_or_advances step && machine_sealed_count_monotone step
  | OpOpen => machine_epoch_same_or_advances step && machine_open_count_monotone step
  | OpIssue => machine_epoch_same_or_advances step
  | OpDelegate => machine_epoch_same_or_advances step
  | OpVerify => machine_epoch_same_or_advances step
  | OpReseal => machine_epoch_same_or_advances step
  end.

Fixpoint machine_trace_valid (steps : list ArcMachineStep) : bool :=
  match steps with
  | [] => true
  | head :: tail => machine_step_valid head && machine_trace_valid tail
  end.

Theorem valid_trace_head_valid :
  forall head tail,
    machine_trace_valid (head :: tail) = true ->
    machine_step_valid head = true.
Proof.
  intros head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  exact H_head.
Qed.

Theorem valid_trace_tail_valid :
  forall head tail,
    machine_trace_valid (head :: tail) = true ->
    machine_trace_valid tail = true.
Proof.
  intros head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  exact H_tail.
Qed.

Theorem rotate_step_valid_implies_epoch_advance :
  forall step,
    step_operation step = OpRotate ->
    machine_step_valid step = true ->
    machine_epoch (step_from step) < machine_epoch (step_to step).
Proof.
  intros step H_op H_valid.
  unfold machine_step_valid in H_valid.
  rewrite H_op in H_valid.
  unfold machine_epoch_strictly_advances in H_valid.
  apply Nat.ltb_lt.
  exact H_valid.
Qed.

Theorem rewrap_step_valid_implies_no_epoch_regression :
  forall step,
    step_operation step = OpRewrap ->
    machine_step_valid step = true ->
    machine_epoch (step_from step) <= machine_epoch (step_to step).
Proof.
  intros step H_op H_valid.
  unfold machine_step_valid in H_valid.
  rewrite H_op in H_valid.
  unfold machine_epoch_same_or_advances in H_valid.
  apply Nat.leb_le.
  exact H_valid.
Qed.

Theorem revoke_step_valid_implies_no_epoch_regression :
  forall step,
    step_operation step = OpRevoke ->
    machine_step_valid step = true ->
    machine_epoch (step_from step) <= machine_epoch (step_to step).
Proof.
  intros step H_op H_valid.
  unfold machine_step_valid in H_valid.
  rewrite H_op in H_valid.
  apply andb_true_iff in H_valid.
  destruct H_valid as [H_epoch H_rev].
  unfold machine_epoch_same_or_advances in H_epoch.
  apply Nat.leb_le.
  exact H_epoch.
Qed.

Theorem revoke_step_valid_implies_revocation_monotone :
  forall step,
    step_operation step = OpRevoke ->
    machine_step_valid step = true ->
    machine_revocation_root (step_from step) <= machine_revocation_root (step_to step).
Proof.
  intros step H_op H_valid.
  unfold machine_step_valid in H_valid.
  rewrite H_op in H_valid.
  apply andb_true_iff in H_valid.
  destruct H_valid as [H_epoch H_rev].
  unfold machine_revocation_monotone_hint in H_rev.
  apply Nat.leb_le.
  exact H_rev.
Qed.

Theorem seal_step_valid_implies_sealed_count_monotone :
  forall step,
    step_operation step = OpSeal ->
    machine_step_valid step = true ->
    machine_sealed_count (step_from step) <= machine_sealed_count (step_to step).
Proof.
  intros step H_op H_valid.
  unfold machine_step_valid in H_valid.
  rewrite H_op in H_valid.
  apply andb_true_iff in H_valid.
  destruct H_valid as [H_epoch H_seal].
  unfold machine_sealed_count_monotone in H_seal.
  apply Nat.leb_le.
  exact H_seal.
Qed.

Theorem open_step_valid_implies_open_count_monotone :
  forall step,
    step_operation step = OpOpen ->
    machine_step_valid step = true ->
    machine_open_count (step_from step) <= machine_open_count (step_to step).
Proof.
  intros step H_op H_valid.
  unfold machine_step_valid in H_valid.
  rewrite H_op in H_valid.
  apply andb_true_iff in H_valid.
  destruct H_valid as [H_epoch H_open].
  unfold machine_open_count_monotone in H_open.
  apply Nat.leb_le.
  exact H_open.
Qed.

Theorem valid_trace_first_rotate_advances :
  forall step rest,
    step_operation step = OpRotate ->
    machine_trace_valid (step :: rest) = true ->
    machine_epoch (step_from step) < machine_epoch (step_to step).
Proof.
  intros step rest H_op H_trace.
  apply rotate_step_valid_implies_epoch_advance.
  - exact H_op.
  - apply valid_trace_head_valid with (tail := rest).
    exact H_trace.
Qed.

Theorem invalid_rotate_regression_rejected :
  forall step,
    step_operation step = OpRotate ->
    machine_epoch (step_to step) <= machine_epoch (step_from step) ->
    machine_step_valid step = false.
Proof.
  intros step H_op H_regress.
  unfold machine_step_valid.
  rewrite H_op.
  unfold machine_epoch_strictly_advances.
  apply Nat.ltb_ge.
  exact H_regress.
Qed.
