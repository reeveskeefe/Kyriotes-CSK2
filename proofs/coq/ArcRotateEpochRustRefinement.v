From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

Require Import ArcTypes.
Require Import ArcAuthority.
Require Import ArcStateMachineCompleteness.
Require Import ArcStateTransitionProofs.
Require Import ArcRustRefinementMap.
Require Import ArcRustRefinementObligations.
Require Import ArcRustRefinementEvidence.
Require Import ArcRustMechanicalRefinement.
Require Import ArcRustFullMechanicalProofGate.
Require Import ArcContextHashRustRefinement.
Require Import ArcDecodeArcObjectRustRefinement.
Require Import ArcEncodeArcObjectRustRefinement.
Require Import ArcVerifyRustRefinement.
Require Import ArcSealRustRefinement.
Require Import ArcOpenRustRefinement.
Require Import ArcAddEpochWrapperRustRefinement.

Inductive RotateEpochGateCase :=
| RotateMissingPreviousAuthorityState
| RotateMissingNextAuthorityState
| RotateMissingPreviousEpoch
| RotateMissingNextEpoch
| RotateEpochRegression
| RotateSameEpoch
| RotateStrictAdvanceReserved
| RotateAuthorityRootContinuityReserved
| RotateChainHashLinkageReserved
| RotateVerifyRoundTripReserved.

Record RotateEpochMechanicalVector := {
  rotate_vector_id : string;
  rotate_vector_case : RotateEpochGateCase;
  rotate_vector_expected_rejection : bool;
  rotate_vector_reserved_valid_case : bool;
  rotate_vector_deterministic : bool
}.

Definition rotate_vector_complete
  (vector : RotateEpochMechanicalVector)
  : bool :=
  rotate_vector_deterministic vector &&
  match rotate_vector_case vector with
  | RotateStrictAdvanceReserved => rotate_vector_reserved_valid_case vector
  | RotateAuthorityRootContinuityReserved => rotate_vector_reserved_valid_case vector
  | RotateChainHashLinkageReserved => rotate_vector_reserved_valid_case vector
  | RotateVerifyRoundTripReserved => rotate_vector_reserved_valid_case vector
  | _ => rotate_vector_expected_rejection vector
  end.

Fixpoint rotate_vectors_complete
  (vectors : list RotateEpochMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      rotate_vector_complete head &&
      rotate_vectors_complete tail
  end.

Definition arc_rotate_epoch_mechanical_vectors : list RotateEpochMechanicalVector :=
  [
    {|
      rotate_vector_id := "rotate.missing-previous-authority-state";
      rotate_vector_case := RotateMissingPreviousAuthorityState;
      rotate_vector_expected_rejection := true;
      rotate_vector_reserved_valid_case := false;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.missing-next-authority-state";
      rotate_vector_case := RotateMissingNextAuthorityState;
      rotate_vector_expected_rejection := true;
      rotate_vector_reserved_valid_case := false;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.missing-previous-epoch";
      rotate_vector_case := RotateMissingPreviousEpoch;
      rotate_vector_expected_rejection := true;
      rotate_vector_reserved_valid_case := false;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.missing-next-epoch";
      rotate_vector_case := RotateMissingNextEpoch;
      rotate_vector_expected_rejection := true;
      rotate_vector_reserved_valid_case := false;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.epoch-regression";
      rotate_vector_case := RotateEpochRegression;
      rotate_vector_expected_rejection := true;
      rotate_vector_reserved_valid_case := false;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.same-epoch";
      rotate_vector_case := RotateSameEpoch;
      rotate_vector_expected_rejection := true;
      rotate_vector_reserved_valid_case := false;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.strict-advance-reserved";
      rotate_vector_case := RotateStrictAdvanceReserved;
      rotate_vector_expected_rejection := false;
      rotate_vector_reserved_valid_case := true;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.authority-root-continuity-reserved";
      rotate_vector_case := RotateAuthorityRootContinuityReserved;
      rotate_vector_expected_rejection := false;
      rotate_vector_reserved_valid_case := true;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.chain-hash-linkage-reserved";
      rotate_vector_case := RotateChainHashLinkageReserved;
      rotate_vector_expected_rejection := false;
      rotate_vector_reserved_valid_case := true;
      rotate_vector_deterministic := true
    |};
    {|
      rotate_vector_id := "rotate.verify-roundtrip-reserved";
      rotate_vector_case := RotateVerifyRoundTripReserved;
      rotate_vector_expected_rejection := false;
      rotate_vector_reserved_valid_case := true;
      rotate_vector_deterministic := true
    |}
  ].

Record RotateEpochRustRefinementStatus := {
  rotate_epoch_rust_symbol_present : bool;
  rotate_epoch_surface_check_pass : bool;
  rotate_epoch_vectors_generated : bool;
  rotate_epoch_vector_schema_checked : bool;
  rotate_epoch_strict_advance_track_present : bool;
  rotate_epoch_regression_rejection_track_present : bool;
  rotate_epoch_chain_linkage_reserved : bool;
  rotate_epoch_mechanically_checked : bool;
  rotate_epoch_mechanically_proven : bool
}.

Definition rotate_epoch_refinement_checked
  (status : RotateEpochRustRefinementStatus)
  : bool :=
  rotate_epoch_rust_symbol_present status &&
  rotate_epoch_surface_check_pass status &&
  rotate_epoch_vectors_generated status &&
  rotate_epoch_vector_schema_checked status &&
  rotate_epoch_strict_advance_track_present status &&
  rotate_epoch_regression_rejection_track_present status &&
  rotate_epoch_chain_linkage_reserved status &&
  rotate_epoch_mechanically_checked status.

Definition rotate_epoch_refinement_fully_proven
  (status : RotateEpochRustRefinementStatus)
  : bool :=
  rotate_epoch_refinement_checked status &&
  rotate_epoch_mechanically_proven status.

Definition arc_current_rotate_epoch_refinement_status
  : RotateEpochRustRefinementStatus :=
  {|
    rotate_epoch_rust_symbol_present := true;
    rotate_epoch_surface_check_pass := true;
    rotate_epoch_vectors_generated := true;
    rotate_epoch_vector_schema_checked := true;
    rotate_epoch_strict_advance_track_present := true;
    rotate_epoch_regression_rejection_track_present := true;
    rotate_epoch_chain_linkage_reserved := true;
    rotate_epoch_mechanically_checked := true;
    rotate_epoch_mechanically_proven := false
  |}.

Theorem current_rotate_epoch_vectors_complete :
  rotate_vectors_complete arc_rotate_epoch_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_rotate_epoch_refinement_checked :
  rotate_epoch_refinement_checked arc_current_rotate_epoch_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_rotate_epoch_refinement_not_fully_proven :
  rotate_epoch_refinement_fully_proven arc_current_rotate_epoch_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem rotate_epoch_checked_requires_surface_check :
  forall status,
    rotate_epoch_refinement_checked status = true ->
    rotate_epoch_surface_check_pass status = true.
Proof.
  intros status H.
  unfold rotate_epoch_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_advance] H_regress] H_chain] H_checked].
  exact H_surface.
Qed.

Theorem rotate_epoch_checked_requires_regression_track :
  forall status,
    rotate_epoch_refinement_checked status = true ->
    rotate_epoch_regression_rejection_track_present status = true.
Proof.
  intros status H.
  unfold rotate_epoch_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_advance] H_regress] H_chain] H_checked].
  exact H_regress.
Qed.

Theorem rotate_epoch_full_proof_requires_checked :
  forall status,
    rotate_epoch_refinement_fully_proven status = true ->
    rotate_epoch_refinement_checked status = true.
Proof.
  intros status H.
  unfold rotate_epoch_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem rotate_epoch_full_proof_requires_proven_flag :
  forall status,
    rotate_epoch_refinement_fully_proven status = true ->
    rotate_epoch_mechanically_proven status = true.
Proof.
  intros status H.
  unfold rotate_epoch_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition arc_full_mechanical_proof_gate_after_rotate_epoch_check : ArcFullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem rotate_epoch_check_keeps_full_gate_open :
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_rotate_epoch_check = false.
Proof.
  reflexivity.
Qed.

Theorem rotate_epoch_eighth_mechanical_target_status :
  context_hash_refinement_checked arc_current_context_hash_refinement_status = true /\
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true /\
  encode_arc_object_refinement_checked arc_current_encode_arc_object_refinement_status = true /\
  verify_refinement_checked arc_current_verify_refinement_status = true /\
  seal_refinement_checked arc_current_seal_refinement_status = true /\
  open_refinement_checked arc_current_open_refinement_status = true /\
  add_wrapper_refinement_checked arc_current_add_epoch_wrapper_refinement_status = true /\
  rotate_epoch_refinement_checked arc_current_rotate_epoch_refinement_status = true /\
  rotate_epoch_refinement_fully_proven arc_current_rotate_epoch_refinement_status = false /\
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_rotate_epoch_check = false.
Proof.
  split.
  - apply current_context_hash_refinement_checked.
  - split.
    + apply current_decode_arc_object_refinement_checked.
    + split.
      * apply current_encode_arc_object_refinement_checked.
      * split.
        -- apply current_verify_refinement_checked.
        -- split.
           ++ apply current_seal_refinement_checked.
           ++ split.
              ** apply current_open_refinement_checked.
              ** split.
                 --- apply current_add_wrapper_refinement_checked.
                 --- split.
                     +++ apply current_rotate_epoch_refinement_checked.
                     +++ split.
                         *** apply current_rotate_epoch_refinement_not_fully_proven.
                         *** apply rotate_epoch_check_keeps_full_gate_open.
Qed.
