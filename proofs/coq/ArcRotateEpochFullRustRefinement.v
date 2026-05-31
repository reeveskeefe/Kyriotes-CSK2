From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

Require Import ArcTypes.
Require Import ArcAuthority.
Require Import ArcTransparencyAppendOnly.
Require Import ArcMerkleTransparencyCompleteness.
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
Require Import ArcRotateEpochRustRefinement.

Inductive RotateEpochFullGateCase :=
| RotateFullMissingTransparencyLog
| RotateFullMissingPreviousAuthorityState
| RotateFullMissingNextAuthorityState
| RotateFullMissingPreviousEpoch
| RotateFullMissingNextEpoch
| RotateFullEpochRegression
| RotateFullSameEpoch
| RotateFullAuthorityRootContinuityReserved
| RotateFullStateRootConsistencyReserved
| RotateFullChainHashLinkageReserved
| RotateFullTransparencyCommitLinkageReserved
| RotateFullVerifyRoundTripReserved.

Record RotateEpochFullMechanicalVector := {
  rotate_full_vector_id : string;
  rotate_full_vector_case : RotateEpochFullGateCase;
  rotate_full_vector_expected_rejection : bool;
  rotate_full_vector_reserved_valid_case : bool;
  rotate_full_vector_deterministic : bool
}.

Definition rotate_full_vector_complete
  (vector : RotateEpochFullMechanicalVector)
  : bool :=
  rotate_full_vector_deterministic vector &&
  match rotate_full_vector_case vector with
  | RotateFullAuthorityRootContinuityReserved => rotate_full_vector_reserved_valid_case vector
  | RotateFullStateRootConsistencyReserved => rotate_full_vector_reserved_valid_case vector
  | RotateFullChainHashLinkageReserved => rotate_full_vector_reserved_valid_case vector
  | RotateFullTransparencyCommitLinkageReserved => rotate_full_vector_reserved_valid_case vector
  | RotateFullVerifyRoundTripReserved => rotate_full_vector_reserved_valid_case vector
  | _ => rotate_full_vector_expected_rejection vector
  end.

Fixpoint rotate_full_vectors_complete
  (vectors : list RotateEpochFullMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      rotate_full_vector_complete head &&
      rotate_full_vectors_complete tail
  end.

Definition arc_rotate_epoch_full_mechanical_vectors : list RotateEpochFullMechanicalVector :=
  [
    {|
      rotate_full_vector_id := "rotate-full.missing-transparency-log";
      rotate_full_vector_case := RotateFullMissingTransparencyLog;
      rotate_full_vector_expected_rejection := true;
      rotate_full_vector_reserved_valid_case := false;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.missing-previous-authority-state";
      rotate_full_vector_case := RotateFullMissingPreviousAuthorityState;
      rotate_full_vector_expected_rejection := true;
      rotate_full_vector_reserved_valid_case := false;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.missing-next-authority-state";
      rotate_full_vector_case := RotateFullMissingNextAuthorityState;
      rotate_full_vector_expected_rejection := true;
      rotate_full_vector_reserved_valid_case := false;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.missing-previous-epoch";
      rotate_full_vector_case := RotateFullMissingPreviousEpoch;
      rotate_full_vector_expected_rejection := true;
      rotate_full_vector_reserved_valid_case := false;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.missing-next-epoch";
      rotate_full_vector_case := RotateFullMissingNextEpoch;
      rotate_full_vector_expected_rejection := true;
      rotate_full_vector_reserved_valid_case := false;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.epoch-regression";
      rotate_full_vector_case := RotateFullEpochRegression;
      rotate_full_vector_expected_rejection := true;
      rotate_full_vector_reserved_valid_case := false;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.same-epoch";
      rotate_full_vector_case := RotateFullSameEpoch;
      rotate_full_vector_expected_rejection := true;
      rotate_full_vector_reserved_valid_case := false;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.authority-root-continuity-reserved";
      rotate_full_vector_case := RotateFullAuthorityRootContinuityReserved;
      rotate_full_vector_expected_rejection := false;
      rotate_full_vector_reserved_valid_case := true;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.state-root-consistency-reserved";
      rotate_full_vector_case := RotateFullStateRootConsistencyReserved;
      rotate_full_vector_expected_rejection := false;
      rotate_full_vector_reserved_valid_case := true;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.chain-hash-linkage-reserved";
      rotate_full_vector_case := RotateFullChainHashLinkageReserved;
      rotate_full_vector_expected_rejection := false;
      rotate_full_vector_reserved_valid_case := true;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.transparency-commit-linkage-reserved";
      rotate_full_vector_case := RotateFullTransparencyCommitLinkageReserved;
      rotate_full_vector_expected_rejection := false;
      rotate_full_vector_reserved_valid_case := true;
      rotate_full_vector_deterministic := true
    |};
    {|
      rotate_full_vector_id := "rotate-full.verify-roundtrip-reserved";
      rotate_full_vector_case := RotateFullVerifyRoundTripReserved;
      rotate_full_vector_expected_rejection := false;
      rotate_full_vector_reserved_valid_case := true;
      rotate_full_vector_deterministic := true
    |}
  ].

Record RotateEpochFullRustRefinementStatus := {
  rotate_epoch_full_rust_symbol_present : bool;
  rotate_epoch_full_surface_check_pass : bool;
  rotate_epoch_full_vectors_generated : bool;
  rotate_epoch_full_vector_schema_checked : bool;
  rotate_epoch_full_strict_advance_track_present : bool;
  rotate_epoch_full_regression_rejection_track_present : bool;
  rotate_epoch_full_state_root_reserved : bool;
  rotate_epoch_full_transparency_commit_reserved : bool;
  rotate_epoch_full_mechanically_checked : bool;
  rotate_epoch_full_mechanically_proven : bool
}.

Definition rotate_epoch_full_refinement_checked
  (status : RotateEpochFullRustRefinementStatus)
  : bool :=
  rotate_epoch_full_rust_symbol_present status &&
  rotate_epoch_full_surface_check_pass status &&
  rotate_epoch_full_vectors_generated status &&
  rotate_epoch_full_vector_schema_checked status &&
  rotate_epoch_full_strict_advance_track_present status &&
  rotate_epoch_full_regression_rejection_track_present status &&
  rotate_epoch_full_state_root_reserved status &&
  rotate_epoch_full_transparency_commit_reserved status &&
  rotate_epoch_full_mechanically_checked status.

Definition rotate_epoch_full_refinement_fully_proven
  (status : RotateEpochFullRustRefinementStatus)
  : bool :=
  rotate_epoch_full_refinement_checked status &&
  rotate_epoch_full_mechanically_proven status.

Definition arc_current_rotate_epoch_full_refinement_status
  : RotateEpochFullRustRefinementStatus :=
  {|
    rotate_epoch_full_rust_symbol_present := true;
    rotate_epoch_full_surface_check_pass := true;
    rotate_epoch_full_vectors_generated := true;
    rotate_epoch_full_vector_schema_checked := true;
    rotate_epoch_full_strict_advance_track_present := true;
    rotate_epoch_full_regression_rejection_track_present := true;
    rotate_epoch_full_state_root_reserved := true;
    rotate_epoch_full_transparency_commit_reserved := true;
    rotate_epoch_full_mechanically_checked := true;
    rotate_epoch_full_mechanically_proven := false
  |}.

Theorem current_rotate_epoch_full_vectors_complete :
  rotate_full_vectors_complete arc_rotate_epoch_full_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_rotate_epoch_full_refinement_checked :
  rotate_epoch_full_refinement_checked arc_current_rotate_epoch_full_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_rotate_epoch_full_refinement_not_fully_proven :
  rotate_epoch_full_refinement_fully_proven arc_current_rotate_epoch_full_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem rotate_epoch_full_checked_requires_surface_check :
  forall status,
    rotate_epoch_full_refinement_checked status = true ->
    rotate_epoch_full_surface_check_pass status = true.
Proof.
  intros status H.
  unfold rotate_epoch_full_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[H_symbol H_surface] H_vectors] H_schema] H_advance] H_regress] H_state] H_transparency] H_checked].
  exact H_surface.
Qed.

Theorem rotate_epoch_full_checked_requires_transparency_track :
  forall status,
    rotate_epoch_full_refinement_checked status = true ->
    rotate_epoch_full_transparency_commit_reserved status = true.
Proof.
  intros status H.
  unfold rotate_epoch_full_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[H_symbol H_surface] H_vectors] H_schema] H_advance] H_regress] H_state] H_transparency] H_checked].
  exact H_transparency.
Qed.

Theorem rotate_epoch_full_proof_requires_checked :
  forall status,
    rotate_epoch_full_refinement_fully_proven status = true ->
    rotate_epoch_full_refinement_checked status = true.
Proof.
  intros status H.
  unfold rotate_epoch_full_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem rotate_epoch_full_proof_requires_proven_flag :
  forall status,
    rotate_epoch_full_refinement_fully_proven status = true ->
    rotate_epoch_full_mechanically_proven status = true.
Proof.
  intros status H.
  unfold rotate_epoch_full_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition arc_full_mechanical_proof_gate_after_rotate_epoch_full_check : ArcFullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem rotate_epoch_full_check_keeps_full_gate_open :
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_rotate_epoch_full_check = false.
Proof.
  reflexivity.
Qed.

Theorem rotate_epoch_full_ninth_mechanical_target_status :
  context_hash_refinement_checked arc_current_context_hash_refinement_status = true /\
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true /\
  encode_arc_object_refinement_checked arc_current_encode_arc_object_refinement_status = true /\
  verify_refinement_checked arc_current_verify_refinement_status = true /\
  seal_refinement_checked arc_current_seal_refinement_status = true /\
  open_refinement_checked arc_current_open_refinement_status = true /\
  add_wrapper_refinement_checked arc_current_add_epoch_wrapper_refinement_status = true /\
  rotate_epoch_refinement_checked arc_current_rotate_epoch_refinement_status = true /\
  rotate_epoch_full_refinement_checked arc_current_rotate_epoch_full_refinement_status = true /\
  rotate_epoch_full_refinement_fully_proven arc_current_rotate_epoch_full_refinement_status = false /\
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_rotate_epoch_full_check = false.
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
                         *** apply current_rotate_epoch_full_refinement_checked.
                         *** split.
                             ---- apply current_rotate_epoch_full_refinement_not_fully_proven.
                             ---- apply rotate_epoch_full_check_keeps_full_gate_open.
Qed.
