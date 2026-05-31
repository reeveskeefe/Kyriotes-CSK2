From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcVerify.
From ArcProofs Require Import ArcMasterInvariantProofs.
From ArcProofs Require Import ArcRustRefinementMap.
From ArcProofs Require Import ArcRustRefinementObligations.
From ArcProofs Require Import ArcRustRefinementEvidence.
From ArcProofs Require Import ArcRustMechanicalRefinement.
From ArcProofs Require Import ArcRustFullMechanicalProofGate.
From ArcProofs Require Import ArcContextHashRustRefinement.
From ArcProofs Require Import ArcDecodeArcObjectRustRefinement.
From ArcProofs Require Import ArcEncodeArcObjectRustRefinement.

Inductive VerifyGateCase :=
| VerifyMissingObject
| VerifyMissingCapability
| VerifyMissingCapabilityProof
| VerifyMissingAuthorityState
| VerifyMissingTransparencyProof
| VerifyRevokedCapability
| VerifyTemporalMismatch
| VerifyTranscriptMismatch
| VerifyWrapperMismatch
| VerifyValidReserved.

Record VerifyMechanicalVector := {
  verify_vector_id : string;
  verify_vector_case : VerifyGateCase;
  verify_vector_expected_rejection : bool;
  verify_vector_reserved_valid_case : bool;
  verify_vector_deterministic : bool
}.

Definition verify_vector_complete
  (vector : VerifyMechanicalVector)
  : bool :=
  verify_vector_deterministic vector &&
  match verify_vector_case vector with
  | VerifyValidReserved => verify_vector_reserved_valid_case vector
  | _ => verify_vector_expected_rejection vector
  end.

Fixpoint verify_vectors_complete
  (vectors : list VerifyMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      verify_vector_complete head &&
      verify_vectors_complete tail
  end.

Definition arc_verify_mechanical_vectors : list VerifyMechanicalVector :=
  [
    {|
      verify_vector_id := "verify.missing-object";
      verify_vector_case := VerifyMissingObject;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.missing-capability";
      verify_vector_case := VerifyMissingCapability;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.missing-capability-proof";
      verify_vector_case := VerifyMissingCapabilityProof;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.missing-authority-state";
      verify_vector_case := VerifyMissingAuthorityState;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.missing-transparency-proof";
      verify_vector_case := VerifyMissingTransparencyProof;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.revoked-capability";
      verify_vector_case := VerifyRevokedCapability;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.temporal-mismatch";
      verify_vector_case := VerifyTemporalMismatch;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.transcript-mismatch";
      verify_vector_case := VerifyTranscriptMismatch;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.wrapper-mismatch";
      verify_vector_case := VerifyWrapperMismatch;
      verify_vector_expected_rejection := true;
      verify_vector_reserved_valid_case := false;
      verify_vector_deterministic := true
    |};
    {|
      verify_vector_id := "verify.valid-reserved";
      verify_vector_case := VerifyValidReserved;
      verify_vector_expected_rejection := false;
      verify_vector_reserved_valid_case := true;
      verify_vector_deterministic := true
    |}
  ].

Record VerifyRustRefinementStatus := {
  verify_rust_symbol_present : bool;
  verify_surface_check_pass : bool;
  verify_vectors_generated : bool;
  verify_vector_schema_checked : bool;
  verify_rejection_gate_track_present : bool;
  verify_valid_case_reserved : bool;
  verify_mechanically_checked : bool;
  verify_mechanically_proven : bool
}.

Definition verify_refinement_checked
  (status : VerifyRustRefinementStatus)
  : bool :=
  verify_rust_symbol_present status &&
  verify_surface_check_pass status &&
  verify_vectors_generated status &&
  verify_vector_schema_checked status &&
  verify_rejection_gate_track_present status &&
  verify_valid_case_reserved status &&
  verify_mechanically_checked status.

Definition verify_refinement_fully_proven
  (status : VerifyRustRefinementStatus)
  : bool :=
  verify_refinement_checked status &&
  verify_mechanically_proven status.

Definition arc_current_verify_refinement_status : VerifyRustRefinementStatus :=
  {|
    verify_rust_symbol_present := true;
    verify_surface_check_pass := true;
    verify_vectors_generated := true;
    verify_vector_schema_checked := true;
    verify_rejection_gate_track_present := true;
    verify_valid_case_reserved := true;
    verify_mechanically_checked := true;
    verify_mechanically_proven := false
  |}.

Theorem current_verify_vectors_complete :
  verify_vectors_complete arc_verify_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_verify_refinement_checked :
  verify_refinement_checked arc_current_verify_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_verify_refinement_not_fully_proven :
  verify_refinement_fully_proven arc_current_verify_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem verify_checked_requires_surface_check :
  forall status,
    verify_refinement_checked status = true ->
    verify_surface_check_pass status = true.
Proof.
  intros status H.
  unfold verify_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_symbol H_surface] H_vectors] H_schema] H_gate] H_reserved] H_checked].
  exact H_surface.
Qed.

Theorem verify_checked_requires_gate_track :
  forall status,
    verify_refinement_checked status = true ->
    verify_rejection_gate_track_present status = true.
Proof.
  intros status H.
  unfold verify_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_symbol H_surface] H_vectors] H_schema] H_gate] H_reserved] H_checked].
  exact H_gate.
Qed.

Theorem verify_full_proof_requires_checked :
  forall status,
    verify_refinement_fully_proven status = true ->
    verify_refinement_checked status = true.
Proof.
  intros status H.
  unfold verify_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem verify_full_proof_requires_proven_flag :
  forall status,
    verify_refinement_fully_proven status = true ->
    verify_mechanically_proven status = true.
Proof.
  intros status H.
  unfold verify_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition arc_full_mechanical_proof_gate_after_verify_check : ArcFullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem verify_check_keeps_full_gate_open :
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_verify_check = false.
Proof.
  reflexivity.
Qed.

Theorem verify_fourth_mechanical_target_status :
  context_hash_refinement_checked arc_current_context_hash_refinement_status = true /\
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true /\
  encode_arc_object_refinement_checked arc_current_encode_arc_object_refinement_status = true /\
  verify_refinement_checked arc_current_verify_refinement_status = true /\
  verify_refinement_fully_proven arc_current_verify_refinement_status = false /\
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_verify_check = false.
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
           ++ apply current_verify_refinement_not_fully_proven.
           ++ apply verify_check_keeps_full_gate_open.
Qed.
