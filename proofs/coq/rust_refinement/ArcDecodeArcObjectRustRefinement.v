From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcEncodingProofs.
From ArcProofs Require Import ArcRustRefinementMap.
From ArcProofs Require Import ArcRustRefinementObligations.
From ArcProofs Require Import ArcRustRefinementEvidence.
From ArcProofs Require Import ArcRustMechanicalRefinement.
From ArcProofs Require Import ArcRustFullMechanicalProofGate.
From ArcProofs Require Import ArcContextHashRustRefinement.

Inductive DecodeArcObjectParserCase :=
| DecodeEmptyInput
| DecodeTinyInput
| DecodeMalformedInput
| DecodeTruncatedInput
| DecodeLimitInput
| DecodeRoundTripReserved.

Record DecodeArcObjectMechanicalVector := {
  decode_vector_id : string;
  decode_vector_case : DecodeArcObjectParserCase;
  decode_vector_bytes_present : bool;
  decode_vector_expected_rejection : bool;
  decode_vector_time_bound_present : bool;
  decode_vector_roundtrip_reserved : bool
}.

Definition decode_vector_complete
  (vector : DecodeArcObjectMechanicalVector)
  : bool :=
  decode_vector_bytes_present vector &&
  decode_vector_time_bound_present vector &&
  match decode_vector_case vector with
  | DecodeRoundTripReserved => decode_vector_roundtrip_reserved vector
  | _ => decode_vector_expected_rejection vector
  end.

Fixpoint decode_vectors_complete
  (vectors : list DecodeArcObjectMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      decode_vector_complete head &&
      decode_vectors_complete tail
  end.

Definition arc_decode_arc_object_mechanical_vectors : list DecodeArcObjectMechanicalVector :=
  [
    {|
      decode_vector_id := "decode.empty";
      decode_vector_case := DecodeEmptyInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.single-zero";
      decode_vector_case := DecodeTinyInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.short-garbage-8";
      decode_vector_case := DecodeMalformedInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.truncated-32";
      decode_vector_case := DecodeTruncatedInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.truncated-127";
      decode_vector_case := DecodeTruncatedInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.repeated-zero-512";
      decode_vector_case := DecodeMalformedInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.repeated-ff-512";
      decode_vector_case := DecodeMalformedInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.deterministic-garbage-4096";
      decode_vector_case := DecodeLimitInput;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := true;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := false
    |};
    {|
      decode_vector_id := "decode.roundtrip-valid-object-reserved";
      decode_vector_case := DecodeRoundTripReserved;
      decode_vector_bytes_present := true;
      decode_vector_expected_rejection := false;
      decode_vector_time_bound_present := true;
      decode_vector_roundtrip_reserved := true
    |}
  ].

Record DecodeArcObjectRustRefinementStatus := {
  decode_arc_object_rust_symbol_present : bool;
  decode_arc_object_vectors_generated : bool;
  decode_arc_object_vector_schema_checked : bool;
  decode_arc_object_rejection_tests_pass : bool;
  decode_arc_object_truncation_tests_pass : bool;
  decode_arc_object_limit_tests_pass : bool;
  decode_arc_object_determinism_tests_pass : bool;
  decode_arc_object_roundtrip_reserved : bool;
  decode_arc_object_mechanically_checked : bool;
  decode_arc_object_mechanically_proven : bool
}.

Definition decode_arc_object_refinement_checked
  (status : DecodeArcObjectRustRefinementStatus)
  : bool :=
  decode_arc_object_rust_symbol_present status &&
  decode_arc_object_vectors_generated status &&
  decode_arc_object_vector_schema_checked status &&
  decode_arc_object_rejection_tests_pass status &&
  decode_arc_object_truncation_tests_pass status &&
  decode_arc_object_limit_tests_pass status &&
  decode_arc_object_determinism_tests_pass status &&
  decode_arc_object_roundtrip_reserved status &&
  decode_arc_object_mechanically_checked status.

Definition decode_arc_object_refinement_fully_proven
  (status : DecodeArcObjectRustRefinementStatus)
  : bool :=
  decode_arc_object_refinement_checked status &&
  decode_arc_object_mechanically_proven status.

Definition arc_current_decode_arc_object_refinement_status
  : DecodeArcObjectRustRefinementStatus :=
  {|
    decode_arc_object_rust_symbol_present := true;
    decode_arc_object_vectors_generated := true;
    decode_arc_object_vector_schema_checked := true;
    decode_arc_object_rejection_tests_pass := true;
    decode_arc_object_truncation_tests_pass := true;
    decode_arc_object_limit_tests_pass := true;
    decode_arc_object_determinism_tests_pass := true;
    decode_arc_object_roundtrip_reserved := true;
    decode_arc_object_mechanically_checked := true;
    decode_arc_object_mechanically_proven := false
  |}.

Theorem current_decode_arc_object_vectors_complete :
  decode_vectors_complete arc_decode_arc_object_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_decode_arc_object_refinement_checked :
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_decode_arc_object_refinement_not_fully_proven :
  decode_arc_object_refinement_fully_proven arc_current_decode_arc_object_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem decode_arc_object_checked_requires_rejection_tests :
  forall status,
    decode_arc_object_refinement_checked status = true ->
    decode_arc_object_rejection_tests_pass status = true.
Proof.
  intros status H.
  unfold decode_arc_object_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[H_symbol H_vectors] H_schema] H_reject] H_trunc] H_limit] H_determinism] H_roundtrip] H_checked].
  exact H_reject.
Qed.

Theorem decode_arc_object_checked_requires_truncation_tests :
  forall status,
    decode_arc_object_refinement_checked status = true ->
    decode_arc_object_truncation_tests_pass status = true.
Proof.
  intros status H.
  unfold decode_arc_object_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[H_symbol H_vectors] H_schema] H_reject] H_trunc] H_limit] H_determinism] H_roundtrip] H_checked].
  exact H_trunc.
Qed.

Theorem decode_arc_object_checked_requires_limit_tests :
  forall status,
    decode_arc_object_refinement_checked status = true ->
    decode_arc_object_limit_tests_pass status = true.
Proof.
  intros status H.
  unfold decode_arc_object_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[H_symbol H_vectors] H_schema] H_reject] H_trunc] H_limit] H_determinism] H_roundtrip] H_checked].
  exact H_limit.
Qed.

Theorem decode_arc_object_full_proof_requires_checked :
  forall status,
    decode_arc_object_refinement_fully_proven status = true ->
    decode_arc_object_refinement_checked status = true.
Proof.
  intros status H.
  unfold decode_arc_object_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem decode_arc_object_full_proof_requires_proven_flag :
  forall status,
    decode_arc_object_refinement_fully_proven status = true ->
    decode_arc_object_mechanically_proven status = true.
Proof.
  intros status H.
  unfold decode_arc_object_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition arc_full_mechanical_proof_gate_after_decode_check : ArcFullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem decode_arc_object_check_keeps_full_gate_open :
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_decode_check = false.
Proof.
  reflexivity.
Qed.

Theorem decode_arc_object_second_mechanical_target_status :
  context_hash_refinement_checked arc_current_context_hash_refinement_status = true /\
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true /\
  decode_arc_object_refinement_fully_proven arc_current_decode_arc_object_refinement_status = false /\
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_decode_check = false.
Proof.
  split.
  - apply current_context_hash_refinement_checked.
  - split.
    + apply current_decode_arc_object_refinement_checked.
    + split.
      * apply current_decode_arc_object_refinement_not_fully_proven.
      * apply decode_arc_object_check_keeps_full_gate_open.
Qed.
