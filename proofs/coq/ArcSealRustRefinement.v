From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

Require Import ArcTypes.
Require Import ArcLifecycleProofs.
Require Import ArcMasterInvariantProofs.
Require Import ArcRustRefinementMap.
Require Import ArcRustRefinementObligations.
Require Import ArcRustRefinementEvidence.
Require Import ArcRustMechanicalRefinement.
Require Import ArcRustFullMechanicalProofGate.
Require Import ArcContextHashRustRefinement.
Require Import ArcDecodeArcObjectRustRefinement.
Require Import ArcEncodeArcObjectRustRefinement.
Require Import ArcVerifyRustRefinement.

Inductive SealGateCase :=
| SealMissingRecipientKey
| SealMissingMessage
| SealMissingCapability
| SealMissingCapabilityProof
| SealMissingAuthorityState
| SealMissingTransparencyProof
| SealTemporalPolicyRequired
| SealLifecycleReserved
| SealVerifyRoundTripReserved
| SealOpenRoundTripReserved.

Record SealMechanicalVector := {
  seal_vector_id : string;
  seal_vector_case : SealGateCase;
  seal_vector_expected_rejection : bool;
  seal_vector_reserved_valid_case : bool;
  seal_vector_deterministic : bool
}.

Definition seal_vector_complete
  (vector : SealMechanicalVector)
  : bool :=
  seal_vector_deterministic vector &&
  match seal_vector_case vector with
  | SealLifecycleReserved => seal_vector_reserved_valid_case vector
  | SealVerifyRoundTripReserved => seal_vector_reserved_valid_case vector
  | SealOpenRoundTripReserved => seal_vector_reserved_valid_case vector
  | _ => seal_vector_expected_rejection vector
  end.

Fixpoint seal_vectors_complete
  (vectors : list SealMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      seal_vector_complete head &&
      seal_vectors_complete tail
  end.

Definition arc_seal_mechanical_vectors : list SealMechanicalVector :=
  [
    {|
      seal_vector_id := "seal.missing-recipient-key";
      seal_vector_case := SealMissingRecipientKey;
      seal_vector_expected_rejection := true;
      seal_vector_reserved_valid_case := false;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.missing-message";
      seal_vector_case := SealMissingMessage;
      seal_vector_expected_rejection := true;
      seal_vector_reserved_valid_case := false;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.missing-capability";
      seal_vector_case := SealMissingCapability;
      seal_vector_expected_rejection := true;
      seal_vector_reserved_valid_case := false;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.missing-capability-proof";
      seal_vector_case := SealMissingCapabilityProof;
      seal_vector_expected_rejection := true;
      seal_vector_reserved_valid_case := false;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.missing-authority-state";
      seal_vector_case := SealMissingAuthorityState;
      seal_vector_expected_rejection := true;
      seal_vector_reserved_valid_case := false;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.missing-transparency-proof";
      seal_vector_case := SealMissingTransparencyProof;
      seal_vector_expected_rejection := true;
      seal_vector_reserved_valid_case := false;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.temporal-policy-required";
      seal_vector_case := SealTemporalPolicyRequired;
      seal_vector_expected_rejection := true;
      seal_vector_reserved_valid_case := false;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.lifecycle-reserved";
      seal_vector_case := SealLifecycleReserved;
      seal_vector_expected_rejection := false;
      seal_vector_reserved_valid_case := true;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.verify-roundtrip-reserved";
      seal_vector_case := SealVerifyRoundTripReserved;
      seal_vector_expected_rejection := false;
      seal_vector_reserved_valid_case := true;
      seal_vector_deterministic := true
    |};
    {|
      seal_vector_id := "seal.open-roundtrip-reserved";
      seal_vector_case := SealOpenRoundTripReserved;
      seal_vector_expected_rejection := false;
      seal_vector_reserved_valid_case := true;
      seal_vector_deterministic := true
    |}
  ].

Record SealRustRefinementStatus := {
  seal_rust_symbol_present : bool;
  seal_surface_check_pass : bool;
  seal_vectors_generated : bool;
  seal_vector_schema_checked : bool;
  seal_lifecycle_track_present : bool;
  seal_verify_roundtrip_reserved : bool;
  seal_open_roundtrip_reserved : bool;
  seal_mechanically_checked : bool;
  seal_mechanically_proven : bool
}.

Definition seal_refinement_checked
  (status : SealRustRefinementStatus)
  : bool :=
  seal_rust_symbol_present status &&
  seal_surface_check_pass status &&
  seal_vectors_generated status &&
  seal_vector_schema_checked status &&
  seal_lifecycle_track_present status &&
  seal_verify_roundtrip_reserved status &&
  seal_open_roundtrip_reserved status &&
  seal_mechanically_checked status.

Definition seal_refinement_fully_proven
  (status : SealRustRefinementStatus)
  : bool :=
  seal_refinement_checked status &&
  seal_mechanically_proven status.

Definition arc_current_seal_refinement_status : SealRustRefinementStatus :=
  {|
    seal_rust_symbol_present := true;
    seal_surface_check_pass := true;
    seal_vectors_generated := true;
    seal_vector_schema_checked := true;
    seal_lifecycle_track_present := true;
    seal_verify_roundtrip_reserved := true;
    seal_open_roundtrip_reserved := true;
    seal_mechanically_checked := true;
    seal_mechanically_proven := false
  |}.

Theorem current_seal_vectors_complete :
  seal_vectors_complete arc_seal_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_seal_refinement_checked :
  seal_refinement_checked arc_current_seal_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_seal_refinement_not_fully_proven :
  seal_refinement_fully_proven arc_current_seal_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem seal_checked_requires_surface_check :
  forall status,
    seal_refinement_checked status = true ->
    seal_surface_check_pass status = true.
Proof.
  intros status H.
  unfold seal_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_lifecycle] H_verify] H_open] H_checked].
  exact H_surface.
Qed.

Theorem seal_checked_requires_lifecycle_track :
  forall status,
    seal_refinement_checked status = true ->
    seal_lifecycle_track_present status = true.
Proof.
  intros status H.
  unfold seal_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_lifecycle] H_verify] H_open] H_checked].
  exact H_lifecycle.
Qed.

Theorem seal_full_proof_requires_checked :
  forall status,
    seal_refinement_fully_proven status = true ->
    seal_refinement_checked status = true.
Proof.
  intros status H.
  unfold seal_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem seal_full_proof_requires_proven_flag :
  forall status,
    seal_refinement_fully_proven status = true ->
    seal_mechanically_proven status = true.
Proof.
  intros status H.
  unfold seal_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition arc_full_mechanical_proof_gate_after_seal_check : ArcFullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem seal_check_keeps_full_gate_open :
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_seal_check = false.
Proof.
  reflexivity.
Qed.

Theorem seal_fifth_mechanical_target_status :
  context_hash_refinement_checked arc_current_context_hash_refinement_status = true /\
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true /\
  encode_arc_object_refinement_checked arc_current_encode_arc_object_refinement_status = true /\
  verify_refinement_checked arc_current_verify_refinement_status = true /\
  seal_refinement_checked arc_current_seal_refinement_status = true /\
  seal_refinement_fully_proven arc_current_seal_refinement_status = false /\
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_seal_check = false.
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
              ** apply current_seal_refinement_not_fully_proven.
              ** apply seal_check_keeps_full_gate_open.
Qed.
