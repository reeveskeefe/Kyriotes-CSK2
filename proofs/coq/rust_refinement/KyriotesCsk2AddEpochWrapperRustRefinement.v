From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2LifecycleProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2StateMachineCompleteness.
From KyriotesCsk2Proofs Require Import KyriotesCsk2MasterInvariantProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementMap.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementObligations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementEvidence.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustMechanicalRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustFullMechanicalProofGate.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ContextHashRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2DecodeKyriotesCsk2ObjectRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2EncodeKyriotesCsk2ObjectRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2VerifyRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2SealRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2OpenRustRefinement.

Inductive AddEpochWrapperGateCase :=
| AddWrapperMissingRecipientSecretKey
| AddWrapperMissingRecipientPublicKey
| AddWrapperMissingObject
| AddWrapperMissingCapability
| AddWrapperMissingCapabilityProof
| AddWrapperMissingPreviousAuthorityState
| AddWrapperMissingNextAuthorityState
| AddWrapperMissingTransparencyProof
| AddWrapperEpochRegression
| AddWrapperBindingReserved
| AddWrapperRewrapRoundTripReserved.

Record AddEpochWrapperMechanicalVector := {
  add_wrapper_vector_id : string;
  add_wrapper_vector_case : AddEpochWrapperGateCase;
  add_wrapper_vector_expected_rejection : bool;
  add_wrapper_vector_reserved_valid_case : bool;
  add_wrapper_vector_deterministic : bool
}.

Definition add_wrapper_vector_complete
  (vector : AddEpochWrapperMechanicalVector)
  : bool :=
  add_wrapper_vector_deterministic vector &&
  match add_wrapper_vector_case vector with
  | AddWrapperBindingReserved => add_wrapper_vector_reserved_valid_case vector
  | AddWrapperRewrapRoundTripReserved => add_wrapper_vector_reserved_valid_case vector
  | _ => add_wrapper_vector_expected_rejection vector
  end.

Fixpoint add_wrapper_vectors_complete
  (vectors : list AddEpochWrapperMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      add_wrapper_vector_complete head &&
      add_wrapper_vectors_complete tail
  end.

Definition kyriotes_csk2_add_epoch_wrapper_mechanical_vectors : list AddEpochWrapperMechanicalVector :=
  [
    {|
      add_wrapper_vector_id := "add-wrapper.missing-recipient-secret-key";
      add_wrapper_vector_case := AddWrapperMissingRecipientSecretKey;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.missing-recipient-public-key";
      add_wrapper_vector_case := AddWrapperMissingRecipientPublicKey;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.missing-object";
      add_wrapper_vector_case := AddWrapperMissingObject;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.missing-capability";
      add_wrapper_vector_case := AddWrapperMissingCapability;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.missing-capability-proof";
      add_wrapper_vector_case := AddWrapperMissingCapabilityProof;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.missing-previous-authority-state";
      add_wrapper_vector_case := AddWrapperMissingPreviousAuthorityState;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.missing-next-authority-state";
      add_wrapper_vector_case := AddWrapperMissingNextAuthorityState;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.missing-transparency-proof";
      add_wrapper_vector_case := AddWrapperMissingTransparencyProof;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.epoch-regression";
      add_wrapper_vector_case := AddWrapperEpochRegression;
      add_wrapper_vector_expected_rejection := true;
      add_wrapper_vector_reserved_valid_case := false;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.binding-reserved";
      add_wrapper_vector_case := AddWrapperBindingReserved;
      add_wrapper_vector_expected_rejection := false;
      add_wrapper_vector_reserved_valid_case := true;
      add_wrapper_vector_deterministic := true
    |};
    {|
      add_wrapper_vector_id := "add-wrapper.rewrap-roundtrip-reserved";
      add_wrapper_vector_case := AddWrapperRewrapRoundTripReserved;
      add_wrapper_vector_expected_rejection := false;
      add_wrapper_vector_reserved_valid_case := true;
      add_wrapper_vector_deterministic := true
    |}
  ].

Record AddEpochWrapperRustRefinementStatus := {
  add_wrapper_rust_symbol_present : bool;
  add_wrapper_surface_check_pass : bool;
  add_wrapper_vectors_generated : bool;
  add_wrapper_vector_schema_checked : bool;
  add_wrapper_epoch_monotonicity_track_present : bool;
  add_wrapper_binding_track_present : bool;
  add_wrapper_rewrap_roundtrip_reserved : bool;
  add_wrapper_mechanically_checked : bool;
  add_wrapper_mechanically_proven : bool
}.

Definition add_wrapper_refinement_checked
  (status : AddEpochWrapperRustRefinementStatus)
  : bool :=
  add_wrapper_rust_symbol_present status &&
  add_wrapper_surface_check_pass status &&
  add_wrapper_vectors_generated status &&
  add_wrapper_vector_schema_checked status &&
  add_wrapper_epoch_monotonicity_track_present status &&
  add_wrapper_binding_track_present status &&
  add_wrapper_rewrap_roundtrip_reserved status &&
  add_wrapper_mechanically_checked status.

Definition add_wrapper_refinement_fully_proven
  (status : AddEpochWrapperRustRefinementStatus)
  : bool :=
  add_wrapper_refinement_checked status &&
  add_wrapper_mechanically_proven status.

Definition kyriotes_csk2_current_add_epoch_wrapper_refinement_status
  : AddEpochWrapperRustRefinementStatus :=
  {|
    add_wrapper_rust_symbol_present := true;
    add_wrapper_surface_check_pass := true;
    add_wrapper_vectors_generated := true;
    add_wrapper_vector_schema_checked := true;
    add_wrapper_epoch_monotonicity_track_present := true;
    add_wrapper_binding_track_present := true;
    add_wrapper_rewrap_roundtrip_reserved := true;
    add_wrapper_mechanically_checked := true;
    add_wrapper_mechanically_proven := false
  |}.

Theorem current_add_wrapper_vectors_complete :
  add_wrapper_vectors_complete kyriotes_csk2_add_epoch_wrapper_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_add_wrapper_refinement_checked :
  add_wrapper_refinement_checked kyriotes_csk2_current_add_epoch_wrapper_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_add_wrapper_refinement_not_fully_proven :
  add_wrapper_refinement_fully_proven kyriotes_csk2_current_add_epoch_wrapper_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem add_wrapper_checked_requires_surface_check :
  forall status,
    add_wrapper_refinement_checked status = true ->
    add_wrapper_surface_check_pass status = true.
Proof.
  intros status H.
  unfold add_wrapper_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_epoch] H_binding] H_roundtrip] H_checked].
  exact H_surface.
Qed.

Theorem add_wrapper_checked_requires_epoch_track :
  forall status,
    add_wrapper_refinement_checked status = true ->
    add_wrapper_epoch_monotonicity_track_present status = true.
Proof.
  intros status H.
  unfold add_wrapper_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_epoch] H_binding] H_roundtrip] H_checked].
  exact H_epoch.
Qed.

Theorem add_wrapper_full_proof_requires_checked :
  forall status,
    add_wrapper_refinement_fully_proven status = true ->
    add_wrapper_refinement_checked status = true.
Proof.
  intros status H.
  unfold add_wrapper_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem add_wrapper_full_proof_requires_proven_flag :
  forall status,
    add_wrapper_refinement_fully_proven status = true ->
    add_wrapper_mechanically_proven status = true.
Proof.
  intros status H.
  unfold add_wrapper_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition kyriotes_csk2_full_mechanical_proof_gate_after_add_wrapper_check : KyriotesCsk2FullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem add_wrapper_check_keeps_full_gate_open :
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_full_mechanical_proof_gate_after_add_wrapper_check = false.
Proof.
  reflexivity.
Qed.

Theorem add_wrapper_seventh_mechanical_target_status :
  context_hash_refinement_checked kyriotes_csk2_current_context_hash_refinement_status = true /\
  decode_kyriotes_csk2_object_refinement_checked kyriotes_csk2_current_decode_kyriotes_csk2_object_refinement_status = true /\
  encode_kyriotes_csk2_object_refinement_checked kyriotes_csk2_current_encode_kyriotes_csk2_object_refinement_status = true /\
  verify_refinement_checked kyriotes_csk2_current_verify_refinement_status = true /\
  seal_refinement_checked kyriotes_csk2_current_seal_refinement_status = true /\
  open_refinement_checked kyriotes_csk2_current_open_refinement_status = true /\
  add_wrapper_refinement_checked kyriotes_csk2_current_add_epoch_wrapper_refinement_status = true /\
  add_wrapper_refinement_fully_proven kyriotes_csk2_current_add_epoch_wrapper_refinement_status = false /\
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_full_mechanical_proof_gate_after_add_wrapper_check = false.
Proof.
  split.
  - apply current_context_hash_refinement_checked.
  - split.
    + apply current_decode_kyriotes_csk2_object_refinement_checked.
    + split.
      * apply current_encode_kyriotes_csk2_object_refinement_checked.
      * split.
        -- apply current_verify_refinement_checked.
        -- split.
           ++ apply current_seal_refinement_checked.
           ++ split.
              ** apply current_open_refinement_checked.
              ** split.
                 --- apply current_add_wrapper_refinement_checked.
                 --- split.
                     +++ apply current_add_wrapper_refinement_not_fully_proven.
                     +++ apply add_wrapper_check_keeps_full_gate_open.
Qed.
