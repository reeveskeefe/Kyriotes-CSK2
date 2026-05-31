From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcLifecycleProofs.
From ArcProofs Require Import ArcMasterInvariantProofs.
From ArcProofs Require Import ArcRustRefinementMap.
From ArcProofs Require Import ArcRustRefinementObligations.
From ArcProofs Require Import ArcRustRefinementEvidence.
From ArcProofs Require Import ArcRustMechanicalRefinement.
From ArcProofs Require Import ArcRustFullMechanicalProofGate.
From ArcProofs Require Import ArcContextHashRustRefinement.
From ArcProofs Require Import ArcDecodeArcObjectRustRefinement.
From ArcProofs Require Import ArcEncodeArcObjectRustRefinement.
From ArcProofs Require Import ArcVerifyRustRefinement.
From ArcProofs Require Import ArcSealRustRefinement.

Inductive OpenGateCase :=
| OpenMissingRecipientSecretKey
| OpenMissingObject
| OpenMissingCapability
| OpenMissingCapabilityProof
| OpenMissingAuthorityState
| OpenRevokedCapability
| OpenTemporalMismatch
| OpenWrapperMismatch
| OpenDecryptFailure
| OpenSealVerifyRoundTripReserved.

Record OpenMechanicalVector := {
  open_vector_id : string;
  open_vector_case : OpenGateCase;
  open_vector_expected_rejection : bool;
  open_vector_reserved_valid_case : bool;
  open_vector_deterministic : bool
}.

Definition open_vector_complete
  (vector : OpenMechanicalVector)
  : bool :=
  open_vector_deterministic vector &&
  match open_vector_case vector with
  | OpenSealVerifyRoundTripReserved => open_vector_reserved_valid_case vector
  | _ => open_vector_expected_rejection vector
  end.

Fixpoint open_vectors_complete
  (vectors : list OpenMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      open_vector_complete head &&
      open_vectors_complete tail
  end.

Definition arc_open_mechanical_vectors : list OpenMechanicalVector :=
  [
    {|
      open_vector_id := "open.missing-recipient-secret-key";
      open_vector_case := OpenMissingRecipientSecretKey;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.missing-object";
      open_vector_case := OpenMissingObject;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.missing-capability";
      open_vector_case := OpenMissingCapability;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.missing-capability-proof";
      open_vector_case := OpenMissingCapabilityProof;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.missing-authority-state";
      open_vector_case := OpenMissingAuthorityState;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.revoked-capability";
      open_vector_case := OpenRevokedCapability;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.temporal-mismatch";
      open_vector_case := OpenTemporalMismatch;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.wrapper-mismatch";
      open_vector_case := OpenWrapperMismatch;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.decrypt-failure";
      open_vector_case := OpenDecryptFailure;
      open_vector_expected_rejection := true;
      open_vector_reserved_valid_case := false;
      open_vector_deterministic := true
    |};
    {|
      open_vector_id := "open.seal-verify-open-roundtrip-reserved";
      open_vector_case := OpenSealVerifyRoundTripReserved;
      open_vector_expected_rejection := false;
      open_vector_reserved_valid_case := true;
      open_vector_deterministic := true
    |}
  ].

Record OpenRustRefinementStatus := {
  open_rust_symbol_present : bool;
  open_surface_check_pass : bool;
  open_vectors_generated : bool;
  open_vector_schema_checked : bool;
  open_authorization_track_present : bool;
  open_decrypt_failure_track_present : bool;
  open_roundtrip_reserved : bool;
  open_mechanically_checked : bool;
  open_mechanically_proven : bool
}.

Definition open_refinement_checked
  (status : OpenRustRefinementStatus)
  : bool :=
  open_rust_symbol_present status &&
  open_surface_check_pass status &&
  open_vectors_generated status &&
  open_vector_schema_checked status &&
  open_authorization_track_present status &&
  open_decrypt_failure_track_present status &&
  open_roundtrip_reserved status &&
  open_mechanically_checked status.

Definition open_refinement_fully_proven
  (status : OpenRustRefinementStatus)
  : bool :=
  open_refinement_checked status &&
  open_mechanically_proven status.

Definition arc_current_open_refinement_status : OpenRustRefinementStatus :=
  {|
    open_rust_symbol_present := true;
    open_surface_check_pass := true;
    open_vectors_generated := true;
    open_vector_schema_checked := true;
    open_authorization_track_present := true;
    open_decrypt_failure_track_present := true;
    open_roundtrip_reserved := true;
    open_mechanically_checked := true;
    open_mechanically_proven := false
  |}.

Theorem current_open_vectors_complete :
  open_vectors_complete arc_open_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_open_refinement_checked :
  open_refinement_checked arc_current_open_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_open_refinement_not_fully_proven :
  open_refinement_fully_proven arc_current_open_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem open_checked_requires_surface_check :
  forall status,
    open_refinement_checked status = true ->
    open_surface_check_pass status = true.
Proof.
  intros status H.
  unfold open_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_auth] H_decrypt] H_roundtrip] H_checked].
  exact H_surface.
Qed.

Theorem open_checked_requires_authorization_track :
  forall status,
    open_refinement_checked status = true ->
    open_authorization_track_present status = true.
Proof.
  intros status H.
  unfold open_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_surface] H_vectors] H_schema] H_auth] H_decrypt] H_roundtrip] H_checked].
  exact H_auth.
Qed.

Theorem open_full_proof_requires_checked :
  forall status,
    open_refinement_fully_proven status = true ->
    open_refinement_checked status = true.
Proof.
  intros status H.
  unfold open_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem open_full_proof_requires_proven_flag :
  forall status,
    open_refinement_fully_proven status = true ->
    open_mechanically_proven status = true.
Proof.
  intros status H.
  unfold open_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition arc_full_mechanical_proof_gate_after_open_check : ArcFullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem open_check_keeps_full_gate_open :
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_open_check = false.
Proof.
  reflexivity.
Qed.

Theorem open_sixth_mechanical_target_status :
  context_hash_refinement_checked arc_current_context_hash_refinement_status = true /\
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true /\
  encode_arc_object_refinement_checked arc_current_encode_arc_object_refinement_status = true /\
  verify_refinement_checked arc_current_verify_refinement_status = true /\
  seal_refinement_checked arc_current_seal_refinement_status = true /\
  open_refinement_checked arc_current_open_refinement_status = true /\
  open_refinement_fully_proven arc_current_open_refinement_status = false /\
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_open_check = false.
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
                 --- apply current_open_refinement_not_fully_proven.
                 --- apply open_check_keeps_full_gate_open.
Qed.
