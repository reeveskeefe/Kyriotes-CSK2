From Coq Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyConsistencyProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyAppendOnly.
From KyriotesCsk2Proofs Require Import KyriotesCsk2MerkleTransparencyCompleteness.
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
From KyriotesCsk2Proofs Require Import KyriotesCsk2AddEpochWrapperRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RotateEpochRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RotateEpochFullRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2CapabilityTreeRustRefinement.

Inductive TransparencyGateCase :=
| TransparencyMissingLog
| TransparencyMissingEntry
| TransparencyMissingEpoch
| TransparencyMissingStateRoot
| TransparencyMissingCommitment
| TransparencyConflictingEpoch
| TransparencyDuplicateConflict
| TransparencyAppendOnlyRegression
| TransparencyLookupMissingEntry
| TransparencyStateRootBindingReserved
| TransparencyValidAppendReserved
| TransparencyValidLookupReserved.

Record TransparencyMechanicalVector := {
  transparency_vector_id : string;
  transparency_vector_case : TransparencyGateCase;
  transparency_vector_expected_rejection : bool;
  transparency_vector_reserved_valid_case : bool;
  transparency_vector_deterministic : bool
}.

Definition transparency_vector_complete
  (vector : TransparencyMechanicalVector)
  : bool :=
  transparency_vector_deterministic vector &&
  match transparency_vector_case vector with
  | TransparencyStateRootBindingReserved => transparency_vector_reserved_valid_case vector
  | TransparencyValidAppendReserved => transparency_vector_reserved_valid_case vector
  | TransparencyValidLookupReserved => transparency_vector_reserved_valid_case vector
  | _ => transparency_vector_expected_rejection vector
  end.

Fixpoint transparency_vectors_complete
  (vectors : list TransparencyMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      transparency_vector_complete head &&
      transparency_vectors_complete tail
  end.

Definition kyriotes_csk2_transparency_mechanical_vectors : list TransparencyMechanicalVector :=
  [
    {|
      transparency_vector_id := "transparency.missing-log";
      transparency_vector_case := TransparencyMissingLog;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.missing-entry";
      transparency_vector_case := TransparencyMissingEntry;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.missing-epoch";
      transparency_vector_case := TransparencyMissingEpoch;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.missing-state-root";
      transparency_vector_case := TransparencyMissingStateRoot;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.missing-commitment";
      transparency_vector_case := TransparencyMissingCommitment;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.conflicting-epoch";
      transparency_vector_case := TransparencyConflictingEpoch;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.duplicate-conflict";
      transparency_vector_case := TransparencyDuplicateConflict;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.append-only-regression";
      transparency_vector_case := TransparencyAppendOnlyRegression;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.lookup-missing-entry";
      transparency_vector_case := TransparencyLookupMissingEntry;
      transparency_vector_expected_rejection := true;
      transparency_vector_reserved_valid_case := false;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.state-root-binding-reserved";
      transparency_vector_case := TransparencyStateRootBindingReserved;
      transparency_vector_expected_rejection := false;
      transparency_vector_reserved_valid_case := true;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.valid-append-reserved";
      transparency_vector_case := TransparencyValidAppendReserved;
      transparency_vector_expected_rejection := false;
      transparency_vector_reserved_valid_case := true;
      transparency_vector_deterministic := true
    |};
    {|
      transparency_vector_id := "transparency.valid-lookup-reserved";
      transparency_vector_case := TransparencyValidLookupReserved;
      transparency_vector_expected_rejection := false;
      transparency_vector_reserved_valid_case := true;
      transparency_vector_deterministic := true
    |}
  ].

Record TransparencyRustRefinementStatus := {
  transparency_rust_source_present : bool;
  transparency_surface_check_pass : bool;
  transparency_vectors_generated : bool;
  transparency_vector_schema_checked : bool;
  transparency_append_track_present : bool;
  transparency_lookup_track_present : bool;
  transparency_conflict_rejection_track_present : bool;
  transparency_state_root_binding_reserved : bool;
  transparency_valid_fixture_reserved : bool;
  transparency_mechanically_checked : bool;
  transparency_mechanically_proven : bool
}.

Definition transparency_refinement_checked
  (status : TransparencyRustRefinementStatus)
  : bool :=
  transparency_rust_source_present status &&
  transparency_surface_check_pass status &&
  transparency_vectors_generated status &&
  transparency_vector_schema_checked status &&
  transparency_append_track_present status &&
  transparency_lookup_track_present status &&
  transparency_conflict_rejection_track_present status &&
  transparency_state_root_binding_reserved status &&
  transparency_valid_fixture_reserved status &&
  transparency_mechanically_checked status.

Definition transparency_refinement_fully_proven
  (status : TransparencyRustRefinementStatus)
  : bool :=
  transparency_refinement_checked status &&
  transparency_mechanically_proven status.

Definition kyriotes_csk2_current_transparency_refinement_status
  : TransparencyRustRefinementStatus :=
  {|
    transparency_rust_source_present := true;
    transparency_surface_check_pass := true;
    transparency_vectors_generated := true;
    transparency_vector_schema_checked := true;
    transparency_append_track_present := true;
    transparency_lookup_track_present := true;
    transparency_conflict_rejection_track_present := true;
    transparency_state_root_binding_reserved := true;
    transparency_valid_fixture_reserved := true;
    transparency_mechanically_checked := true;
    transparency_mechanically_proven := false
  |}.

Theorem current_transparency_vectors_complete :
  transparency_vectors_complete kyriotes_csk2_transparency_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_transparency_refinement_checked :
  transparency_refinement_checked kyriotes_csk2_current_transparency_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_transparency_refinement_not_fully_proven :
  transparency_refinement_fully_proven kyriotes_csk2_current_transparency_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem transparency_checked_requires_surface_check :
  forall status,
    transparency_refinement_checked status = true ->
    transparency_surface_check_pass status = true.
Proof.
  intros status H.
  unfold transparency_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[H_source H_surface] H_vectors] H_schema] H_append] H_lookup] H_conflict] H_state] H_valid] H_checked].
  exact H_surface.
Qed.

Theorem transparency_checked_requires_append_track :
  forall status,
    transparency_refinement_checked status = true ->
    transparency_append_track_present status = true.
Proof.
  intros status H.
  unfold transparency_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[H_source H_surface] H_vectors] H_schema] H_append] H_lookup] H_conflict] H_state] H_valid] H_checked].
  exact H_append.
Qed.

Theorem transparency_full_proof_requires_checked :
  forall status,
    transparency_refinement_fully_proven status = true ->
    transparency_refinement_checked status = true.
Proof.
  intros status H.
  unfold transparency_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem transparency_full_proof_requires_proven_flag :
  forall status,
    transparency_refinement_fully_proven status = true ->
    transparency_mechanically_proven status = true.
Proof.
  intros status H.
  unfold transparency_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition kyriotes_csk2_full_mechanical_proof_gate_after_transparency_check : KyriotesCsk2FullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := true;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem transparency_check_completes_checked_targets_but_keeps_full_gate_open :
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_full_mechanical_proof_gate_after_transparency_check = false.
Proof.
  reflexivity.
Qed.

Theorem all_declared_mechanical_targets_checked_status :
  context_hash_refinement_checked kyriotes_csk2_current_context_hash_refinement_status = true /\
  decode_kyriotes_csk2_object_refinement_checked kyriotes_csk2_current_decode_kyriotes_csk2_object_refinement_status = true /\
  encode_kyriotes_csk2_object_refinement_checked kyriotes_csk2_current_encode_kyriotes_csk2_object_refinement_status = true /\
  verify_refinement_checked kyriotes_csk2_current_verify_refinement_status = true /\
  seal_refinement_checked kyriotes_csk2_current_seal_refinement_status = true /\
  open_refinement_checked kyriotes_csk2_current_open_refinement_status = true /\
  add_wrapper_refinement_checked kyriotes_csk2_current_add_epoch_wrapper_refinement_status = true /\
  rotate_epoch_refinement_checked kyriotes_csk2_current_rotate_epoch_refinement_status = true /\
  rotate_epoch_full_refinement_checked kyriotes_csk2_current_rotate_epoch_full_refinement_status = true /\
  capability_tree_refinement_checked kyriotes_csk2_current_capability_tree_refinement_status = true /\
  transparency_refinement_checked kyriotes_csk2_current_transparency_refinement_status = true /\
  transparency_refinement_fully_proven kyriotes_csk2_current_transparency_refinement_status = false /\
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_full_mechanical_proof_gate_after_transparency_check = false.
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
                     +++ apply current_rotate_epoch_refinement_checked.
                     +++ split.
                         *** apply current_rotate_epoch_full_refinement_checked.
                         *** split.
                             ---- apply current_capability_tree_refinement_checked.
                             ---- split.
                                  +++++ apply current_transparency_refinement_checked.
                                  +++++ split.
                                        ****** apply current_transparency_refinement_not_fully_proven.
                                        ****** apply transparency_check_completes_checked_targets_but_keeps_full_gate_open.
Qed.
