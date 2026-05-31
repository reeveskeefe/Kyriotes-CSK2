From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcMerkle.
From ArcProofs Require Import ArcConcreteMerkleProofs.
From ArcProofs Require Import ArcMerkleConcreteTree.
From ArcProofs Require Import ArcMerkleTransparencyCompleteness.
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
From ArcProofs Require Import ArcOpenRustRefinement.
From ArcProofs Require Import ArcAddEpochWrapperRustRefinement.
From ArcProofs Require Import ArcRotateEpochRustRefinement.
From ArcProofs Require Import ArcRotateEpochFullRustRefinement.

Inductive CapabilityTreeGateCase :=
| CapabilityTreeMissingCapabilityProof
| CapabilityTreeMissingMembershipProof
| CapabilityTreeMissingNonrevocationWitness
| CapabilityTreeRootMismatch
| CapabilityTreeTamperedLeaf
| CapabilityTreeTamperedSibling
| CapabilityTreeSiblingOrderMismatch
| CapabilityTreeEmptyProof
| CapabilityTreeRevokedCapability
| CapabilityTreeValidMembershipReserved
| CapabilityTreeValidNonrevocationReserved.

Record CapabilityTreeMechanicalVector := {
  capability_tree_vector_id : string;
  capability_tree_vector_case : CapabilityTreeGateCase;
  capability_tree_vector_expected_rejection : bool;
  capability_tree_vector_reserved_valid_case : bool;
  capability_tree_vector_deterministic : bool
}.

Definition capability_tree_vector_complete
  (vector : CapabilityTreeMechanicalVector)
  : bool :=
  capability_tree_vector_deterministic vector &&
  match capability_tree_vector_case vector with
  | CapabilityTreeValidMembershipReserved => capability_tree_vector_reserved_valid_case vector
  | CapabilityTreeValidNonrevocationReserved => capability_tree_vector_reserved_valid_case vector
  | _ => capability_tree_vector_expected_rejection vector
  end.

Fixpoint capability_tree_vectors_complete
  (vectors : list CapabilityTreeMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      capability_tree_vector_complete head &&
      capability_tree_vectors_complete tail
  end.

Definition arc_capability_tree_mechanical_vectors : list CapabilityTreeMechanicalVector :=
  [
    {|
      capability_tree_vector_id := "capability-tree.missing-capability-proof";
      capability_tree_vector_case := CapabilityTreeMissingCapabilityProof;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.missing-membership-proof";
      capability_tree_vector_case := CapabilityTreeMissingMembershipProof;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.missing-nonrevocation-witness";
      capability_tree_vector_case := CapabilityTreeMissingNonrevocationWitness;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.root-mismatch";
      capability_tree_vector_case := CapabilityTreeRootMismatch;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.tampered-leaf";
      capability_tree_vector_case := CapabilityTreeTamperedLeaf;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.tampered-sibling";
      capability_tree_vector_case := CapabilityTreeTamperedSibling;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.sibling-order-mismatch";
      capability_tree_vector_case := CapabilityTreeSiblingOrderMismatch;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.empty-proof";
      capability_tree_vector_case := CapabilityTreeEmptyProof;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.revoked-capability";
      capability_tree_vector_case := CapabilityTreeRevokedCapability;
      capability_tree_vector_expected_rejection := true;
      capability_tree_vector_reserved_valid_case := false;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.valid-membership-reserved";
      capability_tree_vector_case := CapabilityTreeValidMembershipReserved;
      capability_tree_vector_expected_rejection := false;
      capability_tree_vector_reserved_valid_case := true;
      capability_tree_vector_deterministic := true
    |};
    {|
      capability_tree_vector_id := "capability-tree.valid-nonrevocation-reserved";
      capability_tree_vector_case := CapabilityTreeValidNonrevocationReserved;
      capability_tree_vector_expected_rejection := false;
      capability_tree_vector_reserved_valid_case := true;
      capability_tree_vector_deterministic := true
    |}
  ].

Record CapabilityTreeRustRefinementStatus := {
  capability_tree_rust_source_present : bool;
  capability_tree_surface_check_pass : bool;
  capability_tree_vectors_generated : bool;
  capability_tree_vector_schema_checked : bool;
  capability_tree_membership_track_present : bool;
  capability_tree_nonrevocation_track_present : bool;
  capability_tree_root_mismatch_track_present : bool;
  capability_tree_tamper_rejection_track_present : bool;
  capability_tree_valid_fixture_reserved : bool;
  capability_tree_mechanically_checked : bool;
  capability_tree_mechanically_proven : bool
}.

Definition capability_tree_refinement_checked
  (status : CapabilityTreeRustRefinementStatus)
  : bool :=
  capability_tree_rust_source_present status &&
  capability_tree_surface_check_pass status &&
  capability_tree_vectors_generated status &&
  capability_tree_vector_schema_checked status &&
  capability_tree_membership_track_present status &&
  capability_tree_nonrevocation_track_present status &&
  capability_tree_root_mismatch_track_present status &&
  capability_tree_tamper_rejection_track_present status &&
  capability_tree_valid_fixture_reserved status &&
  capability_tree_mechanically_checked status.

Definition capability_tree_refinement_fully_proven
  (status : CapabilityTreeRustRefinementStatus)
  : bool :=
  capability_tree_refinement_checked status &&
  capability_tree_mechanically_proven status.

Definition arc_current_capability_tree_refinement_status
  : CapabilityTreeRustRefinementStatus :=
  {|
    capability_tree_rust_source_present := true;
    capability_tree_surface_check_pass := true;
    capability_tree_vectors_generated := true;
    capability_tree_vector_schema_checked := true;
    capability_tree_membership_track_present := true;
    capability_tree_nonrevocation_track_present := true;
    capability_tree_root_mismatch_track_present := true;
    capability_tree_tamper_rejection_track_present := true;
    capability_tree_valid_fixture_reserved := true;
    capability_tree_mechanically_checked := true;
    capability_tree_mechanically_proven := false
  |}.

Theorem current_capability_tree_vectors_complete :
  capability_tree_vectors_complete arc_capability_tree_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_capability_tree_refinement_checked :
  capability_tree_refinement_checked arc_current_capability_tree_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_capability_tree_refinement_not_fully_proven :
  capability_tree_refinement_fully_proven arc_current_capability_tree_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_checked_requires_surface_check :
  forall status,
    capability_tree_refinement_checked status = true ->
    capability_tree_surface_check_pass status = true.
Proof.
  intros status H.
  unfold capability_tree_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[H_source H_surface] H_vectors] H_schema] H_membership] H_nonrevocation] H_root] H_tamper] H_valid] H_checked].
  exact H_surface.
Qed.

Theorem capability_tree_checked_requires_membership_track :
  forall status,
    capability_tree_refinement_checked status = true ->
    capability_tree_membership_track_present status = true.
Proof.
  intros status H.
  unfold capability_tree_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[H_source H_surface] H_vectors] H_schema] H_membership] H_nonrevocation] H_root] H_tamper] H_valid] H_checked].
  exact H_membership.
Qed.

Theorem capability_tree_full_proof_requires_checked :
  forall status,
    capability_tree_refinement_fully_proven status = true ->
    capability_tree_refinement_checked status = true.
Proof.
  intros status H.
  unfold capability_tree_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem capability_tree_full_proof_requires_proven_flag :
  forall status,
    capability_tree_refinement_fully_proven status = true ->
    capability_tree_mechanically_proven status = true.
Proof.
  intros status H.
  unfold capability_tree_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition arc_full_mechanical_proof_gate_after_capability_tree_check : ArcFullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem capability_tree_check_keeps_full_gate_open :
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_capability_tree_check = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_tenth_mechanical_target_status :
  context_hash_refinement_checked arc_current_context_hash_refinement_status = true /\
  decode_arc_object_refinement_checked arc_current_decode_arc_object_refinement_status = true /\
  encode_arc_object_refinement_checked arc_current_encode_arc_object_refinement_status = true /\
  verify_refinement_checked arc_current_verify_refinement_status = true /\
  seal_refinement_checked arc_current_seal_refinement_status = true /\
  open_refinement_checked arc_current_open_refinement_status = true /\
  add_wrapper_refinement_checked arc_current_add_epoch_wrapper_refinement_status = true /\
  rotate_epoch_refinement_checked arc_current_rotate_epoch_refinement_status = true /\
  rotate_epoch_full_refinement_checked arc_current_rotate_epoch_full_refinement_status = true /\
  capability_tree_refinement_checked arc_current_capability_tree_refinement_status = true /\
  capability_tree_refinement_fully_proven arc_current_capability_tree_refinement_status = false /\
  arc_full_mechanical_proof_gate_closed arc_full_mechanical_proof_gate_after_capability_tree_check = false.
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
                             ---- apply current_capability_tree_refinement_checked.
                             ---- split.
                                  +++++ apply current_capability_tree_refinement_not_fully_proven.
                                  +++++ apply capability_tree_check_keeps_full_gate_open.
Qed.
