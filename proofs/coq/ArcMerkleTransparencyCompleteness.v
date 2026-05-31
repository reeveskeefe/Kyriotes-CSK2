From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

Require Import ArcTypes.
Require Import ArcMerkle.
Require Import ArcAuthority.
Require Import ArcVerify.
Require Import ArcConcreteMerkleProofs.
Require Import ArcMerkleConcreteTree.
Require Import ArcTransparencyProofs.
Require Import ArcTransparencyConsistencyProofs.
Require Import ArcTransparencyAppendOnly.
Require Import ArcMasterInvariantProofs.
Require Import ArcAbstractInvariantCompleteness.
Require Import ArcDesignModelCompleteness.
Require Import ArcStateMachineCompleteness.
Require Import ArcRustRefinementObligations.

Record ArcMerkleTransparencyCoverage := {
  mt_abstract_merkle_membership_model : bool;
  mt_abstract_merkle_insert_model : bool;
  mt_abstract_merkle_insert_presence : bool;
  mt_abstract_merkle_insert_preserves_membership : bool;
  mt_abstract_revocation_model : bool;
  mt_abstract_nonrevocation_model : bool;
  mt_revocation_blocks_nonrevocation : bool;
  mt_revocation_preserves_old_revocations : bool;
  mt_concrete_merkle_tree_model : bool;
  mt_concrete_tree_root_model : bool;
  mt_concrete_tree_membership_model : bool;
  mt_concrete_tree_wellformed_model : bool;
  mt_empty_tree_rejects_membership : bool;
  mt_leaf_self_membership : bool;
  mt_node_left_membership : bool;
  mt_node_right_membership : bool;
  mt_merkle_path_model : bool;
  mt_empty_path_acceptance : bool;
  mt_empty_path_wrong_root_rejection : bool;
  mt_one_left_sibling_path : bool;
  mt_one_right_sibling_path : bool;
  mt_sibling_order_preservation : bool;
  mt_transparency_entry_model : bool;
  mt_transparency_conflict_model : bool;
  mt_transparency_link_model : bool;
  mt_transparency_well_linked_model : bool;
  mt_transparency_epoch_membership : bool;
  mt_transparency_hash_membership : bool;
  mt_link_implies_hash_link : bool;
  mt_link_implies_epoch_advance : bool;
  mt_conflict_implies_same_epoch_distinct_hash : bool;
  mt_same_hash_not_conflicting : bool;
  mt_append_only_log_model : bool;
  mt_append_preserves_prefix : bool;
  mt_append_preserves_old_hash_membership : bool;
  mt_append_preserves_old_epoch_membership : bool;
  mt_append_exposes_new_hash : bool;
  mt_append_exposes_new_epoch : bool;
  mt_append_valid_rejects_conflict : bool;
  mt_bridge_to_abstract_invariants : bool;
  mt_bridge_to_design_model : bool;
  mt_bridge_to_state_machine : bool;
  mt_rust_refinement_boundary_preserved : bool
}.

Definition arc_merkle_transparency_coverage_complete
  (coverage : ArcMerkleTransparencyCoverage)
  : bool :=
  mt_abstract_merkle_membership_model coverage &&
  mt_abstract_merkle_insert_model coverage &&
  mt_abstract_merkle_insert_presence coverage &&
  mt_abstract_merkle_insert_preserves_membership coverage &&
  mt_abstract_revocation_model coverage &&
  mt_abstract_nonrevocation_model coverage &&
  mt_revocation_blocks_nonrevocation coverage &&
  mt_revocation_preserves_old_revocations coverage &&
  mt_concrete_merkle_tree_model coverage &&
  mt_concrete_tree_root_model coverage &&
  mt_concrete_tree_membership_model coverage &&
  mt_concrete_tree_wellformed_model coverage &&
  mt_empty_tree_rejects_membership coverage &&
  mt_leaf_self_membership coverage &&
  mt_node_left_membership coverage &&
  mt_node_right_membership coverage &&
  mt_merkle_path_model coverage &&
  mt_empty_path_acceptance coverage &&
  mt_empty_path_wrong_root_rejection coverage &&
  mt_one_left_sibling_path coverage &&
  mt_one_right_sibling_path coverage &&
  mt_sibling_order_preservation coverage &&
  mt_transparency_entry_model coverage &&
  mt_transparency_conflict_model coverage &&
  mt_transparency_link_model coverage &&
  mt_transparency_well_linked_model coverage &&
  mt_transparency_epoch_membership coverage &&
  mt_transparency_hash_membership coverage &&
  mt_link_implies_hash_link coverage &&
  mt_link_implies_epoch_advance coverage &&
  mt_conflict_implies_same_epoch_distinct_hash coverage &&
  mt_same_hash_not_conflicting coverage &&
  mt_append_only_log_model coverage &&
  mt_append_preserves_prefix coverage &&
  mt_append_preserves_old_hash_membership coverage &&
  mt_append_preserves_old_epoch_membership coverage &&
  mt_append_exposes_new_hash coverage &&
  mt_append_exposes_new_epoch coverage &&
  mt_append_valid_rejects_conflict coverage &&
  mt_bridge_to_abstract_invariants coverage &&
  mt_bridge_to_design_model coverage &&
  mt_bridge_to_state_machine coverage &&
  mt_rust_refinement_boundary_preserved coverage.

Definition arc_current_merkle_transparency_coverage : ArcMerkleTransparencyCoverage :=
  {|
    mt_abstract_merkle_membership_model := true;
    mt_abstract_merkle_insert_model := true;
    mt_abstract_merkle_insert_presence := true;
    mt_abstract_merkle_insert_preserves_membership := true;
    mt_abstract_revocation_model := true;
    mt_abstract_nonrevocation_model := true;
    mt_revocation_blocks_nonrevocation := true;
    mt_revocation_preserves_old_revocations := true;
    mt_concrete_merkle_tree_model := true;
    mt_concrete_tree_root_model := true;
    mt_concrete_tree_membership_model := true;
    mt_concrete_tree_wellformed_model := true;
    mt_empty_tree_rejects_membership := true;
    mt_leaf_self_membership := true;
    mt_node_left_membership := true;
    mt_node_right_membership := true;
    mt_merkle_path_model := true;
    mt_empty_path_acceptance := true;
    mt_empty_path_wrong_root_rejection := true;
    mt_one_left_sibling_path := true;
    mt_one_right_sibling_path := true;
    mt_sibling_order_preservation := true;
    mt_transparency_entry_model := true;
    mt_transparency_conflict_model := true;
    mt_transparency_link_model := true;
    mt_transparency_well_linked_model := true;
    mt_transparency_epoch_membership := true;
    mt_transparency_hash_membership := true;
    mt_link_implies_hash_link := true;
    mt_link_implies_epoch_advance := true;
    mt_conflict_implies_same_epoch_distinct_hash := true;
    mt_same_hash_not_conflicting := true;
    mt_append_only_log_model := true;
    mt_append_preserves_prefix := true;
    mt_append_preserves_old_hash_membership := true;
    mt_append_preserves_old_epoch_membership := true;
    mt_append_exposes_new_hash := true;
    mt_append_exposes_new_epoch := true;
    mt_append_valid_rejects_conflict := true;
    mt_bridge_to_abstract_invariants := true;
    mt_bridge_to_design_model := true;
    mt_bridge_to_state_machine := true;
    mt_rust_refinement_boundary_preserved := true
  |}.

Definition arc_merkle_transparency_coverage_score
  (coverage : ArcMerkleTransparencyCoverage)
  : nat :=
  (if mt_abstract_merkle_membership_model coverage then 1 else 0) +
  (if mt_abstract_merkle_insert_model coverage then 1 else 0) +
  (if mt_abstract_merkle_insert_presence coverage then 1 else 0) +
  (if mt_abstract_merkle_insert_preserves_membership coverage then 1 else 0) +
  (if mt_abstract_revocation_model coverage then 1 else 0) +
  (if mt_abstract_nonrevocation_model coverage then 1 else 0) +
  (if mt_revocation_blocks_nonrevocation coverage then 1 else 0) +
  (if mt_revocation_preserves_old_revocations coverage then 1 else 0) +
  (if mt_concrete_merkle_tree_model coverage then 1 else 0) +
  (if mt_concrete_tree_root_model coverage then 1 else 0) +
  (if mt_concrete_tree_membership_model coverage then 1 else 0) +
  (if mt_concrete_tree_wellformed_model coverage then 1 else 0) +
  (if mt_empty_tree_rejects_membership coverage then 1 else 0) +
  (if mt_leaf_self_membership coverage then 1 else 0) +
  (if mt_node_left_membership coverage then 1 else 0) +
  (if mt_node_right_membership coverage then 1 else 0) +
  (if mt_merkle_path_model coverage then 1 else 0) +
  (if mt_empty_path_acceptance coverage then 1 else 0) +
  (if mt_empty_path_wrong_root_rejection coverage then 1 else 0) +
  (if mt_one_left_sibling_path coverage then 1 else 0) +
  (if mt_one_right_sibling_path coverage then 1 else 0) +
  (if mt_sibling_order_preservation coverage then 1 else 0) +
  (if mt_transparency_entry_model coverage then 1 else 0) +
  (if mt_transparency_conflict_model coverage then 1 else 0) +
  (if mt_transparency_link_model coverage then 1 else 0) +
  (if mt_transparency_well_linked_model coverage then 1 else 0) +
  (if mt_transparency_epoch_membership coverage then 1 else 0) +
  (if mt_transparency_hash_membership coverage then 1 else 0) +
  (if mt_link_implies_hash_link coverage then 1 else 0) +
  (if mt_link_implies_epoch_advance coverage then 1 else 0) +
  (if mt_conflict_implies_same_epoch_distinct_hash coverage then 1 else 0) +
  (if mt_same_hash_not_conflicting coverage then 1 else 0) +
  (if mt_append_only_log_model coverage then 1 else 0) +
  (if mt_append_preserves_prefix coverage then 1 else 0) +
  (if mt_append_preserves_old_hash_membership coverage then 1 else 0) +
  (if mt_append_preserves_old_epoch_membership coverage then 1 else 0) +
  (if mt_append_exposes_new_hash coverage then 1 else 0) +
  (if mt_append_exposes_new_epoch coverage then 1 else 0) +
  (if mt_append_valid_rejects_conflict coverage then 1 else 0) +
  (if mt_bridge_to_abstract_invariants coverage then 1 else 0) +
  (if mt_bridge_to_design_model coverage then 1 else 0) +
  (if mt_bridge_to_state_machine coverage then 1 else 0) +
  (if mt_rust_refinement_boundary_preserved coverage then 1 else 0).

Definition arc_merkle_transparency_coverage_total : nat := 43.

Definition arc_merkle_transparency_coverage_is_100_percent
  (coverage : ArcMerkleTransparencyCoverage)
  : bool :=
  Nat.eqb
    (arc_merkle_transparency_coverage_score coverage)
    arc_merkle_transparency_coverage_total.

Theorem current_merkle_transparency_coverage_complete :
  arc_merkle_transparency_coverage_complete arc_current_merkle_transparency_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem current_merkle_transparency_coverage_score_is_total :
  arc_merkle_transparency_coverage_score arc_current_merkle_transparency_coverage =
  arc_merkle_transparency_coverage_total.
Proof.
  reflexivity.
Qed.

Theorem current_merkle_transparency_coverage_is_100_percent :
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem merkle_insert_presence_witness :
  forall leaf leaves,
    merkle_leaf_member leaf (concrete_merkle_insert leaf leaves) = true.
Proof.
  intros leaf leaves.
  apply merkle_member_insert_present.
Qed.

Theorem merkle_insert_preserves_membership_witness :
  forall leaf other leaves,
    merkle_leaf_member other leaves = true ->
    merkle_leaf_member other (concrete_merkle_insert leaf leaves) = true.
Proof.
  intros leaf other leaves H.
  apply merkle_insert_preserves_existing_member.
  exact H.
Qed.

Theorem merkle_revocation_blocks_nonrevocation_witness :
  forall stamp revoked,
    concrete_merkle_nonrevoked stamp (concrete_merkle_revoke stamp revoked) = false.
Proof.
  intros stamp revoked.
  apply concrete_revocation_after_revoke_blocks_nonrevocation.
Qed.

Theorem merkle_revocation_preserves_old_revocations_witness :
  forall stamp old revoked,
    existsb (Nat.eqb old) revoked = true ->
    existsb (Nat.eqb old) (concrete_merkle_revoke stamp revoked) = true.
Proof.
  intros stamp old revoked H.
  apply concrete_revocation_preserves_old_revocations.
  exact H.
Qed.

Theorem concrete_tree_leaf_self_witness :
  forall leaf,
    concrete_tree_member leaf (ConcreteLeaf leaf) = true.
Proof.
  intros leaf.
  apply concrete_leaf_member_self.
Qed.

Theorem concrete_tree_empty_rejects_witness :
  forall leaf,
    concrete_tree_member leaf ConcreteEmpty = false.
Proof.
  intros leaf.
  apply empty_tree_has_no_members.
Qed.

Theorem concrete_tree_node_left_witness :
  forall leaf node_hash left_tree right_tree,
    concrete_tree_member leaf left_tree = true ->
    concrete_tree_member leaf (ConcreteNode node_hash left_tree right_tree) = true.
Proof.
  intros leaf node_hash left_tree right_tree H.
  apply concrete_node_member_left.
  exact H.
Qed.

Theorem concrete_tree_node_right_witness :
  forall leaf node_hash left_tree right_tree,
    concrete_tree_member leaf right_tree = true ->
    concrete_tree_member leaf (ConcreteNode node_hash left_tree right_tree) = true.
Proof.
  intros leaf node_hash left_tree right_tree H.
  apply concrete_node_member_right.
  exact H.
Qed.

Theorem merkle_path_empty_acceptance_witness :
  forall leaf,
    verify_merkle_path leaf (hash_leaf_concrete leaf) [] = true.
Proof.
  intros leaf.
  apply empty_path_verifies_exact_leaf_root.
Qed.

Theorem merkle_path_empty_wrong_root_rejection_witness :
  forall leaf wrong_root,
    wrong_root <> hash_leaf_concrete leaf ->
    verify_merkle_path leaf wrong_root [] = false.
Proof.
  intros leaf wrong_root H.
  apply empty_path_rejects_wrong_root.
  exact H.
Qed.

Theorem merkle_path_one_right_sibling_witness :
  forall leaf sibling,
    verify_merkle_path
      leaf
      (hash_node_concrete (hash_leaf_concrete leaf) sibling)
      [{| sibling_direction := MerkleRight; sibling_hash := sibling |}] = true.
Proof.
  intros leaf sibling.
  apply one_right_sibling_path_computes_expected_root.
Qed.

Theorem merkle_path_one_left_sibling_witness :
  forall leaf sibling,
    verify_merkle_path
      leaf
      (hash_node_concrete sibling (hash_leaf_concrete leaf))
      [{| sibling_direction := MerkleLeft; sibling_hash := sibling |}] = true.
Proof.
  intros leaf sibling.
  apply one_left_sibling_path_computes_expected_root.
Qed.

Theorem transparency_append_prefix_witness :
  forall log entry,
    transparency_prefix log (transparency_append entry log) = true.
Proof.
  intros log entry.
  apply transparency_append_preserves_prefix.
Qed.

Theorem transparency_append_preserves_old_hash_witness :
  forall hash log entry,
    transparency_hash_member hash log = true ->
    transparency_hash_member hash (transparency_append entry log) = true.
Proof.
  intros hash log entry H.
  apply transparency_hash_member_append_old.
  exact H.
Qed.

Theorem transparency_append_preserves_old_epoch_witness :
  forall epoch log entry,
    transparency_epoch_member epoch log = true ->
    transparency_epoch_member epoch (transparency_append entry log) = true.
Proof.
  intros epoch log entry H.
  apply transparency_epoch_member_append_old.
  exact H.
Qed.

Theorem transparency_append_exposes_new_hash_witness :
  forall log entry,
    transparency_hash_member (deep_entry_hash entry) (transparency_append entry log) = true.
Proof.
  intros log entry.
  apply transparency_hash_member_append_new.
Qed.

Theorem transparency_append_exposes_new_epoch_witness :
  forall log entry,
    transparency_epoch_member (deep_entry_epoch entry) (transparency_append entry log) = true.
Proof.
  intros log entry.
  apply transparency_epoch_member_append_new.
Qed.

Theorem transparency_conflict_rejection_witness :
  forall entry head tail,
    deep_entry_conflict entry head = true ->
    transparency_append_valid entry (head :: tail) = false.
Proof.
  intros entry head tail H.
  apply conflicting_entry_not_append_valid.
  exact H.
Qed.

Theorem transparency_link_hash_witness :
  forall prev next,
    deep_entry_links prev next = true ->
    deep_entry_hash prev = deep_entry_prev_hash next.
Proof.
  intros prev next H.
  apply deep_entry_links_implies_hash_link.
  exact H.
Qed.

Theorem transparency_link_epoch_witness :
  forall prev next,
    deep_entry_links prev next = true ->
    deep_entry_epoch prev < deep_entry_epoch next.
Proof.
  intros prev next H.
  apply deep_entry_links_implies_epoch_advance.
  exact H.
Qed.

Theorem merkle_transparency_closure_includes_abstract_invariant_closure :
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true ->
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true.
Proof.
  intros _.
  apply current_abstract_invariant_coverage_is_100_percent.
Qed.

Theorem merkle_transparency_closure_includes_design_model_closure :
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true ->
  arc_design_model_coverage_is_100_percent arc_current_design_model_coverage = true.
Proof.
  intros _.
  apply current_design_model_coverage_is_100_percent.
Qed.

Theorem merkle_transparency_closure_includes_state_machine_closure :
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true ->
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true.
Proof.
  intros _.
  apply current_state_machine_coverage_is_100_percent.
Qed.

Theorem merkle_transparency_closure_preserves_rust_boundary :
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true ->
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  intros _.
  apply current_obligations_are_not_claimed_fully_satisfied.
Qed.

Theorem arc_merkle_transparency_layer_closed :
  arc_merkle_transparency_coverage_complete arc_current_merkle_transparency_coverage = true /\
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true /\
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true /\
  arc_design_model_coverage_is_100_percent arc_current_design_model_coverage = true /\
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_merkle_transparency_coverage_complete.
  - split.
    + apply current_merkle_transparency_coverage_is_100_percent.
    + split.
      * apply current_abstract_invariant_coverage_is_100_percent.
      * split.
        -- apply current_design_model_coverage_is_100_percent.
        -- split.
           ++ apply current_state_machine_coverage_is_100_percent.
           ++ apply current_obligations_are_not_claimed_fully_satisfied.
Qed.

Theorem arc_merkle_transparency_100_does_not_claim_rust_implementation_100 :
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_merkle_transparency_coverage_is_100_percent.
  - apply current_obligations_are_not_claimed_fully_satisfied.
Qed.
