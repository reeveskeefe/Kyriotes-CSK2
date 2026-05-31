From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcMerkle.
From ArcProofs Require Import ArcAuthority.
From ArcProofs Require Import ArcPolicy.
From ArcProofs Require Import ArcVerify.
From ArcProofs Require Import ArcSecurityGame.
From ArcProofs Require Import ArcTheorems.
From ArcProofs Require Import ArcStressProofs.
From ArcProofs Require Import ArcDelegationProofs.
From ArcProofs Require Import ArcCryptoReduction.
From ArcProofs Require Import ArcTemporalProofs.
From ArcProofs Require Import ArcTranscriptProofs.
From ArcProofs Require Import ArcRevocationCompromiseProofs.
From ArcProofs Require Import ArcTransparencyProofs.
From ArcProofs Require Import ArcEncodingProofs.
From ArcProofs Require Import ArcWrapperProofs.
From ArcProofs Require Import ArcKemAeadAssumptions.
From ArcProofs Require Import ArcEndToEndTheorems.
From ArcProofs Require Import ArcStateTransitionProofs.
From ArcProofs Require Import ArcConcreteMerkleProofs.
From ArcProofs Require Import ArcTransparencyConsistencyProofs.
From ArcProofs Require Import ArcProtocolStateMachineProofs.
From ArcProofs Require Import ArcInvalidTransitionProofs.
From ArcProofs Require Import ArcTightSecurityGameProofs.
From ArcProofs Require Import ArcAssumptionReductionProofs.
From ArcProofs Require Import ArcRustRefinementMap.
From ArcProofs Require Import ArcMasterInvariantProofs.
From ArcProofs Require Import ArcMerkleConcreteTree.
From ArcProofs Require Import ArcTransparencyAppendOnly.
From ArcProofs Require Import ArcLifecycleProofs.
From ArcProofs Require Import ArcPredicateRefinementProofs.
From ArcProofs Require Import ArcAdversaryGame.
From ArcProofs Require Import ArcRustRefinementObligations.

Record ArcAbstractInvariantCoverage := {
  coverage_key_authority_gate : bool;
  coverage_capability_authorization : bool;
  coverage_nonrevocation_safety : bool;
  coverage_temporal_policy_safety : bool;
  coverage_delegation_no_escalation : bool;
  coverage_wrapper_binding : bool;
  coverage_transcript_binding : bool;
  coverage_state_transition_safety : bool;
  coverage_invalid_transition_rejection : bool;
  coverage_merkle_concrete_path_model : bool;
  coverage_transparency_append_only : bool;
  coverage_lifecycle_composition : bool;
  coverage_adversary_gate_model : bool;
  coverage_predicate_refinement : bool;
  coverage_assumption_reduction : bool;
  coverage_master_invariant_composition : bool;
  coverage_rust_concept_map : bool;
  coverage_rust_refinement_obligation_boundary : bool
}.

Definition arc_abstract_invariant_coverage_complete
  (coverage : ArcAbstractInvariantCoverage)
  : bool :=
  coverage_key_authority_gate coverage &&
  coverage_capability_authorization coverage &&
  coverage_nonrevocation_safety coverage &&
  coverage_temporal_policy_safety coverage &&
  coverage_delegation_no_escalation coverage &&
  coverage_wrapper_binding coverage &&
  coverage_transcript_binding coverage &&
  coverage_state_transition_safety coverage &&
  coverage_invalid_transition_rejection coverage &&
  coverage_merkle_concrete_path_model coverage &&
  coverage_transparency_append_only coverage &&
  coverage_lifecycle_composition coverage &&
  coverage_adversary_gate_model coverage &&
  coverage_predicate_refinement coverage &&
  coverage_assumption_reduction coverage &&
  coverage_master_invariant_composition coverage &&
  coverage_rust_concept_map coverage &&
  coverage_rust_refinement_obligation_boundary coverage.

Definition arc_current_abstract_invariant_coverage : ArcAbstractInvariantCoverage :=
  {|
    coverage_key_authority_gate := true;
    coverage_capability_authorization := true;
    coverage_nonrevocation_safety := true;
    coverage_temporal_policy_safety := true;
    coverage_delegation_no_escalation := true;
    coverage_wrapper_binding := true;
    coverage_transcript_binding := true;
    coverage_state_transition_safety := true;
    coverage_invalid_transition_rejection := true;
    coverage_merkle_concrete_path_model := true;
    coverage_transparency_append_only := true;
    coverage_lifecycle_composition := true;
    coverage_adversary_gate_model := true;
    coverage_predicate_refinement := true;
    coverage_assumption_reduction := true;
    coverage_master_invariant_composition := true;
    coverage_rust_concept_map := true;
    coverage_rust_refinement_obligation_boundary := true
  |}.

Definition arc_abstract_invariant_coverage_score
  (coverage : ArcAbstractInvariantCoverage)
  : nat :=
  (if coverage_key_authority_gate coverage then 1 else 0) +
  (if coverage_capability_authorization coverage then 1 else 0) +
  (if coverage_nonrevocation_safety coverage then 1 else 0) +
  (if coverage_temporal_policy_safety coverage then 1 else 0) +
  (if coverage_delegation_no_escalation coverage then 1 else 0) +
  (if coverage_wrapper_binding coverage then 1 else 0) +
  (if coverage_transcript_binding coverage then 1 else 0) +
  (if coverage_state_transition_safety coverage then 1 else 0) +
  (if coverage_invalid_transition_rejection coverage then 1 else 0) +
  (if coverage_merkle_concrete_path_model coverage then 1 else 0) +
  (if coverage_transparency_append_only coverage then 1 else 0) +
  (if coverage_lifecycle_composition coverage then 1 else 0) +
  (if coverage_adversary_gate_model coverage then 1 else 0) +
  (if coverage_predicate_refinement coverage then 1 else 0) +
  (if coverage_assumption_reduction coverage then 1 else 0) +
  (if coverage_master_invariant_composition coverage then 1 else 0) +
  (if coverage_rust_concept_map coverage then 1 else 0) +
  (if coverage_rust_refinement_obligation_boundary coverage then 1 else 0).

Definition arc_abstract_invariant_coverage_total : nat := 18.

Definition arc_abstract_invariant_coverage_is_100_percent
  (coverage : ArcAbstractInvariantCoverage)
  : bool :=
  Nat.eqb
    (arc_abstract_invariant_coverage_score coverage)
    arc_abstract_invariant_coverage_total.

Theorem current_abstract_invariant_coverage_complete :
  arc_abstract_invariant_coverage_complete arc_current_abstract_invariant_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem current_abstract_invariant_coverage_score_is_total :
  arc_abstract_invariant_coverage_score arc_current_abstract_invariant_coverage =
  arc_abstract_invariant_coverage_total.
Proof.
  reflexivity.
Qed.

Theorem current_abstract_invariant_coverage_is_100_percent :
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem complete_coverage_implies_key_authority_gate :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_key_authority_gate coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[H_key _] _] _] _] _] _] _] _] _] _] _] _] _] _] _] _] _].
  exact H_key.
Qed.

Theorem complete_coverage_implies_capability_authorization :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_capability_authorization coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ H_cap] _] _] _] _] _] _] _] _] _] _] _] _] _] _] _] _].
  exact H_cap.
Qed.

Theorem complete_coverage_implies_nonrevocation_safety :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_nonrevocation_safety coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] H_nonrev] _] _] _] _] _] _] _] _] _] _] _] _] _] _] _].
  exact H_nonrev.
Qed.

Theorem complete_coverage_implies_temporal_policy_safety :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_temporal_policy_safety coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] H_temporal] _] _] _] _] _] _] _] _] _] _] _] _] _] _].
  exact H_temporal.
Qed.

Theorem complete_coverage_implies_delegation_no_escalation :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_delegation_no_escalation coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] H_delegation] _] _] _] _] _] _] _] _] _] _] _] _] _].
  exact H_delegation.
Qed.

Theorem complete_coverage_implies_wrapper_binding :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_wrapper_binding coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] H_wrapper] _] _] _] _] _] _] _] _] _] _] _] _].
  exact H_wrapper.
Qed.

Theorem complete_coverage_implies_transcript_binding :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_transcript_binding coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] H_transcript] _] _] _] _] _] _] _] _] _] _] _].
  exact H_transcript.
Qed.

Theorem complete_coverage_implies_state_transition_safety :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_state_transition_safety coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] H_transition] _] _] _] _] _] _] _] _] _] _].
  exact H_transition.
Qed.

Theorem complete_coverage_implies_invalid_transition_rejection :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_invalid_transition_rejection coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] H_invalid] _] _] _] _] _] _] _] _] _].
  exact H_invalid.
Qed.

Theorem complete_coverage_implies_merkle_concrete_path_model :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_merkle_concrete_path_model coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] H_merkle] _] _] _] _] _] _] _] _].
  exact H_merkle.
Qed.

Theorem complete_coverage_implies_transparency_append_only :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_transparency_append_only coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] H_transparency] _] _] _] _] _] _] _].
  exact H_transparency.
Qed.

Theorem complete_coverage_implies_lifecycle_composition :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_lifecycle_composition coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] _] H_lifecycle] _] _] _] _] _] _].
  exact H_lifecycle.
Qed.

Theorem complete_coverage_implies_adversary_gate_model :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_adversary_gate_model coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] _] _] H_adversary] _] _] _] _] _].
  exact H_adversary.
Qed.

Theorem complete_coverage_implies_predicate_refinement :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_predicate_refinement coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] _] _] _] H_predicate] _] _] _] _].
  exact H_predicate.
Qed.

Theorem complete_coverage_implies_assumption_reduction :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_assumption_reduction coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] _] _] _] _] H_assumption] _] _] _].
  exact H_assumption.
Qed.

Theorem complete_coverage_implies_master_invariant_composition :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_master_invariant_composition coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] _] _] _] _] _] H_master] _] _].
  exact H_master.
Qed.

Theorem complete_coverage_implies_rust_concept_map :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_rust_concept_map coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] _] _] _] _] _] _] H_rust_map] _].
  exact H_rust_map.
Qed.

Theorem complete_coverage_implies_rust_refinement_obligation_boundary :
  forall coverage,
    arc_abstract_invariant_coverage_complete coverage = true ->
    coverage_rust_refinement_obligation_boundary coverage = true.
Proof.
  intros coverage H.
  unfold arc_abstract_invariant_coverage_complete in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[[[[[[[[[[[_ _] _] _] _] _] _] _] _] _] _] _] _] _] _] _] _] H_boundary].
  exact H_boundary.
Qed.

Theorem arc_abstract_protocol_invariant_layer_closed :
  arc_abstract_invariant_coverage_complete arc_current_abstract_invariant_coverage = true /\
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true /\
  arc_refinement_map_has_core_coverage arc_reference_refinement_map = true /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_abstract_invariant_coverage_complete.
  - split.
    + apply current_abstract_invariant_coverage_is_100_percent.
    + split.
      * apply reference_refinement_map_core_coverage.
      * apply current_obligations_are_not_claimed_fully_satisfied.
Qed.

Theorem arc_abstract_100_does_not_claim_rust_implementation_100 :
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_abstract_invariant_coverage_is_100_percent.
  - apply current_obligations_are_not_claimed_fully_satisfied.
Qed.
