From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Verify.
From KyriotesCsk2Proofs Require Import KyriotesCsk2WrapperProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2MasterInvariantProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2MerkleConcreteTree.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyAppendOnly.

Record ConcretePredicateEvidence := {
  concrete_key_material_valid : bool;
  concrete_capability_path_valid : bool;
  concrete_nonrevocation_path_valid : bool;
  concrete_authority_state_valid : bool;
  concrete_temporal_policy_valid : bool;
  concrete_object_binding_valid : bool;
  concrete_wrapper_binding_valid : bool;
  concrete_transparency_append_valid : bool;
  concrete_transition_valid : bool;
  concrete_invalid_transition_rejected : bool;
  concrete_refinement_coverage_valid : bool
}.

Definition abstract_bundle_from_concrete_predicates
  (evidence : ConcretePredicateEvidence)
  : KyriotesCsk2AbstractInvariantBundle :=
  {|
    bundle_key_gate := concrete_key_material_valid evidence;
    bundle_capability_gate := concrete_capability_path_valid evidence;
    bundle_nonrevocation_gate := concrete_nonrevocation_path_valid evidence;
    bundle_authority_state_gate := concrete_authority_state_valid evidence;
    bundle_temporal_gate := concrete_temporal_policy_valid evidence;
    bundle_object_binding_gate := concrete_object_binding_valid evidence;
    bundle_wrapper_gate := concrete_wrapper_binding_valid evidence;
    bundle_transparency_gate := concrete_transparency_append_valid evidence;
    bundle_transition_gate := concrete_transition_valid evidence;
    bundle_invalid_transition_rejection_gate := concrete_invalid_transition_rejected evidence;
    bundle_refinement_map_gate := concrete_refinement_coverage_valid evidence
  |}.

Definition concrete_predicates_hold (evidence : ConcretePredicateEvidence) : bool :=
  concrete_key_material_valid evidence &&
  concrete_capability_path_valid evidence &&
  concrete_nonrevocation_path_valid evidence &&
  concrete_authority_state_valid evidence &&
  concrete_temporal_policy_valid evidence &&
  concrete_object_binding_valid evidence &&
  concrete_wrapper_binding_valid evidence &&
  concrete_transparency_append_valid evidence &&
  concrete_transition_valid evidence &&
  concrete_invalid_transition_rejected evidence &&
  concrete_refinement_coverage_valid evidence.

Theorem concrete_predicates_refine_abstract_invariants :
  forall evidence,
    concrete_predicates_hold evidence = true ->
    kyriotes_csk2_abstract_invariants_hold
      (abstract_bundle_from_concrete_predicates evidence) = true.
Proof.
  intros evidence H.
  unfold concrete_predicates_hold in H.
  unfold kyriotes_csk2_abstract_invariants_hold.
  unfold abstract_bundle_from_concrete_predicates.
  simpl.
  exact H.
Qed.

Theorem concrete_capability_path_refines_capability_gate :
  forall evidence,
    concrete_predicates_hold evidence = true ->
    bundle_capability_gate (abstract_bundle_from_concrete_predicates evidence) = true.
Proof.
  intros evidence H.
  apply abstract_invariants_hold_implies_capability_gate.
  apply concrete_predicates_refine_abstract_invariants.
  exact H.
Qed.

Theorem concrete_nonrevocation_path_refines_nonrevocation_gate :
  forall evidence,
    concrete_predicates_hold evidence = true ->
    bundle_nonrevocation_gate (abstract_bundle_from_concrete_predicates evidence) = true.
Proof.
  intros evidence H.
  apply abstract_invariants_hold_implies_nonrevocation_gate.
  apply concrete_predicates_refine_abstract_invariants.
  exact H.
Qed.

Theorem concrete_wrapper_refines_wrapper_gate :
  forall evidence,
    concrete_predicates_hold evidence = true ->
    bundle_wrapper_gate (abstract_bundle_from_concrete_predicates evidence) = true.
Proof.
  intros evidence H.
  apply abstract_invariants_hold_implies_wrapper_gate.
  apply concrete_predicates_refine_abstract_invariants.
  exact H.
Qed.

Theorem concrete_transparency_refines_transparency_gate :
  forall evidence,
    concrete_predicates_hold evidence = true ->
    bundle_transparency_gate (abstract_bundle_from_concrete_predicates evidence) = true.
Proof.
  intros evidence H.
  apply abstract_invariants_hold_implies_transparency_gate.
  apply concrete_predicates_refine_abstract_invariants.
  exact H.
Qed.

Theorem concrete_transition_refines_transition_gate :
  forall evidence,
    concrete_predicates_hold evidence = true ->
    bundle_transition_gate (abstract_bundle_from_concrete_predicates evidence) = true.
Proof.
  intros evidence H.
  apply abstract_invariants_hold_implies_transition_gate.
  apply concrete_predicates_refine_abstract_invariants.
  exact H.
Qed.

Theorem concrete_invalid_rejection_refines_invalid_transition_gate :
  forall evidence,
    concrete_predicates_hold evidence = true ->
    bundle_invalid_transition_rejection_gate (abstract_bundle_from_concrete_predicates evidence) = true.
Proof.
  intros evidence H.
  apply abstract_invariants_hold_implies_invalid_transition_rejection_gate.
  apply concrete_predicates_refine_abstract_invariants.
  exact H.
Qed.
