From Coq Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementMap.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementObligations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementEvidence.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustMechanicalRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2AbstractInvariantCompleteness.
From KyriotesCsk2Proofs Require Import KyriotesCsk2DesignModelCompleteness.
From KyriotesCsk2Proofs Require Import KyriotesCsk2StateMachineCompleteness.
From KyriotesCsk2Proofs Require Import KyriotesCsk2MerkleTransparencyCompleteness.
From KyriotesCsk2Proofs Require Import KyriotesCsk2CryptoReductionCompleteness.

Record KyriotesCsk2FullMechanicalProofGate := {
  full_gate_inventory_exists : bool;
  full_gate_targets_declared : bool;
  full_gate_harness_complete : bool;
  full_gate_all_targets_checked : bool;
  full_gate_all_targets_proven : bool;
  full_gate_ci_enforced : bool;
  full_gate_rust_equivalence_claim_allowed : bool
}.

Definition kyriotes_csk2_full_mechanical_proof_gate_closed
  (gate : KyriotesCsk2FullMechanicalProofGate)
  : bool :=
  full_gate_inventory_exists gate &&
  full_gate_targets_declared gate &&
  full_gate_harness_complete gate &&
  full_gate_all_targets_checked gate &&
  full_gate_all_targets_proven gate &&
  full_gate_ci_enforced gate &&
  full_gate_rust_equivalence_claim_allowed gate.

Definition kyriotes_csk2_current_full_mechanical_proof_gate : KyriotesCsk2FullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Definition kyriotes_csk2_full_mechanical_proof_gate_ready_but_open
  (gate : KyriotesCsk2FullMechanicalProofGate)
  : bool :=
  full_gate_inventory_exists gate &&
  full_gate_targets_declared gate &&
  full_gate_harness_complete gate &&
  full_gate_ci_enforced gate &&
  negb (full_gate_all_targets_checked gate) &&
  negb (full_gate_all_targets_proven gate) &&
  negb (full_gate_rust_equivalence_claim_allowed gate).

Theorem current_full_mechanical_proof_gate_is_open :
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_current_full_mechanical_proof_gate = false.
Proof.
  reflexivity.
Qed.

Theorem current_full_mechanical_proof_gate_is_ready_but_open :
  kyriotes_csk2_full_mechanical_proof_gate_ready_but_open kyriotes_csk2_current_full_mechanical_proof_gate = true.
Proof.
  reflexivity.
Qed.

Theorem full_mechanical_proof_requires_checked_targets :
  forall gate,
    kyriotes_csk2_full_mechanical_proof_gate_closed gate = true ->
    full_gate_all_targets_checked gate = true.
Proof.
  intros gate H.
  unfold kyriotes_csk2_full_mechanical_proof_gate_closed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_inventory H_targets] H_harness] H_checked] H_proven] H_ci] H_claim].
  exact H_checked.
Qed.

Theorem full_mechanical_proof_requires_proven_targets :
  forall gate,
    kyriotes_csk2_full_mechanical_proof_gate_closed gate = true ->
    full_gate_all_targets_proven gate = true.
Proof.
  intros gate H.
  unfold kyriotes_csk2_full_mechanical_proof_gate_closed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_inventory H_targets] H_harness] H_checked] H_proven] H_ci] H_claim].
  exact H_proven.
Qed.

Theorem full_mechanical_proof_required_before_rust_equivalence_claim :
  forall gate,
    kyriotes_csk2_full_mechanical_proof_gate_closed gate = true ->
    full_gate_rust_equivalence_claim_allowed gate = true.
Proof.
  intros gate H.
  unfold kyriotes_csk2_full_mechanical_proof_gate_closed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_inventory H_targets] H_harness] H_checked] H_proven] H_ci] H_claim].
  exact H_claim.
Qed.

Theorem current_gate_preserves_prior_closed_layers :
  kyriotes_csk2_full_mechanical_proof_gate_ready_but_open kyriotes_csk2_current_full_mechanical_proof_gate = true ->
  kyriotes_csk2_abstract_invariant_coverage_is_100_percent kyriotes_csk2_current_abstract_invariant_coverage = true /\
  kyriotes_csk2_design_model_coverage_is_100_percent kyriotes_csk2_current_design_model_coverage = true /\
  kyriotes_csk2_state_machine_coverage_is_100_percent kyriotes_csk2_current_state_machine_coverage = true /\
  kyriotes_csk2_merkle_transparency_coverage_is_100_percent kyriotes_csk2_current_merkle_transparency_coverage = true /\
  kyriotes_csk2_crypto_reduction_coverage_is_100_percent kyriotes_csk2_current_crypto_reduction_coverage = true /\
  kyriotes_csk2_rust_coq_refinement_evidence_is_100_percent kyriotes_csk2_current_rust_coq_refinement_evidence_coverage = true /\
  kyriotes_csk2_rust_mechanical_refinement_coverage_is_100_percent kyriotes_csk2_current_rust_mechanical_refinement_coverage = true.
Proof.
  intros _.
  split.
  - apply current_abstract_invariant_coverage_is_100_percent.
  - split.
    + apply current_design_model_coverage_is_100_percent.
    + split.
      * apply current_state_machine_coverage_is_100_percent.
      * split.
        -- apply current_merkle_transparency_coverage_is_100_percent.
        -- split.
           ++ apply current_crypto_reduction_coverage_is_100_percent.
           ++ split.
              ** apply current_rust_coq_refinement_evidence_is_100_percent.
              ** apply current_rust_mechanical_refinement_coverage_is_100_percent.
Qed.

Theorem kyriotes_csk2_full_mechanical_proof_status_is_honestly_open :
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_current_full_mechanical_proof_gate = false /\
  kyriotes_csk2_full_mechanical_proof_gate_ready_but_open kyriotes_csk2_current_full_mechanical_proof_gate = true /\
  mechanical_proof_list_complete kyriotes_csk2_rust_mechanical_refinement_targets = false.
Proof.
  split.
  - apply current_full_mechanical_proof_gate_is_open.
  - split.
    + apply current_full_mechanical_proof_gate_is_ready_but_open.
    + apply current_mechanical_proof_list_not_complete.
Qed.
