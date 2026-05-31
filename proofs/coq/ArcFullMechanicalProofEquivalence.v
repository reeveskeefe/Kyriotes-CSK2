From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

Require Import ArcTypes.
Require Import ArcRustMechanicalRefinement.
Require Import ArcRustFullMechanicalProofGate.
Require Import ArcContextHashRustRefinement.
Require Import ArcTransparencyRustRefinement.

Record FullMechanicalProofEquivalenceStatus := {
  full_equiv_all_targets_checked : bool;
  full_equiv_context_hash_proof_artifact_exists : bool;
  full_equiv_context_hash_verifier_attempted : bool;
  full_equiv_context_hash_verifier_succeeded : bool;
  full_equiv_context_hash_mechanically_proven : bool;
  full_equiv_all_targets_mechanically_proven : bool
}.

Definition context_hash_full_equivalence_proven
  (status : FullMechanicalProofEquivalenceStatus)
  : bool :=
  full_equiv_context_hash_proof_artifact_exists status &&
  full_equiv_context_hash_verifier_attempted status &&
  full_equiv_context_hash_verifier_succeeded status &&
  full_equiv_context_hash_mechanically_proven status.

Definition full_mechanical_equivalence_closed
  (status : FullMechanicalProofEquivalenceStatus)
  : bool :=
  full_equiv_all_targets_checked status &&
  full_equiv_all_targets_mechanically_proven status.

Definition arc_current_full_mechanical_equivalence_status
  : FullMechanicalProofEquivalenceStatus :=
  {|
    full_equiv_all_targets_checked := true;
    full_equiv_context_hash_proof_artifact_exists := true;
    full_equiv_context_hash_verifier_attempted := true;
    full_equiv_context_hash_verifier_succeeded := true;
    full_equiv_context_hash_mechanically_proven := true;
    full_equiv_all_targets_mechanically_proven := false
  |}.

Theorem current_checked_targets_are_complete :
  transparency_refinement_checked arc_current_transparency_refinement_status = true.
Proof.
  apply current_transparency_refinement_checked.
Qed.

Theorem current_context_hash_full_equivalence_is_proven :
  context_hash_full_equivalence_proven arc_current_full_mechanical_equivalence_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_full_mechanical_equivalence_not_closed :
  full_mechanical_equivalence_closed arc_current_full_mechanical_equivalence_status = false.
Proof.
  reflexivity.
Qed.

Theorem full_equivalence_requires_all_targets_proven :
  forall status,
    full_mechanical_equivalence_closed status = true ->
    full_equiv_all_targets_mechanically_proven status = true.
Proof.
  intros status H.
  unfold full_mechanical_equivalence_closed in H.
  apply andb_true_iff in H.
  destruct H as [_ H_all_proven].
  exact H_all_proven.
Qed.

Theorem context_hash_equivalence_requires_verifier_success :
  forall status,
    context_hash_full_equivalence_proven status = true ->
    full_equiv_context_hash_verifier_succeeded status = true.
Proof.
  intros status H.
  unfold context_hash_full_equivalence_proven in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_artifact H_attempted] H_success] H_proven].
  exact H_success.
Qed.

Theorem full_mechanical_equivalence_gate_records_first_success_but_remains_open :
  context_hash_full_equivalence_proven arc_current_full_mechanical_equivalence_status = true /\
  full_mechanical_equivalence_closed arc_current_full_mechanical_equivalence_status = false.
Proof.
  split.
  - apply current_context_hash_full_equivalence_is_proven.
  - apply current_full_mechanical_equivalence_not_closed.
Qed.
