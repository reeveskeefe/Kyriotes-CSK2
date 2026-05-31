From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

Require Import ArcTypes.
Require Import ArcMerkle.
Require Import ArcAuthority.
Require Import ArcPolicy.
Require Import ArcVerify.
Require Import ArcSecurityGame.
Require Import ArcTheorems.
Require Import ArcStressProofs.
Require Import ArcDelegationProofs.
Require Import ArcCryptoReduction.
Require Import ArcTemporalProofs.
Require Import ArcTranscriptProofs.
Require Import ArcRevocationCompromiseProofs.
Require Import ArcTransparencyProofs.
Require Import ArcEncodingProofs.
Require Import ArcWrapperProofs.
Require Import ArcKemAeadAssumptions.
Require Import ArcEndToEndTheorems.
Require Import ArcStateTransitionProofs.
Require Import ArcConcreteMerkleProofs.
Require Import ArcTransparencyConsistencyProofs.
Require Import ArcProtocolStateMachineProofs.
Require Import ArcInvalidTransitionProofs.
Require Import ArcTightSecurityGameProofs.

Record ConcreteDesignLemmas := {
  lemma_merkle_insert_present : bool;
  lemma_revocation_monotone : bool;
  lemma_transparency_linked : bool;
  lemma_state_machine_valid : bool;
  lemma_invalid_transitions_rejected : bool;
  lemma_tight_game_complete : bool;
  lemma_refinement_mapped : bool
}.

Definition concrete_design_lemmas_hold (lemmas : ConcreteDesignLemmas) : bool :=
  lemma_merkle_insert_present lemmas &&
  lemma_revocation_monotone lemmas &&
  lemma_transparency_linked lemmas &&
  lemma_state_machine_valid lemmas &&
  lemma_invalid_transitions_rejected lemmas &&
  lemma_tight_game_complete lemmas &&
  lemma_refinement_mapped lemmas.

Definition reduced_assumption_surface (lemmas : ConcreteDesignLemmas) (assumptions : PrimitiveAssumptions) : bool :=
  concrete_design_lemmas_hold lemmas &&
  assumes_no_aead_break assumptions &&
  assumes_no_kem_break assumptions &&
  assumes_no_hkdf_break assumptions &&
  assumes_no_signature_break assumptions &&
  assumes_no_hash_binding_break assumptions.

Theorem concrete_design_lemmas_hold_implies_merkle_insert_present :
  forall lemmas,
    concrete_design_lemmas_hold lemmas = true ->
    lemma_merkle_insert_present lemmas = true.
Proof.
  intros lemmas H.
  unfold concrete_design_lemmas_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_merkle _] _] _] _] _] _].
  exact H_merkle.
Qed.

Theorem concrete_design_lemmas_hold_implies_revocation_monotone :
  forall lemmas,
    concrete_design_lemmas_hold lemmas = true ->
    lemma_revocation_monotone lemmas = true.
Proof.
  intros lemmas H.
  unfold concrete_design_lemmas_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ H_rev] _] _] _] _] _].
  exact H_rev.
Qed.

Theorem concrete_design_lemmas_hold_implies_transparency_linked :
  forall lemmas,
    concrete_design_lemmas_hold lemmas = true ->
    lemma_transparency_linked lemmas = true.
Proof.
  intros lemmas H.
  unfold concrete_design_lemmas_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] H_trans] _] _] _] _].
  exact H_trans.
Qed.

Theorem concrete_design_lemmas_hold_implies_state_machine_valid :
  forall lemmas,
    concrete_design_lemmas_hold lemmas = true ->
    lemma_state_machine_valid lemmas = true.
Proof.
  intros lemmas H.
  unfold concrete_design_lemmas_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] H_machine] _] _] _].
  exact H_machine.
Qed.

Theorem concrete_design_lemmas_hold_implies_invalid_rejected :
  forall lemmas,
    concrete_design_lemmas_hold lemmas = true ->
    lemma_invalid_transitions_rejected lemmas = true.
Proof.
  intros lemmas H.
  unfold concrete_design_lemmas_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] _] H_invalid] _] _].
  exact H_invalid.
Qed.

Theorem concrete_design_lemmas_hold_implies_tight_game :
  forall lemmas,
    concrete_design_lemmas_hold lemmas = true ->
    lemma_tight_game_complete lemmas = true.
Proof.
  intros lemmas H.
  unfold concrete_design_lemmas_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] _] _] H_game] _].
  exact H_game.
Qed.

Theorem concrete_design_lemmas_hold_implies_refinement :
  forall lemmas,
    concrete_design_lemmas_hold lemmas = true ->
    lemma_refinement_mapped lemmas = true.
Proof.
  intros lemmas H.
  unfold concrete_design_lemmas_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] _] _] _] H_refine].
  exact H_refine.
Qed.

Theorem reduced_assumption_surface_implies_design_lemmas :
  forall lemmas assumptions,
    reduced_assumption_surface lemmas assumptions = true ->
    concrete_design_lemmas_hold lemmas = true.
Proof.
  intros lemmas assumptions H.
  unfold reduced_assumption_surface in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[H_design _] _] _] _] _].
  exact H_design.
Qed.

Theorem reduced_assumption_surface_removes_merkle_binding_assumption :
  forall lemmas assumptions,
    reduced_assumption_surface lemmas assumptions = true ->
    lemma_merkle_insert_present lemmas = true /\
    lemma_revocation_monotone lemmas = true.
Proof.
  intros lemmas assumptions H.
  pose proof (reduced_assumption_surface_implies_design_lemmas lemmas assumptions H) as H_design.
  split.
  - apply concrete_design_lemmas_hold_implies_merkle_insert_present. exact H_design.
  - apply concrete_design_lemmas_hold_implies_revocation_monotone. exact H_design.
Qed.

Theorem reduced_assumption_surface_keeps_only_primitive_core :
  forall lemmas assumptions,
    reduced_assumption_surface lemmas assumptions = true ->
    assumes_no_aead_break assumptions = true /\
    assumes_no_kem_break assumptions = true /\
    assumes_no_hkdf_break assumptions = true /\
    assumes_no_signature_break assumptions = true /\
    assumes_no_hash_binding_break assumptions = true.
Proof.
  intros lemmas assumptions H.
  unfold reduced_assumption_surface in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[H_design H_aead] H_kem] H_hkdf] H_sig] H_hash].
  repeat split; assumption.
Qed.
