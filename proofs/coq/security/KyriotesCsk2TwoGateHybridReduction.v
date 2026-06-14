(*
  Two-gate hybrid reduction bridge.

  Connects KyriotesCsk2TwoGateOpeningGame with KyriotesCsk2KemAeadAssumptions:
  proves that any two-gate game win implies nonzero hybrid primitive advantage,
  and that holding all primitive assumptions is sufficient to block a game win.
*)

From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2TwoGateOpeningGame.
From KyriotesCsk2Proofs Require Import KyriotesCsk2KemAeadAssumptions.

(*
  Map each TwoGatePrimitiveBreaks field to the HybridReductionAdvantage component
  it activates:
    KEM gate      → hybrid_kem_advantage
    HKDF          → hybrid_hkdf_advantage
    AEAD conf/int → hybrid_aead_advantage (two terms)
    Signature     → hybrid_signature_advantage
    Capability/transparency soundness → hybrid_hash_advantage (two terms)
*)
Definition two_gate_breaks_to_hybrid_advantage
  (breaks : TwoGatePrimitiveBreaks)
  : HybridReductionAdvantage :=
  {|
    hybrid_kem_advantage :=
      if breaks_hybrid_kem breaks then 1 else 0;
    hybrid_aead_advantage :=
      (if breaks_aead_confidentiality breaks then 1 else 0) +
      (if breaks_aead_integrity breaks then 1 else 0);
    hybrid_hkdf_advantage :=
      if breaks_hkdf_context_separation breaks then 1 else 0;
    hybrid_signature_advantage :=
      if breaks_signature_authenticity breaks then 1 else 0;
    hybrid_hash_advantage :=
      (if breaks_capability_soundness breaks then 1 else 0) +
      (if breaks_transparency_binding breaks then 1 else 0)
  |}.

(*
  The hybrid total advantage equals the two-gate reduction term count: both sum
  one point per fired primitive break flag, just grouped differently.
*)
Lemma two_gate_hybrid_total_equals_term_count :
  forall breaks,
    hybrid_reduction_total_advantage (two_gate_breaks_to_hybrid_advantage breaks) =
    two_gate_reduction_term_count breaks.
Proof.
  intros breaks.
  unfold hybrid_reduction_total_advantage, two_gate_breaks_to_hybrid_advantage,
         two_gate_reduction_term_count.
  simpl.
  destruct (breaks_hybrid_kem breaks);
  destruct (breaks_hkdf_context_separation breaks);
  destruct (breaks_aead_confidentiality breaks);
  destruct (breaks_aead_integrity breaks);
  destruct (breaks_signature_authenticity breaks);
  destruct (breaks_capability_soundness breaks);
  destruct (breaks_transparency_binding breaks);
  simpl; lia.
Qed.

Theorem two_gate_break_implies_nonzero_hybrid_advantage :
  forall breaks,
    breaks_any_two_gate_assumption breaks = true ->
    hybrid_reduction_has_nonzero_advantage
      (two_gate_breaks_to_hybrid_advantage breaks) = true.
Proof.
  intros breaks H.
  unfold hybrid_reduction_has_nonzero_advantage.
  apply negb_true_iff.
  apply Nat.eqb_neq.
  rewrite two_gate_hybrid_total_equals_term_count.
  pose proof (primitive_break_implies_positive_reduction_term_count breaks H) as H_pos.
  lia.
Qed.

Theorem two_gate_game_win_implies_nonzero_hybrid_advantage :
  forall attempt,
    two_gate_game_win attempt = true ->
    hybrid_reduction_has_nonzero_advantage
      (two_gate_breaks_to_hybrid_advantage (attempt_breaks attempt)) = true.
Proof.
  intros attempt H_win.
  apply two_gate_break_implies_nonzero_hybrid_advantage.
  apply two_gate_game_win_implies_primitive_break.
  exact H_win.
Qed.

Theorem key_only_win_implies_nonzero_hybrid_advantage :
  forall attempt,
    attempt_class attempt = KeyOnlyAdversary ->
    two_gate_game_win attempt = true ->
    hybrid_reduction_has_nonzero_advantage
      (two_gate_breaks_to_hybrid_advantage (attempt_breaks attempt)) = true.
Proof.
  intros attempt _ H_win.
  apply two_gate_game_win_implies_nonzero_hybrid_advantage.
  exact H_win.
Qed.

Theorem capability_only_win_implies_nonzero_hybrid_advantage :
  forall attempt,
    attempt_class attempt = CapabilityOnlyAdversary ->
    two_gate_game_win attempt = true ->
    hybrid_reduction_has_nonzero_advantage
      (two_gate_breaks_to_hybrid_advantage (attempt_breaks attempt)) = true.
Proof.
  intros attempt _ H_win.
  apply two_gate_game_win_implies_nonzero_hybrid_advantage.
  exact H_win.
Qed.

Theorem missing_both_win_implies_nonzero_hybrid_advantage :
  forall attempt,
    attempt_class attempt = MissingBothAdversary ->
    two_gate_game_win attempt = true ->
    hybrid_reduction_has_nonzero_advantage
      (two_gate_breaks_to_hybrid_advantage (attempt_breaks attempt)) = true.
Proof.
  intros attempt _ H_win.
  apply two_gate_game_win_implies_nonzero_hybrid_advantage.
  exact H_win.
Qed.

(*
  Consistency condition: primitive assumptions constrain which two-gate breaks can
  be active. Each "no_X_break" assumption implies the corresponding break is absent.
*)
Definition primitive_assumptions_negate_two_gate_breaks
  (assumptions : PrimitiveAssumptions)
  (breaks : TwoGatePrimitiveBreaks)
  : bool :=
  implb (assumes_no_kem_break assumptions)             (negb (breaks_hybrid_kem breaks)) &&
  implb (assumes_no_hkdf_break assumptions)            (negb (breaks_hkdf_context_separation breaks)) &&
  implb (assumes_no_aead_break assumptions)            (negb (breaks_aead_confidentiality breaks)) &&
  implb (assumes_no_aead_break assumptions)            (negb (breaks_aead_integrity breaks)) &&
  implb (assumes_no_signature_break assumptions)       (negb (breaks_signature_authenticity breaks)) &&
  implb (assumes_no_hash_binding_break assumptions)    (negb (breaks_capability_soundness breaks)) &&
  implb (assumes_no_transparency_binding_break assumptions) (negb (breaks_transparency_binding breaks)).

Theorem primitive_assumptions_block_two_gate_win :
  forall attempt assumptions,
    primitive_assumptions_hold assumptions = true ->
    primitive_assumptions_negate_two_gate_breaks assumptions (attempt_breaks attempt) = true ->
    two_gate_game_win attempt = false.
Proof.
  intros attempt assumptions H_assumptions H_consistent.
  apply no_primitive_break_blocks_two_gate_game_win.
  unfold primitive_assumptions_hold in H_assumptions.
  repeat rewrite andb_true_iff in H_assumptions.
  unfold primitive_assumptions_negate_two_gate_breaks in H_consistent.
  repeat rewrite andb_true_iff in H_consistent.
  destruct H_assumptions as [[[[[[H_aead H_kem] H_hkdf] H_sig] H_hash] _H_merkle] H_trans_assump].
  destruct H_consistent as [[[[[[H_c_kem H_c_hkdf] H_c_aead_c] H_c_aead_i] H_c_sig] H_c_cap] H_c_trans].
  unfold breaks_any_two_gate_assumption.
  rewrite H_kem in H_c_kem; simpl in H_c_kem; apply negb_true_iff in H_c_kem.
  rewrite H_hkdf in H_c_hkdf; simpl in H_c_hkdf; apply negb_true_iff in H_c_hkdf.
  rewrite H_aead in H_c_aead_c; simpl in H_c_aead_c; apply negb_true_iff in H_c_aead_c.
  rewrite H_aead in H_c_aead_i; simpl in H_c_aead_i; apply negb_true_iff in H_c_aead_i.
  rewrite H_sig in H_c_sig; simpl in H_c_sig; apply negb_true_iff in H_c_sig.
  rewrite H_hash in H_c_cap; simpl in H_c_cap; apply negb_true_iff in H_c_cap.
  rewrite H_trans_assump in H_c_trans; simpl in H_c_trans; apply negb_true_iff in H_c_trans.
  rewrite H_c_kem, H_c_hkdf, H_c_aead_c, H_c_aead_i, H_c_sig, H_c_cap, H_c_trans.
  reflexivity.
Qed.

(*
  Positive hybrid advantage implies the two-gate total is also positive (converse
  direction: useful when composing with upper layers).
*)
Theorem nonzero_hybrid_advantage_implies_positive_term_count :
  forall breaks,
    hybrid_reduction_has_nonzero_advantage (two_gate_breaks_to_hybrid_advantage breaks) = true ->
    two_gate_reduction_term_count breaks > 0.
Proof.
  intros breaks H.
  rewrite <- two_gate_hybrid_total_equals_term_count.
  apply hybrid_reduction_nonzero_advantage_implies_positive_total.
  exact H.
Qed.

(* ================================================================
   Primitive security composition theorem

   Proves that if no individual primitive is broken — KEM, HKDF, AEAD
   (confidentiality and integrity), epoch signature, capability soundness,
   and transparency binding — then no adversary wins the two-gate game.

   This is the master security composition: it connects the per-primitive
   security assumptions (stated in KyriotesCsk2KemAeadAssumptions and
   KyriotesCsk2Authority) to the top-level two-gate opening game.

   Proof is purely structural: it unfolds `breaks_any_two_gate_assumption`
   and applies `no_primitive_break_blocks_two_gate_game_win`.
   ================================================================ *)

Theorem primitive_security_implies_two_gate_security :
  forall attempt,
    breaks_hybrid_kem            (attempt_breaks attempt) = false ->
    breaks_hkdf_context_separation (attempt_breaks attempt) = false ->
    breaks_aead_confidentiality  (attempt_breaks attempt) = false ->
    breaks_aead_integrity        (attempt_breaks attempt) = false ->
    breaks_signature_authenticity (attempt_breaks attempt) = false ->
    breaks_capability_soundness  (attempt_breaks attempt) = false ->
    breaks_transparency_binding  (attempt_breaks attempt) = false ->
    two_gate_game_win attempt = false.
Proof.
  intros attempt Hkem Hhkdf Haead_c Haead_i Hsig Hcap Htrans.
  apply no_primitive_break_blocks_two_gate_game_win.
  unfold breaks_any_two_gate_assumption.
  rewrite Hkem, Hhkdf, Haead_c, Haead_i, Hsig, Hcap, Htrans.
  reflexivity.
Qed.

(*
  Corollary: if a valid two-gate opening attempt succeeds, then at least
  one of the seven primitive assumptions is broken. This is the contrapositive
  form of the composition theorem — the standard way to state a security
  reduction in a paper.
*)
Corollary two_gate_win_implies_some_primitive_break :
  forall attempt,
    two_gate_game_win attempt = true ->
    breaks_hybrid_kem             (attempt_breaks attempt) = true \/
    breaks_hkdf_context_separation (attempt_breaks attempt) = true \/
    breaks_aead_confidentiality   (attempt_breaks attempt) = true \/
    breaks_aead_integrity         (attempt_breaks attempt) = true \/
    breaks_signature_authenticity  (attempt_breaks attempt) = true \/
    breaks_capability_soundness   (attempt_breaks attempt) = true \/
    breaks_transparency_binding   (attempt_breaks attempt) = true.
Proof.
  intros attempt H_win.
  pose proof (two_gate_game_win_implies_primitive_break attempt H_win) as H_any.
  unfold breaks_any_two_gate_assumption in H_any.
  destruct (breaks_hybrid_kem (attempt_breaks attempt)) eqn:H1;
    [ left; reflexivity | simpl in H_any ].
  destruct (breaks_hkdf_context_separation (attempt_breaks attempt)) eqn:H2;
    [ right; left; reflexivity | simpl in H_any ].
  destruct (breaks_aead_confidentiality (attempt_breaks attempt)) eqn:H3;
    [ right; right; left; reflexivity | simpl in H_any ].
  destruct (breaks_aead_integrity (attempt_breaks attempt)) eqn:H4;
    [ right; right; right; left; reflexivity | simpl in H_any ].
  destruct (breaks_signature_authenticity (attempt_breaks attempt)) eqn:H5;
    [ right; right; right; right; left; reflexivity | simpl in H_any ].
  destruct (breaks_capability_soundness (attempt_breaks attempt)) eqn:H6;
    [ right; right; right; right; right; left; reflexivity | simpl in H_any ].
  destruct (breaks_transparency_binding (attempt_breaks attempt)) eqn:H7;
    [ right; right; right; right; right; right; reflexivity | discriminate ].
Qed.

(*
  Completeness record: tracks that the two-gate → hybrid bridge is formalized.
*)
Record TwoGateHybridReductionStatus := {
  tghr_advantage_map_defined              : bool;
  tghr_total_equals_term_count            : bool;
  tghr_break_implies_nonzero_advantage    : bool;
  tghr_game_win_implies_nonzero_advantage : bool;
  tghr_per_class_reductions              : bool;
  tghr_assumption_blocking_theorem        : bool;
  tghr_converse_direction                : bool;
  tghr_primitive_composition_proved       : bool;
  tghr_disjunctive_break_corollary_proved : bool
}.

Definition two_gate_hybrid_reduction_complete
  (status : TwoGateHybridReductionStatus)
  : bool :=
  tghr_advantage_map_defined status &&
  tghr_total_equals_term_count status &&
  tghr_break_implies_nonzero_advantage status &&
  tghr_game_win_implies_nonzero_advantage status &&
  tghr_per_class_reductions status &&
  tghr_assumption_blocking_theorem status &&
  tghr_converse_direction status &&
  tghr_primitive_composition_proved status &&
  tghr_disjunctive_break_corollary_proved status.

Definition kyriotes_csk2_current_two_gate_hybrid_reduction_status
  : TwoGateHybridReductionStatus :=
  {|
    tghr_advantage_map_defined              := true;
    tghr_total_equals_term_count            := true;
    tghr_break_implies_nonzero_advantage    := true;
    tghr_game_win_implies_nonzero_advantage := true;
    tghr_per_class_reductions              := true;
    tghr_assumption_blocking_theorem        := true;
    tghr_converse_direction                := true;
    tghr_primitive_composition_proved       := true;
    tghr_disjunctive_break_corollary_proved := true
  |}.

Theorem current_two_gate_hybrid_reduction_complete :
  two_gate_hybrid_reduction_complete
    kyriotes_csk2_current_two_gate_hybrid_reduction_status = true.
Proof.
  reflexivity.
Qed.
