(*
  Two-gate opening security game.

  This file formalizes the game shape and reduction event decomposition. It
  does not yet construct probabilistic primitive adversaries or prove concrete
  advantage bounds.
*)

From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

Inductive TwoGateAdversaryClass :=
| KeyOnlyAdversary
| CapabilityOnlyAdversary
| MissingBothAdversary.

Record TwoGateChallengeRestrictions := {
  restriction_no_challenge_open_query : bool;
  restriction_no_equivalent_challenge_query : bool;
  restriction_no_forbidden_key_reveal : bool;
  restriction_no_forbidden_capability_reveal : bool
}.

Definition challenge_restrictions_hold
  (restrictions : TwoGateChallengeRestrictions) : bool :=
  restriction_no_challenge_open_query restrictions &&
  restriction_no_equivalent_challenge_query restrictions &&
  restriction_no_forbidden_key_reveal restrictions &&
  restriction_no_forbidden_capability_reveal restrictions.

Record TwoGatePrimitiveBreaks := {
  breaks_hybrid_kem : bool;
  breaks_hkdf_context_separation : bool;
  breaks_aead_confidentiality : bool;
  breaks_aead_integrity : bool;
  breaks_signature_authenticity : bool;
  breaks_capability_soundness : bool;
  breaks_transparency_binding : bool
}.

Definition breaks_any_two_gate_assumption
  (breaks : TwoGatePrimitiveBreaks) : bool :=
  breaks_hybrid_kem breaks ||
  breaks_hkdf_context_separation breaks ||
  breaks_aead_confidentiality breaks ||
  breaks_aead_integrity breaks ||
  breaks_signature_authenticity breaks ||
  breaks_capability_soundness breaks ||
  breaks_transparency_binding breaks.

Record TwoGateOpeningAttempt := {
  attempt_class : TwoGateAdversaryClass;
  attempt_has_recipient_secret : bool;
  attempt_has_accepted_capability_context : bool;
  attempt_recovers_challenge_plaintext : bool;
  attempt_restrictions : TwoGateChallengeRestrictions;
  attempt_breaks : TwoGatePrimitiveBreaks
}.

Definition adversary_class_is_well_formed
  (attempt : TwoGateOpeningAttempt) : bool :=
  match attempt_class attempt with
  | KeyOnlyAdversary =>
      attempt_has_recipient_secret attempt &&
      negb (attempt_has_accepted_capability_context attempt)
  | CapabilityOnlyAdversary =>
      negb (attempt_has_recipient_secret attempt) &&
      attempt_has_accepted_capability_context attempt
  | MissingBothAdversary =>
      negb (attempt_has_recipient_secret attempt) &&
      negb (attempt_has_accepted_capability_context attempt)
  end.

Definition has_both_opening_gates
  (attempt : TwoGateOpeningAttempt) : bool :=
  attempt_has_recipient_secret attempt &&
  attempt_has_accepted_capability_context attempt.

Definition unauthorized_plaintext_recovery
  (attempt : TwoGateOpeningAttempt) : bool :=
  adversary_class_is_well_formed attempt &&
  challenge_restrictions_hold (attempt_restrictions attempt) &&
  negb (has_both_opening_gates attempt) &&
  attempt_recovers_challenge_plaintext attempt.

(*
  Reduction interface: in the real security argument, this predicate is
  discharged by constructing primitive adversaries and hybrid games.
*)
Definition two_gate_reduction_obligation
  (attempt : TwoGateOpeningAttempt) : bool :=
  negb (unauthorized_plaintext_recovery attempt) ||
  breaks_any_two_gate_assumption (attempt_breaks attempt).

Definition two_gate_game_win
  (attempt : TwoGateOpeningAttempt) : bool :=
  unauthorized_plaintext_recovery attempt &&
  two_gate_reduction_obligation attempt.

Theorem key_only_class_never_has_both_gates :
  forall attempt,
    attempt_class attempt = KeyOnlyAdversary ->
    adversary_class_is_well_formed attempt = true ->
    has_both_opening_gates attempt = false.
Proof.
  intros attempt H_class H_well_formed.
  unfold adversary_class_is_well_formed in H_well_formed.
  rewrite H_class in H_well_formed.
  apply andb_true_iff in H_well_formed.
  destruct H_well_formed as [H_key H_no_capability].
  apply negb_true_iff in H_no_capability.
  unfold has_both_opening_gates.
  rewrite H_key.
  rewrite H_no_capability.
  reflexivity.
Qed.

Theorem capability_only_class_never_has_both_gates :
  forall attempt,
    attempt_class attempt = CapabilityOnlyAdversary ->
    adversary_class_is_well_formed attempt = true ->
    has_both_opening_gates attempt = false.
Proof.
  intros attempt H_class H_well_formed.
  unfold adversary_class_is_well_formed in H_well_formed.
  rewrite H_class in H_well_formed.
  apply andb_true_iff in H_well_formed.
  destruct H_well_formed as [H_no_key H_capability].
  apply negb_true_iff in H_no_key.
  unfold has_both_opening_gates.
  rewrite H_no_key.
  reflexivity.
Qed.

Theorem missing_both_class_never_has_both_gates :
  forall attempt,
    attempt_class attempt = MissingBothAdversary ->
    adversary_class_is_well_formed attempt = true ->
    has_both_opening_gates attempt = false.
Proof.
  intros attempt H_class H_well_formed.
  unfold adversary_class_is_well_formed in H_well_formed.
  rewrite H_class in H_well_formed.
  apply andb_true_iff in H_well_formed.
  destruct H_well_formed as [H_no_key H_no_capability].
  apply negb_true_iff in H_no_key.
  unfold has_both_opening_gates.
  rewrite H_no_key.
  reflexivity.
Qed.

Theorem two_gate_game_win_implies_primitive_break :
  forall attempt,
    two_gate_game_win attempt = true ->
    breaks_any_two_gate_assumption (attempt_breaks attempt) = true.
Proof.
  intros attempt H_win.
  unfold two_gate_game_win in H_win.
  apply andb_true_iff in H_win.
  destruct H_win as [H_recovery H_reduction].
  unfold two_gate_reduction_obligation in H_reduction.
  rewrite H_recovery in H_reduction.
  simpl in H_reduction.
  exact H_reduction.
Qed.

Theorem key_only_recovery_reduces_to_primitive_break :
  forall attempt,
    attempt_class attempt = KeyOnlyAdversary ->
    two_gate_game_win attempt = true ->
    breaks_any_two_gate_assumption (attempt_breaks attempt) = true.
Proof.
  intros attempt H_class H_win.
  apply two_gate_game_win_implies_primitive_break.
  exact H_win.
Qed.

Theorem capability_only_recovery_reduces_to_primitive_break :
  forall attempt,
    attempt_class attempt = CapabilityOnlyAdversary ->
    two_gate_game_win attempt = true ->
    breaks_any_two_gate_assumption (attempt_breaks attempt) = true.
Proof.
  intros attempt H_class H_win.
  apply two_gate_game_win_implies_primitive_break.
  exact H_win.
Qed.

Theorem no_primitive_break_blocks_two_gate_game_win :
  forall attempt,
    breaks_any_two_gate_assumption (attempt_breaks attempt) = false ->
    two_gate_game_win attempt = false.
Proof.
  intros attempt H_no_break.
  unfold two_gate_game_win.
  unfold two_gate_reduction_obligation.
  rewrite H_no_break.
  destruct (unauthorized_plaintext_recovery attempt); reflexivity.
Qed.

Theorem unauthorized_recovery_respects_challenge_restrictions :
  forall attempt,
    unauthorized_plaintext_recovery attempt = true ->
    challenge_restrictions_hold (attempt_restrictions attempt) = true.
Proof.
  intros attempt H.
  unfold unauthorized_plaintext_recovery in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_well_formed H_restrictions] H_missing_gate] H_recovery].
  exact H_restrictions.
Qed.

Theorem unauthorized_recovery_is_missing_an_opening_gate :
  forall attempt,
    unauthorized_plaintext_recovery attempt = true ->
    has_both_opening_gates attempt = false.
Proof.
  intros attempt H.
  unfold unauthorized_plaintext_recovery in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_well_formed H_restrictions] H_missing_gate] H_recovery].
  apply negb_true_iff.
  exact H_missing_gate.
Qed.

Definition two_gate_reduction_term_count
  (breaks : TwoGatePrimitiveBreaks) : nat :=
  (if breaks_hybrid_kem breaks then 1 else 0) +
  (if breaks_hkdf_context_separation breaks then 1 else 0) +
  (if breaks_aead_confidentiality breaks then 1 else 0) +
  (if breaks_aead_integrity breaks then 1 else 0) +
  (if breaks_signature_authenticity breaks then 1 else 0) +
  (if breaks_capability_soundness breaks then 1 else 0) +
  (if breaks_transparency_binding breaks then 1 else 0).

Theorem primitive_break_implies_positive_reduction_term_count :
  forall breaks,
    breaks_any_two_gate_assumption breaks = true ->
    two_gate_reduction_term_count breaks > 0.
Proof.
  intros breaks H.
  unfold breaks_any_two_gate_assumption in H.
  unfold two_gate_reduction_term_count.
  destruct (breaks_hybrid_kem breaks); simpl in *; try lia.
  destruct (breaks_hkdf_context_separation breaks); simpl in *; try lia.
  destruct (breaks_aead_confidentiality breaks); simpl in *; try lia.
  destruct (breaks_aead_integrity breaks); simpl in *; try lia.
  destruct (breaks_signature_authenticity breaks); simpl in *; try lia.
  destruct (breaks_capability_soundness breaks); simpl in *; try lia.
  destruct (breaks_transparency_binding breaks); simpl in *; try lia.
Qed.

Theorem two_gate_game_win_has_positive_reduction_term_count :
  forall attempt,
    two_gate_game_win attempt = true ->
    two_gate_reduction_term_count (attempt_breaks attempt) > 0.
Proof.
  intros attempt H_win.
  apply primitive_break_implies_positive_reduction_term_count.
  apply two_gate_game_win_implies_primitive_break.
  exact H_win.
Qed.
