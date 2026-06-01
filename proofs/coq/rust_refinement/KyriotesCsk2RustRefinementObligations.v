From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementMap.

Inductive RustRefinementStrength :=
| ConceptMapped
| ModelEquivalent
| ImplementationChecked.

Record RustRefinementObligation := {
  obligation_module : RustModule;
  obligation_symbol : string;
  obligation_property : string;
  obligation_strength : RustRefinementStrength;
  obligation_satisfied : bool
}.

Definition obligation_is_conceptual_only
  (obligation : RustRefinementObligation)
  : bool :=
  match obligation_strength obligation with
  | ConceptMapped => true
  | _ => false
  end.

Definition obligation_is_implementation_checked
  (obligation : RustRefinementObligation)
  : bool :=
  match obligation_strength obligation with
  | ImplementationChecked => obligation_satisfied obligation
  | _ => false
  end.

Fixpoint obligations_all_satisfied
  (obligations : list RustRefinementObligation)
  : bool :=
  match obligations with
  | [] => true
  | head :: tail => obligation_satisfied head && obligations_all_satisfied tail
  end.

Fixpoint obligations_have_implementation_checked_item
  (obligations : list RustRefinementObligation)
  : bool :=
  match obligations with
  | [] => false
  | head :: tail =>
      obligation_is_implementation_checked head ||
      obligations_have_implementation_checked_item tail
  end.

Definition current_kyriotes_csk2_refinement_obligations : list RustRefinementObligation :=
  [
    {| obligation_module := RustEncoding; obligation_symbol := "decode_kyriotes_csk2_object"; obligation_property := "Rust decoder refines Coq codec model"; obligation_strength := ConceptMapped; obligation_satisfied := false |};
    {| obligation_module := RustVerify; obligation_symbol := "verify"; obligation_property := "Rust verify refines Coq verify_open_context"; obligation_strength := ConceptMapped; obligation_satisfied := false |};
    {| obligation_module := RustEngine; obligation_symbol := "open"; obligation_property := "Rust open refines Coq lifecycle open semantics"; obligation_strength := ConceptMapped; obligation_satisfied := false |};
    {| obligation_module := RustEngine; obligation_symbol := "add_epoch_wrapper"; obligation_property := "Rust rewrap refines Coq transition model"; obligation_strength := ConceptMapped; obligation_satisfied := false |};
    {| obligation_module := RustCapabilityTree; obligation_symbol := "capability_tree"; obligation_property := "Rust tree refines Coq concrete Merkle tree"; obligation_strength := ConceptMapped; obligation_satisfied := false |};
    {| obligation_module := RustTransparency; obligation_symbol := "transparency"; obligation_property := "Rust log refines Coq append-only log"; obligation_strength := ConceptMapped; obligation_satisfied := false |}
  ].

Theorem conceptual_obligation_is_not_implementation_checked :
  forall obligation,
    obligation_is_conceptual_only obligation = true ->
    obligation_is_implementation_checked obligation = false.
Proof.
  intros obligation H.
  unfold obligation_is_conceptual_only in H.
  unfold obligation_is_implementation_checked.
  destruct obligation as [m s p strength satisfied].
  simpl in *.
  destruct strength; try reflexivity; discriminate.
Qed.

Theorem implementation_checked_obligation_is_satisfied :
  forall obligation,
    obligation_is_implementation_checked obligation = true ->
    obligation_satisfied obligation = true.
Proof.
  intros obligation H.
  unfold obligation_is_implementation_checked in H.
  destruct obligation as [m s p strength satisfied].
  simpl in *.
  destruct strength; try discriminate.
  exact H.
Qed.

Theorem all_satisfied_head :
  forall head tail,
    obligations_all_satisfied (head :: tail) = true ->
    obligation_satisfied head = true.
Proof.
  intros head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  exact H_head.
Qed.

Theorem all_satisfied_tail :
  forall head tail,
    obligations_all_satisfied (head :: tail) = true ->
    obligations_all_satisfied tail = true.
Proof.
  intros head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  exact H_tail.
Qed.

Theorem current_obligations_are_not_claimed_fully_satisfied :
  obligations_all_satisfied current_kyriotes_csk2_refinement_obligations = false.
Proof.
  reflexivity.
Qed.

Theorem current_obligations_have_no_implementation_checked_item :
  obligations_have_implementation_checked_item current_kyriotes_csk2_refinement_obligations = false.
Proof.
  reflexivity.
Qed.

Theorem current_refinement_map_is_conceptual_not_full_rust_verification :
  obligations_all_satisfied current_kyriotes_csk2_refinement_obligations = false /\
  obligations_have_implementation_checked_item current_kyriotes_csk2_refinement_obligations = false.
Proof.
  split.
  - apply current_obligations_are_not_claimed_fully_satisfied.
  - apply current_obligations_have_no_implementation_checked_item.
Qed.
