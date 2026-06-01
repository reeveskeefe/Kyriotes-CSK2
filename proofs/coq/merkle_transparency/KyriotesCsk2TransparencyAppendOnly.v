From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyConsistencyProofs.

Fixpoint transparency_prefix
  (old_log new_log : list DeepTransparencyEntry)
  : bool :=
  match old_log, new_log with
  | [], _ => true
  | _, [] => false
  | old_head :: old_tail, new_head :: new_tail =>
      deep_entry_same_hash old_head new_head &&
      transparency_prefix old_tail new_tail
  end.

Definition transparency_append
  (entry : DeepTransparencyEntry)
  (log : list DeepTransparencyEntry)
  : list DeepTransparencyEntry :=
  log ++ [entry].

Fixpoint transparency_lookup_epoch
  (target_epoch : Epoch)
  (log : list DeepTransparencyEntry)
  : option DeepTransparencyEntry :=
  match log with
  | [] => None
  | head :: tail =>
      if Nat.eqb target_epoch (deep_entry_epoch head)
      then Some head
      else transparency_lookup_epoch target_epoch tail
  end.

Fixpoint transparency_no_epoch_conflicts
  (entry : DeepTransparencyEntry)
  (log : list DeepTransparencyEntry)
  : bool :=
  match log with
  | [] => true
  | head :: tail =>
      negb (deep_entry_conflict entry head) &&
      transparency_no_epoch_conflicts entry tail
  end.

Definition transparency_append_valid
  (entry : DeepTransparencyEntry)
  (log : list DeepTransparencyEntry)
  : bool :=
  transparency_no_epoch_conflicts entry log &&
  match log with
  | [] => true
  | last :: rest => true
  end.

Theorem transparency_prefix_refl :
  forall log,
    transparency_prefix log log = true.
Proof.
  induction log as [| head tail IH].
  - reflexivity.
  - simpl.
    unfold deep_entry_same_hash.
    rewrite Nat.eqb_refl.
    exact IH.
Qed.

Theorem empty_log_prefix :
  forall log,
    transparency_prefix [] log = true.
Proof.
  intros log.
  reflexivity.
Qed.

Theorem transparency_append_preserves_prefix :
  forall log entry,
    transparency_prefix log (transparency_append entry log) = true.
Proof.
  induction log as [| head tail IH]; intros entry.
  - reflexivity.
  - unfold transparency_append in *.
    simpl.
    unfold deep_entry_same_hash.
    rewrite Nat.eqb_refl.
    simpl.
    apply IH.
Qed.

Theorem transparency_lookup_head :
  forall entry rest,
    transparency_lookup_epoch (deep_entry_epoch entry) (entry :: rest) = Some entry.
Proof.
  intros entry rest.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem transparency_hash_member_append_old :
  forall hash log entry,
    transparency_hash_member hash log = true ->
    transparency_hash_member hash (transparency_append entry log) = true.
Proof.
  induction log as [| head tail IH]; intros entry H.
  - discriminate.
  - simpl in *.
    unfold transparency_append in *.
    simpl.
    destruct (hash =? deep_entry_hash head) eqn:H_head.
    + reflexivity.
    + apply IH.
      exact H.
Qed.

Theorem transparency_epoch_member_append_old :
  forall epoch log entry,
    transparency_epoch_member epoch log = true ->
    transparency_epoch_member epoch (transparency_append entry log) = true.
Proof.
  induction log as [| head tail IH]; intros entry H.
  - discriminate.
  - simpl in *.
    unfold transparency_append in *.
    simpl.
    destruct (epoch =? deep_entry_epoch head) eqn:H_head.
    + reflexivity.
    + apply IH.
      exact H.
Qed.

Theorem transparency_hash_member_append_new :
  forall log entry,
    transparency_hash_member (deep_entry_hash entry) (transparency_append entry log) = true.
Proof.
  induction log as [| head tail IH]; intros entry.
  - unfold transparency_append.
    simpl.
    rewrite Nat.eqb_refl.
    reflexivity.
  - unfold transparency_append in *.
    simpl.
    destruct (deep_entry_hash entry =? deep_entry_hash head); simpl.
    + reflexivity.
    + apply IH.
Qed.

Theorem transparency_epoch_member_append_new :
  forall log entry,
    transparency_epoch_member (deep_entry_epoch entry) (transparency_append entry log) = true.
Proof.
  induction log as [| head tail IH]; intros entry.
  - unfold transparency_append.
    simpl.
    rewrite Nat.eqb_refl.
    reflexivity.
  - unfold transparency_append in *.
    simpl.
    destruct (deep_entry_epoch entry =? deep_entry_epoch head); simpl.
    + reflexivity.
    + apply IH.
Qed.

Theorem no_epoch_conflict_cons_implies_head_safe :
  forall entry head tail,
    transparency_no_epoch_conflicts entry (head :: tail) = true ->
    deep_entry_conflict entry head = false.
Proof.
  intros entry head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  apply negb_true_iff in H_head.
  exact H_head.
Qed.

Theorem no_epoch_conflict_cons_implies_tail_safe :
  forall entry head tail,
    transparency_no_epoch_conflicts entry (head :: tail) = true ->
    transparency_no_epoch_conflicts entry tail = true.
Proof.
  intros entry head tail H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_head H_tail].
  exact H_tail.
Qed.

Theorem append_valid_implies_no_conflicts :
  forall entry log,
    transparency_append_valid entry log = true ->
    transparency_no_epoch_conflicts entry log = true.
Proof.
  intros entry log H.
  unfold transparency_append_valid in H.
  apply andb_true_iff in H.
  destruct H as [H_conflict H_tail].
  exact H_conflict.
Qed.

Theorem conflicting_entry_not_append_valid :
  forall entry head tail,
    deep_entry_conflict entry head = true ->
    transparency_append_valid entry (head :: tail) = false.
Proof.
  intros entry head tail H.
  unfold transparency_append_valid.
  simpl.
  rewrite H.
  reflexivity.
Qed.
