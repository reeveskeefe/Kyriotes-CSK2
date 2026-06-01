From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Merkle.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Authority.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Policy.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Verify.
From KyriotesCsk2Proofs Require Import KyriotesCsk2SecurityGame.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Theorems.
From KyriotesCsk2Proofs Require Import KyriotesCsk2StressProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2DelegationProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2CryptoReduction.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TemporalProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TranscriptProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RevocationCompromiseProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2EncodingProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2WrapperProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2KemAeadAssumptions.
From KyriotesCsk2Proofs Require Import KyriotesCsk2EndToEndTheorems.
From KyriotesCsk2Proofs Require Import KyriotesCsk2StateTransitionProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ConcreteMerkleProofs.

Record DeepTransparencyEntry := {
  deep_entry_epoch : Epoch;
  deep_entry_authority_root : Hash;
  deep_entry_revocation_root : Hash;
  deep_entry_transparency_root : Hash;
  deep_entry_prev_hash : Hash;
  deep_entry_hash : Hash
}.

Definition deep_entry_same_epoch (a b : DeepTransparencyEntry) : bool :=
  Nat.eqb (deep_entry_epoch a) (deep_entry_epoch b).

Definition deep_entry_same_hash (a b : DeepTransparencyEntry) : bool :=
  Nat.eqb (deep_entry_hash a) (deep_entry_hash b).

Definition deep_entry_conflict (a b : DeepTransparencyEntry) : bool :=
  deep_entry_same_epoch a b && negb (deep_entry_same_hash a b).

Definition deep_entry_links (prev next : DeepTransparencyEntry) : bool :=
  Nat.eqb (deep_entry_hash prev) (deep_entry_prev_hash next) &&
  Nat.ltb (deep_entry_epoch prev) (deep_entry_epoch next).

Fixpoint transparency_log_well_linked_from
  (previous : DeepTransparencyEntry)
  (entries : list DeepTransparencyEntry)
  : bool :=
  match entries with
  | [] => true
  | next :: rest =>
      deep_entry_links previous next &&
      transparency_log_well_linked_from next rest
  end.

Definition transparency_log_well_linked (entries : list DeepTransparencyEntry) : bool :=
  match entries with
  | [] => true
  | first :: rest => transparency_log_well_linked_from first rest
  end.

Fixpoint transparency_epoch_member (epoch : Epoch) (entries : list DeepTransparencyEntry) : bool :=
  match entries with
  | [] => false
  | head :: tail => Nat.eqb epoch (deep_entry_epoch head) || transparency_epoch_member epoch tail
  end.

Fixpoint transparency_hash_member (hash : Hash) (entries : list DeepTransparencyEntry) : bool :=
  match entries with
  | [] => false
  | head :: tail => Nat.eqb hash (deep_entry_hash head) || transparency_hash_member hash tail
  end.

Theorem deep_entry_conflict_implies_same_epoch_distinct_hash :
  forall a b,
    deep_entry_conflict a b = true ->
    deep_entry_epoch a = deep_entry_epoch b /\
    deep_entry_hash a <> deep_entry_hash b.
Proof.
  intros a b H.
  unfold deep_entry_conflict in H.
  apply andb_true_iff in H.
  destruct H as [H_epoch H_hash].
  unfold deep_entry_same_epoch in H_epoch.
  unfold deep_entry_same_hash in H_hash.
  apply Nat.eqb_eq in H_epoch.
  apply negb_true_iff in H_hash.
  apply Nat.eqb_neq in H_hash.
  split; assumption.
Qed.

Theorem same_hash_entries_not_conflicting :
  forall a b,
    deep_entry_hash a = deep_entry_hash b ->
    deep_entry_conflict a b = false.
Proof.
  intros a b H.
  unfold deep_entry_conflict.
  unfold deep_entry_same_hash.
  rewrite H.
  rewrite Nat.eqb_refl.
  simpl.
  destruct (deep_entry_same_epoch a b); reflexivity.
Qed.

Theorem deep_entry_links_implies_hash_link :
  forall prev next,
    deep_entry_links prev next = true ->
    deep_entry_hash prev = deep_entry_prev_hash next.
Proof.
  intros prev next H.
  unfold deep_entry_links in H.
  apply andb_true_iff in H.
  destruct H as [H_hash H_epoch].
  apply Nat.eqb_eq.
  exact H_hash.
Qed.

Theorem deep_entry_links_implies_epoch_advance :
  forall prev next,
    deep_entry_links prev next = true ->
    deep_entry_epoch prev < deep_entry_epoch next.
Proof.
  intros prev next H.
  unfold deep_entry_links in H.
  apply andb_true_iff in H.
  destruct H as [H_hash H_epoch].
  apply Nat.ltb_lt.
  exact H_epoch.
Qed.

Theorem well_linked_pair_implies_first_link :
  forall first second rest,
    transparency_log_well_linked (first :: second :: rest) = true ->
    deep_entry_links first second = true.
Proof.
  intros first second rest H.
  unfold transparency_log_well_linked in H.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_link H_rest].
  exact H_link.
Qed.

Theorem well_linked_pair_implies_tail_well_linked :
  forall first second rest,
    transparency_log_well_linked (first :: second :: rest) = true ->
    transparency_log_well_linked (second :: rest) = true.
Proof.
  intros first second rest H.
  unfold transparency_log_well_linked in *.
  simpl in H.
  apply andb_true_iff in H.
  destruct H as [H_link H_rest].
  exact H_rest.
Qed.

Theorem transparency_epoch_member_head :
  forall entry rest,
    transparency_epoch_member (deep_entry_epoch entry) (entry :: rest) = true.
Proof.
  intros entry rest.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem transparency_hash_member_head :
  forall entry rest,
    transparency_hash_member (deep_entry_hash entry) (entry :: rest) = true.
Proof.
  intros entry rest.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem transparency_epoch_member_tail_preserved :
  forall epoch head tail,
    transparency_epoch_member epoch tail = true ->
    transparency_epoch_member epoch (head :: tail) = true.
Proof.
  intros epoch head tail H.
  simpl.
  rewrite H.
  destruct (Nat.eqb epoch (deep_entry_epoch head)); reflexivity.
Qed.

Theorem transparency_hash_member_tail_preserved :
  forall hash head tail,
    transparency_hash_member hash tail = true ->
    transparency_hash_member hash (head :: tail) = true.
Proof.
  intros hash head tail H.
  simpl.
  rewrite H.
  destruct (Nat.eqb hash (deep_entry_hash head)); reflexivity.
Qed.

Theorem linked_log_second_epoch_greater_than_first :
  forall first second rest,
    transparency_log_well_linked (first :: second :: rest) = true ->
    deep_entry_epoch first < deep_entry_epoch second.
Proof.
  intros first second rest H.
  apply deep_entry_links_implies_epoch_advance.
  apply well_linked_pair_implies_first_link with (rest := rest).
  exact H.
Qed.

Theorem linked_log_second_prev_hash_matches_first_hash :
  forall first second rest,
    transparency_log_well_linked (first :: second :: rest) = true ->
    deep_entry_prev_hash second = deep_entry_hash first.
Proof.
  intros first second rest H.
  symmetry.
  apply deep_entry_links_implies_hash_link.
  apply well_linked_pair_implies_first_link with (rest := rest).
  exact H.
Qed.

Theorem transparency_conflict_rejected_by_hash_equality :
  forall a b,
    deep_entry_epoch a = deep_entry_epoch b ->
    deep_entry_hash a = deep_entry_hash b ->
    deep_entry_conflict a b = false.
Proof.
  intros a b H_epoch H_hash.
  apply same_hash_entries_not_conflicting.
  exact H_hash.
Qed.
