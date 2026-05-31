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

Fixpoint merkle_leaf_member (leaf : Hash) (leaves : list Hash) : bool :=
  match leaves with
  | [] => false
  | head :: tail => Nat.eqb leaf head || merkle_leaf_member leaf tail
  end.

Fixpoint merkle_leaf_count (leaf : Hash) (leaves : list Hash) : nat :=
  match leaves with
  | [] => 0
  | head :: tail =>
      if Nat.eqb leaf head
      then S (merkle_leaf_count leaf tail)
      else merkle_leaf_count leaf tail
  end.

Definition concrete_merkle_root (leaves : list Hash) : Hash :=
  fold_left Nat.add leaves 0.

Definition concrete_merkle_insert (leaf : Hash) (leaves : list Hash) : list Hash :=
  if merkle_leaf_member leaf leaves then leaves else leaf :: leaves.

Definition concrete_merkle_revoke (stamp : nat) (revoked : list nat) : list nat :=
  if existsb (Nat.eqb stamp) revoked then revoked else stamp :: revoked.

Definition concrete_merkle_nonrevoked (stamp : nat) (revoked : list nat) : bool :=
  negb (existsb (Nat.eqb stamp) revoked).

Theorem merkle_member_head :
  forall leaf tail,
    merkle_leaf_member leaf (leaf :: tail) = true.
Proof.
  intros leaf tail.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem merkle_member_tail_preserved :
  forall leaf head tail,
    merkle_leaf_member leaf tail = true ->
    merkle_leaf_member leaf (head :: tail) = true.
Proof.
  intros leaf head tail H.
  simpl.
  rewrite H.
  destruct (Nat.eqb leaf head); reflexivity.
Qed.

Theorem merkle_member_insert_present :
  forall leaf leaves,
    merkle_leaf_member leaf (concrete_merkle_insert leaf leaves) = true.
Proof.
  intros leaf leaves.
  unfold concrete_merkle_insert.
  destruct (merkle_leaf_member leaf leaves) eqn:H_member.
  - exact H_member.
  - apply merkle_member_head.
Qed.

Theorem merkle_insert_preserves_existing_member :
  forall leaf other leaves,
    merkle_leaf_member other leaves = true ->
    merkle_leaf_member other (concrete_merkle_insert leaf leaves) = true.
Proof.
  intros leaf other leaves H.
  unfold concrete_merkle_insert.
  destruct (merkle_leaf_member leaf leaves) eqn:H_leaf.
  - exact H.
  - apply merkle_member_tail_preserved.
    exact H.
Qed.

Theorem merkle_insert_idempotent_when_present :
  forall leaf leaves,
    merkle_leaf_member leaf leaves = true ->
    concrete_merkle_insert leaf leaves = leaves.
Proof.
  intros leaf leaves H.
  unfold concrete_merkle_insert.
  rewrite H.
  reflexivity.
Qed.

Theorem merkle_insert_adds_when_absent :
  forall leaf leaves,
    merkle_leaf_member leaf leaves = false ->
    concrete_merkle_insert leaf leaves = leaf :: leaves.
Proof.
  intros leaf leaves H.
  unfold concrete_merkle_insert.
  rewrite H.
  reflexivity.
Qed.

Theorem merkle_count_zero_implies_not_member :
  forall leaf leaves,
    merkle_leaf_count leaf leaves = 0 ->
    merkle_leaf_member leaf leaves = false.
Proof.
  induction leaves as [| head tail IH]; intros H.
  - reflexivity.
  - simpl in H.
    simpl.
    destruct (Nat.eqb leaf head) eqn:H_eq.
    + discriminate.
    + apply IH in H.
      exact H.
Qed.

Theorem merkle_member_implies_positive_count :
  forall leaf leaves,
    merkle_leaf_member leaf leaves = true ->
    merkle_leaf_count leaf leaves > 0.
Proof.
  induction leaves as [| head tail IH]; intros H.
  - discriminate.
  - simpl in H.
    simpl.
    destruct (Nat.eqb leaf head) eqn:H_eq.
    + lia.
    + apply IH in H.
      lia.
Qed.

Theorem concrete_revocation_after_revoke_blocks_nonrevocation :
  forall stamp revoked,
    concrete_merkle_nonrevoked stamp (concrete_merkle_revoke stamp revoked) = false.
Proof.
  intros stamp revoked.
  unfold concrete_merkle_nonrevoked.
  unfold concrete_merkle_revoke.
  destruct (existsb (Nat.eqb stamp) revoked) eqn:H_exists.
  - simpl.
    rewrite H_exists.
    reflexivity.
  - simpl.
    rewrite Nat.eqb_refl.
    reflexivity.
Qed.

Theorem concrete_revocation_preserves_old_revocations :
  forall stamp old revoked,
    existsb (Nat.eqb old) revoked = true ->
    existsb (Nat.eqb old) (concrete_merkle_revoke stamp revoked) = true.
Proof.
  intros stamp old revoked H.
  unfold concrete_merkle_revoke.
  destruct (existsb (Nat.eqb stamp) revoked) eqn:H_stamp.
  - exact H.
  - simpl.
    rewrite H.
    destruct (Nat.eqb old stamp); reflexivity.
Qed.

Theorem concrete_nonrevocation_false_iff_present_direction :
  forall stamp revoked,
    concrete_merkle_nonrevoked stamp revoked = false ->
    existsb (Nat.eqb stamp) revoked = true.
Proof.
  intros stamp revoked H.
  unfold concrete_merkle_nonrevoked in H.
  apply negb_false_iff in H.
  exact H.
Qed.

Theorem concrete_nonrevocation_true_iff_absent_direction :
  forall stamp revoked,
    concrete_merkle_nonrevoked stamp revoked = true ->
    existsb (Nat.eqb stamp) revoked = false.
Proof.
  intros stamp revoked H.
  unfold concrete_merkle_nonrevoked in H.
  apply negb_true_iff in H.
  exact H.
Qed.

Theorem concrete_root_insert_changes_or_leaf_zero :
  forall leaf leaves,
    merkle_leaf_member leaf leaves = false ->
    concrete_merkle_root (concrete_merkle_insert leaf leaves) =
    fold_left Nat.add leaves leaf.
Proof.
  intros leaf leaves H.
  unfold concrete_merkle_insert.
  rewrite H.
  unfold concrete_merkle_root.
  simpl.
  reflexivity.
Qed.
