From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Merkle.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ConcreteMerkleProofs.

Inductive ConcreteMerkleTree :=
| ConcreteEmpty
| ConcreteLeaf (leaf_hash : Hash)
| ConcreteNode (node_hash : Hash) (left_tree : ConcreteMerkleTree) (right_tree : ConcreteMerkleTree).

Inductive MerkleDirection :=
| MerkleLeft
| MerkleRight.

Record ConcreteMerkleSibling := {
  sibling_direction : MerkleDirection;
  sibling_hash : Hash
}.

Definition hash_leaf_concrete (leaf : Hash) : Hash :=
  S leaf.

Definition hash_node_concrete (left_hash right_hash : Hash) : Hash :=
  S (left_hash + right_hash).

Definition concrete_tree_root (tree : ConcreteMerkleTree) : Hash :=
  match tree with
  | ConcreteEmpty => 0
  | ConcreteLeaf leaf => hash_leaf_concrete leaf
  | ConcreteNode node_hash _ _ => node_hash
  end.

Fixpoint concrete_tree_member (leaf : Hash) (tree : ConcreteMerkleTree) : bool :=
  match tree with
  | ConcreteEmpty => false
  | ConcreteLeaf candidate => Nat.eqb leaf candidate
  | ConcreteNode _ left_tree right_tree =>
      concrete_tree_member leaf left_tree || concrete_tree_member leaf right_tree
  end.

Fixpoint concrete_tree_well_formed (tree : ConcreteMerkleTree) : bool :=
  match tree with
  | ConcreteEmpty => true
  | ConcreteLeaf _ => true
  | ConcreteNode node_hash left_tree right_tree =>
      Nat.eqb node_hash (hash_node_concrete (concrete_tree_root left_tree) (concrete_tree_root right_tree)) &&
      concrete_tree_well_formed left_tree &&
      concrete_tree_well_formed right_tree
  end.

Definition apply_merkle_sibling (current_hash : Hash) (sibling : ConcreteMerkleSibling) : Hash :=
  match sibling_direction sibling with
  | MerkleLeft => hash_node_concrete (sibling_hash sibling) current_hash
  | MerkleRight => hash_node_concrete current_hash (sibling_hash sibling)
  end.

Fixpoint verify_merkle_path_from (current_hash : Hash) (path : list ConcreteMerkleSibling) : Hash :=
  match path with
  | [] => current_hash
  | sibling :: rest => verify_merkle_path_from (apply_merkle_sibling current_hash sibling) rest
  end.

Definition verify_merkle_path (leaf root : Hash) (path : list ConcreteMerkleSibling) : bool :=
  Nat.eqb (verify_merkle_path_from (hash_leaf_concrete leaf) path) root.

Definition sibling_order_preserved (a b : ConcreteMerkleSibling) : bool :=
  match sibling_direction a, sibling_direction b with
  | MerkleLeft, MerkleLeft => Nat.eqb (sibling_hash a) (sibling_hash b)
  | MerkleRight, MerkleRight => Nat.eqb (sibling_hash a) (sibling_hash b)
  | _, _ => false
  end.

Theorem concrete_leaf_member_self :
  forall leaf,
    concrete_tree_member leaf (ConcreteLeaf leaf) = true.
Proof.
  intros leaf.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem concrete_leaf_rejects_other :
  forall leaf other,
    leaf <> other ->
    concrete_tree_member leaf (ConcreteLeaf other) = false.
Proof.
  intros leaf other H.
  simpl.
  apply Nat.eqb_neq.
  exact H.
Qed.

Theorem concrete_node_member_left :
  forall leaf node_hash left right,
    concrete_tree_member leaf left = true ->
    concrete_tree_member leaf (ConcreteNode node_hash left right) = true.
Proof.
  intros leaf node_hash left right H.
  simpl.
  rewrite H.
  reflexivity.
Qed.

Theorem concrete_node_member_right :
  forall leaf node_hash left right,
    concrete_tree_member leaf right = true ->
    concrete_tree_member leaf (ConcreteNode node_hash left right) = true.
Proof.
  intros leaf node_hash left right H.
  simpl.
  rewrite H.
  destruct (concrete_tree_member leaf left); reflexivity.
Qed.

Theorem concrete_well_formed_node_root :
  forall node_hash left right,
    concrete_tree_well_formed (ConcreteNode node_hash left right) = true ->
    node_hash = hash_node_concrete (concrete_tree_root left) (concrete_tree_root right).
Proof.
  intros node_hash left right H.
  simpl in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_root H_left] H_right].
  apply Nat.eqb_eq.
  exact H_root.
Qed.

Theorem concrete_well_formed_node_left :
  forall node_hash left right,
    concrete_tree_well_formed (ConcreteNode node_hash left right) = true ->
    concrete_tree_well_formed left = true.
Proof.
  intros node_hash left right H.
  simpl in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_root H_left] H_right].
  exact H_left.
Qed.

Theorem concrete_well_formed_node_right :
  forall node_hash left right,
    concrete_tree_well_formed (ConcreteNode node_hash left right) = true ->
    concrete_tree_well_formed right = true.
Proof.
  intros node_hash left right H.
  simpl in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_root H_left] H_right].
  exact H_right.
Qed.

Theorem empty_tree_has_no_members :
  forall leaf,
    concrete_tree_member leaf ConcreteEmpty = false.
Proof.
  intros leaf.
  reflexivity.
Qed.

Theorem empty_path_verifies_exact_leaf_root :
  forall leaf,
    verify_merkle_path leaf (hash_leaf_concrete leaf) [] = true.
Proof.
  intros leaf.
  unfold verify_merkle_path.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem empty_path_rejects_wrong_root :
  forall leaf wrong_root,
    wrong_root <> hash_leaf_concrete leaf ->
    verify_merkle_path leaf wrong_root [] = false.
Proof.
  intros leaf wrong_root H.
  unfold verify_merkle_path.
  simpl.
  destruct wrong_root as [| wrong_pred].
  - reflexivity.
  - simpl.
    apply Nat.eqb_neq.
    intro Contra.
    apply H.
    unfold hash_leaf_concrete.
    rewrite Contra.
    reflexivity.
Qed.

Theorem verified_empty_path_root_equals_leaf_hash :
  forall leaf root,
    verify_merkle_path leaf root [] = true ->
    root = hash_leaf_concrete leaf.
Proof.
  intros leaf root H.
  unfold verify_merkle_path in H.
  simpl in H.
  destruct root as [| root_pred].
  - discriminate.
  - simpl in H.
    apply Nat.eqb_eq in H.
    unfold hash_leaf_concrete.
    rewrite H.
    reflexivity.
Qed.

Theorem one_right_sibling_path_computes_expected_root :
  forall leaf sibling,
    verify_merkle_path
      leaf
      (hash_node_concrete (hash_leaf_concrete leaf) sibling)
      [{| sibling_direction := MerkleRight; sibling_hash := sibling |}] = true.
Proof.
  intros leaf sibling.
  unfold verify_merkle_path.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem one_left_sibling_path_computes_expected_root :
  forall leaf sibling,
    verify_merkle_path
      leaf
      (hash_node_concrete sibling (hash_leaf_concrete leaf))
      [{| sibling_direction := MerkleLeft; sibling_hash := sibling |}] = true.
Proof.
  intros leaf sibling.
  unfold verify_merkle_path.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem sibling_order_preserved_implies_same_direction_left :
  forall a b,
    sibling_order_preserved a b = true ->
    sibling_direction a = MerkleLeft ->
    sibling_direction b = MerkleLeft.
Proof.
  intros a b H Hdir.
  unfold sibling_order_preserved in H.
  destruct a as [adir ahash].
  destruct b as [bdir bhash].
  simpl in *.
  destruct adir; destruct bdir; try discriminate; reflexivity.
Qed.

Theorem sibling_order_preserved_implies_same_direction_right :
  forall a b,
    sibling_order_preserved a b = true ->
    sibling_direction a = MerkleRight ->
    sibling_direction b = MerkleRight.
Proof.
  intros a b H Hdir.
  unfold sibling_order_preserved in H.
  destruct a as [adir ahash].
  destruct b as [bdir bhash].
  simpl in *.
  destruct adir; destruct bdir; try discriminate; reflexivity.
Qed.

Theorem sibling_order_preserved_implies_same_hash :
  forall a b,
    sibling_order_preserved a b = true ->
    sibling_hash a = sibling_hash b.
Proof.
  intros a b H.
  unfold sibling_order_preserved in H.
  destruct a as [adir ahash].
  destruct b as [bdir bhash].
  simpl in *.
  destruct adir; destruct bdir; try discriminate;
  apply Nat.eqb_eq;
  exact H.
Qed.
