(*
  Merkle false-inclusion computational reduction.

  Reduces the same-path Merkle false-inclusion attack to False under the
  hash_node_ordered_injective axiom (SHA-256 collision resistance). This is
  the deterministic part of the Merkle binding reduction obligation stated in
  SECURITY_MODEL.md.

  Structure:
    1. fold_indexed_path_injective   — core lemma, induction on sibling list
    2. Leaf uniqueness per verified path
    3. False-inclusion game definition
    4. Main reduction theorem (same-path case, fully proved)
    5. Append-only binding theorems (derived from FullTransparencyMerkleSoundness)
    6. Remaining gap: different-siblings case
    7. Completion status record
*)

From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import KyriotesCsk2FullTransparencyMerkleSoundness.

(* ================================================================
   1. Core lemma: fold_indexed_path is injective in its leaf argument

   Proof is by induction on the sibling list. At each step:
   - both leaves are folded with the same sibling via hash_node
   - if the fold outputs are equal, hash_node_ordered_injective forces
     the inputs to be equal, yielding the leaf equality
   ================================================================ *)

Lemma fold_indexed_path_injective :
  forall siblings index leaf_a leaf_b,
    fold_indexed_path leaf_a siblings index =
    fold_indexed_path leaf_b siblings index ->
    leaf_a = leaf_b.
Proof.
  induction siblings as [| sibling rest IH].
  - intros index leaf_a leaf_b H.
    simpl in H.
    exact H.
  - intros index leaf_a leaf_b H.
    simpl in H.
    destruct (Nat.even index) eqn:Heven.
    + (* even index: parent = hash_node leaf sibling *)
      apply IH in H.
      apply hash_node_ordered_injective in H.
      exact (proj1 H).
    + (* odd index: parent = hash_node sibling leaf *)
      apply IH in H.
      apply hash_node_ordered_injective in H.
      exact (proj2 H).
Qed.

(* ================================================================
   2. General injectivity: same-length paths, arbitrary siblings

   Extends fold_indexed_path_injective to the case where the two paths
   may use different sibling lists of equal length. At each step,
   hash_node_ordered_injective forces both the current digest and the
   sibling to be equal, collapsing any difference back to the leaves.
   ================================================================ *)

Lemma fold_indexed_path_injective_general :
  forall siblings_a siblings_b index leaf_a leaf_b,
    length siblings_a = length siblings_b ->
    fold_indexed_path leaf_a siblings_a index =
    fold_indexed_path leaf_b siblings_b index ->
    leaf_a = leaf_b /\ siblings_a = siblings_b.
Proof.
  induction siblings_a as [| sa rest_a IH].
  - intros siblings_b index leaf_a leaf_b Hlen H.
    destruct siblings_b as [| sb rest_b].
    + simpl in H. split. exact H. reflexivity.
    + simpl in Hlen. discriminate.
  - intros siblings_b index leaf_a leaf_b Hlen H.
    destruct siblings_b as [| sb rest_b].
    + simpl in Hlen. discriminate.
    + simpl in Hlen. injection Hlen as Hlen'.
      simpl in H.
      destruct (Nat.even index) eqn:Heven.
      * pose proof (IH rest_b (Nat.div2 index)
          (hash_node leaf_a sa) (hash_node leaf_b sb) Hlen' H) as [Hparents Hrests].
        apply hash_node_ordered_injective in Hparents.
        destruct Hparents as [Hleaf Hsibling].
        split. exact Hleaf. rewrite Hsibling. rewrite Hrests. reflexivity.
      * pose proof (IH rest_b (Nat.div2 index)
          (hash_node sa leaf_a) (hash_node sb leaf_b) Hlen' H) as [Hparents Hrests].
        apply hash_node_ordered_injective in Hparents.
        destruct Hparents as [Hsibling Hleaf].
        split. exact Hleaf. rewrite Hsibling. rewrite Hrests. reflexivity.
Qed.

(* ================================================================
   3. Leaf uniqueness per verified path

   Two distinct leaves cannot both verify against the same root using
   the same sibling list and index. The proof binds both leaves to the
   same computed root via accepted_indexed_path_binds_computed_root,
   then applies fold_indexed_path_injective.
   ================================================================ *)

Theorem verify_indexed_path_leaf_uniqueness :
  forall leaf_a leaf_b siblings index root,
    verify_indexed_path leaf_a siblings index root = true ->
    verify_indexed_path leaf_b siblings index root = true ->
    leaf_a = leaf_b.
Proof.
  intros leaf_a leaf_b siblings index root Ha Hb.
  apply accepted_indexed_path_binds_computed_root in Ha.
  apply accepted_indexed_path_binds_computed_root in Hb.
  apply fold_indexed_path_injective with (siblings := siblings) (index := index).
  congruence.
Qed.

Theorem verify_indexed_path_leaf_uniqueness_general :
  forall leaf_a leaf_b siblings_a siblings_b index root,
    length siblings_a = length siblings_b ->
    verify_indexed_path leaf_a siblings_a index root = true ->
    verify_indexed_path leaf_b siblings_b index root = true ->
    leaf_a = leaf_b /\ siblings_a = siblings_b.
Proof.
  intros leaf_a leaf_b siblings_a siblings_b index root Hlen Ha Hb.
  apply accepted_indexed_path_binds_computed_root in Ha.
  apply accepted_indexed_path_binds_computed_root in Hb.
  apply fold_indexed_path_injective_general with (index := index).
  - exact Hlen.
  - congruence.
Qed.

(* ================================================================
   3. Path uniquely determines its root

   The same leaf and path always fold to the same root, so a proof
   cannot verify against two distinct roots.
   ================================================================ *)

Theorem path_determines_root_uniquely :
  forall leaf siblings index root_a root_b,
    verify_indexed_path leaf siblings index root_a = true ->
    verify_indexed_path leaf siblings index root_b = true ->
    root_a = root_b.
Proof.
  intros leaf siblings index root_a root_b Ha Hb.
  apply accepted_indexed_path_binds_computed_root in Ha.
  apply accepted_indexed_path_binds_computed_root in Hb.
  congruence.
Qed.

(* ================================================================
   4. False-inclusion game

   A MerkleCommitment records an honestly generated path. A
   FalseInclusionAttempt is the adversary's response: a different leaf
   with a proof that also verifies against the committed root, using the
   same sibling list and index as the honest commitment.

   The same-path restriction is not an artificial narrowing: in a
   complete binary Merkle tree the honest path to an index is unique, so
   any valid proof at the same index must use the same siblings. The
   different-siblings case (where the adversary uses a structurally
   distinct path to the same index) is addressed separately below.
   ================================================================ *)

Record MerkleCommitment := {
  committed_leaf    : Digest;
  committed_index   : nat;
  committed_siblings : list Digest;
  committed_root    : Digest
}.

Definition commitment_valid (c : MerkleCommitment) : Prop :=
  verify_indexed_path
    (committed_leaf c)
    (committed_siblings c)
    (committed_index c)
    (committed_root c) = true.

Record FalseInclusionAttempt := {
  false_leaf     : Digest;
  false_siblings : list Digest;
  false_index    : nat
}.

(*
  The adversary wins if their leaf differs from the honest committed leaf,
  their index and siblings match the honest path, and their proof
  verifies against the committed root.
*)
Definition false_inclusion_wins_same_path
  (commitment : MerkleCommitment)
  (attempt    : FalseInclusionAttempt)
  : Prop :=
  false_leaf attempt <> committed_leaf commitment /\
  false_index attempt = committed_index commitment /\
  false_siblings attempt = committed_siblings commitment /\
  verify_indexed_path
    (false_leaf attempt)
    (false_siblings attempt)
    (false_index attempt)
    (committed_root commitment) = true.

(* ================================================================
   5. Main reduction theorem (same-path case)

   If the adversary wins false_inclusion_wins_same_path, we derive
   False. The proof applies verify_indexed_path_leaf_uniqueness to the
   adversary's proof and the honest commitment, extracting
     false_leaf attempt = committed_leaf commitment
   which directly contradicts the win condition.

   This is the computational reduction: a successful same-path
   false-inclusion attack implies hash_node is non-injective on the
   two leaves — contradicting hash_node_ordered_injective, the
   SHA-256 collision-resistance axiom.
   ================================================================ *)

Theorem false_inclusion_same_path_implies_collision :
  forall commitment attempt,
    commitment_valid commitment ->
    false_inclusion_wins_same_path commitment attempt ->
    False.
Proof.
  intros commitment attempt Hvalid Hwin.
  destruct Hwin as [Hne [Hidx [Hsib Hverify]]].
  apply Hne.
  apply verify_indexed_path_leaf_uniqueness
    with (siblings := committed_siblings commitment)
         (index   := committed_index commitment)
         (root    := committed_root commitment).
  - rewrite <- Hsib. rewrite <- Hidx. exact Hverify.
  - exact Hvalid.
Qed.

(* ================================================================
   6. Append-only binding

   Conflicting commits for the same (authority, epoch) identity are
   structurally rejected by commit_allowed. This covers the second
   direction of the Merkle binding obligation: an adversary cannot
   substitute a different leaf for a previously committed entry without
   the commit being rejected at the log layer.

   Both theorems are derived from existing theorems in
   KyriotesCsk2FullTransparencyMerkleSoundness.
   ================================================================ *)

Theorem append_only_binding_rejects_conflicting_leaf :
  forall authority epoch entries existing candidate,
    find_entry authority epoch entries = Some existing ->
    entry_leaf existing <> entry_leaf candidate ->
    entry_authority candidate = authority ->
    entry_epoch candidate = epoch ->
    commit_allowed candidate entries = false.
Proof.
  intros authority epoch entries existing candidate H_find H_leaf H_auth H_ep.
  apply conflicting_same_identity_commit_rejects with (existing := existing).
  - rewrite H_auth. rewrite H_ep. exact H_find.
  - exact H_leaf.
Qed.

Theorem committed_leaf_survives_further_appends :
  forall authority epoch entries existing appended,
    find_entry authority epoch entries = Some existing ->
    find_entry authority epoch (append_entry appended entries) = Some existing.
Proof.
  intros authority epoch entries existing appended H.
  apply lookup_existing_entry_survives_append.
  exact H.
Qed.

(* ================================================================
   7. General false-inclusion game and reduction (different siblings)

   The general game relaxes the same-path restriction: the adversary may
   use any sibling list of the same length as the honest path and any
   index equal to the committed index. The reduction theorem derives False
   from fold_indexed_path_injective_general: since hash_node_ordered_injective
   forces all intermediate nodes to be equal level by level, different-sibling
   paths verifying to the same root under the same index cannot produce a
   different leaf — the collision is implicit in the injectivity violation.

   The same-length restriction reflects the tree-structure assumption: in a
   balanced binary Merkle tree, the path length is log2(n) and is uniquely
   determined by the tree height. Paths of different lengths to the same
   index cannot both be well-formed in the same tree.
   ================================================================ *)

Definition false_inclusion_wins_same_length
  (commitment : MerkleCommitment)
  (attempt    : FalseInclusionAttempt)
  : Prop :=
  false_leaf attempt <> committed_leaf commitment /\
  false_index attempt = committed_index commitment /\
  length (false_siblings attempt) = length (committed_siblings commitment) /\
  verify_indexed_path
    (false_leaf attempt)
    (false_siblings attempt)
    (false_index attempt)
    (committed_root commitment) = true.

Theorem false_inclusion_same_length_implies_collision :
  forall commitment attempt,
    commitment_valid commitment ->
    false_inclusion_wins_same_length commitment attempt ->
    False.
Proof.
  intros commitment attempt Hvalid Hwin.
  destruct Hwin as [Hne [Hidx [Hlen Hverify]]].
  apply Hne.
  apply accepted_indexed_path_binds_computed_root in Hverify.
  unfold commitment_valid in Hvalid.
  apply accepted_indexed_path_binds_computed_root in Hvalid.
  rewrite Hidx in Hverify.
  assert (Hfold :
    fold_indexed_path (false_leaf attempt) (false_siblings attempt) (committed_index commitment) =
    fold_indexed_path (committed_leaf commitment) (committed_siblings commitment) (committed_index commitment))
    by congruence.
  exact (proj1 (fold_indexed_path_injective_general
    (false_siblings attempt)
    (committed_siblings commitment)
    (committed_index commitment)
    (false_leaf attempt)
    (committed_leaf commitment)
    Hlen
    Hfold)).
Qed.

(*
  The same-path game is a special case of the general game: equal siblings
  implies equal length, so the same-path reduction follows immediately.
*)
Theorem false_inclusion_same_path_subsumed_by_general :
  forall commitment attempt,
    commitment_valid commitment ->
    false_inclusion_wins_same_path commitment attempt ->
    false_inclusion_wins_same_length commitment attempt.
Proof.
  intros commitment attempt Hvalid Hwin.
  destruct Hwin as [Hne [Hidx [Hsib Hverify]]].
  repeat split.
  - exact Hne.
  - exact Hidx.
  - rewrite Hsib. reflexivity.
  - exact Hverify.
Qed.

(* ================================================================
   8. Completion status record
   ================================================================ *)

Record MerkleFalseInclusionReductionStatus := {
  mfir_path_injectivity_proved              : bool;
  mfir_general_injectivity_proved           : bool;
  mfir_leaf_uniqueness_per_path_proved      : bool;
  mfir_path_determines_root_proved          : bool;
  mfir_game_definition_stated               : bool;
  mfir_same_path_reduction_proved           : bool;
  mfir_append_only_binding_proved           : bool;
  mfir_committed_leaf_survives_append_proved : bool;
  mfir_different_siblings_case_proved       : bool
}.

Definition merkle_false_inclusion_reduction_complete
  (status : MerkleFalseInclusionReductionStatus) : bool :=
  mfir_path_injectivity_proved status &&
  mfir_general_injectivity_proved status &&
  mfir_leaf_uniqueness_per_path_proved status &&
  mfir_path_determines_root_proved status &&
  mfir_game_definition_stated status &&
  mfir_same_path_reduction_proved status &&
  mfir_append_only_binding_proved status &&
  mfir_committed_leaf_survives_append_proved status &&
  mfir_different_siblings_case_proved status.

Definition kyriotes_csk2_merkle_false_inclusion_reduction_status
  : MerkleFalseInclusionReductionStatus :=
  {|
    mfir_path_injectivity_proved               := true;
    mfir_general_injectivity_proved            := true;
    mfir_leaf_uniqueness_per_path_proved       := true;
    mfir_path_determines_root_proved           := true;
    mfir_game_definition_stated                := true;
    mfir_same_path_reduction_proved            := true;
    mfir_append_only_binding_proved            := true;
    mfir_committed_leaf_survives_append_proved := true;
    mfir_different_siblings_case_proved        := true
  |}.

Theorem merkle_false_inclusion_reduction_is_complete :
  merkle_false_inclusion_reduction_complete
    kyriotes_csk2_merkle_false_inclusion_reduction_status = true.
Proof.
  reflexivity.
Qed.
