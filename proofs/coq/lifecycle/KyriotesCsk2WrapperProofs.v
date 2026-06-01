From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy KyriotesCsk2Verify KyriotesCsk2SecurityGame KyriotesCsk2Theorems KyriotesCsk2StressProofs KyriotesCsk2DelegationProofs KyriotesCsk2CryptoReduction KyriotesCsk2TemporalProofs KyriotesCsk2TranscriptProofs KyriotesCsk2RevocationCompromiseProofs KyriotesCsk2TransparencyProofs KyriotesCsk2EncodingProofs.

Record AuthorityWrapper := {
  wrapper_epoch : Epoch;
  wrapper_authority_root : Hash;
  wrapper_revocation_root : Hash;
  wrapper_transparency_root : Hash;
  wrapper_context_hash : Hash;
  wrapper_recipient_key_hash : Hash
}.

Definition wrapper_matches_object
  (wrapper : AuthorityWrapper)
  (obj : KyriotesCsk2Object)
  : bool :=
  Nat.eqb (wrapper_epoch wrapper) (bound_epoch obj) &&
  Nat.eqb (wrapper_authority_root wrapper) (bound_authority_root obj) &&
  Nat.eqb (wrapper_revocation_root wrapper) (bound_revocation_root obj) &&
  Nat.eqb (wrapper_transparency_root wrapper) (bound_transparency_root obj) &&
  Nat.eqb (wrapper_context_hash wrapper) (aad_context_hash obj).

Definition wrapper_matches_state
  (wrapper : AuthorityWrapper)
  (state : AuthorityState)
  : bool :=
  Nat.eqb (wrapper_epoch wrapper) (epoch state) &&
  Nat.eqb (wrapper_authority_root wrapper) (authority_root state) &&
  Nat.eqb (wrapper_revocation_root wrapper) (revocation_root state) &&
  Nat.eqb (wrapper_transparency_root wrapper) (transparency_root state).

Definition wrapper_open_allowed
  (obj : KyriotesCsk2Object)
  (cap : Capability)
  (state : AuthorityState)
  (wrapper : AuthorityWrapper)
  : bool :=
  verify_open_context obj cap state &&
  wrapper_matches_object wrapper obj &&
  wrapper_matches_state wrapper state.

Definition wrapper_in_list
  (target_epoch : Epoch)
  (wrappers : list AuthorityWrapper)
  : bool :=
  existsb (fun wrapper => Nat.eqb (wrapper_epoch wrapper) target_epoch) wrappers.

Definition wrapper_set_open_allowed
  (target_epoch : Epoch)
  (obj : KyriotesCsk2Object)
  (cap : Capability)
  (state : AuthorityState)
  (wrappers : list AuthorityWrapper)
  : bool :=
  verify_open_context obj cap state &&
  wrapper_in_list target_epoch wrappers &&
  Nat.eqb target_epoch (bound_epoch obj).

Theorem wrapper_matches_object_implies_exact_object_fields :
  forall wrapper obj,
    wrapper_matches_object wrapper obj = true ->
    wrapper_epoch wrapper = bound_epoch obj /\
    wrapper_authority_root wrapper = bound_authority_root obj /\
    wrapper_revocation_root wrapper = bound_revocation_root obj /\
    wrapper_transparency_root wrapper = bound_transparency_root obj /\
    wrapper_context_hash wrapper = aad_context_hash obj.
Proof.
  intros wrapper obj H.
  unfold wrapper_matches_object in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_epoch H_auth] H_rev] H_trans] H_ctx].
  repeat split; apply Nat.eqb_eq; assumption.
Qed.

Theorem wrapper_matches_state_implies_exact_state_fields :
  forall wrapper state,
    wrapper_matches_state wrapper state = true ->
    wrapper_epoch wrapper = epoch state /\
    wrapper_authority_root wrapper = authority_root state /\
    wrapper_revocation_root wrapper = revocation_root state /\
    wrapper_transparency_root wrapper = transparency_root state.
Proof.
  intros wrapper state H.
  unfold wrapper_matches_state in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_epoch H_auth] H_rev] H_trans].
  repeat split; apply Nat.eqb_eq; assumption.
Qed.

Theorem wrapper_epoch_object_mismatch_rejected :
  forall wrapper obj,
    wrapper_epoch wrapper <> bound_epoch obj ->
    wrapper_matches_object wrapper obj = false.
Proof.
  intros wrapper obj H.
  unfold wrapper_matches_object.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem wrapper_authority_object_mismatch_rejected :
  forall wrapper obj,
    wrapper_authority_root wrapper <> bound_authority_root obj ->
    wrapper_matches_object wrapper obj = false.
Proof.
  intros wrapper obj H.
  unfold wrapper_matches_object.
  destruct (Nat.eqb (wrapper_epoch wrapper) (bound_epoch obj)); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_revocation_object_mismatch_rejected :
  forall wrapper obj,
    wrapper_revocation_root wrapper <> bound_revocation_root obj ->
    wrapper_matches_object wrapper obj = false.
Proof.
  intros wrapper obj H.
  unfold wrapper_matches_object.
  destruct (Nat.eqb (wrapper_epoch wrapper) (bound_epoch obj)); simpl.
  - destruct (Nat.eqb (wrapper_authority_root wrapper) (bound_authority_root obj)); simpl.
    + apply Nat.eqb_neq in H.
      rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_transparency_object_mismatch_rejected :
  forall wrapper obj,
    wrapper_transparency_root wrapper <> bound_transparency_root obj ->
    wrapper_matches_object wrapper obj = false.
Proof.
  intros wrapper obj H.
  unfold wrapper_matches_object.
  destruct (Nat.eqb (wrapper_epoch wrapper) (bound_epoch obj)); simpl.
  - destruct (Nat.eqb (wrapper_authority_root wrapper) (bound_authority_root obj)); simpl.
    + destruct (Nat.eqb (wrapper_revocation_root wrapper) (bound_revocation_root obj)); simpl.
      * apply Nat.eqb_neq in H.
        rewrite H.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_context_object_mismatch_rejected :
  forall wrapper obj,
    wrapper_context_hash wrapper <> aad_context_hash obj ->
    wrapper_matches_object wrapper obj = false.
Proof.
  intros wrapper obj H.
  unfold wrapper_matches_object.
  destruct (Nat.eqb (wrapper_epoch wrapper) (bound_epoch obj)); simpl.
  - destruct (Nat.eqb (wrapper_authority_root wrapper) (bound_authority_root obj)); simpl.
    + destruct (Nat.eqb (wrapper_revocation_root wrapper) (bound_revocation_root obj)); simpl.
      * destruct (Nat.eqb (wrapper_transparency_root wrapper) (bound_transparency_root obj)); simpl.
        -- apply Nat.eqb_neq in H.
           rewrite H.
           reflexivity.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_object_mismatch_blocks_open :
  forall obj cap state wrapper,
    wrapper_matches_object wrapper obj = false ->
    wrapper_open_allowed obj cap state wrapper = false.
Proof.
  intros obj cap state wrapper H.
  unfold wrapper_open_allowed.
  destruct (verify_open_context obj cap state); simpl.
  - rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_state_mismatch_blocks_open :
  forall obj cap state wrapper,
    wrapper_matches_state wrapper state = false ->
    wrapper_open_allowed obj cap state wrapper = false.
Proof.
  intros obj cap state wrapper H.
  unfold wrapper_open_allowed.
  destruct (verify_open_context obj cap state); simpl.
  - destruct (wrapper_matches_object wrapper obj); simpl.
    + rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_open_implies_verified_open :
  forall obj cap state wrapper,
    wrapper_open_allowed obj cap state wrapper = true ->
    verify_open_context obj cap state = true.
Proof.
  intros obj cap state wrapper H.
  unfold wrapper_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_open H_obj] H_state].
  exact H_open.
Qed.

Theorem wrapper_open_implies_exact_epoch_binding :
  forall obj cap state wrapper,
    wrapper_open_allowed obj cap state wrapper = true ->
    wrapper_epoch wrapper = bound_epoch obj /\
    wrapper_epoch wrapper = epoch state.
Proof.
  intros obj cap state wrapper H.
  unfold wrapper_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_open H_obj] H_state].
  pose proof (wrapper_matches_object_implies_exact_object_fields wrapper obj H_obj) as [H_obj_epoch _].
  pose proof (wrapper_matches_state_implies_exact_state_fields wrapper state H_state) as [H_state_epoch _].
  split; assumption.
Qed.

Theorem missing_wrapper_blocks_wrapper_set_open :
  forall target_epoch obj cap state wrappers,
    wrapper_in_list target_epoch wrappers = false ->
    wrapper_set_open_allowed target_epoch obj cap state wrappers = false.
Proof.
  intros target_epoch obj cap state wrappers H.
  unfold wrapper_set_open_allowed.
  destruct (verify_open_context obj cap state); simpl.
  - rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_target_epoch_mismatch_blocks_wrapper_set_open :
  forall target_epoch obj cap state wrappers,
    target_epoch <> bound_epoch obj ->
    wrapper_set_open_allowed target_epoch obj cap state wrappers = false.
Proof.
  intros target_epoch obj cap state wrappers H.
  unfold wrapper_set_open_allowed.
  destruct (verify_open_context obj cap state); simpl.
  - destruct (wrapper_in_list target_epoch wrappers); simpl.
    + apply Nat.eqb_neq in H.
      rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem wrapper_in_list_cons_self :
  forall wrapper wrappers,
    wrapper_in_list (wrapper_epoch wrapper) (wrapper :: wrappers) = true.
Proof.
  intros wrapper wrappers.
  unfold wrapper_in_list.
  simpl.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem adding_wrapper_preserves_target_presence :
  forall target_epoch wrapper wrappers,
    wrapper_in_list target_epoch wrappers = true ->
    wrapper_in_list target_epoch (wrapper :: wrappers) = true.
Proof.
  intros target_epoch wrapper wrappers H.
  unfold wrapper_in_list in *.
  simpl.
  rewrite H.
  destruct (Nat.eqb (wrapper_epoch wrapper) target_epoch); reflexivity.
Qed.
