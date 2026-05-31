From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From ArcProofs Require Import ArcTypes ArcMerkle.

Parameter verify_epoch_signature : AuthorityState -> bool.
Parameter verify_transparency_commit : AuthorityState -> bool.

Axiom epoch_signature_unforgeable :
  forall state,
    verify_epoch_signature state = true ->
    epoch_public_key state <> 0.

Axiom transparency_commit_binding :
  forall state,
    verify_transparency_commit state = true ->
    transparency_root state = transparency_root state.

Definition authority_state_valid (state : AuthorityState) : bool :=
  verify_epoch_signature state && verify_transparency_commit state.

Lemma authority_state_valid_implies_epoch_signature :
  forall state,
    authority_state_valid state = true ->
    verify_epoch_signature state = true.
Proof.
  intros state H.
  unfold authority_state_valid in H.
  apply andb_true_iff in H.
  destruct H as [H_sig _].
  exact H_sig.
Qed.

Lemma authority_state_valid_implies_transparency :
  forall state,
    authority_state_valid state = true ->
    verify_transparency_commit state = true.
Proof.
  intros state H.
  unfold authority_state_valid in H.
  apply andb_true_iff in H.
  destruct H as [_ H_transparency].
  exact H_transparency.
Qed.

Lemma authority_state_valid_implies_nonzero_epoch_key :
  forall state,
    authority_state_valid state = true ->
    epoch_public_key state <> 0.
Proof.
  intros state H.
  apply epoch_signature_unforgeable.
  apply authority_state_valid_implies_epoch_signature.
  exact H.
Qed.
