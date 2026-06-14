From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle.

Parameter verify_epoch_signature : AuthorityState -> bool.
Parameter verify_transparency_commit : AuthorityState -> bool.

(*
  Structural: a verifiable epoch signature requires a non-zero public key.
  This is a basic well-formedness property of the epoch state.
*)
Axiom epoch_key_is_nonzero :
  forall state,
    verify_epoch_signature state = true ->
    epoch_public_key state <> 0.

(*
  Binding: the same epoch key cannot validly sign two different authority
  roots at the same epoch number. Producing such a pair requires breaking
  the signature scheme's existential unforgeability under chosen-message
  attack (EUF-CMA). This is the ML-DSA / ML-KEM epoch-binding property.
*)
Axiom epoch_signature_unforgeable :
  forall state_a state_b,
    verify_epoch_signature state_a = true ->
    verify_epoch_signature state_b = true ->
    epoch_public_key state_a = epoch_public_key state_b ->
    epoch state_a = epoch state_b ->
    authority_root state_a = authority_root state_b.

(*
  Binding: the transparency commitment is unique per epoch key.
  The same epoch key signs at most one transparency root — producing two
  valid commits with the same key but different roots requires breaking the
  signature scheme's binding (EUF-CMA), since the transparency root is
  included in the signed epoch message.
*)
Axiom transparency_commit_binding :
  forall state_a state_b,
    verify_transparency_commit state_a = true ->
    verify_transparency_commit state_b = true ->
    epoch_public_key state_a = epoch_public_key state_b ->
    transparency_root state_a = transparency_root state_b.

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
  apply epoch_key_is_nonzero.
  apply authority_state_valid_implies_epoch_signature.
  exact H.
Qed.
