From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

Require Import ArcTypes.
Require Import ArcSecurityGame.
Require Import ArcTightSecurityGameProofs.
Require Import ArcAssumptionReductionProofs.
Require Import ArcMasterInvariantProofs.

Record ArcAdversaryObservation := {
  adversary_has_key_material : bool;
  adversary_has_capability : bool;
  adversary_has_nonrevocation : bool;
  adversary_has_valid_transcript : bool;
  adversary_has_valid_wrapper : bool;
  adversary_has_valid_transparency : bool;
  adversary_breaks_aead : bool;
  adversary_breaks_kem : bool;
  adversary_breaks_hkdf : bool;
  adversary_breaks_signature : bool;
  adversary_breaks_hash_binding : bool
}.

Definition adversary_breaks_any_primitive
  (obs : ArcAdversaryObservation)
  : bool :=
  adversary_breaks_aead obs ||
  adversary_breaks_kem obs ||
  adversary_breaks_hkdf obs ||
  adversary_breaks_signature obs ||
  adversary_breaks_hash_binding obs.

Definition adversary_has_all_authorization_gates
  (obs : ArcAdversaryObservation)
  : bool :=
  adversary_has_key_material obs &&
  adversary_has_capability obs &&
  adversary_has_nonrevocation obs &&
  adversary_has_valid_transcript obs &&
  adversary_has_valid_wrapper obs &&
  adversary_has_valid_transparency obs.

Definition adversary_win_permitted
  (obs : ArcAdversaryObservation)
  : bool :=
  adversary_has_all_authorization_gates obs ||
  adversary_breaks_any_primitive obs.

Definition adversary_win_without_authorization
  (obs : ArcAdversaryObservation)
  : bool :=
  negb (adversary_has_all_authorization_gates obs) &&
  adversary_win_permitted obs.

Definition adversary_advantage_score
  (obs : ArcAdversaryObservation)
  : nat :=
  (if adversary_breaks_aead obs then 1 else 0) +
  (if adversary_breaks_kem obs then 1 else 0) +
  (if adversary_breaks_hkdf obs then 1 else 0) +
  (if adversary_breaks_signature obs then 1 else 0) +
  (if adversary_breaks_hash_binding obs then 1 else 0).

Theorem adversary_all_gates_implies_win_permitted :
  forall obs,
    adversary_has_all_authorization_gates obs = true ->
    adversary_win_permitted obs = true.
Proof.
  intros obs H.
  unfold adversary_win_permitted.
  rewrite H.
  reflexivity.
Qed.

Theorem adversary_primitive_break_implies_win_permitted :
  forall obs,
    adversary_breaks_any_primitive obs = true ->
    adversary_win_permitted obs = true.
Proof.
  intros obs H.
  unfold adversary_win_permitted.
  rewrite H.
  destruct (adversary_has_all_authorization_gates obs); reflexivity.
Qed.

Theorem adversary_win_without_authorization_implies_primitive_break :
  forall obs,
    adversary_win_without_authorization obs = true ->
    adversary_breaks_any_primitive obs = true.
Proof.
  intros obs H.
  unfold adversary_win_without_authorization in H.
  apply andb_true_iff in H.
  destruct H as [H_no_auth H_win].
  unfold adversary_win_permitted in H_win.
  destruct (adversary_has_all_authorization_gates obs) eqn:H_auth.
  - simpl in H_no_auth. discriminate.
  - simpl in H_win. exact H_win.
Qed.

Theorem zero_advantage_score_implies_no_primitive_break :
  forall obs,
    adversary_advantage_score obs = 0 ->
    adversary_breaks_any_primitive obs = false.
Proof.
  intros obs H.
  unfold adversary_advantage_score in H.
  unfold adversary_breaks_any_primitive.

  destruct (adversary_breaks_aead obs) eqn:H_aead.
  - simpl in H. lia.
  - simpl in H.
    destruct (adversary_breaks_kem obs) eqn:H_kem.
    + simpl in H. lia.
    + simpl in H.
      destruct (adversary_breaks_hkdf obs) eqn:H_hkdf.
      * simpl in H. lia.
      * simpl in H.
        destruct (adversary_breaks_signature obs) eqn:H_sig.
        -- simpl in H. lia.
        -- simpl in H.
           destruct (adversary_breaks_hash_binding obs) eqn:H_hash.
           ++ simpl in H. lia.
           ++ reflexivity.
Qed.

Theorem no_auth_and_zero_advantage_blocks_win :
  forall obs,
    adversary_has_all_authorization_gates obs = false ->
    adversary_advantage_score obs = 0 ->
    adversary_win_permitted obs = false.
Proof.
  intros obs H_auth H_score.
  unfold adversary_win_permitted.
  rewrite H_auth.
  simpl.
  apply zero_advantage_score_implies_no_primitive_break.
  exact H_score.
Qed.

Theorem permitted_win_implies_authorized_or_advantage_positive :
  forall obs,
    adversary_win_permitted obs = true ->
    adversary_has_all_authorization_gates obs = true \/
    adversary_advantage_score obs > 0.
Proof.
  intros obs H.
  unfold adversary_win_permitted in H.
  destruct (adversary_has_all_authorization_gates obs) eqn:H_auth.
  - left.
    reflexivity.
  - right.
    simpl in H.
    unfold adversary_breaks_any_primitive in H.
    unfold adversary_advantage_score.

    destruct (adversary_breaks_aead obs) eqn:H_aead.
    + simpl. lia.
    + simpl in H. simpl.
      destruct (adversary_breaks_kem obs) eqn:H_kem.
      * simpl. lia.
      * simpl in H. simpl.
        destruct (adversary_breaks_hkdf obs) eqn:H_hkdf.
        -- simpl. lia.
        -- simpl in H. simpl.
           destruct (adversary_breaks_signature obs) eqn:H_sig.
           ++ simpl. lia.
           ++ simpl in H. simpl.
              destruct (adversary_breaks_hash_binding obs) eqn:H_hash.
              ** simpl. lia.
              ** discriminate.
Qed.
