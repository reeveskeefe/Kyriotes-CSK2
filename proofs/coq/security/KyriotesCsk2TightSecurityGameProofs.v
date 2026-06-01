From Coq Require Import List Bool Arith.PeanoNat Lia.
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
From KyriotesCsk2Proofs Require Import KyriotesCsk2TransparencyConsistencyProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ProtocolStateMachineProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2InvalidTransitionProofs.

Record TightSecurityAttempt := {
  tight_has_key_material : bool;
  tight_has_valid_capability : bool;
  tight_has_nonrevocation : bool;
  tight_has_valid_authority_state : bool;
  tight_has_valid_transcript : bool;
  tight_has_valid_wrapper : bool;
  tight_has_valid_transparency : bool;
  tight_primitive_assumptions_hold : bool
}.

Definition tight_authorized_attempt (attempt : TightSecurityAttempt) : bool :=
  tight_has_key_material attempt &&
  tight_has_valid_capability attempt &&
  tight_has_nonrevocation attempt &&
  tight_has_valid_authority_state attempt &&
  tight_has_valid_transcript attempt &&
  tight_has_valid_wrapper attempt &&
  tight_has_valid_transparency attempt &&
  tight_primitive_assumptions_hold attempt.

Definition tight_unauthorized_success (attempt : TightSecurityAttempt) : bool :=
  negb (tight_authorized_attempt attempt).

Definition tight_missing_authorization_gate (attempt : TightSecurityAttempt) : bool :=
  negb (tight_has_key_material attempt) ||
  negb (tight_has_valid_capability attempt) ||
  negb (tight_has_nonrevocation attempt) ||
  negb (tight_has_valid_authority_state attempt) ||
  negb (tight_has_valid_transcript attempt) ||
  negb (tight_has_valid_wrapper attempt) ||
  negb (tight_has_valid_transparency attempt) ||
  negb (tight_primitive_assumptions_hold attempt).

Theorem tight_authorized_attempt_implies_key_material :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_has_key_material attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_key _] _] _] _] _] _] _].
  exact H_key.
Qed.

Theorem tight_authorized_attempt_implies_valid_capability :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_has_valid_capability attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[_ H_cap] _] _] _] _] _] _].
  exact H_cap.
Qed.

Theorem tight_authorized_attempt_implies_nonrevocation :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_has_nonrevocation attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[_ _] H_nonrev] _] _] _] _] _].
  exact H_nonrev.
Qed.

Theorem tight_authorized_attempt_implies_authority_state :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_has_valid_authority_state attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[_ _] _] H_auth] _] _] _] _].
  exact H_auth.
Qed.

Theorem tight_authorized_attempt_implies_transcript :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_has_valid_transcript attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[_ _] _] _] H_transcript] _] _] _].
  exact H_transcript.
Qed.

Theorem tight_authorized_attempt_implies_wrapper :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_has_valid_wrapper attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[_ _] _] _] _] H_wrapper] _] _].
  exact H_wrapper.
Qed.

Theorem tight_authorized_attempt_implies_transparency :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_has_valid_transparency attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[_ _] _] _] _] _] H_transparency] _].
  exact H_transparency.
Qed.

Theorem tight_authorized_attempt_implies_primitives :
  forall attempt,
    tight_authorized_attempt attempt = true ->
    tight_primitive_assumptions_hold attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[_ _] _] _] _] _] _] H_primitives].
  exact H_primitives.
Qed.

Theorem tight_missing_gate_implies_not_authorized :
  forall attempt,
    tight_missing_authorization_gate attempt = true ->
    tight_authorized_attempt attempt = false.
Proof.
  intros attempt H.
  unfold tight_missing_authorization_gate in H.
  unfold tight_authorized_attempt.

  destruct (tight_has_key_material attempt) eqn:H_key; simpl in *.
  - destruct (tight_has_valid_capability attempt) eqn:H_cap; simpl in *.
    + destruct (tight_has_nonrevocation attempt) eqn:H_nonrev; simpl in *.
      * destruct (tight_has_valid_authority_state attempt) eqn:H_auth; simpl in *.
        -- destruct (tight_has_valid_transcript attempt) eqn:H_transcript; simpl in *.
           ++ destruct (tight_has_valid_wrapper attempt) eqn:H_wrapper; simpl in *.
              ** destruct (tight_has_valid_transparency attempt) eqn:H_transparency; simpl in *.
                 --- destruct (tight_primitive_assumptions_hold attempt) eqn:H_primitive; simpl in *.
                     +++ discriminate.
                     +++ reflexivity.
                 --- reflexivity.
              ** reflexivity.
           ++ reflexivity.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem tight_not_authorized_implies_missing_gate :
  forall attempt,
    tight_authorized_attempt attempt = false ->
    tight_missing_authorization_gate attempt = true.
Proof.
  intros attempt H.
  unfold tight_authorized_attempt in H.
  unfold tight_missing_authorization_gate.

  destruct (tight_has_key_material attempt) eqn:H_key; simpl in *.
  - destruct (tight_has_valid_capability attempt) eqn:H_cap; simpl in *.
    + destruct (tight_has_nonrevocation attempt) eqn:H_nonrev; simpl in *.
      * destruct (tight_has_valid_authority_state attempt) eqn:H_auth; simpl in *.
        -- destruct (tight_has_valid_transcript attempt) eqn:H_transcript; simpl in *.
           ++ destruct (tight_has_valid_wrapper attempt) eqn:H_wrapper; simpl in *.
              ** destruct (tight_has_valid_transparency attempt) eqn:H_transparency; simpl in *.
                 --- destruct (tight_primitive_assumptions_hold attempt) eqn:H_primitive; simpl in *.
                     +++ discriminate.
                     +++ reflexivity.
                 --- reflexivity.
              ** reflexivity.
           ++ reflexivity.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem tight_security_equivalence :
  forall attempt,
    tight_unauthorized_success attempt = true <->
    tight_missing_authorization_gate attempt = true.
Proof.
  intros attempt.
  split.
  - intros H.
    unfold tight_unauthorized_success in H.
    apply negb_true_iff in H.
    apply tight_not_authorized_implies_missing_gate.
    exact H.
  - intros H.
    unfold tight_unauthorized_success.
    apply negb_true_iff.
    apply tight_missing_gate_implies_not_authorized.
    exact H.
Qed.
