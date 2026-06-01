From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy.

Definition object_bound_to_state (obj : KyriotesCsk2Object) (state : AuthorityState) : bool :=
  Nat.eqb (bound_authority_root obj) (authority_root state) &&
  Nat.eqb (bound_revocation_root obj) (revocation_root state) &&
  Nat.eqb (bound_transparency_root obj) (transparency_root state) &&
  Nat.eqb (bound_epoch obj) (epoch state).

Definition verify_open_context (obj : KyriotesCsk2Object) (cap : Capability) (state : AuthorityState) : bool :=
  authority_state_valid state &&
  object_bound_to_state obj state &&
  capability_in_authority_root cap state &&
  capability_not_revoked cap state &&
  policy_accepts cap obj.

Lemma object_bound_to_state_implies_roots_and_epoch :
  forall obj state,
    object_bound_to_state obj state = true ->
    bound_authority_root obj = authority_root state /\
    bound_revocation_root obj = revocation_root state /\
    bound_transparency_root obj = transparency_root state /\
    bound_epoch obj = epoch state.
Proof.
  intros obj state H.
  unfold object_bound_to_state in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_auth H_rev] H_trans] H_epoch].
  repeat split; apply Nat.eqb_eq; assumption.
Qed.

Lemma verify_open_context_implies_authority_valid :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    authority_state_valid state = true.
Proof.
  intros obj cap state H.
  unfold verify_open_context in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_auth _] _] _] _].
  exact H_auth.
Qed.

Lemma verify_open_context_implies_policy_accepts :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    policy_accepts cap obj = true.
Proof.
  intros obj cap state H.
  unfold verify_open_context in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[ _ _] _] _] H_policy].
  exact H_policy.
Qed.

Lemma verify_open_context_implies_capability_in_authority :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    capability_in_authority_root cap state = true.
Proof.
  intros obj cap state H.
  unfold verify_open_context in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[ _ _] H_inc] _] _].
  exact H_inc.
Qed.

Lemma verify_open_context_implies_not_revoked :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    capability_not_revoked cap state = true.
Proof.
  intros obj cap state H.
  unfold verify_open_context in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[ _ _] _] H_not_revoked] _].
  exact H_not_revoked.
Qed.

Lemma verify_open_context_implies_object_bound :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    object_bound_to_state obj state = true.
Proof.
  intros obj cap state H.
  unfold verify_open_context in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[ _ H_bound] _] _] _].
  exact H_bound.
Qed.
