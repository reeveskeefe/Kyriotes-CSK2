From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy KyriotesCsk2Verify.

Parameter adversary_outputs_object : KyriotesCsk2Object.
Parameter adversary_outputs_capability : Capability.
Parameter adversary_outputs_state : AuthorityState.

Definition adversary_wins_authorization_game : bool :=
  verify_open_context
    adversary_outputs_object
    adversary_outputs_capability
    adversary_outputs_state.

Definition unauthorized_capability (cap : Capability) (obj : KyriotesCsk2Object) : bool :=
  negb (policy_accepts cap obj).

Theorem no_unauthorized_verified_open :
  forall obj cap state,
    verify_open_context obj cap state = true ->
    unauthorized_capability cap obj = false.
Proof.
  intros obj cap state H.
  unfold unauthorized_capability.
  apply negb_false_iff.
  apply verify_open_context_implies_policy_accepts with (state := state).
  exact H.
Qed.

Theorem adversary_authorization_win_implies_authorized :
  adversary_wins_authorization_game = true ->
  unauthorized_capability adversary_outputs_capability adversary_outputs_object = false.
Proof.
  intro H.
  unfold adversary_wins_authorization_game in H.
  apply no_unauthorized_verified_open with (state := adversary_outputs_state).
  exact H.
Qed.
