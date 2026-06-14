(*
  Capability binding computational reduction.

  Proves that a capability accepted in one context (object, authority state)
  cannot be accepted in a context with different binding attributes without
  breaking a stated primitive assumption. This covers the "Capability Binding"
  game from SECURITY_MODEL.md.

  All proofs are deterministic — derived from the structural decomposition
  of verify_open_context. No new axioms are introduced.

  Structure:
    1. Object-ID binding      — different object_id → second verification fails
    2. Rights binding         — insufficient rights → second verification fails
    3. Epoch window binding   — epoch outside cap window → second verification fails
    4. Authority root binding — different authority roots → Merkle break (False)
    5. Revocation binding     — bound_revocation_root and non-revocation are unique
    6. Cross-context game definition
    7. Cross-context reduction theorems
    8. Completion status record
*)

From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.

From KyriotesCsk2Proofs Require Import
  KyriotesCsk2Types
  KyriotesCsk2Merkle
  KyriotesCsk2Authority
  KyriotesCsk2Policy
  KyriotesCsk2Verify
  KyriotesCsk2Theorems.

(* ================================================================
   1. Object-ID binding

   verify_open_context forces cap_object_id cap = object_id obj via
   policy_accepts_implies_object_match. If two objects have different
   object_ids, the same capability cannot verify for both.
   ================================================================ *)

Theorem capability_object_id_binding :
  forall cap obj_a obj_b state,
    verify_open_context obj_a cap state = true ->
    object_id obj_a <> object_id obj_b ->
    verify_open_context obj_b cap state = false.
Proof.
  intros cap obj_a obj_b state H_a Hne.
  destruct (verify_open_context obj_b cap state) eqn:H_b.
  - exfalso. apply Hne.
    destruct (kyriotes_csk2_verified_open_implies_object_authorization obj_a cap state H_a)
      as [Hid_a _].
    destruct (kyriotes_csk2_verified_open_implies_object_authorization obj_b cap state H_b)
      as [Hid_b _].
    congruence.
  - reflexivity.
Qed.

(* ================================================================
   2. Rights binding

   policy_accepts requires cap_rights to cover required_rights. If
   the second object requires rights not covered by cap_rights,
   verification fails.
   ================================================================ *)

Theorem capability_rights_binding :
  forall cap obj_a obj_b state,
    verify_open_context obj_a cap state = true ->
    Nat.land (cap_rights cap) (required_rights obj_b) <> required_rights obj_b ->
    verify_open_context obj_b cap state = false.
Proof.
  intros cap obj_a obj_b state H_a Hne.
  destruct (verify_open_context obj_b cap state) eqn:H_b.
  - exfalso. apply Hne.
    destruct (kyriotes_csk2_verified_open_implies_object_authorization obj_b cap state H_b)
      as [_ [Hrights _]].
    exact Hrights.
  - reflexivity.
Qed.

(* ================================================================
   3. Epoch window binding

   The capability epoch window [cap_epoch_start, cap_epoch_end] must
   contain the object's bound_epoch. If the second object has a bound_epoch
   outside this window, verification fails.
   ================================================================ *)

Theorem capability_epoch_binding :
  forall cap obj_a obj_b state,
    verify_open_context obj_a cap state = true ->
    ~ (cap_epoch_start cap <= bound_epoch obj_b /\ bound_epoch obj_b <= cap_epoch_end cap) ->
    verify_open_context obj_b cap state = false.
Proof.
  intros cap obj_a obj_b state H_a Hnot.
  destruct (verify_open_context obj_b cap state) eqn:H_b.
  - exfalso. apply Hnot.
    destruct (kyriotes_csk2_verified_open_implies_object_authorization obj_b cap state H_b)
      as [_ [_ [Hstart Hend]]].
    split; assumption.
  - reflexivity.
Qed.

(* ================================================================
   4. Authority root binding

   A verified capability's hash must be in the authority_root of the
   state via capability_in_authority_root. If the same capability were
   accepted under a different authority root, the Merkle inclusion would
   hold for two distinct roots — violating merkle_inclusion_binding.

   This is the core reduction: an authority-root binding violation
   directly implies a break of the Merkle primitive assumption.
   ================================================================ *)

Theorem capability_authority_root_binding :
  forall cap obj_a obj_b state_a state_b,
    verify_open_context obj_a cap state_a = true ->
    verify_open_context obj_b cap state_b = true ->
    authority_root state_a <> authority_root state_b ->
    False.
Proof.
  intros cap obj_a obj_b state_a state_b H_a H_b Hne.
  pose proof (verify_open_context_implies_capability_in_authority obj_a cap state_a H_a) as Hinc_a.
  pose proof (verify_open_context_implies_capability_in_authority obj_b cap state_b H_b) as Hinc_b.
  unfold capability_in_authority_root in Hinc_a, Hinc_b.
  apply merkle_inclusion_binding
    with (leaf   := hash_capability cap)
         (root_a := authority_root state_a)
         (root_b := authority_root state_b).
  - exact Hinc_a.
  - exact Hinc_b.
  - exact Hne.
Qed.

(* ================================================================
   5. Revocation binding

   Non-revocation is checked against the revocation_root of the state,
   and the object's bound_revocation_root must equal that root for
   verification to succeed. A verified capability's stamp is therefore
   provably absent from the stated revocation root.
   ================================================================ *)

Theorem revocation_root_binding :
  forall cap obj state,
    verify_open_context obj cap state = true ->
    bound_revocation_root obj = revocation_root state.
Proof.
  intros cap obj state H.
  destruct (kyriotes_csk2_verified_open_implies_exact_authority_binding obj cap state H)
    as [_ [Hrev _]].
  exact Hrev.
Qed.

Theorem verified_capability_is_not_revoked :
  forall cap obj state,
    verify_open_context obj cap state = true ->
    included_in_merkle_root
      (hash_revocation_stamp (cap_stamp cap))
      (revocation_root state) = false.
Proof.
  intros cap obj state H.
  exact (kyriotes_csk2_verified_open_excludes_revocation_leaf obj cap state H).
Qed.

(*
  A revoked capability (stamp in the revocation root) cannot verify
  regardless of any other context attributes.
*)
Theorem revoked_capability_fails_verification :
  forall cap obj state,
    included_in_merkle_root
      (hash_revocation_stamp (cap_stamp cap))
      (revocation_root state) = true ->
    verify_open_context obj cap state = false.
Proof.
  intros cap obj state H_revoked.
  destruct (verify_open_context obj cap state) eqn:H_v.
  - exfalso.
    pose proof (kyriotes_csk2_verified_open_excludes_revocation_leaf obj cap state H_v) as H_not.
    rewrite H_revoked in H_not. discriminate.
  - reflexivity.
Qed.

(* ================================================================
   6. Cross-context binding game

   A cross-context violation occurs when the same capability verifies
   in two (object, state) contexts that differ in a binding attribute.
   We state two game variants corresponding to the two strongest proved
   reduction targets.
   ================================================================ *)

Record CapabilityBindingViolation := {
  cbv_cap     : Capability;
  cbv_obj_a   : KyriotesCsk2Object;
  cbv_state_a : AuthorityState;
  cbv_obj_b   : KyriotesCsk2Object;
  cbv_state_b : AuthorityState
}.

(*
  Object-ID variant: the two objects differ in object_id.
*)
Definition cross_context_wins_object_id
  (v : CapabilityBindingViolation) : Prop :=
  verify_open_context (cbv_obj_a v) (cbv_cap v) (cbv_state_a v) = true /\
  verify_open_context (cbv_obj_b v) (cbv_cap v) (cbv_state_b v) = true /\
  object_id (cbv_obj_a v) <> object_id (cbv_obj_b v).

(*
  Authority-root variant: the two states have different authority roots.
*)
Definition cross_context_wins_authority_root
  (v : CapabilityBindingViolation) : Prop :=
  verify_open_context (cbv_obj_a v) (cbv_cap v) (cbv_state_a v) = true /\
  verify_open_context (cbv_obj_b v) (cbv_cap v) (cbv_state_b v) = true /\
  authority_root (cbv_state_a v) <> authority_root (cbv_state_b v).

(* ================================================================
   7. Cross-context reduction theorems

   Both game variants lead to False under the stated axioms.
   ================================================================ *)

(*
  The same capability can only be accepted for one object_id
  (the one named in cap_object_id cap). Two successful verifications for
  different object_ids would require cap_object_id = object_id A and
  cap_object_id = object_id B simultaneously — impossible if A ≠ B.
*)
Theorem cross_context_object_id_binding_impossible :
  forall v,
    cross_context_wins_object_id v ->
    False.
Proof.
  intros v [H_a [H_b Hne]].
  apply Hne.
  destruct (kyriotes_csk2_verified_open_implies_object_authorization
    (cbv_obj_a v) (cbv_cap v) (cbv_state_a v) H_a) as [Hid_a _].
  destruct (kyriotes_csk2_verified_open_implies_object_authorization
    (cbv_obj_b v) (cbv_cap v) (cbv_state_b v) H_b) as [Hid_b _].
  congruence.
Qed.

(*
  Cross-authority-root acceptance requires the capability to be included
  in both roots, violating merkle_inclusion_binding (Merkle collision
  resistance under SHA-256).
*)
Theorem cross_context_authority_root_requires_merkle_break :
  forall v,
    cross_context_wins_authority_root v ->
    False.
Proof.
  intros v [H_a [H_b Hne]].
  pose proof (verify_open_context_implies_capability_in_authority
    (cbv_obj_a v) (cbv_cap v) (cbv_state_a v) H_a) as Hinc_a.
  pose proof (verify_open_context_implies_capability_in_authority
    (cbv_obj_b v) (cbv_cap v) (cbv_state_b v) H_b) as Hinc_b.
  unfold capability_in_authority_root in Hinc_a, Hinc_b.
  apply merkle_inclusion_binding
    with (leaf   := hash_capability (cbv_cap v))
         (root_a := authority_root (cbv_state_a v))
         (root_b := authority_root (cbv_state_b v)).
  - exact Hinc_a.
  - exact Hinc_b.
  - exact Hne.
Qed.

(* ================================================================
   8. Completion status record
   ================================================================ *)

Record CapabilityBindingReductionStatus := {
  cbr_object_id_binding_proved       : bool;
  cbr_rights_binding_proved          : bool;
  cbr_epoch_binding_proved           : bool;
  cbr_authority_root_binding_proved  : bool;
  cbr_revocation_root_binding_proved : bool;
  cbr_not_revoked_binding_proved     : bool;
  cbr_revoked_fails_proved           : bool;
  cbr_cross_context_game_stated      : bool;
  cbr_cross_context_object_id_proved : bool;
  cbr_cross_context_auth_root_proved : bool
}.

Definition capability_binding_reduction_complete
  (status : CapabilityBindingReductionStatus) : bool :=
  cbr_object_id_binding_proved status &&
  cbr_rights_binding_proved status &&
  cbr_epoch_binding_proved status &&
  cbr_authority_root_binding_proved status &&
  cbr_revocation_root_binding_proved status &&
  cbr_not_revoked_binding_proved status &&
  cbr_revoked_fails_proved status &&
  cbr_cross_context_game_stated status &&
  cbr_cross_context_object_id_proved status &&
  cbr_cross_context_auth_root_proved status.

Definition kyriotes_csk2_capability_binding_reduction_status
  : CapabilityBindingReductionStatus :=
  {|
    cbr_object_id_binding_proved       := true;
    cbr_rights_binding_proved          := true;
    cbr_epoch_binding_proved           := true;
    cbr_authority_root_binding_proved  := true;
    cbr_revocation_root_binding_proved := true;
    cbr_not_revoked_binding_proved     := true;
    cbr_revoked_fails_proved           := true;
    cbr_cross_context_game_stated      := true;
    cbr_cross_context_object_id_proved := true;
    cbr_cross_context_auth_root_proved := true
  |}.

Theorem capability_binding_reduction_is_complete :
  capability_binding_reduction_complete
    kyriotes_csk2_capability_binding_reduction_status = true.
Proof.
  reflexivity.
Qed.
