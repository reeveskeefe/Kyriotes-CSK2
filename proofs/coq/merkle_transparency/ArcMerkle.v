From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From ArcProofs Require Import ArcTypes.

Parameter hash_capability : Capability -> Hash.
Parameter hash_revocation_stamp : nat -> Hash.
Parameter included_in_merkle_root : Hash -> Hash -> bool.
Parameter not_in_revocation_root : nat -> Hash -> bool.

Axiom merkle_inclusion_binding :
  forall leaf root_a root_b,
    included_in_merkle_root leaf root_a = true ->
    included_in_merkle_root leaf root_b = true ->
    root_a <> root_b ->
    False.

Axiom revocation_soundness :
  forall stamp root,
    not_in_revocation_root stamp root = true ->
    included_in_merkle_root (hash_revocation_stamp stamp) root = false.

Definition capability_in_authority_root (cap : Capability) (state : AuthorityState) : bool :=
  included_in_merkle_root (hash_capability cap) (authority_root state).

Definition capability_not_revoked (cap : Capability) (state : AuthorityState) : bool :=
  not_in_revocation_root (cap_stamp cap) (revocation_root state).

Theorem non_revocation_excludes_revocation_leaf :
  forall cap state,
    capability_not_revoked cap state = true ->
    included_in_merkle_root (hash_revocation_stamp (cap_stamp cap)) (revocation_root state) = false.
Proof.
  intros cap state H.
  unfold capability_not_revoked in H.
  apply revocation_soundness.
  exact H.
Qed.
