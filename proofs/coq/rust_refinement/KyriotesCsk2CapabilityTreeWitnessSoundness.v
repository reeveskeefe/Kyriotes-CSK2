(*
  Capability-tree witness soundness expansion lane.

  This file models KYRIOTES-CSK2-owned capability witness binding with deterministic
  symbolic Merkle roots. It does not prove SHA or production Merkle security.
*)

From Coq Require Import Bool.Bool.
From Coq Require Import Arith.Arith.
From Coq Require Import Lists.List.
Import ListNotations.

Record CapabilityClaim := {
  claim_subject : nat;
  claim_rights : nat;
  claim_policy_hash : nat
}.

Record Capability := {
  capability_id : nat;
  capability_subject : nat;
  capability_rights : nat;
  capability_policy_hash : nat;
  capability_revoked : bool
}.

Record ModelMerklePath := {
  path_leaf_hash : nat;
  path_siblings : list nat
}.

Record CapabilityWitness := {
  witness_capability : Capability;
  witness_path : ModelMerklePath
}.

Definition AuthorityRoot := nat.
Definition RevocationRoot := nat.

Definition mix (a b : nat) : nat :=
  a + b + 1.

Definition capability_leaf_hash (capability : Capability) : nat :=
  let revoked_bit := if capability_revoked capability then 1 else 0 in
  capability_id capability +
  capability_subject capability +
  capability_rights capability +
  capability_policy_hash capability +
  revoked_bit.

Definition revocation_root_for (capability : Capability) : RevocationRoot :=
  mix (capability_id capability) (if capability_revoked capability then 1 else 0).

Fixpoint fold_merkle_path (current : nat) (siblings : list nat) : nat :=
  match siblings with
  | [] => current
  | sibling :: rest => fold_merkle_path (mix current sibling) rest
  end.

Definition compute_root (path : ModelMerklePath) : AuthorityRoot :=
  match path_siblings path with
  | [] => 0
  | siblings => fold_merkle_path (path_leaf_hash path) siblings
  end.

Definition path_nonempty (path : ModelMerklePath) : bool :=
  match path_siblings path with
  | [] => false
  | _ :: _ => true
  end.

Definition accepts_capability_witness
  (authority_root : AuthorityRoot)
  (revocation_root : RevocationRoot)
  (claim : CapabilityClaim)
  (witness : CapabilityWitness) : bool :=
  let capability := witness_capability witness in
  let path := witness_path witness in
  andb (path_nonempty path)
    (andb (capability_subject capability =? claim_subject claim)
      (andb (capability_rights capability =? claim_rights claim)
        (andb (capability_policy_hash capability =? claim_policy_hash claim)
          (andb (negb (capability_revoked capability))
            (andb (path_leaf_hash path =? capability_leaf_hash capability)
              (andb (compute_root path =? authority_root)
                (revocation_root_for capability =? revocation_root))))))).

Definition valid_claim : CapabilityClaim :=
  {|
    claim_subject := 7;
    claim_rights := 3;
    claim_policy_hash := 11
  |}.

Definition valid_capability : Capability :=
  {|
    capability_id := 19;
    capability_subject := 7;
    capability_rights := 3;
    capability_policy_hash := 11;
    capability_revoked := false
  |}.

Definition valid_path : ModelMerklePath :=
  {|
    path_leaf_hash := capability_leaf_hash valid_capability;
    path_siblings := [23; 29]
  |}.

Definition valid_witness : CapabilityWitness :=
  {|
    witness_capability := valid_capability;
    witness_path := valid_path
  |}.

Theorem capability_tree_witness_soundness :
  forall authority_root revocation_root claim witness,
    accepts_capability_witness authority_root revocation_root claim witness = true ->
    path_siblings (witness_path witness) <> [] /\
    capability_subject (witness_capability witness) = claim_subject claim /\
    capability_rights (witness_capability witness) = claim_rights claim /\
    capability_policy_hash (witness_capability witness) = claim_policy_hash claim /\
    capability_revoked (witness_capability witness) = false /\
    path_leaf_hash (witness_path witness) =
      capability_leaf_hash (witness_capability witness) /\
    compute_root (witness_path witness) = authority_root /\
    revocation_root_for (witness_capability witness) = revocation_root.
Proof.
  intros authority_root revocation_root claim witness H.
  unfold accepts_capability_witness in H.
  repeat rewrite andb_true_iff in H.
  destruct H as
    [H_nonempty
      [H_subject
        [H_rights
          [H_policy
            [H_revoked
              [H_leaf [H_root H_revocation]]]]]]].
  repeat split.
  - intros Empty.
    unfold path_nonempty in H_nonempty.
    rewrite Empty in H_nonempty.
    discriminate H_nonempty.
  - apply Nat.eqb_eq. exact H_subject.
  - apply Nat.eqb_eq. exact H_rights.
  - apply Nat.eqb_eq. exact H_policy.
  - destruct (capability_revoked (witness_capability witness)); simpl in H_revoked;
      [discriminate H_revoked | reflexivity].
  - apply Nat.eqb_eq. exact H_leaf.
  - apply Nat.eqb_eq. exact H_root.
  - apply Nat.eqb_eq. exact H_revocation.
Qed.

Theorem capability_tree_valid_non_revoked_witness_accepts :
  accepts_capability_witness
    (compute_root (witness_path valid_witness))
    (revocation_root_for (witness_capability valid_witness))
    valid_claim
    valid_witness = true.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_empty_witness_rejects :
  let empty_path := {|
    path_leaf_hash := capability_leaf_hash valid_capability;
    path_siblings := []
  |} in
  let empty_witness := {|
    witness_capability := valid_capability;
    witness_path := empty_path
  |} in
  accepts_capability_witness
    (compute_root valid_path)
    (revocation_root_for valid_capability)
    valid_claim
    empty_witness = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_wrong_subject_rejects :
  let wrong_claim := {|
    claim_subject := 8;
    claim_rights := claim_rights valid_claim;
    claim_policy_hash := claim_policy_hash valid_claim
  |} in
  accepts_capability_witness
    (compute_root valid_path)
    (revocation_root_for valid_capability)
    wrong_claim
    valid_witness = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_wrong_rights_rejects :
  let wrong_claim := {|
    claim_subject := claim_subject valid_claim;
    claim_rights := 4;
    claim_policy_hash := claim_policy_hash valid_claim
  |} in
  accepts_capability_witness
    (compute_root valid_path)
    (revocation_root_for valid_capability)
    wrong_claim
    valid_witness = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_wrong_policy_hash_rejects :
  let wrong_claim := {|
    claim_subject := claim_subject valid_claim;
    claim_rights := claim_rights valid_claim;
    claim_policy_hash := 12
  |} in
  accepts_capability_witness
    (compute_root valid_path)
    (revocation_root_for valid_capability)
    wrong_claim
    valid_witness = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_wrong_authority_root_rejects :
  accepts_capability_witness
    (S (compute_root valid_path))
    (revocation_root_for valid_capability)
    valid_claim
    valid_witness = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_revoked_capability_rejects :
  let revoked_capability := {|
    capability_id := capability_id valid_capability;
    capability_subject := capability_subject valid_capability;
    capability_rights := capability_rights valid_capability;
    capability_policy_hash := capability_policy_hash valid_capability;
    capability_revoked := true
  |} in
  let revoked_path := {|
    path_leaf_hash := capability_leaf_hash revoked_capability;
    path_siblings := path_siblings valid_path
  |} in
  let revoked_witness := {|
    witness_capability := revoked_capability;
    witness_path := revoked_path
  |} in
  accepts_capability_witness
    (compute_root revoked_path)
    (revocation_root_for revoked_capability)
    valid_claim
    revoked_witness = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_tampered_leaf_rejects :
  let tampered_path := {|
    path_leaf_hash := S (path_leaf_hash valid_path);
    path_siblings := path_siblings valid_path
  |} in
  let tampered_witness := {|
    witness_capability := valid_capability;
    witness_path := tampered_path
  |} in
  accepts_capability_witness
    (compute_root valid_path)
    (revocation_root_for valid_capability)
    valid_claim
    tampered_witness = false.
Proof.
  reflexivity.
Qed.

Theorem capability_tree_rejection_is_deterministic_for_equal_invalid_inputs :
  let tampered_path := {|
    path_leaf_hash := S (path_leaf_hash valid_path);
    path_siblings := path_siblings valid_path
  |} in
  let tampered_witness := {|
    witness_capability := valid_capability;
    witness_path := tampered_path
  |} in
  accepts_capability_witness
    (compute_root valid_path)
    (revocation_root_for valid_capability)
    valid_claim
    tampered_witness =
  accepts_capability_witness
    (compute_root valid_path)
    (revocation_root_for valid_capability)
    valid_claim
    tampered_witness.
Proof.
  reflexivity.
Qed.
