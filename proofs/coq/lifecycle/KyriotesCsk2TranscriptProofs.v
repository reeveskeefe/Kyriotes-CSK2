From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy KyriotesCsk2Verify KyriotesCsk2SecurityGame KyriotesCsk2Theorems KyriotesCsk2StressProofs KyriotesCsk2DelegationProofs KyriotesCsk2CryptoReduction KyriotesCsk2TemporalProofs.

Record KyriotesCsk2Transcript := {
  transcript_object_id : ObjectId;
  transcript_required_rights : Rights;
  transcript_authority_root : Hash;
  transcript_revocation_root : Hash;
  transcript_transparency_root : Hash;
  transcript_epoch : Epoch;
  transcript_context_hash : Hash
}.

Definition transcript_matches_object (tr : KyriotesCsk2Transcript) (obj : KyriotesCsk2Object) : bool :=
  Nat.eqb (transcript_object_id tr) (object_id obj) &&
  Nat.eqb (transcript_required_rights tr) (required_rights obj) &&
  Nat.eqb (transcript_authority_root tr) (bound_authority_root obj) &&
  Nat.eqb (transcript_revocation_root tr) (bound_revocation_root obj) &&
  Nat.eqb (transcript_transparency_root tr) (bound_transparency_root obj) &&
  Nat.eqb (transcript_epoch tr) (bound_epoch obj) &&
  Nat.eqb (transcript_context_hash tr) (aad_context_hash obj).

Definition transcript_matches_state (tr : KyriotesCsk2Transcript) (state : AuthorityState) : bool :=
  Nat.eqb (transcript_authority_root tr) (authority_root state) &&
  Nat.eqb (transcript_revocation_root tr) (revocation_root state) &&
  Nat.eqb (transcript_transparency_root tr) (transparency_root state) &&
  Nat.eqb (transcript_epoch tr) (epoch state).

Definition transcript_matches_capability (tr : KyriotesCsk2Transcript) (cap : Capability) : bool :=
  Nat.eqb (transcript_object_id tr) (cap_object_id cap) &&
  has_rights (cap_rights cap) (transcript_required_rights tr) &&
  epoch_in_window (transcript_epoch tr) (cap_epoch_start cap) (cap_epoch_end cap).

Definition transcript_accepts_open
  (tr : KyriotesCsk2Transcript)
  (obj : KyriotesCsk2Object)
  (cap : Capability)
  (state : AuthorityState)
  : bool :=
  transcript_matches_object tr obj &&
  transcript_matches_state tr state &&
  transcript_matches_capability tr cap &&
  verify_open_context obj cap state.

Theorem transcript_matches_object_implies_exact_object_fields :
  forall tr obj,
    transcript_matches_object tr obj = true ->
    transcript_object_id tr = object_id obj /\
    transcript_required_rights tr = required_rights obj /\
    transcript_authority_root tr = bound_authority_root obj /\
    transcript_revocation_root tr = bound_revocation_root obj /\
    transcript_transparency_root tr = bound_transparency_root obj /\
    transcript_epoch tr = bound_epoch obj /\
    transcript_context_hash tr = aad_context_hash obj.
Proof.
  intros tr obj H.
  unfold transcript_matches_object in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_object H_rights] H_authority] H_revocation] H_transparency] H_epoch] H_context].
  repeat split; apply Nat.eqb_eq; assumption.
Qed.

Theorem transcript_matches_state_implies_exact_state_fields :
  forall tr state,
    transcript_matches_state tr state = true ->
    transcript_authority_root tr = authority_root state /\
    transcript_revocation_root tr = revocation_root state /\
    transcript_transparency_root tr = transparency_root state /\
    transcript_epoch tr = epoch state.
Proof.
  intros tr state H.
  unfold transcript_matches_state in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_authority H_revocation] H_transparency] H_epoch].
  repeat split; apply Nat.eqb_eq; assumption.
Qed.

Theorem transcript_matches_capability_implies_authorization_fields :
  forall tr cap,
    transcript_matches_capability tr cap = true ->
    transcript_object_id tr = cap_object_id cap /\
    Nat.land (cap_rights cap) (transcript_required_rights tr) = transcript_required_rights tr /\
    cap_epoch_start cap <= transcript_epoch tr /\
    transcript_epoch tr <= cap_epoch_end cap.
Proof.
  intros tr cap H.
  unfold transcript_matches_capability in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_object H_rights] H_epoch].
  repeat split.
  - apply Nat.eqb_eq. exact H_object.
  - apply has_rights_true. exact H_rights.
  - apply epoch_in_window_true_bounds in H_epoch. destruct H_epoch as [H_start _]. exact H_start.
  - apply epoch_in_window_true_bounds in H_epoch. destruct H_epoch as [_ H_end]. exact H_end.
Qed.

Theorem transcript_object_id_mutation_rejected :
  forall tr obj,
    transcript_object_id tr <> object_id obj ->
    transcript_matches_object tr obj = false.
Proof.
  intros tr obj H.
  unfold transcript_matches_object.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem transcript_required_rights_mutation_rejected :
  forall tr obj,
    transcript_required_rights tr <> required_rights obj ->
    transcript_matches_object tr obj = false.
Proof.
  intros tr obj H.
  unfold transcript_matches_object.
  destruct (Nat.eqb (transcript_object_id tr) (object_id obj)); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem transcript_authority_root_mutation_rejected :
  forall tr obj,
    transcript_authority_root tr <> bound_authority_root obj ->
    transcript_matches_object tr obj = false.
Proof.
  intros tr obj H.
  unfold transcript_matches_object.
  destruct (Nat.eqb (transcript_object_id tr) (object_id obj)); simpl.
  - destruct (Nat.eqb (transcript_required_rights tr) (required_rights obj)); simpl.
    + apply Nat.eqb_neq in H.
      rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_revocation_root_mutation_rejected :
  forall tr obj,
    transcript_revocation_root tr <> bound_revocation_root obj ->
    transcript_matches_object tr obj = false.
Proof.
  intros tr obj H.
  unfold transcript_matches_object.
  destruct (Nat.eqb (transcript_object_id tr) (object_id obj)); simpl.
  - destruct (Nat.eqb (transcript_required_rights tr) (required_rights obj)); simpl.
    + destruct (Nat.eqb (transcript_authority_root tr) (bound_authority_root obj)); simpl.
      * apply Nat.eqb_neq in H.
        rewrite H.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_transparency_root_mutation_rejected :
  forall tr obj,
    transcript_transparency_root tr <> bound_transparency_root obj ->
    transcript_matches_object tr obj = false.
Proof.
  intros tr obj H.
  unfold transcript_matches_object.
  destruct (Nat.eqb (transcript_object_id tr) (object_id obj)); simpl.
  - destruct (Nat.eqb (transcript_required_rights tr) (required_rights obj)); simpl.
    + destruct (Nat.eqb (transcript_authority_root tr) (bound_authority_root obj)); simpl.
      * destruct (Nat.eqb (transcript_revocation_root tr) (bound_revocation_root obj)); simpl.
        -- apply Nat.eqb_neq in H.
           rewrite H.
           reflexivity.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_epoch_mutation_rejected :
  forall tr obj,
    transcript_epoch tr <> bound_epoch obj ->
    transcript_matches_object tr obj = false.
Proof.
  intros tr obj H.
  unfold transcript_matches_object.
  destruct (Nat.eqb (transcript_object_id tr) (object_id obj)); simpl.
  - destruct (Nat.eqb (transcript_required_rights tr) (required_rights obj)); simpl.
    + destruct (Nat.eqb (transcript_authority_root tr) (bound_authority_root obj)); simpl.
      * destruct (Nat.eqb (transcript_revocation_root tr) (bound_revocation_root obj)); simpl.
        -- destruct (Nat.eqb (transcript_transparency_root tr) (bound_transparency_root obj)); simpl.
           ++ apply Nat.eqb_neq in H.
              rewrite H.
              reflexivity.
           ++ reflexivity.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_context_hash_mutation_rejected :
  forall tr obj,
    transcript_context_hash tr <> aad_context_hash obj ->
    transcript_matches_object tr obj = false.
Proof.
  intros tr obj H.
  unfold transcript_matches_object.
  destruct (Nat.eqb (transcript_object_id tr) (object_id obj)); simpl.
  - destruct (Nat.eqb (transcript_required_rights tr) (required_rights obj)); simpl.
    + destruct (Nat.eqb (transcript_authority_root tr) (bound_authority_root obj)); simpl.
      * destruct (Nat.eqb (transcript_revocation_root tr) (bound_revocation_root obj)); simpl.
        -- destruct (Nat.eqb (transcript_transparency_root tr) (bound_transparency_root obj)); simpl.
           ++ destruct (Nat.eqb (transcript_epoch tr) (bound_epoch obj)); simpl.
              ** apply Nat.eqb_neq in H.
                 rewrite H.
                 reflexivity.
              ** reflexivity.
           ++ reflexivity.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_state_authority_root_mutation_rejected :
  forall tr state,
    transcript_authority_root tr <> authority_root state ->
    transcript_matches_state tr state = false.
Proof.
  intros tr state H.
  unfold transcript_matches_state.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem transcript_state_revocation_root_mutation_rejected :
  forall tr state,
    transcript_revocation_root tr <> revocation_root state ->
    transcript_matches_state tr state = false.
Proof.
  intros tr state H.
  unfold transcript_matches_state.
  destruct (Nat.eqb (transcript_authority_root tr) (authority_root state)); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem transcript_state_transparency_root_mutation_rejected :
  forall tr state,
    transcript_transparency_root tr <> transparency_root state ->
    transcript_matches_state tr state = false.
Proof.
  intros tr state H.
  unfold transcript_matches_state.
  destruct (Nat.eqb (transcript_authority_root tr) (authority_root state)); simpl.
  - destruct (Nat.eqb (transcript_revocation_root tr) (revocation_root state)); simpl.
    + apply Nat.eqb_neq in H.
      rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_state_epoch_mutation_rejected :
  forall tr state,
    transcript_epoch tr <> epoch state ->
    transcript_matches_state tr state = false.
Proof.
  intros tr state H.
  unfold transcript_matches_state.
  destruct (Nat.eqb (transcript_authority_root tr) (authority_root state)); simpl.
  - destruct (Nat.eqb (transcript_revocation_root tr) (revocation_root state)); simpl.
    + destruct (Nat.eqb (transcript_transparency_root tr) (transparency_root state)); simpl.
      * apply Nat.eqb_neq in H.
        rewrite H.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_capability_object_id_mismatch_rejected :
  forall tr cap,
    transcript_object_id tr <> cap_object_id cap ->
    transcript_matches_capability tr cap = false.
Proof.
  intros tr cap H.
  unfold transcript_matches_capability.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem transcript_capability_rights_mismatch_rejected :
  forall tr cap,
    Nat.land (cap_rights cap) (transcript_required_rights tr) <> transcript_required_rights tr ->
    transcript_matches_capability tr cap = false.
Proof.
  intros tr cap H.
  unfold transcript_matches_capability.
  destruct (Nat.eqb (transcript_object_id tr) (cap_object_id cap)); simpl.
  - unfold has_rights.
    apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem transcript_capability_epoch_before_window_rejected :
  forall tr cap,
    transcript_epoch tr < cap_epoch_start cap ->
    transcript_matches_capability tr cap = false.
Proof.
  intros tr cap H.
  unfold transcript_matches_capability.
  destruct (Nat.eqb (transcript_object_id tr) (cap_object_id cap)); simpl.
  - destruct (has_rights (cap_rights cap) (transcript_required_rights tr)); simpl.
    + unfold epoch_in_window.
      assert (Nat.leb (cap_epoch_start cap) (transcript_epoch tr) = false) as H_before.
      { apply Nat.leb_gt. exact H. }
      rewrite H_before.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_capability_epoch_after_window_rejected :
  forall tr cap,
    cap_epoch_end cap < transcript_epoch tr ->
    transcript_matches_capability tr cap = false.
Proof.
  intros tr cap H.
  unfold transcript_matches_capability.
  destruct (Nat.eqb (transcript_object_id tr) (cap_object_id cap)); simpl.
  - destruct (has_rights (cap_rights cap) (transcript_required_rights tr)); simpl.
    + unfold epoch_in_window.
      destruct (Nat.leb (cap_epoch_start cap) (transcript_epoch tr)); simpl.
      * assert (Nat.leb (transcript_epoch tr) (cap_epoch_end cap) = false) as H_after.
        { apply Nat.leb_gt. exact H. }
        rewrite H_after.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_object_mismatch_blocks_acceptance :
  forall tr obj cap state,
    transcript_matches_object tr obj = false ->
    transcript_accepts_open tr obj cap state = false.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open.
  rewrite H.
  reflexivity.
Qed.

Theorem transcript_state_mismatch_blocks_acceptance :
  forall tr obj cap state,
    transcript_matches_state tr state = false ->
    transcript_accepts_open tr obj cap state = false.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open.
  destruct (transcript_matches_object tr obj); simpl.
  - rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem transcript_capability_mismatch_blocks_acceptance :
  forall tr obj cap state,
    transcript_matches_capability tr cap = false ->
    transcript_accepts_open tr obj cap state = false.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open.
  destruct (transcript_matches_object tr obj); simpl.
  - destruct (transcript_matches_state tr state); simpl.
    + rewrite H.
      reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_verify_failure_blocks_acceptance :
  forall tr obj cap state,
    verify_open_context obj cap state = false ->
    transcript_accepts_open tr obj cap state = false.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open.
  destruct (transcript_matches_object tr obj); simpl.
  - destruct (transcript_matches_state tr state); simpl.
    + destruct (transcript_matches_capability tr cap); simpl.
      * exact H.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem transcript_acceptance_implies_object_match :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_matches_object tr obj = true.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_object H_state] H_cap] H_verify].
  exact H_object.
Qed.

Theorem transcript_acceptance_implies_state_match :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_matches_state tr state = true.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_object H_state] H_cap] H_verify].
  exact H_state.
Qed.

Theorem transcript_acceptance_implies_capability_match :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_matches_capability tr cap = true.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_object H_state] H_cap] H_verify].
  exact H_cap.
Qed.

Theorem transcript_acceptance_implies_verified_open :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    verify_open_context obj cap state = true.
Proof.
  intros tr obj cap state H.
  unfold transcript_accepts_open in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[H_object H_state] H_cap] H_verify].
  exact H_verify.
Qed.

Theorem transcript_acceptance_implies_exact_object_fields :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_object_id tr = object_id obj /\
    transcript_required_rights tr = required_rights obj /\
    transcript_authority_root tr = bound_authority_root obj /\
    transcript_revocation_root tr = bound_revocation_root obj /\
    transcript_transparency_root tr = bound_transparency_root obj /\
    transcript_epoch tr = bound_epoch obj /\
    transcript_context_hash tr = aad_context_hash obj.
Proof.
  intros tr obj cap state H.
  apply transcript_matches_object_implies_exact_object_fields.
  apply transcript_acceptance_implies_object_match with (cap := cap) (state := state).
  exact H.
Qed.

Theorem transcript_acceptance_implies_exact_state_fields :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_authority_root tr = authority_root state /\
    transcript_revocation_root tr = revocation_root state /\
    transcript_transparency_root tr = transparency_root state /\
    transcript_epoch tr = epoch state.
Proof.
  intros tr obj cap state H.
  apply transcript_matches_state_implies_exact_state_fields.
  apply transcript_acceptance_implies_state_match with (obj := obj) (cap := cap).
  exact H.
Qed.

Theorem transcript_acceptance_implies_exact_capability_authorization :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_object_id tr = cap_object_id cap /\
    Nat.land (cap_rights cap) (transcript_required_rights tr) = transcript_required_rights tr /\
    cap_epoch_start cap <= transcript_epoch tr /\
    transcript_epoch tr <= cap_epoch_end cap.
Proof.
  intros tr obj cap state H.
  apply transcript_matches_capability_implies_authorization_fields.
  apply transcript_acceptance_implies_capability_match with (obj := obj) (state := state).
  exact H.
Qed.

Theorem transcript_acceptance_implies_exact_cross_binding :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    object_id obj = cap_object_id cap /\
    bound_authority_root obj = authority_root state /\
    bound_revocation_root obj = revocation_root state /\
    bound_transparency_root obj = transparency_root state /\
    bound_epoch obj = epoch state.
Proof.
  intros tr obj cap state H.
  pose proof (transcript_acceptance_implies_exact_object_fields tr obj cap state H)
    as [H_obj [H_rights [H_auth_obj [H_rev_obj [H_trans_obj [H_epoch_obj H_context]]]]]].
  pose proof (transcript_acceptance_implies_exact_state_fields tr obj cap state H)
    as [H_auth_state [H_rev_state [H_trans_state H_epoch_state]]].
  pose proof (transcript_acceptance_implies_exact_capability_authorization tr obj cap state H)
    as [H_cap_object _].
  repeat split.
  - rewrite <- H_obj. exact H_cap_object.
  - rewrite <- H_auth_obj. exact H_auth_state.
  - rewrite <- H_rev_obj. exact H_rev_state.
  - rewrite <- H_trans_obj. exact H_trans_state.
  - rewrite <- H_epoch_obj. exact H_epoch_state.
Qed.

Theorem transcript_any_object_field_mutation_blocks_acceptance :
  forall tr obj cap state,
    transcript_object_id tr <> object_id obj \/
    transcript_required_rights tr <> required_rights obj \/
    transcript_authority_root tr <> bound_authority_root obj \/
    transcript_revocation_root tr <> bound_revocation_root obj \/
    transcript_transparency_root tr <> bound_transparency_root obj \/
    transcript_epoch tr <> bound_epoch obj \/
    transcript_context_hash tr <> aad_context_hash obj ->
    transcript_accepts_open tr obj cap state = false.
Proof.
  intros tr obj cap state H.
  apply transcript_object_mismatch_blocks_acceptance.
  destruct H as [H_obj | [H_rights | [H_auth | [H_rev | [H_trans | [H_epoch | H_context]]]]]].
  - apply transcript_object_id_mutation_rejected. exact H_obj.
  - apply transcript_required_rights_mutation_rejected. exact H_rights.
  - apply transcript_authority_root_mutation_rejected. exact H_auth.
  - apply transcript_revocation_root_mutation_rejected. exact H_rev.
  - apply transcript_transparency_root_mutation_rejected. exact H_trans.
  - apply transcript_epoch_mutation_rejected. exact H_epoch.
  - apply transcript_context_hash_mutation_rejected. exact H_context.
Qed.

Theorem transcript_any_state_field_mutation_blocks_acceptance :
  forall tr obj cap state,
    transcript_authority_root tr <> authority_root state \/
    transcript_revocation_root tr <> revocation_root state \/
    transcript_transparency_root tr <> transparency_root state \/
    transcript_epoch tr <> epoch state ->
    transcript_accepts_open tr obj cap state = false.
Proof.
  intros tr obj cap state H.
  apply transcript_state_mismatch_blocks_acceptance.
  destruct H as [H_auth | [H_rev | [H_trans | H_epoch]]].
  - apply transcript_state_authority_root_mutation_rejected. exact H_auth.
  - apply transcript_state_revocation_root_mutation_rejected. exact H_rev.
  - apply transcript_state_transparency_root_mutation_rejected. exact H_trans.
  - apply transcript_state_epoch_mutation_rejected. exact H_epoch.
Qed.

Theorem transcript_any_capability_field_mutation_blocks_acceptance :
  forall tr obj cap state,
    transcript_object_id tr <> cap_object_id cap \/
    Nat.land (cap_rights cap) (transcript_required_rights tr) <> transcript_required_rights tr \/
    transcript_epoch tr < cap_epoch_start cap \/
    cap_epoch_end cap < transcript_epoch tr ->
    transcript_accepts_open tr obj cap state = false.
Proof.
  intros tr obj cap state H.
  apply transcript_capability_mismatch_blocks_acceptance.
  destruct H as [H_obj | [H_rights | [H_before | H_after]]].
  - apply transcript_capability_object_id_mismatch_rejected. exact H_obj.
  - apply transcript_capability_rights_mismatch_rejected. exact H_rights.
  - apply transcript_capability_epoch_before_window_rejected. exact H_before.
  - apply transcript_capability_epoch_after_window_rejected. exact H_after.
Qed.

Theorem transcript_acceptance_cannot_have_context_hash_mismatch :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_context_hash tr <> aad_context_hash obj ->
    False.
Proof.
  intros tr obj cap state H_accept H_bad.
  pose proof (transcript_acceptance_implies_exact_object_fields tr obj cap state H_accept)
    as [_ [_ [_ [_ [_ [_ H_context]]]]]].
  contradiction.
Qed.

Theorem transcript_acceptance_cannot_have_authority_substitution :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_authority_root tr <> authority_root state ->
    False.
Proof.
  intros tr obj cap state H_accept H_bad.
  pose proof (transcript_acceptance_implies_exact_state_fields tr obj cap state H_accept)
    as [H_authority _].
  contradiction.
Qed.

Theorem transcript_acceptance_cannot_have_revocation_substitution :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_revocation_root tr <> revocation_root state ->
    False.
Proof.
  intros tr obj cap state H_accept H_bad.
  pose proof (transcript_acceptance_implies_exact_state_fields tr obj cap state H_accept)
    as [_ [H_revocation _]].
  contradiction.
Qed.

Theorem transcript_acceptance_cannot_have_transparency_substitution :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_transparency_root tr <> transparency_root state ->
    False.
Proof.
  intros tr obj cap state H_accept H_bad.
  pose proof (transcript_acceptance_implies_exact_state_fields tr obj cap state H_accept)
    as [_ [_ [H_transparency _]]].
  contradiction.
Qed.

Theorem transcript_acceptance_cannot_have_epoch_substitution :
  forall tr obj cap state,
    transcript_accepts_open tr obj cap state = true ->
    transcript_epoch tr <> epoch state ->
    False.
Proof.
  intros tr obj cap state H_accept H_bad.
  pose proof (transcript_acceptance_implies_exact_state_fields tr obj cap state H_accept)
    as [_ [_ [_ H_epoch]]].
  contradiction.
Qed.
