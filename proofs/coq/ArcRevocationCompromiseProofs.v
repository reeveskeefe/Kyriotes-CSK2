From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
Require Import ArcTypes ArcMerkle ArcAuthority ArcPolicy ArcVerify ArcSecurityGame ArcTheorems ArcStressProofs ArcDelegationProofs ArcCryptoReduction ArcTemporalProofs ArcTranscriptProofs.

Definition stamp_eqb (a b : nat) : bool :=
  Nat.eqb a b.

Definition stamp_in_revocation_set (stamp : nat) (revoked : list nat) : bool :=
  existsb (stamp_eqb stamp) revoked.

Definition revocation_set_extends (old_revoked new_revoked : list nat) : Prop :=
  forall stamp,
    stamp_in_revocation_set stamp old_revoked = true ->
    stamp_in_revocation_set stamp new_revoked = true.

Definition capability_revoked_by_set (cap : Capability) (revoked : list nat) : bool :=
  stamp_in_revocation_set (cap_stamp cap) revoked.

Definition capability_not_revoked_by_set (cap : Capability) (revoked : list nat) : bool :=
  negb (capability_revoked_by_set cap revoked).

Definition open_allowed_under_revocation_set
  (obj : ArcObject)
  (cap : Capability)
  (state : AuthorityState)
  (revoked : list nat)
  : bool :=
  verify_open_context obj cap state &&
  capability_not_revoked_by_set cap revoked.

Record CompromiseNotice := {
  notice_epoch : Epoch;
  notice_epoch_public_key : PublicKey;
  notice_recovery_root : Hash
}.

Definition compromise_notice_matches_state
  (notice : CompromiseNotice)
  (state : AuthorityState)
  : bool :=
  Nat.eqb (notice_epoch notice) (epoch state) &&
  Nat.eqb (notice_epoch_public_key notice) (epoch_public_key state).

Definition compromise_notice_in_list
  (state : AuthorityState)
  (notices : list CompromiseNotice)
  : bool :=
  existsb (fun notice => compromise_notice_matches_state notice state) notices.

Definition state_not_compromised_by_notices
  (state : AuthorityState)
  (notices : list CompromiseNotice)
  : bool :=
  negb (compromise_notice_in_list state notices).

Definition open_allowed_under_compromise_notices
  (obj : ArcObject)
  (cap : Capability)
  (state : AuthorityState)
  (notices : list CompromiseNotice)
  : bool :=
  verify_open_context obj cap state &&
  state_not_compromised_by_notices state notices.

Theorem stamp_eqb_refl :
  forall stamp,
    stamp_eqb stamp stamp = true.
Proof.
  intros stamp.
  unfold stamp_eqb.
  apply Nat.eqb_refl.
Qed.

Theorem stamp_in_revocation_set_cons_self :
  forall stamp revoked,
    stamp_in_revocation_set stamp (stamp :: revoked) = true.
Proof.
  intros stamp revoked.
  unfold stamp_in_revocation_set.
  simpl.
  rewrite stamp_eqb_refl.
  reflexivity.
Qed.

Theorem stamp_in_revocation_set_cons_preserves :
  forall stamp head revoked,
    stamp_in_revocation_set stamp revoked = true ->
    stamp_in_revocation_set stamp (head :: revoked) = true.
Proof.
  intros stamp head revoked H.
  unfold stamp_in_revocation_set in *.
  simpl.
  rewrite H.
  destruct (stamp_eqb stamp head); reflexivity.
Qed.

Theorem revocation_set_extends_refl :
  forall revoked,
    revocation_set_extends revoked revoked.
Proof.
  intros revoked stamp H.
  exact H.
Qed.

Theorem revocation_set_extends_cons :
  forall old_revoked new_stamp,
    revocation_set_extends old_revoked (new_stamp :: old_revoked).
Proof.
  intros old_revoked new_stamp stamp H.
  apply stamp_in_revocation_set_cons_preserves.
  exact H.
Qed.

Theorem revocation_set_extends_trans :
  forall a b c,
    revocation_set_extends a b ->
    revocation_set_extends b c ->
    revocation_set_extends a c.
Proof.
  intros a b c H_ab H_bc stamp H_in.
  apply H_bc.
  apply H_ab.
  exact H_in.
Qed.

Theorem revoked_capability_rejected_by_revocation_set :
  forall obj cap state revoked,
    capability_revoked_by_set cap revoked = true ->
    open_allowed_under_revocation_set obj cap state revoked = false.
Proof.
  intros obj cap state revoked H_revoked.
  unfold open_allowed_under_revocation_set.
  unfold capability_not_revoked_by_set.
  rewrite H_revoked.
  simpl.
  destruct (verify_open_context obj cap state); reflexivity.
Qed.

Theorem non_revoked_open_implies_not_in_revocation_set :
  forall obj cap state revoked,
    open_allowed_under_revocation_set obj cap state revoked = true ->
    capability_revoked_by_set cap revoked = false.
Proof.
  intros obj cap state revoked H.
  unfold open_allowed_under_revocation_set in H.
  apply andb_true_iff in H.
  destruct H as [_ H_not_revoked].
  unfold capability_not_revoked_by_set in H_not_revoked.
  apply negb_true_iff in H_not_revoked.
  exact H_not_revoked.
Qed.

Theorem non_revoked_open_implies_verified_open :
  forall obj cap state revoked,
    open_allowed_under_revocation_set obj cap state revoked = true ->
    verify_open_context obj cap state = true.
Proof.
  intros obj cap state revoked H.
  unfold open_allowed_under_revocation_set in H.
  apply andb_true_iff in H.
  destruct H as [H_open _].
  exact H_open.
Qed.

Theorem revocation_monotonicity_preserves_revoked_stamp :
  forall old_revoked new_revoked cap,
    revocation_set_extends old_revoked new_revoked ->
    capability_revoked_by_set cap old_revoked = true ->
    capability_revoked_by_set cap new_revoked = true.
Proof.
  intros old_revoked new_revoked cap H_extends H_revoked.
  unfold capability_revoked_by_set in *.
  apply H_extends.
  exact H_revoked.
Qed.

Theorem revocation_monotonicity_blocks_reopened_capability :
  forall obj cap state old_revoked new_revoked,
    revocation_set_extends old_revoked new_revoked ->
    capability_revoked_by_set cap old_revoked = true ->
    open_allowed_under_revocation_set obj cap state new_revoked = false.
Proof.
  intros obj cap state old_revoked new_revoked H_extends H_revoked_old.
  apply revoked_capability_rejected_by_revocation_set.
  apply revocation_monotonicity_preserves_revoked_stamp with (old_revoked := old_revoked).
  - exact H_extends.
  - exact H_revoked_old.
Qed.

Theorem once_revoked_stays_blocked_under_extension :
  forall obj cap state old_revoked new_stamp,
    capability_revoked_by_set cap old_revoked = true ->
    open_allowed_under_revocation_set obj cap state (new_stamp :: old_revoked) = false.
Proof.
  intros obj cap state old_revoked new_stamp H_revoked.
  apply revocation_monotonicity_blocks_reopened_capability with (old_revoked := old_revoked).
  - apply revocation_set_extends_cons.
  - exact H_revoked.
Qed.

Theorem newly_revoked_stamp_blocks_open :
  forall obj cap state revoked,
    open_allowed_under_revocation_set obj cap state (cap_stamp cap :: revoked) = false.
Proof.
  intros obj cap state revoked.
  apply revoked_capability_rejected_by_revocation_set.
  unfold capability_revoked_by_set.
  apply stamp_in_revocation_set_cons_self.
Qed.

Theorem verified_open_with_revocation_set_implies_arc_safety :
  forall obj cap state revoked,
    open_allowed_under_revocation_set obj cap state revoked = true ->
    capability_in_authority_root cap state = true /\
    capability_not_revoked cap state = true /\
    policy_accepts cap obj = true /\
    object_bound_to_state obj state = true /\
    authority_state_valid state = true /\
    capability_revoked_by_set cap revoked = false.
Proof.
  intros obj cap state revoked H_allowed.
  pose proof (non_revoked_open_implies_verified_open obj cap state revoked H_allowed) as H_open.
  pose proof (arc_verified_open_safety obj cap state H_open)
    as [H_inclusion [H_not_revoked [H_policy [H_bound H_authority]]]].
  pose proof (non_revoked_open_implies_not_in_revocation_set obj cap state revoked H_allowed) as H_not_in_set.
  repeat split; assumption.
Qed.

Theorem compromise_notice_matches_state_refl :
  forall epoch_value epoch_pk recovery_root,
    compromise_notice_matches_state
      {| notice_epoch := epoch_value;
         notice_epoch_public_key := epoch_pk;
         notice_recovery_root := recovery_root |}
      {| authority_root := recovery_root;
         revocation_root := recovery_root;
         transparency_root := recovery_root;
         epoch := epoch_value;
         epoch_public_key := epoch_pk;
         root_public_key := recovery_root |} = true.
Proof.
  intros epoch_value epoch_pk recovery_root.
  unfold compromise_notice_matches_state.
  simpl.
  repeat rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem compromise_notice_in_list_cons_match :
  forall state notice notices,
    compromise_notice_matches_state notice state = true ->
    compromise_notice_in_list state (notice :: notices) = true.
Proof.
  intros state notice notices H.
  unfold compromise_notice_in_list.
  simpl.
  rewrite H.
  reflexivity.
Qed.

Theorem matching_compromise_notice_blocks_open :
  forall obj cap state notice notices,
    compromise_notice_matches_state notice state = true ->
    open_allowed_under_compromise_notices obj cap state (notice :: notices) = false.
Proof.
  intros obj cap state notice notices H_match.
  unfold open_allowed_under_compromise_notices.
  unfold state_not_compromised_by_notices.
  pose proof (compromise_notice_in_list_cons_match state notice notices H_match) as H_in.
  rewrite H_in.
  simpl.
  destruct (verify_open_context obj cap state); reflexivity.
Qed.

Theorem compromised_state_rejected_by_notices :
  forall obj cap state notices,
    compromise_notice_in_list state notices = true ->
    open_allowed_under_compromise_notices obj cap state notices = false.
Proof.
  intros obj cap state notices H_compromised.
  unfold open_allowed_under_compromise_notices.
  unfold state_not_compromised_by_notices.
  rewrite H_compromised.
  simpl.
  destruct (verify_open_context obj cap state); reflexivity.
Qed.

Theorem compromise_safe_open_implies_no_matching_notice :
  forall obj cap state notices,
    open_allowed_under_compromise_notices obj cap state notices = true ->
    compromise_notice_in_list state notices = false.
Proof.
  intros obj cap state notices H.
  unfold open_allowed_under_compromise_notices in H.
  apply andb_true_iff in H.
  destruct H as [_ H_not_compromised].
  unfold state_not_compromised_by_notices in H_not_compromised.
  apply negb_true_iff in H_not_compromised.
  exact H_not_compromised.
Qed.

Theorem compromise_safe_open_implies_verified_open :
  forall obj cap state notices,
    open_allowed_under_compromise_notices obj cap state notices = true ->
    verify_open_context obj cap state = true.
Proof.
  intros obj cap state notices H.
  unfold open_allowed_under_compromise_notices in H.
  apply andb_true_iff in H.
  destruct H as [H_open _].
  exact H_open.
Qed.

Theorem compromise_notice_epoch_mismatch_is_not_match :
  forall notice state,
    notice_epoch notice <> epoch state ->
    compromise_notice_matches_state notice state = false.
Proof.
  intros notice state H.
  unfold compromise_notice_matches_state.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem compromise_notice_key_mismatch_is_not_match :
  forall notice state,
    notice_epoch_public_key notice <> epoch_public_key state ->
    compromise_notice_matches_state notice state = false.
Proof.
  intros notice state H.
  unfold compromise_notice_matches_state.
  destruct (Nat.eqb (notice_epoch notice) (epoch state)); simpl.
  - apply Nat.eqb_neq in H.
    rewrite H.
    reflexivity.
  - reflexivity.
Qed.

Theorem compromise_safe_open_preserves_arc_safety :
  forall obj cap state notices,
    open_allowed_under_compromise_notices obj cap state notices = true ->
    capability_in_authority_root cap state = true /\
    capability_not_revoked cap state = true /\
    policy_accepts cap obj = true /\
    object_bound_to_state obj state = true /\
    authority_state_valid state = true /\
    compromise_notice_in_list state notices = false.
Proof.
  intros obj cap state notices H_allowed.
  pose proof (compromise_safe_open_implies_verified_open obj cap state notices H_allowed) as H_open.
  pose proof (arc_verified_open_safety obj cap state H_open)
    as [H_inclusion [H_not_revoked [H_policy [H_bound H_authority]]]].
  pose proof (compromise_safe_open_implies_no_matching_notice obj cap state notices H_allowed) as H_no_notice.
  repeat split; assumption.
Qed.

Definition open_allowed_under_revocation_and_compromise
  (obj : ArcObject)
  (cap : Capability)
  (state : AuthorityState)
  (revoked : list nat)
  (notices : list CompromiseNotice)
  : bool :=
  verify_open_context obj cap state &&
  capability_not_revoked_by_set cap revoked &&
  state_not_compromised_by_notices state notices.

Theorem revoked_or_compromised_blocks_combined_open :
  forall obj cap state revoked notices,
    capability_revoked_by_set cap revoked = true \/
    compromise_notice_in_list state notices = true ->
    open_allowed_under_revocation_and_compromise obj cap state revoked notices = false.
Proof.
  intros obj cap state revoked notices H.
  unfold open_allowed_under_revocation_and_compromise.
  destruct H as [H_revoked | H_compromised].
  - unfold capability_not_revoked_by_set.
    rewrite H_revoked.
    simpl.
    destruct (verify_open_context obj cap state); reflexivity.
  - unfold state_not_compromised_by_notices.
    rewrite H_compromised.
    simpl.
    destruct (verify_open_context obj cap state); simpl.
    + destruct (capability_not_revoked_by_set cap revoked); reflexivity.
    + reflexivity.
Qed.

Theorem combined_open_implies_no_revocation_and_no_compromise :
  forall obj cap state revoked notices,
    open_allowed_under_revocation_and_compromise obj cap state revoked notices = true ->
    verify_open_context obj cap state = true /\
    capability_revoked_by_set cap revoked = false /\
    compromise_notice_in_list state notices = false.
Proof.
  intros obj cap state revoked notices H.
  unfold open_allowed_under_revocation_and_compromise in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[H_open H_not_revoked_set] H_not_compromised].
  unfold capability_not_revoked_by_set in H_not_revoked_set.
  apply negb_true_iff in H_not_revoked_set.
  unfold state_not_compromised_by_notices in H_not_compromised.
  apply negb_true_iff in H_not_compromised.
  repeat split; assumption.
Qed.

Theorem combined_open_preserves_full_safety :
  forall obj cap state revoked notices,
    open_allowed_under_revocation_and_compromise obj cap state revoked notices = true ->
    capability_in_authority_root cap state = true /\
    capability_not_revoked cap state = true /\
    policy_accepts cap obj = true /\
    object_bound_to_state obj state = true /\
    authority_state_valid state = true /\
    capability_revoked_by_set cap revoked = false /\
    compromise_notice_in_list state notices = false.
Proof.
  intros obj cap state revoked notices H_combined.
  pose proof (combined_open_implies_no_revocation_and_no_compromise obj cap state revoked notices H_combined)
    as [H_open [H_not_revoked_set H_no_compromise]].
  pose proof (arc_verified_open_safety obj cap state H_open)
    as [H_inclusion [H_not_revoked [H_policy [H_bound H_authority]]]].
  repeat split; assumption.
Qed.

Theorem combined_open_rejected_after_revocation_extension :
  forall obj cap state old_revoked new_revoked notices,
    revocation_set_extends old_revoked new_revoked ->
    capability_revoked_by_set cap old_revoked = true ->
    open_allowed_under_revocation_and_compromise obj cap state new_revoked notices = false.
Proof.
  intros obj cap state old_revoked new_revoked notices H_extends H_revoked.
  apply revoked_or_compromised_blocks_combined_open.
  left.
  apply revocation_monotonicity_preserves_revoked_stamp with (old_revoked := old_revoked).
  - exact H_extends.
  - exact H_revoked.
Qed.

Theorem combined_open_rejected_by_matching_compromise_notice :
  forall obj cap state revoked notice notices,
    compromise_notice_matches_state notice state = true ->
    open_allowed_under_revocation_and_compromise obj cap state revoked (notice :: notices) = false.
Proof.
  intros obj cap state revoked notice notices H_match.
  apply revoked_or_compromised_blocks_combined_open.
  right.
  apply compromise_notice_in_list_cons_match.
  exact H_match.
Qed.

Theorem no_reopened_access_after_new_revocation :
  forall obj cap state revoked notices,
    open_allowed_under_revocation_and_compromise obj cap state (cap_stamp cap :: revoked) notices = false.
Proof.
  intros obj cap state revoked notices.
  apply revoked_or_compromised_blocks_combined_open.
  left.
  unfold capability_revoked_by_set.
  apply stamp_in_revocation_set_cons_self.
Qed.
