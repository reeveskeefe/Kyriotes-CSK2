From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
Require Import ArcTypes ArcMerkle ArcAuthority ArcPolicy ArcVerify ArcSecurityGame ArcTheorems ArcStressProofs ArcDelegationProofs ArcCryptoReduction ArcTemporalProofs ArcTranscriptProofs ArcRevocationCompromiseProofs ArcTransparencyProofs ArcEncodingProofs ArcWrapperProofs ArcKemAeadAssumptions.

Definition end_to_end_open_allowed
  (obj : ArcObject)
  (cap : Capability)
  (state : AuthorityState)
  (transcript : ArcTranscript)
  (commit : TransparencyCommit)
  (wrapper : AuthorityWrapper)
  (revoked : list nat)
  (notices : list CompromiseNotice)
  (assumptions : PrimitiveAssumptions)
  : bool :=
  transcript_accepts_open transcript obj cap state &&
  transparency_open_allowed obj cap state commit &&
  wrapper_open_allowed obj cap state wrapper &&
  open_allowed_under_revocation_and_compromise obj cap state revoked notices &&
  primitive_assumptions_hold assumptions.

Theorem end_to_end_open_implies_transcript_acceptance :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    transcript_accepts_open transcript obj cap state = true.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  unfold end_to_end_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_transcript H_transparency] H_wrapper] H_rev_comp] H_assumptions].
  exact H_transcript.
Qed.

Theorem end_to_end_open_implies_transparency_open :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    transparency_open_allowed obj cap state commit = true.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  unfold end_to_end_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_transcript H_transparency] H_wrapper] H_rev_comp] H_assumptions].
  exact H_transparency.
Qed.

Theorem end_to_end_open_implies_wrapper_open :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    wrapper_open_allowed obj cap state wrapper = true.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  unfold end_to_end_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_transcript H_transparency] H_wrapper] H_rev_comp] H_assumptions].
  exact H_wrapper.
Qed.

Theorem end_to_end_open_implies_revocation_compromise_open :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    open_allowed_under_revocation_and_compromise obj cap state revoked notices = true.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  unfold end_to_end_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_transcript H_transparency] H_wrapper] H_rev_comp] H_assumptions].
  exact H_rev_comp.
Qed.

Theorem end_to_end_open_implies_primitive_assumptions :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    primitive_assumptions_hold assumptions = true.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  unfold end_to_end_open_allowed in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_transcript H_transparency] H_wrapper] H_rev_comp] H_assumptions].
  exact H_assumptions.
Qed.

Theorem end_to_end_open_implies_verified_open :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    verify_open_context obj cap state = true.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  pose proof (end_to_end_open_implies_transcript_acceptance obj cap state transcript commit wrapper revoked notices assumptions H) as H_transcript.
  apply transcript_acceptance_implies_verified_open with (tr := transcript).
  exact H_transcript.
Qed.

Theorem end_to_end_open_implies_arc_safety :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    capability_in_authority_root cap state = true /\
    capability_not_revoked cap state = true /\
    policy_accepts cap obj = true /\
    object_bound_to_state obj state = true /\
    authority_state_valid state = true.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  apply arc_verified_open_safety.
  apply end_to_end_open_implies_verified_open with
    (transcript := transcript)
    (commit := commit)
    (wrapper := wrapper)
    (revoked := revoked)
    (notices := notices)
    (assumptions := assumptions).
  exact H.
Qed.

Theorem end_to_end_open_implies_transcript_binding :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    transcript_object_id transcript = object_id obj /\
    transcript_required_rights transcript = required_rights obj /\
    transcript_authority_root transcript = bound_authority_root obj /\
    transcript_revocation_root transcript = bound_revocation_root obj /\
    transcript_transparency_root transcript = bound_transparency_root obj /\
    transcript_epoch transcript = bound_epoch obj /\
    transcript_context_hash transcript = aad_context_hash obj.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  apply transcript_acceptance_implies_exact_object_fields with (cap := cap) (state := state).
  apply end_to_end_open_implies_transcript_acceptance with
    (commit := commit)
    (wrapper := wrapper)
    (revoked := revoked)
    (notices := notices)
    (assumptions := assumptions).
  exact H.
Qed.

Theorem end_to_end_open_implies_transparency_binding :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    bound_authority_root obj = authority_root state /\
    bound_revocation_root obj = revocation_root state /\
    bound_transparency_root obj = transparency_root state /\
    bound_epoch obj = epoch state.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  apply transparency_open_implies_exact_cross_binding with (commit := commit) (cap := cap).
  apply end_to_end_open_implies_transparency_open with
    (transcript := transcript)
    (wrapper := wrapper)
    (revoked := revoked)
    (notices := notices)
    (assumptions := assumptions).
  exact H.
Qed.

Theorem end_to_end_open_implies_wrapper_binding :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    wrapper_epoch wrapper = bound_epoch obj /\
    wrapper_epoch wrapper = epoch state.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  apply wrapper_open_implies_exact_epoch_binding with (cap := cap).
  apply end_to_end_open_implies_wrapper_open with
    (transcript := transcript)
    (commit := commit)
    (revoked := revoked)
    (notices := notices)
    (assumptions := assumptions).
  exact H.
Qed.

Theorem end_to_end_open_implies_no_revocation_or_compromise :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    capability_revoked_by_set cap revoked = false /\
    compromise_notice_in_list state notices = false.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  pose proof (end_to_end_open_implies_revocation_compromise_open obj cap state transcript commit wrapper revoked notices assumptions H) as H_rev_comp.
  pose proof (combined_open_implies_no_revocation_and_no_compromise obj cap state revoked notices H_rev_comp)
    as [_ [H_revoked H_compromise]].
  split; assumption.
Qed.

Theorem end_to_end_open_implies_temporal_window :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = true ->
    cap_epoch_start cap <= bound_epoch obj /\
    bound_epoch obj <= cap_epoch_end cap.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H.
  apply verified_open_implies_temporal_epoch_window with (state := state).
  apply end_to_end_open_implies_verified_open with
    (transcript := transcript)
    (commit := commit)
    (wrapper := wrapper)
    (revoked := revoked)
    (notices := notices)
    (assumptions := assumptions).
  exact H.
Qed.

Theorem end_to_end_rejects_revoked_capability :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    capability_revoked_by_set cap revoked = true ->
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = false.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H_revoked.
  unfold end_to_end_open_allowed.
  destruct (transcript_accepts_open transcript obj cap state); simpl.
  - destruct (transparency_open_allowed obj cap state commit); simpl.
    + destruct (wrapper_open_allowed obj cap state wrapper); simpl.
      * pose proof (revoked_or_compromised_blocks_combined_open obj cap state revoked notices (or_introl H_revoked)) as H_block.
        rewrite H_block.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem end_to_end_rejects_compromised_state :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    compromise_notice_in_list state notices = true ->
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = false.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H_compromise.
  unfold end_to_end_open_allowed.
  destruct (transcript_accepts_open transcript obj cap state); simpl.
  - destruct (transparency_open_allowed obj cap state commit); simpl.
    + destruct (wrapper_open_allowed obj cap state wrapper); simpl.
      * pose proof (revoked_or_compromised_blocks_combined_open obj cap state revoked notices (or_intror H_compromise)) as H_block.
        rewrite H_block.
        reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem end_to_end_rejects_failed_primitive_assumptions :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    primitive_assumptions_hold assumptions = false ->
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = false.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H_assumptions.
  unfold end_to_end_open_allowed.
  destruct (transcript_accepts_open transcript obj cap state); simpl.
  - destruct (transparency_open_allowed obj cap state commit); simpl.
    + destruct (wrapper_open_allowed obj cap state wrapper); simpl.
      * destruct (open_allowed_under_revocation_and_compromise obj cap state revoked notices); simpl.
        -- exact H_assumptions.
        -- reflexivity.
      * reflexivity.
    + reflexivity.
  - reflexivity.
Qed.

Theorem end_to_end_key_only_is_insufficient :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    policy_accepts cap obj = false ->
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = false.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H_policy.
  unfold end_to_end_open_allowed.
  destruct (transcript_accepts_open transcript obj cap state) eqn:H_transcript; simpl.
  - pose proof (transcript_acceptance_implies_verified_open transcript obj cap state H_transcript) as H_open.
    pose proof (verify_open_context_implies_policy_accepts obj cap state H_open) as H_policy_true.
    rewrite H_policy_true in H_policy.
    discriminate.
  - reflexivity.
Qed.

Theorem end_to_end_capability_only_is_insufficient :
  forall obj cap state transcript commit wrapper revoked notices assumptions,
    object_bound_to_state obj state = false ->
    end_to_end_open_allowed obj cap state transcript commit wrapper revoked notices assumptions = false.
Proof.
  intros obj cap state transcript commit wrapper revoked notices assumptions H_bound.
  unfold end_to_end_open_allowed.
  destruct (transcript_accepts_open transcript obj cap state) eqn:H_transcript; simpl.
  - pose proof (transcript_acceptance_implies_verified_open transcript obj cap state H_transcript) as H_open.
    pose proof (verify_open_context_implies_object_bound obj cap state H_open) as H_bound_true.
    rewrite H_bound_true in H_bound.
    discriminate.
  - reflexivity.
Qed.
