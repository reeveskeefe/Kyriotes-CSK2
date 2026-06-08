From Coq Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types KyriotesCsk2Merkle KyriotesCsk2Authority KyriotesCsk2Policy KyriotesCsk2Verify KyriotesCsk2SecurityGame KyriotesCsk2Theorems KyriotesCsk2StressProofs KyriotesCsk2DelegationProofs KyriotesCsk2CryptoReduction KyriotesCsk2TemporalProofs KyriotesCsk2TranscriptProofs KyriotesCsk2RevocationCompromiseProofs KyriotesCsk2TransparencyProofs.

Definition EncodedBytes := list nat.

Record DecodeLimits := {
  max_payload_len : nat;
  max_wrapper_count : nat;
  max_proof_siblings : nat;
  max_context_len : nat
}.

Record EncodedKyriotesCsk2Object := {
  encoded_magic : nat;
  encoded_payload_len : nat;
  encoded_wrapper_count : nat;
  encoded_proof_siblings : nat;
  encoded_context_len : nat;
  encoded_object : KyriotesCsk2Object
}.

(* Symbolic tag for the structured Coq codec. The production byte codec's
   literal KCS2 magic is checked by the Rust/Kani refinement lane. *)
Definition KYRIOTES_CSK2_MAGIC : nat := 1.

Definition magic_valid (encoded : EncodedKyriotesCsk2Object) : bool :=
  Nat.eqb (encoded_magic encoded) KYRIOTES_CSK2_MAGIC.

Definition payload_within_limit (limits : DecodeLimits) (encoded : EncodedKyriotesCsk2Object) : bool :=
  Nat.leb (encoded_payload_len encoded) (max_payload_len limits).

Definition wrapper_count_within_limit (limits : DecodeLimits) (encoded : EncodedKyriotesCsk2Object) : bool :=
  Nat.leb (encoded_wrapper_count encoded) (max_wrapper_count limits).

Definition proof_siblings_within_limit (limits : DecodeLimits) (encoded : EncodedKyriotesCsk2Object) : bool :=
  Nat.leb (encoded_proof_siblings encoded) (max_proof_siblings limits).

Definition context_within_limit (limits : DecodeLimits) (encoded : EncodedKyriotesCsk2Object) : bool :=
  Nat.leb (encoded_context_len encoded) (max_context_len limits).

Definition decode_shape_valid (limits : DecodeLimits) (encoded : EncodedKyriotesCsk2Object) : bool :=
  magic_valid encoded &&
  payload_within_limit limits encoded &&
  wrapper_count_within_limit limits encoded &&
  proof_siblings_within_limit limits encoded &&
  context_within_limit limits encoded.

Definition CANONICAL_PAYLOAD_LEN : nat := 0.
Definition CANONICAL_WRAPPER_COUNT : nat := 1.
Definition CANONICAL_PROOF_SIBLINGS : nat := 0.
Definition CANONICAL_CONTEXT_LEN : nat := 1.

Definition canonical_encoding_shape (encoded : EncodedKyriotesCsk2Object) : bool :=
  Nat.eqb (encoded_magic encoded) KYRIOTES_CSK2_MAGIC &&
  Nat.eqb (encoded_payload_len encoded) CANONICAL_PAYLOAD_LEN &&
  Nat.eqb (encoded_wrapper_count encoded) CANONICAL_WRAPPER_COUNT &&
  Nat.eqb (encoded_proof_siblings encoded) CANONICAL_PROOF_SIBLINGS &&
  Nat.eqb (encoded_context_len encoded) CANONICAL_CONTEXT_LEN.

Definition canonical_encode_object
  (obj : KyriotesCsk2Object)
  : EncodedKyriotesCsk2Object :=
  {|
    encoded_magic := KYRIOTES_CSK2_MAGIC;
    encoded_payload_len := CANONICAL_PAYLOAD_LEN;
    encoded_wrapper_count := CANONICAL_WRAPPER_COUNT;
    encoded_proof_siblings := CANONICAL_PROOF_SIBLINGS;
    encoded_context_len := CANONICAL_CONTEXT_LEN;
    encoded_object := obj
  |}.

Definition canonical_decode_object
  (limits : DecodeLimits)
  (encoded : EncodedKyriotesCsk2Object)
  : option KyriotesCsk2Object :=
  if decode_shape_valid limits encoded && canonical_encoding_shape encoded
  then Some (encoded_object encoded)
  else None.

Theorem canonical_decode_correct :
  forall limits encoded,
    decode_shape_valid limits encoded = true ->
    canonical_encoding_shape encoded = true ->
    canonical_decode_object limits encoded = Some (encoded_object encoded).
Proof.
  intros limits encoded H_shape H_canonical.
  unfold canonical_decode_object.
  rewrite H_shape, H_canonical.
  reflexivity.
Qed.

Theorem canonical_decode_rejects_invalid_shape :
  forall limits encoded,
    decode_shape_valid limits encoded = false ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H_shape.
  unfold canonical_decode_object.
  rewrite H_shape.
  reflexivity.
Qed.

Theorem canonical_decode_rejects_noncanonical_shape :
  forall limits encoded,
    canonical_encoding_shape encoded = false ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H_canonical.
  unfold canonical_decode_object.
  rewrite H_canonical.
  destruct (decode_shape_valid limits encoded); reflexivity.
Qed.

Theorem canonical_encode_has_canonical_shape :
  forall obj,
    canonical_encoding_shape (canonical_encode_object obj) = true.
Proof.
  intros obj.
  unfold canonical_encoding_shape, canonical_encode_object.
  simpl.
  repeat rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem canonical_encode_decode_roundtrip :
  forall limits obj,
    decode_shape_valid limits (canonical_encode_object obj) = true ->
    canonical_decode_object limits (canonical_encode_object obj) = Some obj.
Proof.
  intros limits obj H_shape.
  apply canonical_decode_correct.
  - exact H_shape.
  - apply canonical_encode_has_canonical_shape.
Qed.

Theorem bad_magic_rejected :
  forall limits encoded,
    encoded_magic encoded <> KYRIOTES_CSK2_MAGIC ->
    decode_shape_valid limits encoded = false.
Proof.
  intros limits encoded H.
  unfold decode_shape_valid.
  unfold magic_valid.
  apply Nat.eqb_neq in H.
  rewrite H.
  reflexivity.
Qed.

Theorem oversized_payload_rejected :
  forall limits encoded,
    max_payload_len limits < encoded_payload_len encoded ->
    decode_shape_valid limits encoded = false.
Proof.
  intros limits encoded H.
  unfold decode_shape_valid.
  assert (payload_within_limit limits encoded = false) as H_payload.
  {
    unfold payload_within_limit.
    apply Nat.leb_gt.
    exact H.
  }
  rewrite H_payload.
  destruct (magic_valid encoded); reflexivity.
Qed.

Theorem oversized_wrapper_count_rejected :
  forall limits encoded,
    max_wrapper_count limits < encoded_wrapper_count encoded ->
    decode_shape_valid limits encoded = false.
Proof.
  intros limits encoded H.
  unfold decode_shape_valid.
  assert (wrapper_count_within_limit limits encoded = false) as H_wrapper.
  {
    unfold wrapper_count_within_limit.
    apply Nat.leb_gt.
    exact H.
  }
  rewrite H_wrapper.
  destruct (magic_valid encoded); destruct (payload_within_limit limits encoded); reflexivity.
Qed.

Theorem oversized_proof_siblings_rejected :
  forall limits encoded,
    max_proof_siblings limits < encoded_proof_siblings encoded ->
    decode_shape_valid limits encoded = false.
Proof.
  intros limits encoded H.
  unfold decode_shape_valid.
  assert (proof_siblings_within_limit limits encoded = false) as H_proof.
  {
    unfold proof_siblings_within_limit.
    apply Nat.leb_gt.
    exact H.
  }
  rewrite H_proof.
  destruct (magic_valid encoded);
  destruct (payload_within_limit limits encoded);
  destruct (wrapper_count_within_limit limits encoded);
  reflexivity.
Qed.

Theorem oversized_context_rejected :
  forall limits encoded,
    max_context_len limits < encoded_context_len encoded ->
    decode_shape_valid limits encoded = false.
Proof.
  intros limits encoded H.
  unfold decode_shape_valid.
  assert (context_within_limit limits encoded = false) as H_context.
  {
    unfold context_within_limit.
    apply Nat.leb_gt.
    exact H.
  }
  rewrite H_context.
  destruct (magic_valid encoded);
  destruct (payload_within_limit limits encoded);
  destruct (wrapper_count_within_limit limits encoded);
  destruct (proof_siblings_within_limit limits encoded);
  reflexivity.
Qed.

Theorem invalid_shape_decodes_to_none :
  forall limits encoded,
    decode_shape_valid limits encoded = false ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H.
  apply canonical_decode_rejects_invalid_shape.
  exact H.
Qed.

Theorem valid_shape_decodes_to_embedded_object :
  forall limits encoded,
    decode_shape_valid limits encoded = true ->
    canonical_encoding_shape encoded = true ->
    canonical_decode_object limits encoded = Some (encoded_object encoded).
Proof.
  intros limits encoded H_shape H_canonical.
  apply canonical_decode_correct.
  - exact H_shape.
  - exact H_canonical.
Qed.

Theorem bad_magic_decodes_to_none :
  forall limits encoded,
    encoded_magic encoded <> KYRIOTES_CSK2_MAGIC ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H.
  apply invalid_shape_decodes_to_none.
  apply bad_magic_rejected.
  exact H.
Qed.

Theorem oversized_payload_decodes_to_none :
  forall limits encoded,
    max_payload_len limits < encoded_payload_len encoded ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H.
  apply invalid_shape_decodes_to_none.
  apply oversized_payload_rejected.
  exact H.
Qed.

Theorem oversized_wrapper_count_decodes_to_none :
  forall limits encoded,
    max_wrapper_count limits < encoded_wrapper_count encoded ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H.
  apply invalid_shape_decodes_to_none.
  apply oversized_wrapper_count_rejected.
  exact H.
Qed.

Theorem oversized_proof_siblings_decodes_to_none :
  forall limits encoded,
    max_proof_siblings limits < encoded_proof_siblings encoded ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H.
  apply invalid_shape_decodes_to_none.
  apply oversized_proof_siblings_rejected.
  exact H.
Qed.

Theorem oversized_context_decodes_to_none :
  forall limits encoded,
    max_context_len limits < encoded_context_len encoded ->
    canonical_decode_object limits encoded = None.
Proof.
  intros limits encoded H.
  apply invalid_shape_decodes_to_none.
  apply oversized_context_rejected.
  exact H.
Qed.

Theorem canonical_roundtrip_preserves_object :
  forall limits obj,
    decode_shape_valid limits (canonical_encode_object obj) = true ->
    canonical_decode_object limits (canonical_encode_object obj) = Some obj.
Proof.
  intros limits obj H.
  apply canonical_encode_decode_roundtrip.
  exact H.
Qed.

Theorem canonical_shape_reencodes_exactly :
  forall encoded,
    canonical_encoding_shape encoded = true ->
    canonical_encode_object (encoded_object encoded) = encoded.
Proof.
  intros [magic payload wrappers siblings context obj] H.
  unfold canonical_encoding_shape in H.
  simpl in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[H_magic H_payload] H_wrappers] H_siblings] H_context].
  apply Nat.eqb_eq in H_magic.
  apply Nat.eqb_eq in H_payload.
  apply Nat.eqb_eq in H_wrappers.
  apply Nat.eqb_eq in H_siblings.
  apply Nat.eqb_eq in H_context.
  simpl.
  subst.
  reflexivity.
Qed.

Theorem accepted_decode_implies_shape_valid_and_canonical :
  forall limits encoded obj,
    canonical_decode_object limits encoded = Some obj ->
    decode_shape_valid limits encoded = true /\
    canonical_encoding_shape encoded = true /\
    obj = encoded_object encoded.
Proof.
  intros limits encoded obj H.
  unfold canonical_decode_object in H.
  destruct (decode_shape_valid limits encoded) eqn:H_shape.
  - destruct (canonical_encoding_shape encoded) eqn:H_canonical.
    + inversion H.
      repeat split; assumption.
    + discriminate.
  - discriminate.
Qed.

Theorem accepted_decode_reencodes_exactly :
  forall limits encoded obj,
    canonical_decode_object limits encoded = Some obj ->
    canonical_encode_object obj = encoded.
Proof.
  intros limits encoded obj H_decode.
  pose proof
    (accepted_decode_implies_shape_valid_and_canonical
      limits encoded obj H_decode)
    as [_ [H_canonical H_obj]].
  rewrite H_obj.
  apply canonical_shape_reencodes_exactly.
  exact H_canonical.
Qed.
