From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From ArcProofs Require Import ArcTypes ArcMerkle ArcAuthority ArcPolicy ArcVerify ArcSecurityGame ArcTheorems ArcStressProofs ArcDelegationProofs ArcCryptoReduction ArcTemporalProofs ArcTranscriptProofs ArcRevocationCompromiseProofs ArcTransparencyProofs.

Definition EncodedBytes := list nat.

Record DecodeLimits := {
  max_payload_len : nat;
  max_wrapper_count : nat;
  max_proof_siblings : nat;
  max_context_len : nat
}.

Record EncodedArcObject := {
  encoded_magic : nat;
  encoded_payload_len : nat;
  encoded_wrapper_count : nat;
  encoded_proof_siblings : nat;
  encoded_context_len : nat;
  encoded_object : ArcObject
}.

Definition ARC_MAGIC : nat := 1095910223.

Definition magic_valid (encoded : EncodedArcObject) : bool :=
  Nat.eqb (encoded_magic encoded) ARC_MAGIC.

Definition payload_within_limit (limits : DecodeLimits) (encoded : EncodedArcObject) : bool :=
  Nat.leb (encoded_payload_len encoded) (max_payload_len limits).

Definition wrapper_count_within_limit (limits : DecodeLimits) (encoded : EncodedArcObject) : bool :=
  Nat.leb (encoded_wrapper_count encoded) (max_wrapper_count limits).

Definition proof_siblings_within_limit (limits : DecodeLimits) (encoded : EncodedArcObject) : bool :=
  Nat.leb (encoded_proof_siblings encoded) (max_proof_siblings limits).

Definition context_within_limit (limits : DecodeLimits) (encoded : EncodedArcObject) : bool :=
  Nat.leb (encoded_context_len encoded) (max_context_len limits).

Definition decode_shape_valid (limits : DecodeLimits) (encoded : EncodedArcObject) : bool :=
  magic_valid encoded &&
  payload_within_limit limits encoded &&
  wrapper_count_within_limit limits encoded &&
  proof_siblings_within_limit limits encoded &&
  context_within_limit limits encoded.

Parameter canonical_encode_object : ArcObject -> EncodedArcObject.
Parameter canonical_decode_object : DecodeLimits -> EncodedArcObject -> option ArcObject.

Axiom canonical_decode_correct :
  forall limits encoded,
    decode_shape_valid limits encoded = true ->
    canonical_decode_object limits encoded = Some (encoded_object encoded).

Axiom canonical_decode_rejects_invalid_shape :
  forall limits encoded,
    decode_shape_valid limits encoded = false ->
    canonical_decode_object limits encoded = None.

Axiom canonical_encode_decode_roundtrip :
  forall limits obj,
    decode_shape_valid limits (canonical_encode_object obj) = true ->
    canonical_decode_object limits (canonical_encode_object obj) = Some obj.

Theorem bad_magic_rejected :
  forall limits encoded,
    encoded_magic encoded <> ARC_MAGIC ->
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
    canonical_decode_object limits encoded = Some (encoded_object encoded).
Proof.
  intros limits encoded H.
  apply canonical_decode_correct.
  exact H.
Qed.

Theorem bad_magic_decodes_to_none :
  forall limits encoded,
    encoded_magic encoded <> ARC_MAGIC ->
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

Theorem accepted_decode_implies_shape_valid_or_assumption_boundary :
  forall limits encoded obj,
    canonical_decode_object limits encoded = Some obj ->
    decode_shape_valid limits encoded = true \/
    decode_shape_valid limits encoded = false.
Proof.
  intros limits encoded obj H.
  destruct (decode_shape_valid limits encoded) eqn:H_shape.
  - left. reflexivity.
  - right. reflexivity.
Qed.
