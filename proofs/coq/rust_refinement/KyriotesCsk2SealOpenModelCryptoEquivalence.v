From Coq Require Import List Bool Arith.PeanoNat.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2SealRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2OpenRustRefinement.
Import ListNotations.

Record ModelCryptoBinding := {
  model_bind_object_id : ObjectId;
  model_bind_rights : Rights;
  model_bind_policy_hash : Hash;
  model_bind_epoch : Epoch;
  model_bind_authority_root : Hash;
  model_bind_revocation_root : Hash;
  model_bind_transparency_root : Hash;
  model_bind_capability_stamp : nat;
  model_bind_temporal_policy : nat
}.

Record ModelRecipient := {
  model_recipient_public : nat;
  model_recipient_secret : nat
}.

Record ModelPayloadCiphertext := {
  model_payload_binding : ModelCryptoBinding;
  model_payload_dek : nat;
  model_payload_plaintext : Bytes
}.

Record ModelWrappedDek := {
  model_wrapper_binding : ModelCryptoBinding;
  model_wrapper_recipient_public : nat;
  model_wrapper_dek : nat
}.

Record ModelSealedObject := {
  model_sealed_binding : ModelCryptoBinding;
  model_sealed_epoch : Epoch;
  model_sealed_recipient_public : nat;
  model_sealed_payload_ciphertext : ModelPayloadCiphertext;
  model_sealed_wrapped_dek : ModelWrappedDek
}.

Definition model_crypto_binding_eqb (left right : ModelCryptoBinding) : bool :=
  Nat.eqb (model_bind_object_id left) (model_bind_object_id right) &&
  Nat.eqb (model_bind_rights left) (model_bind_rights right) &&
  Nat.eqb (model_bind_policy_hash left) (model_bind_policy_hash right) &&
  Nat.eqb (model_bind_epoch left) (model_bind_epoch right) &&
  Nat.eqb (model_bind_authority_root left) (model_bind_authority_root right) &&
  Nat.eqb (model_bind_revocation_root left) (model_bind_revocation_root right) &&
  Nat.eqb (model_bind_transparency_root left) (model_bind_transparency_root right) &&
  Nat.eqb (model_bind_capability_stamp left) (model_bind_capability_stamp right) &&
  Nat.eqb (model_bind_temporal_policy left) (model_bind_temporal_policy right).

Lemma model_crypto_binding_eqb_refl :
  forall binding, model_crypto_binding_eqb binding binding = true.
Proof.
  intros binding.
  unfold model_crypto_binding_eqb.
  repeat rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Definition model_dek (binding : ModelCryptoBinding) (recipient_public : nat) : nat :=
  model_bind_object_id binding +
  model_bind_rights binding +
  model_bind_policy_hash binding +
  model_bind_epoch binding +
  model_bind_authority_root binding +
  model_bind_revocation_root binding +
  model_bind_transparency_root binding +
  model_bind_capability_stamp binding +
  model_bind_temporal_policy binding +
  recipient_public.

Definition model_encrypt_payload
  (binding : ModelCryptoBinding)
  (dek : nat)
  (message : Bytes)
  : ModelPayloadCiphertext :=
  {|
    model_payload_binding := binding;
    model_payload_dek := dek;
    model_payload_plaintext := message
  |}.

Definition model_decrypt_payload
  (binding : ModelCryptoBinding)
  (dek : nat)
  (ciphertext : ModelPayloadCiphertext)
  : option Bytes :=
  if model_crypto_binding_eqb binding (model_payload_binding ciphertext)
  then
    if Nat.eqb dek (model_payload_dek ciphertext)
    then Some (model_payload_plaintext ciphertext)
    else None
  else None.

Definition model_wrap_dek
  (binding : ModelCryptoBinding)
  (recipient_public : nat)
  (dek : nat)
  : ModelWrappedDek :=
  {|
    model_wrapper_binding := binding;
    model_wrapper_recipient_public := recipient_public;
    model_wrapper_dek := dek
  |}.

Definition model_unwrap_dek
  (binding : ModelCryptoBinding)
  (recipient_secret : nat)
  (wrapped : ModelWrappedDek)
  : option nat :=
  if model_crypto_binding_eqb binding (model_wrapper_binding wrapped)
  then
    if Nat.eqb recipient_secret (model_wrapper_recipient_public wrapped)
    then Some (model_wrapper_dek wrapped)
    else None
  else None.

Definition model_seal
  (recipient : ModelRecipient)
  (binding : ModelCryptoBinding)
  (message : Bytes)
  : ModelSealedObject :=
  let dek := model_dek binding (model_recipient_public recipient) in
  {|
    model_sealed_binding := binding;
    model_sealed_epoch := model_bind_epoch binding;
    model_sealed_recipient_public := model_recipient_public recipient;
    model_sealed_payload_ciphertext := model_encrypt_payload binding dek message;
    model_sealed_wrapped_dek := model_wrap_dek binding (model_recipient_public recipient) dek
  |}.

Definition model_open
  (recipient_secret : nat)
  (expected_binding : ModelCryptoBinding)
  (expected_epoch : Epoch)
  (sealed : ModelSealedObject)
  : option Bytes :=
  if Nat.eqb expected_epoch (model_sealed_epoch sealed)
  then
    if model_crypto_binding_eqb expected_binding (model_sealed_binding sealed)
    then
      match model_unwrap_dek expected_binding recipient_secret (model_sealed_wrapped_dek sealed) with
      | Some dek => model_decrypt_payload expected_binding dek (model_sealed_payload_ciphertext sealed)
      | None => None
      end
    else None
  else None.

Theorem model_open_after_model_seal_returns_message :
  forall binding recipient message,
    model_recipient_secret recipient = model_recipient_public recipient ->
    model_open
      (model_recipient_secret recipient)
      binding
      (model_bind_epoch binding)
      (model_seal recipient binding message) = Some message.
Proof.
  intros binding recipient message Hmatching_secret.
  unfold model_open, model_seal, model_unwrap_dek, model_decrypt_payload,
    model_wrap_dek, model_encrypt_payload.
  simpl.
  repeat rewrite model_crypto_binding_eqb_refl.
  repeat rewrite Nat.eqb_refl.
  rewrite Hmatching_secret.
  rewrite Nat.eqb_refl.
  replace (model_dek binding (model_recipient_public recipient) =?
           model_dek binding (model_recipient_public recipient)) with true
    by (symmetry; apply Nat.eqb_refl).
  reflexivity.
Qed.

Definition model_sample_binding : ModelCryptoBinding :=
  {|
    model_bind_object_id := 11;
    model_bind_rights := 7;
    model_bind_policy_hash := 19;
    model_bind_epoch := 3;
    model_bind_authority_root := 23;
    model_bind_revocation_root := 29;
    model_bind_transparency_root := 31;
    model_bind_capability_stamp := 37;
    model_bind_temporal_policy := 41
  |}.

Definition model_sample_recipient : ModelRecipient :=
  {|
    model_recipient_public := 5;
    model_recipient_secret := 5
  |}.

Definition model_sample_message : Bytes := [1; 2; 3; 4].

Definition model_sample_sealed : ModelSealedObject :=
  model_seal model_sample_recipient model_sample_binding model_sample_message.

Definition model_binding_with_object_id (object_id : ObjectId) : ModelCryptoBinding :=
  {|
    model_bind_object_id := object_id;
    model_bind_rights := model_bind_rights model_sample_binding;
    model_bind_policy_hash := model_bind_policy_hash model_sample_binding;
    model_bind_epoch := model_bind_epoch model_sample_binding;
    model_bind_authority_root := model_bind_authority_root model_sample_binding;
    model_bind_revocation_root := model_bind_revocation_root model_sample_binding;
    model_bind_transparency_root := model_bind_transparency_root model_sample_binding;
    model_bind_capability_stamp := model_bind_capability_stamp model_sample_binding;
    model_bind_temporal_policy := model_bind_temporal_policy model_sample_binding
  |}.

Definition model_binding_with_policy_hash (policy_hash : Hash) : ModelCryptoBinding :=
  {|
    model_bind_object_id := model_bind_object_id model_sample_binding;
    model_bind_rights := model_bind_rights model_sample_binding;
    model_bind_policy_hash := policy_hash;
    model_bind_epoch := model_bind_epoch model_sample_binding;
    model_bind_authority_root := model_bind_authority_root model_sample_binding;
    model_bind_revocation_root := model_bind_revocation_root model_sample_binding;
    model_bind_transparency_root := model_bind_transparency_root model_sample_binding;
    model_bind_capability_stamp := model_bind_capability_stamp model_sample_binding;
    model_bind_temporal_policy := model_bind_temporal_policy model_sample_binding
  |}.

Definition model_binding_with_capability_stamp (stamp : nat) : ModelCryptoBinding :=
  {|
    model_bind_object_id := model_bind_object_id model_sample_binding;
    model_bind_rights := model_bind_rights model_sample_binding;
    model_bind_policy_hash := model_bind_policy_hash model_sample_binding;
    model_bind_epoch := model_bind_epoch model_sample_binding;
    model_bind_authority_root := model_bind_authority_root model_sample_binding;
    model_bind_revocation_root := model_bind_revocation_root model_sample_binding;
    model_bind_transparency_root := model_bind_transparency_root model_sample_binding;
    model_bind_capability_stamp := stamp;
    model_bind_temporal_policy := model_bind_temporal_policy model_sample_binding
  |}.

Definition model_binding_with_authority_root (root : Hash) : ModelCryptoBinding :=
  {|
    model_bind_object_id := model_bind_object_id model_sample_binding;
    model_bind_rights := model_bind_rights model_sample_binding;
    model_bind_policy_hash := model_bind_policy_hash model_sample_binding;
    model_bind_epoch := model_bind_epoch model_sample_binding;
    model_bind_authority_root := root;
    model_bind_revocation_root := model_bind_revocation_root model_sample_binding;
    model_bind_transparency_root := model_bind_transparency_root model_sample_binding;
    model_bind_capability_stamp := model_bind_capability_stamp model_sample_binding;
    model_bind_temporal_policy := model_bind_temporal_policy model_sample_binding
  |}.

Definition model_sealed_with_payload_ciphertext
  (ciphertext : ModelPayloadCiphertext)
  : ModelSealedObject :=
  {|
    model_sealed_binding := model_sealed_binding model_sample_sealed;
    model_sealed_epoch := model_sealed_epoch model_sample_sealed;
    model_sealed_recipient_public := model_sealed_recipient_public model_sample_sealed;
    model_sealed_payload_ciphertext := ciphertext;
    model_sealed_wrapped_dek := model_sealed_wrapped_dek model_sample_sealed
  |}.

Definition model_sealed_with_wrapped_dek
  (wrapped : ModelWrappedDek)
  : ModelSealedObject :=
  {|
    model_sealed_binding := model_sealed_binding model_sample_sealed;
    model_sealed_epoch := model_sealed_epoch model_sample_sealed;
    model_sealed_recipient_public := model_sealed_recipient_public model_sample_sealed;
    model_sealed_payload_ciphertext := model_sealed_payload_ciphertext model_sample_sealed;
    model_sealed_wrapped_dek := wrapped
  |}.

Definition model_tampered_payload_ciphertext : ModelPayloadCiphertext :=
  {|
    model_payload_binding := model_payload_binding (model_sealed_payload_ciphertext model_sample_sealed);
    model_payload_dek := S (model_payload_dek (model_sealed_payload_ciphertext model_sample_sealed));
    model_payload_plaintext := model_payload_plaintext (model_sealed_payload_ciphertext model_sample_sealed)
  |}.

Definition model_tampered_wrapped_dek : ModelWrappedDek :=
  {|
    model_wrapper_binding := model_binding_with_policy_hash 20;
    model_wrapper_recipient_public := model_wrapper_recipient_public (model_sealed_wrapped_dek model_sample_sealed);
    model_wrapper_dek := model_wrapper_dek (model_sealed_wrapped_dek model_sample_sealed)
  |}.

Theorem model_open_rejects_wrong_recipient_secret :
  model_open 6 model_sample_binding (model_bind_epoch model_sample_binding) model_sample_sealed = None.
Proof. reflexivity. Qed.

Theorem model_open_rejects_altered_object_id :
  model_open
    (model_recipient_secret model_sample_recipient)
    (model_binding_with_object_id 12)
    (model_bind_epoch model_sample_binding)
    model_sample_sealed = None.
Proof. reflexivity. Qed.

Theorem model_open_rejects_altered_policy_hash :
  model_open
    (model_recipient_secret model_sample_recipient)
    (model_binding_with_policy_hash 20)
    (model_bind_epoch model_sample_binding)
    model_sample_sealed = None.
Proof. reflexivity. Qed.

Theorem model_open_rejects_altered_capability_stamp :
  model_open
    (model_recipient_secret model_sample_recipient)
    (model_binding_with_capability_stamp 38)
    (model_bind_epoch model_sample_binding)
    model_sample_sealed = None.
Proof. reflexivity. Qed.

Theorem model_open_rejects_altered_authority_root :
  model_open
    (model_recipient_secret model_sample_recipient)
    (model_binding_with_authority_root 24)
    (model_bind_epoch model_sample_binding)
    model_sample_sealed = None.
Proof. reflexivity. Qed.

Theorem model_open_rejects_altered_payload_ciphertext :
  model_open
    (model_recipient_secret model_sample_recipient)
    model_sample_binding
    (model_bind_epoch model_sample_binding)
    (model_sealed_with_payload_ciphertext model_tampered_payload_ciphertext) = None.
Proof. reflexivity. Qed.

Theorem model_open_rejects_altered_wrapper_binding :
  model_open
    (model_recipient_secret model_sample_recipient)
    model_sample_binding
    (model_bind_epoch model_sample_binding)
    (model_sealed_with_wrapped_dek model_tampered_wrapped_dek) = None.
Proof. reflexivity. Qed.

Theorem model_open_rejects_wrong_epoch_wrapper_selection :
  model_open
    (model_recipient_secret model_sample_recipient)
    model_sample_binding
    4
    model_sample_sealed = None.
Proof. reflexivity. Qed.
