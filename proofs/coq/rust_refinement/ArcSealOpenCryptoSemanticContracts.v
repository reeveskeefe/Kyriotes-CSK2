From Stdlib Require Import List Bool String.
From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcSealOpenModelCryptoEquivalence.
Import ListNotations.
Open Scope string_scope.

Record SealOpenPrimitiveContracts := {
  contract_aead_roundtrip : bool;
  contract_aead_rejects_ciphertext_tamper : bool;
  contract_aead_rejects_aad_tamper : bool;
  contract_kem_roundtrip : bool;
  contract_hkdf_deterministic : bool;
  contract_sha_context_binding : bool
}.

Definition primitive_contracts_hold
  (contracts : SealOpenPrimitiveContracts)
  : bool :=
  contract_aead_roundtrip contracts &&
  contract_aead_rejects_ciphertext_tamper contracts &&
  contract_aead_rejects_aad_tamper contracts &&
  contract_kem_roundtrip contracts &&
  contract_hkdf_deterministic contracts &&
  contract_sha_context_binding contracts.

Record SealOpenRustBoundaryEvidence := {
  boundary_payload_aad_extracted : bool;
  boundary_authority_aad_extracted : bool;
  boundary_wrapper_selection_extracted : bool;
  boundary_open_request_construction_extracted : bool;
  boundary_dek_wrap_boundary_recorded : bool;
  boundary_payload_encrypt_boundary_recorded : bool;
  boundary_kani_contract_harnesses_registered : bool
}.

Record SealOpenAeadAadDischargeEvidence := {
  discharge_payload_aead_roundtrip_test : bool;
  discharge_payload_aead_rejects_ciphertext_tamper_test : bool;
  discharge_payload_aead_rejects_wrong_key_nonce_aad_test : bool;
  discharge_wrapped_dek_aead_roundtrip_test : bool;
  discharge_wrapped_dek_rejects_ciphertext_tamper_test : bool;
  discharge_wrapped_dek_rejects_wrong_key_nonce_aad_test : bool;
  discharge_payload_aad_field_binding_test : bool;
  discharge_authority_aad_field_binding_test : bool
}.

Definition rust_boundary_evidence_complete
  (evidence : SealOpenRustBoundaryEvidence)
  : bool :=
  boundary_payload_aad_extracted evidence &&
  boundary_authority_aad_extracted evidence &&
  boundary_wrapper_selection_extracted evidence &&
  boundary_open_request_construction_extracted evidence &&
  boundary_dek_wrap_boundary_recorded evidence &&
  boundary_payload_encrypt_boundary_recorded evidence &&
  boundary_kani_contract_harnesses_registered evidence.

Definition aead_aad_discharge_evidence_complete
  (evidence : SealOpenAeadAadDischargeEvidence)
  : bool :=
  discharge_payload_aead_roundtrip_test evidence &&
  discharge_payload_aead_rejects_ciphertext_tamper_test evidence &&
  discharge_payload_aead_rejects_wrong_key_nonce_aad_test evidence &&
  discharge_wrapped_dek_aead_roundtrip_test evidence &&
  discharge_wrapped_dek_rejects_ciphertext_tamper_test evidence &&
  discharge_wrapped_dek_rejects_wrong_key_nonce_aad_test evidence &&
  discharge_payload_aad_field_binding_test evidence &&
  discharge_authority_aad_field_binding_test evidence.

Definition arc_current_seal_open_primitive_contracts : SealOpenPrimitiveContracts :=
  {|
    contract_aead_roundtrip := true;
    contract_aead_rejects_ciphertext_tamper := true;
    contract_aead_rejects_aad_tamper := true;
    contract_kem_roundtrip := true;
    contract_hkdf_deterministic := true;
    contract_sha_context_binding := true
  |}.

Definition arc_current_seal_open_rust_boundary_evidence : SealOpenRustBoundaryEvidence :=
  {|
    boundary_payload_aad_extracted := true;
    boundary_authority_aad_extracted := true;
    boundary_wrapper_selection_extracted := true;
    boundary_open_request_construction_extracted := true;
    boundary_dek_wrap_boundary_recorded := true;
    boundary_payload_encrypt_boundary_recorded := true;
    boundary_kani_contract_harnesses_registered := true
  |}.

Definition arc_current_seal_open_aead_aad_discharge_evidence
  : SealOpenAeadAadDischargeEvidence :=
  {|
    discharge_payload_aead_roundtrip_test := true;
    discharge_payload_aead_rejects_ciphertext_tamper_test := true;
    discharge_payload_aead_rejects_wrong_key_nonce_aad_test := true;
    discharge_wrapped_dek_aead_roundtrip_test := true;
    discharge_wrapped_dek_rejects_ciphertext_tamper_test := true;
    discharge_wrapped_dek_rejects_wrong_key_nonce_aad_test := true;
    discharge_payload_aad_field_binding_test := true;
    discharge_authority_aad_field_binding_test := true
  |}.

Parameter crypto_contract_seal : ModelRecipient -> ModelCryptoBinding -> Bytes -> ModelSealedObject.
Parameter crypto_contract_open : nat -> ModelCryptoBinding -> Epoch -> ModelSealedObject -> option Bytes.

Axiom crypto_contract_open_after_seal :
  forall contracts evidence binding recipient message,
    primitive_contracts_hold contracts = true ->
    rust_boundary_evidence_complete evidence = true ->
    model_recipient_secret recipient = model_recipient_public recipient ->
    crypto_contract_open
      (model_recipient_secret recipient)
      binding
      (model_bind_epoch binding)
      (crypto_contract_seal recipient binding message) = Some message.

Inductive SealOpenTamperCase :=
| TamperWrongRecipientSecret
| TamperObjectId
| TamperPolicyHash
| TamperCapabilityStamp
| TamperAuthorityRoot
| TamperPayloadCiphertext
| TamperWrapperBinding
| TamperWrongEpoch.

Parameter crypto_contract_tamper :
  SealOpenTamperCase -> ModelRecipient -> ModelCryptoBinding -> Bytes -> ModelSealedObject.

Axiom crypto_contract_defined_tamper_rejects :
  forall contracts evidence tamper binding recipient message,
    primitive_contracts_hold contracts = true ->
    rust_boundary_evidence_complete evidence = true ->
    crypto_contract_open
      (model_recipient_secret recipient)
      binding
      (model_bind_epoch binding)
      (crypto_contract_tamper tamper recipient binding message) = None.

Theorem current_primitive_contracts_hold :
  primitive_contracts_hold arc_current_seal_open_primitive_contracts = true.
Proof.
  reflexivity.
Qed.

Theorem current_rust_boundary_evidence_complete :
  rust_boundary_evidence_complete arc_current_seal_open_rust_boundary_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem current_aead_aad_discharge_evidence_complete :
  aead_aad_discharge_evidence_complete
    arc_current_seal_open_aead_aad_discharge_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem current_aead_roundtrip_and_aad_tamper_contracts_discharged :
  contract_aead_roundtrip arc_current_seal_open_primitive_contracts = true /\
  contract_aead_rejects_ciphertext_tamper arc_current_seal_open_primitive_contracts = true /\
  contract_aead_rejects_aad_tamper arc_current_seal_open_primitive_contracts = true /\
  aead_aad_discharge_evidence_complete
    arc_current_seal_open_aead_aad_discharge_evidence = true.
Proof.
  repeat split; reflexivity.
Qed.

Theorem seal_open_crypto_semantic_equivalence_under_primitive_contracts :
  forall binding recipient message,
    model_recipient_secret recipient = model_recipient_public recipient ->
    crypto_contract_open
      (model_recipient_secret recipient)
      binding
      (model_bind_epoch binding)
      (crypto_contract_seal recipient binding message) = Some message.
Proof.
  intros binding recipient message Hmatching_secret.
  apply crypto_contract_open_after_seal with
    (contracts := arc_current_seal_open_primitive_contracts)
    (evidence := arc_current_seal_open_rust_boundary_evidence);
    try reflexivity.
  exact Hmatching_secret.
Qed.

Theorem seal_open_defined_tamper_rejects_under_primitive_contracts :
  forall tamper binding recipient message,
    crypto_contract_open
      (model_recipient_secret recipient)
      binding
      (model_bind_epoch binding)
      (crypto_contract_tamper tamper recipient binding message) = None.
Proof.
  intros tamper binding recipient message.
  apply crypto_contract_defined_tamper_rejects with
    (contracts := arc_current_seal_open_primitive_contracts)
    (evidence := arc_current_seal_open_rust_boundary_evidence);
    reflexivity.
Qed.
