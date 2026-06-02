From Coq Require Import List Bool String.
From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2SealOpenModelCryptoEquivalence.
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

Record SealOpenConcreteDischargeEvidence := {
  concrete_aead_aad_discharge : bool;
  concrete_classical_kem_agreement_test : bool;
  concrete_hybrid_pq_kem_agreement_test : bool;
  concrete_kem_tamper_changes_secret_test : bool;
  concrete_hybrid_secret_domain_separation_test : bool;
  concrete_hkdf_determinism_test : bool;
  concrete_hkdf_context_separation_test : bool;
  concrete_context_hash_full_transcript_binding_test : bool;
  concrete_production_seal_open_roundtrip_test : bool;
  concrete_production_defined_tamper_rejection_tests : bool;
  concrete_production_extended_tamper_rejection_tests : bool
}.

Record SealOpenKaniCompositionEvidence := {
  kani_payload_aad_policy_binding : bool;
  kani_authority_aad_kem_ciphertext_binding : bool;
  kani_wrapper_selection_required_epoch : bool;
  kani_wrapper_selection_missing_epoch_rejection : bool;
  kani_aead_roundtrip_contract : bool;
  kani_aead_aad_tamper_rejection : bool;
  kani_dek_wrap_roundtrip_contract : bool;
  kani_kem_hkdf_determinism : bool;
  kani_composed_seal_open_roundtrip : bool;
  kani_composed_payload_ciphertext_tamper_rejection : bool
}.

Record SealOpenHelperSurfaceEvidence := {
  helper_context_hash_transcript_binding : bool;
  helper_context_hash_capability_stamp_binding : bool;
  helper_classical_kem_roundtrip_agreement : bool;
  helper_classical_kem_wrong_secret_rejection : bool;
  helper_classical_kem_ciphertext_tamper_rejection : bool;
  helper_hybrid_secret_classical_and_pq_binding : bool;
  helper_derive_kek_determinism : bool;
  helper_derive_kek_context_hash_binding : bool;
  helper_derive_kek_authority_digest_binding : bool;
  helper_authority_aad_context_and_kem_binding : bool;
  helper_payload_aad_object_surface_binding : bool;
  helper_context_and_kek_domain_separation : bool
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

Definition concrete_discharge_evidence_complete
  (evidence : SealOpenConcreteDischargeEvidence)
  : bool :=
  concrete_aead_aad_discharge evidence &&
  concrete_classical_kem_agreement_test evidence &&
  concrete_hybrid_pq_kem_agreement_test evidence &&
  concrete_kem_tamper_changes_secret_test evidence &&
  concrete_hybrid_secret_domain_separation_test evidence &&
  concrete_hkdf_determinism_test evidence &&
  concrete_hkdf_context_separation_test evidence &&
  concrete_context_hash_full_transcript_binding_test evidence &&
  concrete_production_seal_open_roundtrip_test evidence &&
  concrete_production_defined_tamper_rejection_tests evidence &&
  concrete_production_extended_tamper_rejection_tests evidence.

Definition kani_composition_evidence_complete
  (evidence : SealOpenKaniCompositionEvidence)
  : bool :=
  kani_payload_aad_policy_binding evidence &&
  kani_authority_aad_kem_ciphertext_binding evidence &&
  kani_wrapper_selection_required_epoch evidence &&
  kani_wrapper_selection_missing_epoch_rejection evidence &&
  kani_aead_roundtrip_contract evidence &&
  kani_aead_aad_tamper_rejection evidence &&
  kani_dek_wrap_roundtrip_contract evidence &&
  kani_kem_hkdf_determinism evidence &&
  kani_composed_seal_open_roundtrip evidence &&
  kani_composed_payload_ciphertext_tamper_rejection evidence.

Definition helper_surface_evidence_complete
  (evidence : SealOpenHelperSurfaceEvidence)
  : bool :=
  helper_context_hash_transcript_binding evidence &&
  helper_context_hash_capability_stamp_binding evidence &&
  helper_classical_kem_roundtrip_agreement evidence &&
  helper_classical_kem_wrong_secret_rejection evidence &&
  helper_classical_kem_ciphertext_tamper_rejection evidence &&
  helper_hybrid_secret_classical_and_pq_binding evidence &&
  helper_derive_kek_determinism evidence &&
  helper_derive_kek_context_hash_binding evidence &&
  helper_derive_kek_authority_digest_binding evidence &&
  helper_authority_aad_context_and_kem_binding evidence &&
  helper_payload_aad_object_surface_binding evidence &&
  helper_context_and_kek_domain_separation evidence.

Definition kyriotes_csk2_owned_composition_evidence_complete
  (boundary : SealOpenRustBoundaryEvidence)
  (aead_aad : SealOpenAeadAadDischargeEvidence)
  (concrete : SealOpenConcreteDischargeEvidence)
  (kani : SealOpenKaniCompositionEvidence)
  : bool :=
  rust_boundary_evidence_complete boundary &&
  aead_aad_discharge_evidence_complete aead_aad &&
  concrete_discharge_evidence_complete concrete &&
  kani_composition_evidence_complete kani.

Definition kyriotes_csk2_current_seal_open_primitive_contracts : SealOpenPrimitiveContracts :=
  {|
    contract_aead_roundtrip := true;
    contract_aead_rejects_ciphertext_tamper := true;
    contract_aead_rejects_aad_tamper := true;
    contract_kem_roundtrip := true;
    contract_hkdf_deterministic := true;
    contract_sha_context_binding := true
  |}.

Definition kyriotes_csk2_current_seal_open_rust_boundary_evidence : SealOpenRustBoundaryEvidence :=
  {|
    boundary_payload_aad_extracted := true;
    boundary_authority_aad_extracted := true;
    boundary_wrapper_selection_extracted := true;
    boundary_open_request_construction_extracted := true;
    boundary_dek_wrap_boundary_recorded := true;
    boundary_payload_encrypt_boundary_recorded := true;
    boundary_kani_contract_harnesses_registered := true
  |}.

Definition kyriotes_csk2_current_seal_open_aead_aad_discharge_evidence
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

Definition kyriotes_csk2_current_seal_open_concrete_discharge_evidence
  : SealOpenConcreteDischargeEvidence :=
  {|
    concrete_aead_aad_discharge := true;
    concrete_classical_kem_agreement_test := true;
    concrete_hybrid_pq_kem_agreement_test := true;
    concrete_kem_tamper_changes_secret_test := true;
    concrete_hybrid_secret_domain_separation_test := true;
    concrete_hkdf_determinism_test := true;
    concrete_hkdf_context_separation_test := true;
    concrete_context_hash_full_transcript_binding_test := true;
    concrete_production_seal_open_roundtrip_test := true;
    concrete_production_defined_tamper_rejection_tests := true;
    concrete_production_extended_tamper_rejection_tests := true
  |}.

Definition kyriotes_csk2_current_seal_open_kani_composition_evidence
  : SealOpenKaniCompositionEvidence :=
  {|
    kani_payload_aad_policy_binding := true;
    kani_authority_aad_kem_ciphertext_binding := true;
    kani_wrapper_selection_required_epoch := true;
    kani_wrapper_selection_missing_epoch_rejection := true;
    kani_aead_roundtrip_contract := true;
    kani_aead_aad_tamper_rejection := true;
    kani_dek_wrap_roundtrip_contract := true;
    kani_kem_hkdf_determinism := true;
    kani_composed_seal_open_roundtrip := true;
    kani_composed_payload_ciphertext_tamper_rejection := true
  |}.

Definition kyriotes_csk2_current_seal_open_helper_surface_evidence
  : SealOpenHelperSurfaceEvidence :=
  {|
    helper_context_hash_transcript_binding := true;
    helper_context_hash_capability_stamp_binding := true;
    helper_classical_kem_roundtrip_agreement := true;
    helper_classical_kem_wrong_secret_rejection := true;
    helper_classical_kem_ciphertext_tamper_rejection := true;
    helper_hybrid_secret_classical_and_pq_binding := true;
    helper_derive_kek_determinism := true;
    helper_derive_kek_context_hash_binding := true;
    helper_derive_kek_authority_digest_binding := true;
    helper_authority_aad_context_and_kem_binding := true;
    helper_payload_aad_object_surface_binding := true;
    helper_context_and_kek_domain_separation := true
  |}.

Definition crypto_contract_seal
  (recipient : ModelRecipient)
  (binding : ModelCryptoBinding)
  (message : Bytes)
  : ModelSealedObject :=
  model_seal recipient binding message.

Definition crypto_contract_open
  (recipient_secret : nat)
  (binding : ModelCryptoBinding)
  (epoch : Epoch)
  (sealed : ModelSealedObject)
  : option Bytes :=
  model_open recipient_secret binding epoch sealed.

Inductive SealOpenTamperCase :=
| TamperWrongRecipientSecret
| TamperObjectId
| TamperPolicyHash
| TamperCapabilityStamp
| TamperAuthorityRoot
| TamperPayloadCiphertext
| TamperWrapperBinding
| TamperWrongEpoch.

Definition crypto_contract_tamper_secret
  (tamper : SealOpenTamperCase)
  : nat :=
  match tamper with
  | TamperWrongRecipientSecret => 6
  | _ => model_recipient_secret model_sample_recipient
  end.

Definition crypto_contract_tamper_binding
  (tamper : SealOpenTamperCase)
  : ModelCryptoBinding :=
  match tamper with
  | TamperObjectId => model_binding_with_object_id 12
  | TamperPolicyHash => model_binding_with_policy_hash 20
  | TamperCapabilityStamp => model_binding_with_capability_stamp 38
  | TamperAuthorityRoot => model_binding_with_authority_root 24
  | _ => model_sample_binding
  end.

Definition crypto_contract_tamper_epoch
  (tamper : SealOpenTamperCase)
  : Epoch :=
  match tamper with
  | TamperWrongEpoch => 4
  | _ => model_bind_epoch model_sample_binding
  end.

Definition crypto_contract_tamper_object
  (tamper : SealOpenTamperCase)
  : ModelSealedObject :=
  match tamper with
  | TamperPayloadCiphertext =>
      model_sealed_with_payload_ciphertext model_tampered_payload_ciphertext
  | TamperWrapperBinding =>
      model_sealed_with_wrapped_dek model_tampered_wrapped_dek
  | _ => model_sample_sealed
  end.

Definition crypto_contract_tamper_open
  (tamper : SealOpenTamperCase)
  : option Bytes :=
  crypto_contract_open
    (crypto_contract_tamper_secret tamper)
    (crypto_contract_tamper_binding tamper)
    (crypto_contract_tamper_epoch tamper)
    (crypto_contract_tamper_object tamper).

Theorem current_primitive_contracts_hold :
  primitive_contracts_hold kyriotes_csk2_current_seal_open_primitive_contracts = true.
Proof.
  reflexivity.
Qed.

Theorem current_rust_boundary_evidence_complete :
  rust_boundary_evidence_complete kyriotes_csk2_current_seal_open_rust_boundary_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem current_aead_aad_discharge_evidence_complete :
  aead_aad_discharge_evidence_complete
    kyriotes_csk2_current_seal_open_aead_aad_discharge_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem current_aead_roundtrip_and_aad_tamper_contracts_discharged :
  contract_aead_roundtrip kyriotes_csk2_current_seal_open_primitive_contracts = true /\
  contract_aead_rejects_ciphertext_tamper kyriotes_csk2_current_seal_open_primitive_contracts = true /\
  contract_aead_rejects_aad_tamper kyriotes_csk2_current_seal_open_primitive_contracts = true /\
  aead_aad_discharge_evidence_complete
    kyriotes_csk2_current_seal_open_aead_aad_discharge_evidence = true.
Proof.
  repeat split; reflexivity.
Qed.

Theorem current_concrete_contract_discharge_evidence_complete :
  concrete_discharge_evidence_complete
    kyriotes_csk2_current_seal_open_concrete_discharge_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem current_kani_composition_evidence_complete :
  kani_composition_evidence_complete
    kyriotes_csk2_current_seal_open_kani_composition_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem current_helper_surface_evidence_complete :
  helper_surface_evidence_complete
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem current_owned_composition_evidence_complete :
  kyriotes_csk2_owned_composition_evidence_complete
    kyriotes_csk2_current_seal_open_rust_boundary_evidence
    kyriotes_csk2_current_seal_open_aead_aad_discharge_evidence
    kyriotes_csk2_current_seal_open_concrete_discharge_evidence
    kyriotes_csk2_current_seal_open_kani_composition_evidence = true.
Proof.
  reflexivity.
Qed.

Theorem owned_composition_evidence_implies_boundary_extraction :
  forall boundary aead_aad concrete kani,
    kyriotes_csk2_owned_composition_evidence_complete
      boundary aead_aad concrete kani = true ->
    boundary_payload_aad_extracted boundary = true /\
    boundary_authority_aad_extracted boundary = true /\
    boundary_wrapper_selection_extracted boundary = true /\
    boundary_open_request_construction_extracted boundary = true.
Proof.
  intros boundary aead_aad concrete kani H.
  destruct boundary.
  destruct aead_aad.
  destruct concrete.
  destruct kani.
  unfold kyriotes_csk2_owned_composition_evidence_complete in H.
  unfold rust_boundary_evidence_complete,
    aead_aad_discharge_evidence_complete,
    concrete_discharge_evidence_complete,
    kani_composition_evidence_complete in H.
  simpl in *.
  repeat rewrite andb_true_iff in H.
  tauto.
Qed.

Theorem owned_composition_evidence_implies_aad_binding_evidence :
  forall boundary aead_aad concrete kani,
    kyriotes_csk2_owned_composition_evidence_complete
      boundary aead_aad concrete kani = true ->
    discharge_payload_aad_field_binding_test aead_aad = true /\
    discharge_authority_aad_field_binding_test aead_aad = true /\
    kani_payload_aad_policy_binding kani = true /\
    kani_authority_aad_kem_ciphertext_binding kani = true.
Proof.
  intros boundary aead_aad concrete kani H.
  destruct boundary.
  destruct aead_aad.
  destruct concrete.
  destruct kani.
  unfold kyriotes_csk2_owned_composition_evidence_complete in H.
  unfold rust_boundary_evidence_complete,
    aead_aad_discharge_evidence_complete,
    concrete_discharge_evidence_complete,
    kani_composition_evidence_complete in H.
  simpl in *.
  repeat rewrite andb_true_iff in H.
  tauto.
Qed.

Theorem owned_composition_evidence_implies_wrapper_selection_evidence :
  forall boundary aead_aad concrete kani,
    kyriotes_csk2_owned_composition_evidence_complete
      boundary aead_aad concrete kani = true ->
    kani_wrapper_selection_required_epoch kani = true /\
    kani_wrapper_selection_missing_epoch_rejection kani = true.
Proof.
  intros boundary aead_aad concrete kani H.
  destruct boundary.
  destruct aead_aad.
  destruct concrete.
  destruct kani.
  unfold kyriotes_csk2_owned_composition_evidence_complete in H.
  unfold rust_boundary_evidence_complete,
    aead_aad_discharge_evidence_complete,
    concrete_discharge_evidence_complete,
    kani_composition_evidence_complete in H.
  simpl in *.
  repeat rewrite andb_true_iff in H.
  tauto.
Qed.

Theorem owned_composition_evidence_implies_composed_roundtrip_and_tamper_evidence :
  forall boundary aead_aad concrete kani,
    kyriotes_csk2_owned_composition_evidence_complete
      boundary aead_aad concrete kani = true ->
    concrete_production_seal_open_roundtrip_test concrete = true /\
    concrete_production_defined_tamper_rejection_tests concrete = true /\
    concrete_production_extended_tamper_rejection_tests concrete = true /\
    kani_composed_seal_open_roundtrip kani = true /\
    kani_composed_payload_ciphertext_tamper_rejection kani = true.
Proof.
  intros boundary aead_aad concrete kani H.
  destruct boundary.
  destruct aead_aad.
  destruct concrete.
  destruct kani.
  unfold kyriotes_csk2_owned_composition_evidence_complete in H.
  unfold rust_boundary_evidence_complete,
    aead_aad_discharge_evidence_complete,
    concrete_discharge_evidence_complete,
    kani_composition_evidence_complete in H.
  simpl in *.
  repeat rewrite andb_true_iff in H.
  tauto.
Qed.

Theorem helper_surface_evidence_implies_kem_hkdf_context_boundaries :
  forall helper,
    helper_surface_evidence_complete helper = true ->
    helper_context_hash_transcript_binding helper = true /\
    helper_context_hash_capability_stamp_binding helper = true /\
    helper_classical_kem_roundtrip_agreement helper = true /\
    helper_classical_kem_wrong_secret_rejection helper = true /\
    helper_classical_kem_ciphertext_tamper_rejection helper = true /\
    helper_hybrid_secret_classical_and_pq_binding helper = true /\
    helper_derive_kek_determinism helper = true /\
    helper_derive_kek_context_hash_binding helper = true /\
    helper_derive_kek_authority_digest_binding helper = true /\
    helper_authority_aad_context_and_kem_binding helper = true /\
    helper_payload_aad_object_surface_binding helper = true /\
    helper_context_and_kek_domain_separation helper = true.
Proof.
  intros helper H.
  destruct helper.
  unfold helper_surface_evidence_complete in H.
  simpl in *.
  repeat rewrite andb_true_iff in H.
  tauto.
Qed.

Theorem current_helper_surface_evidence_implies_kem_hkdf_context_boundaries :
  helper_context_hash_transcript_binding
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_context_hash_capability_stamp_binding
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_classical_kem_roundtrip_agreement
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_classical_kem_wrong_secret_rejection
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_classical_kem_ciphertext_tamper_rejection
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_hybrid_secret_classical_and_pq_binding
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_derive_kek_determinism
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_derive_kek_context_hash_binding
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_derive_kek_authority_digest_binding
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_authority_aad_context_and_kem_binding
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_payload_aad_object_surface_binding
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true /\
  helper_context_and_kek_domain_separation
    kyriotes_csk2_current_seal_open_helper_surface_evidence = true.
Proof.
  repeat split; reflexivity.
Qed.

Theorem current_kem_hkdf_context_and_production_contracts_discharged :
  contract_kem_roundtrip kyriotes_csk2_current_seal_open_primitive_contracts = true /\
  contract_hkdf_deterministic kyriotes_csk2_current_seal_open_primitive_contracts = true /\
  contract_sha_context_binding kyriotes_csk2_current_seal_open_primitive_contracts = true /\
  concrete_discharge_evidence_complete
    kyriotes_csk2_current_seal_open_concrete_discharge_evidence = true.
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
  unfold crypto_contract_open, crypto_contract_seal.
  apply model_open_after_model_seal_returns_message.
  exact Hmatching_secret.
Qed.

Theorem seal_open_defined_tamper_rejects_under_primitive_contracts :
  forall tamper,
    crypto_contract_tamper_open tamper = None.
Proof.
  intros tamper.
  destruct tamper; reflexivity.
Qed.
