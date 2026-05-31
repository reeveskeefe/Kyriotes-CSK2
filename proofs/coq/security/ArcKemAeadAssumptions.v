From Stdlib Require Import List Bool Arith.PeanoNat Lia.
Import ListNotations.
From ArcProofs Require Import ArcTypes ArcMerkle ArcAuthority ArcPolicy ArcVerify ArcSecurityGame ArcTheorems ArcStressProofs ArcDelegationProofs ArcCryptoReduction ArcTemporalProofs ArcTranscriptProofs ArcRevocationCompromiseProofs ArcTransparencyProofs ArcEncodingProofs ArcWrapperProofs.

Definition SecretKey := nat.
Definition PublicEncapsulationKey := nat.
Definition CiphertextKEM := nat.
Definition SharedSecret := nat.
Definition Plaintext := nat.
Definition CiphertextAEAD := nat.
Definition Nonce := nat.
Definition DomainSeparator := nat.
Definition DerivedKey := nat.

Parameter kem_encapsulate : PublicEncapsulationKey -> CiphertextKEM * SharedSecret.
Parameter kem_decapsulate : SecretKey -> CiphertextKEM -> option SharedSecret.
Parameter public_key_matches_secret_key : PublicEncapsulationKey -> SecretKey -> bool.

Parameter hkdf_derive : SharedSecret -> DomainSeparator -> Hash -> DerivedKey.
Parameter aead_encrypt : DerivedKey -> Nonce -> Plaintext -> Hash -> CiphertextAEAD.
Parameter aead_decrypt : DerivedKey -> Nonce -> CiphertextAEAD -> Hash -> option Plaintext.

Definition kem_correct_for_keypair
  (pk : PublicEncapsulationKey)
  (sk : SecretKey)
  : Prop :=
  public_key_matches_secret_key pk sk = true ->
  forall kem_ct shared,
    kem_encapsulate pk = (kem_ct, shared) ->
    kem_decapsulate sk kem_ct = Some shared.

Definition hkdf_context_binding
  (shared : SharedSecret)
  (domain : DomainSeparator)
  (ctx_a ctx_b : Hash)
  : Prop :=
  ctx_a <> ctx_b ->
  hkdf_derive shared domain ctx_a <> hkdf_derive shared domain ctx_b.

Definition hkdf_domain_separation
  (shared : SharedSecret)
  (domain_a domain_b : DomainSeparator)
  (ctx : Hash)
  : Prop :=
  domain_a <> domain_b ->
  hkdf_derive shared domain_a ctx <> hkdf_derive shared domain_b ctx.

Definition aead_correct_for_key
  (key : DerivedKey)
  (nonce : Nonce)
  (plaintext : Plaintext)
  (aad : Hash)
  : Prop :=
  aead_decrypt key nonce (aead_encrypt key nonce plaintext aad) aad = Some plaintext.

Definition aead_aad_binding
  (key : DerivedKey)
  (nonce : Nonce)
  (plaintext : Plaintext)
  (aad_a aad_b : Hash)
  : Prop :=
  aad_a <> aad_b ->
  aead_decrypt key nonce (aead_encrypt key nonce plaintext aad_a) aad_b = None.

Definition aead_key_binding
  (key_a key_b : DerivedKey)
  (nonce : Nonce)
  (plaintext : Plaintext)
  (aad : Hash)
  : Prop :=
  key_a <> key_b ->
  aead_decrypt key_b nonce (aead_encrypt key_a nonce plaintext aad) aad = None.

Record PrimitiveAssumptions := {
  assumes_no_aead_break : bool;
  assumes_no_kem_break : bool;
  assumes_no_hkdf_break : bool;
  assumes_no_signature_break : bool;
  assumes_no_hash_binding_break : bool;
  assumes_no_merkle_binding_break : bool;
  assumes_no_transparency_binding_break : bool
}.

Definition primitive_assumptions_hold (assumptions : PrimitiveAssumptions) : bool :=
  assumes_no_aead_break assumptions &&
  assumes_no_kem_break assumptions &&
  assumes_no_hkdf_break assumptions &&
  assumes_no_signature_break assumptions &&
  assumes_no_hash_binding_break assumptions &&
  assumes_no_merkle_binding_break assumptions &&
  assumes_no_transparency_binding_break assumptions.

Definition assumptions_to_break_list
  (assumptions : PrimitiveAssumptions)
  : list PrimitiveBreak :=
  (if assumes_no_aead_break assumptions then [] else [BreakAEAD]) ++
  (if assumes_no_kem_break assumptions then [] else [BreakKEM]) ++
  (if assumes_no_hkdf_break assumptions then [] else [BreakHKDF]) ++
  (if assumes_no_signature_break assumptions then [] else [BreakSignature]) ++
  (if assumes_no_hash_binding_break assumptions then [] else [BreakHashBinding]) ++
  (if assumes_no_merkle_binding_break assumptions then [] else [BreakMerkleBinding]) ++
  (if assumes_no_transparency_binding_break assumptions then [] else [BreakTransparencyBinding]).

Theorem primitive_assumptions_hold_implies_no_aead_break :
  forall assumptions,
    primitive_assumptions_hold assumptions = true ->
    assumes_no_aead_break assumptions = true.
Proof.
  intros assumptions H.
  unfold primitive_assumptions_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[H_aead _] _] _] _] _] _].
  exact H_aead.
Qed.

Theorem primitive_assumptions_hold_implies_no_kem_break :
  forall assumptions,
    primitive_assumptions_hold assumptions = true ->
    assumes_no_kem_break assumptions = true.
Proof.
  intros assumptions H.
  unfold primitive_assumptions_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ H_kem] _] _] _] _] _].
  exact H_kem.
Qed.

Theorem primitive_assumptions_hold_implies_no_hkdf_break :
  forall assumptions,
    primitive_assumptions_hold assumptions = true ->
    assumes_no_hkdf_break assumptions = true.
Proof.
  intros assumptions H.
  unfold primitive_assumptions_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] H_hkdf] _] _] _] _].
  exact H_hkdf.
Qed.

Theorem primitive_assumptions_hold_implies_no_signature_break :
  forall assumptions,
    primitive_assumptions_hold assumptions = true ->
    assumes_no_signature_break assumptions = true.
Proof.
  intros assumptions H.
  unfold primitive_assumptions_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] H_sig] _] _] _].
  exact H_sig.
Qed.

Theorem primitive_assumptions_hold_implies_no_hash_break :
  forall assumptions,
    primitive_assumptions_hold assumptions = true ->
    assumes_no_hash_binding_break assumptions = true.
Proof.
  intros assumptions H.
  unfold primitive_assumptions_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] _] H_hash] _] _].
  exact H_hash.
Qed.

Theorem primitive_assumptions_hold_implies_no_merkle_break :
  forall assumptions,
    primitive_assumptions_hold assumptions = true ->
    assumes_no_merkle_binding_break assumptions = true.
Proof.
  intros assumptions H.
  unfold primitive_assumptions_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] _] _] H_merkle] _].
  exact H_merkle.
Qed.

Theorem primitive_assumptions_hold_implies_no_transparency_break :
  forall assumptions,
    primitive_assumptions_hold assumptions = true ->
    assumes_no_transparency_binding_break assumptions = true.
Proof.
  intros assumptions H.
  unfold primitive_assumptions_hold in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[_ _] _] _] _] _] H_transparency].
  exact H_transparency.
Qed.

Theorem aead_correctness_recovers_plaintext :
  forall key nonce plaintext aad,
    aead_correct_for_key key nonce plaintext aad ->
    aead_decrypt key nonce (aead_encrypt key nonce plaintext aad) aad = Some plaintext.
Proof.
  intros key nonce plaintext aad H.
  unfold aead_correct_for_key in H.
  exact H.
Qed.

Theorem aead_rejects_wrong_aad_under_binding :
  forall key nonce plaintext aad_a aad_b,
    aead_aad_binding key nonce plaintext aad_a aad_b ->
    aad_a <> aad_b ->
    aead_decrypt key nonce (aead_encrypt key nonce plaintext aad_a) aad_b = None.
Proof.
  intros key nonce plaintext aad_a aad_b H_binding H_neq.
  unfold aead_aad_binding in H_binding.
  apply H_binding.
  exact H_neq.
Qed.

Theorem aead_rejects_wrong_key_under_binding :
  forall key_a key_b nonce plaintext aad,
    aead_key_binding key_a key_b nonce plaintext aad ->
    key_a <> key_b ->
    aead_decrypt key_b nonce (aead_encrypt key_a nonce plaintext aad) aad = None.
Proof.
  intros key_a key_b nonce plaintext aad H_binding H_neq.
  unfold aead_key_binding in H_binding.
  apply H_binding.
  exact H_neq.
Qed.

Theorem hkdf_rejects_context_substitution_under_binding :
  forall shared domain ctx_a ctx_b,
    hkdf_context_binding shared domain ctx_a ctx_b ->
    ctx_a <> ctx_b ->
    hkdf_derive shared domain ctx_a <> hkdf_derive shared domain ctx_b.
Proof.
  intros shared domain ctx_a ctx_b H_binding H_neq.
  unfold hkdf_context_binding in H_binding.
  apply H_binding.
  exact H_neq.
Qed.

Theorem hkdf_rejects_domain_substitution_under_binding :
  forall shared domain_a domain_b ctx,
    hkdf_domain_separation shared domain_a domain_b ctx ->
    domain_a <> domain_b ->
    hkdf_derive shared domain_a ctx <> hkdf_derive shared domain_b ctx.
Proof.
  intros shared domain_a domain_b ctx H_binding H_neq.
  unfold hkdf_domain_separation in H_binding.
  apply H_binding.
  exact H_neq.
Qed.

Theorem kem_correctness_decapsulates_encapsulated_secret :
  forall pk sk kem_ct shared,
    kem_correct_for_keypair pk sk ->
    public_key_matches_secret_key pk sk = true ->
    kem_encapsulate pk = (kem_ct, shared) ->
    kem_decapsulate sk kem_ct = Some shared.
Proof.
  intros pk sk kem_ct shared H_correct H_match H_enc.
  unfold kem_correct_for_keypair in H_correct.
  apply H_correct.
  - exact H_match.
  - exact H_enc.
Qed.
