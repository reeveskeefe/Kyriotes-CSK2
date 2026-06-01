From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From KyriotesCsk2Proofs Require Import KyriotesCsk2Types.
From KyriotesCsk2Proofs Require Import KyriotesCsk2EncodingProofs.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementMap.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementObligations.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustRefinementEvidence.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustMechanicalRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2RustFullMechanicalProofGate.
From KyriotesCsk2Proofs Require Import KyriotesCsk2ContextHashRustRefinement.
From KyriotesCsk2Proofs Require Import KyriotesCsk2DecodeKyriotesCsk2ObjectRustRefinement.

Inductive EncodeKyriotesCsk2ObjectRoundTripCase :=
| EncodeMinimalValidReserved
| EncodeMultiWrapperReserved
| EncodeTemporalPolicyReserved
| EncodeRevocationProofReserved
| EncodeTransparencyBoundReserved.

Record EncodeKyriotesCsk2ObjectMechanicalVector := {
  encode_vector_id : string;
  encode_vector_case : EncodeKyriotesCsk2ObjectRoundTripCase;
  encode_vector_fixture_reserved : bool;
  encode_vector_canonical_required : bool;
  encode_vector_decode_pairing_required : bool
}.

Definition encode_vector_complete
  (vector : EncodeKyriotesCsk2ObjectMechanicalVector)
  : bool :=
  encode_vector_fixture_reserved vector &&
  encode_vector_canonical_required vector &&
  encode_vector_decode_pairing_required vector.

Fixpoint encode_vectors_complete
  (vectors : list EncodeKyriotesCsk2ObjectMechanicalVector)
  : bool :=
  match vectors with
  | [] => true
  | head :: tail =>
      encode_vector_complete head &&
      encode_vectors_complete tail
  end.

Definition kyriotes_csk2_encode_kyriotes_csk2_object_mechanical_vectors : list EncodeKyriotesCsk2ObjectMechanicalVector :=
  [
    {|
      encode_vector_id := "encode.minimal-valid-object-reserved";
      encode_vector_case := EncodeMinimalValidReserved;
      encode_vector_fixture_reserved := true;
      encode_vector_canonical_required := true;
      encode_vector_decode_pairing_required := true
    |};
    {|
      encode_vector_id := "encode.multi-wrapper-valid-object-reserved";
      encode_vector_case := EncodeMultiWrapperReserved;
      encode_vector_fixture_reserved := true;
      encode_vector_canonical_required := true;
      encode_vector_decode_pairing_required := true
    |};
    {|
      encode_vector_id := "encode.temporal-policy-valid-object-reserved";
      encode_vector_case := EncodeTemporalPolicyReserved;
      encode_vector_fixture_reserved := true;
      encode_vector_canonical_required := true;
      encode_vector_decode_pairing_required := true
    |};
    {|
      encode_vector_id := "encode.revocation-proof-valid-object-reserved";
      encode_vector_case := EncodeRevocationProofReserved;
      encode_vector_fixture_reserved := true;
      encode_vector_canonical_required := true;
      encode_vector_decode_pairing_required := true
    |};
    {|
      encode_vector_id := "encode.transparency-bound-valid-object-reserved";
      encode_vector_case := EncodeTransparencyBoundReserved;
      encode_vector_fixture_reserved := true;
      encode_vector_canonical_required := true;
      encode_vector_decode_pairing_required := true
    |}
  ].

Record EncodeKyriotesCsk2ObjectRustRefinementStatus := {
  encode_kyriotes_csk2_object_rust_symbol_present : bool;
  encode_kyriotes_csk2_object_vectors_generated : bool;
  encode_kyriotes_csk2_object_vector_schema_checked : bool;
  encode_kyriotes_csk2_object_surface_check_pass : bool;
  encode_kyriotes_csk2_object_canonical_track_present : bool;
  encode_kyriotes_csk2_object_decode_pairing_track_present : bool;
  encode_kyriotes_csk2_object_roundtrip_reserved : bool;
  encode_kyriotes_csk2_object_mechanically_checked : bool;
  encode_kyriotes_csk2_object_mechanically_proven : bool
}.

Definition encode_kyriotes_csk2_object_refinement_checked
  (status : EncodeKyriotesCsk2ObjectRustRefinementStatus)
  : bool :=
  encode_kyriotes_csk2_object_rust_symbol_present status &&
  encode_kyriotes_csk2_object_vectors_generated status &&
  encode_kyriotes_csk2_object_vector_schema_checked status &&
  encode_kyriotes_csk2_object_surface_check_pass status &&
  encode_kyriotes_csk2_object_canonical_track_present status &&
  encode_kyriotes_csk2_object_decode_pairing_track_present status &&
  encode_kyriotes_csk2_object_roundtrip_reserved status &&
  encode_kyriotes_csk2_object_mechanically_checked status.

Definition encode_kyriotes_csk2_object_refinement_fully_proven
  (status : EncodeKyriotesCsk2ObjectRustRefinementStatus)
  : bool :=
  encode_kyriotes_csk2_object_refinement_checked status &&
  encode_kyriotes_csk2_object_mechanically_proven status.

Definition kyriotes_csk2_current_encode_kyriotes_csk2_object_refinement_status
  : EncodeKyriotesCsk2ObjectRustRefinementStatus :=
  {|
    encode_kyriotes_csk2_object_rust_symbol_present := true;
    encode_kyriotes_csk2_object_vectors_generated := true;
    encode_kyriotes_csk2_object_vector_schema_checked := true;
    encode_kyriotes_csk2_object_surface_check_pass := true;
    encode_kyriotes_csk2_object_canonical_track_present := true;
    encode_kyriotes_csk2_object_decode_pairing_track_present := true;
    encode_kyriotes_csk2_object_roundtrip_reserved := true;
    encode_kyriotes_csk2_object_mechanically_checked := true;
    encode_kyriotes_csk2_object_mechanically_proven := false
  |}.

Theorem current_encode_kyriotes_csk2_object_vectors_complete :
  encode_vectors_complete kyriotes_csk2_encode_kyriotes_csk2_object_mechanical_vectors = true.
Proof.
  reflexivity.
Qed.

Theorem current_encode_kyriotes_csk2_object_refinement_checked :
  encode_kyriotes_csk2_object_refinement_checked kyriotes_csk2_current_encode_kyriotes_csk2_object_refinement_status = true.
Proof.
  reflexivity.
Qed.

Theorem current_encode_kyriotes_csk2_object_refinement_not_fully_proven :
  encode_kyriotes_csk2_object_refinement_fully_proven kyriotes_csk2_current_encode_kyriotes_csk2_object_refinement_status = false.
Proof.
  reflexivity.
Qed.

Theorem encode_kyriotes_csk2_object_checked_requires_canonical_track :
  forall status,
    encode_kyriotes_csk2_object_refinement_checked status = true ->
    encode_kyriotes_csk2_object_canonical_track_present status = true.
Proof.
  intros status H.
  unfold encode_kyriotes_csk2_object_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_vectors] H_schema] H_surface] H_canonical] H_decode_pairing] H_roundtrip] H_checked].
  exact H_canonical.
Qed.

Theorem encode_kyriotes_csk2_object_checked_requires_decode_pairing_track :
  forall status,
    encode_kyriotes_csk2_object_refinement_checked status = true ->
    encode_kyriotes_csk2_object_decode_pairing_track_present status = true.
Proof.
  intros status H.
  unfold encode_kyriotes_csk2_object_refinement_checked in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[[[H_symbol H_vectors] H_schema] H_surface] H_canonical] H_decode_pairing] H_roundtrip] H_checked].
  exact H_decode_pairing.
Qed.

Theorem encode_kyriotes_csk2_object_full_proof_requires_checked :
  forall status,
    encode_kyriotes_csk2_object_refinement_fully_proven status = true ->
    encode_kyriotes_csk2_object_refinement_checked status = true.
Proof.
  intros status H.
  unfold encode_kyriotes_csk2_object_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_checked.
Qed.

Theorem encode_kyriotes_csk2_object_full_proof_requires_proven_flag :
  forall status,
    encode_kyriotes_csk2_object_refinement_fully_proven status = true ->
    encode_kyriotes_csk2_object_mechanically_proven status = true.
Proof.
  intros status H.
  unfold encode_kyriotes_csk2_object_refinement_fully_proven in H.
  apply andb_true_iff in H.
  destruct H as [H_checked H_proven].
  exact H_proven.
Qed.

Definition kyriotes_csk2_full_mechanical_proof_gate_after_encode_check : KyriotesCsk2FullMechanicalProofGate :=
  {|
    full_gate_inventory_exists := true;
    full_gate_targets_declared := true;
    full_gate_harness_complete := true;
    full_gate_all_targets_checked := false;
    full_gate_all_targets_proven := false;
    full_gate_ci_enforced := true;
    full_gate_rust_equivalence_claim_allowed := false
  |}.

Theorem encode_kyriotes_csk2_object_check_keeps_full_gate_open :
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_full_mechanical_proof_gate_after_encode_check = false.
Proof.
  reflexivity.
Qed.

Theorem encode_kyriotes_csk2_object_third_mechanical_target_status :
  context_hash_refinement_checked kyriotes_csk2_current_context_hash_refinement_status = true /\
  decode_kyriotes_csk2_object_refinement_checked kyriotes_csk2_current_decode_kyriotes_csk2_object_refinement_status = true /\
  encode_kyriotes_csk2_object_refinement_checked kyriotes_csk2_current_encode_kyriotes_csk2_object_refinement_status = true /\
  encode_kyriotes_csk2_object_refinement_fully_proven kyriotes_csk2_current_encode_kyriotes_csk2_object_refinement_status = false /\
  kyriotes_csk2_full_mechanical_proof_gate_closed kyriotes_csk2_full_mechanical_proof_gate_after_encode_check = false.
Proof.
  split.
  - apply current_context_hash_refinement_checked.
  - split.
    + apply current_decode_kyriotes_csk2_object_refinement_checked.
    + split.
      * apply current_encode_kyriotes_csk2_object_refinement_checked.
      * split.
        -- apply current_encode_kyriotes_csk2_object_refinement_not_fully_proven.
        -- apply encode_kyriotes_csk2_object_check_keeps_full_gate_open.
Qed.
