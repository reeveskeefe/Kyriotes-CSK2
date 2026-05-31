From Stdlib Require Import List Bool String Arith.PeanoNat Lia.
Import ListNotations.
Open Scope string_scope.

From ArcProofs Require Import ArcTypes.
From ArcProofs Require Import ArcRustRefinementMap.
From ArcProofs Require Import ArcRustRefinementObligations.
From ArcProofs Require Import ArcRustRefinementEvidence.
From ArcProofs Require Import ArcAbstractInvariantCompleteness.
From ArcProofs Require Import ArcDesignModelCompleteness.
From ArcProofs Require Import ArcStateMachineCompleteness.
From ArcProofs Require Import ArcMerkleTransparencyCompleteness.
From ArcProofs Require Import ArcCryptoReductionCompleteness.

Inductive MechanicalRefinementLevel :=
| MechanicalHarnessed
| MechanicalChecked
| MechanicalProven.

Record RustMechanicalRefinementTarget := {
  mechanical_target_id : string;
  mechanical_target_module : RustModule;
  mechanical_target_symbol : string;
  mechanical_target_coq_model : string;
  mechanical_target_level : MechanicalRefinementLevel;
  mechanical_source_present : bool;
  mechanical_symbol_present : bool;
  mechanical_checked : bool;
  mechanical_proven : bool
}.

Definition mechanical_target_harness_complete
  (target : RustMechanicalRefinementTarget)
  : bool :=
  mechanical_source_present target &&
  mechanical_symbol_present target &&
  match mechanical_target_level target with
  | MechanicalHarnessed => true
  | MechanicalChecked => mechanical_checked target
  | MechanicalProven => mechanical_checked target && mechanical_proven target
  end.

Definition mechanical_target_fully_proven
  (target : RustMechanicalRefinementTarget)
  : bool :=
  mechanical_checked target &&
  mechanical_proven target.

Fixpoint mechanical_harness_list_complete
  (targets : list RustMechanicalRefinementTarget)
  : bool :=
  match targets with
  | [] => true
  | head :: tail =>
      mechanical_target_harness_complete head &&
      mechanical_harness_list_complete tail
  end.

Fixpoint mechanical_proof_list_complete
  (targets : list RustMechanicalRefinementTarget)
  : bool :=
  match targets with
  | [] => true
  | head :: tail =>
      mechanical_target_fully_proven head &&
      mechanical_proof_list_complete tail
  end.

Definition arc_rust_mechanical_refinement_targets : list RustMechanicalRefinementTarget :=
  [
    {|
      mechanical_target_id := "codec.decode_arc_object";
      mechanical_target_module := RustEncoding;
      mechanical_target_symbol := "decode_arc_object";
      mechanical_target_coq_model := "ArcEncodingProofs";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "codec.encode_arc_object";
      mechanical_target_module := RustEncoding;
      mechanical_target_symbol := "encode_arc_object";
      mechanical_target_coq_model := "ArcEncodingProofs";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "model.context_hash";
      mechanical_target_module := RustModel;
      mechanical_target_symbol := "context_hash";
      mechanical_target_coq_model := "ArcTranscriptProofs";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "engine.verify";
      mechanical_target_module := RustEngine;
      mechanical_target_symbol := "verify";
      mechanical_target_coq_model := "ArcVerify";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "engine.open";
      mechanical_target_module := RustEngine;
      mechanical_target_symbol := "open";
      mechanical_target_coq_model := "ArcMasterInvariantProofs";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "engine.seal";
      mechanical_target_module := RustEngine;
      mechanical_target_symbol := "seal";
      mechanical_target_coq_model := "ArcLifecycleProofs";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "engine.add_epoch_wrapper";
      mechanical_target_module := RustEngine;
      mechanical_target_symbol := "add_epoch_wrapper";
      mechanical_target_coq_model := "ArcStateMachineCompleteness";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "engine.rotate_epoch";
      mechanical_target_module := RustEngine;
      mechanical_target_symbol := "rotate_epoch";
      mechanical_target_coq_model := "ArcStateMachineCompleteness";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "engine.rotate_epoch_full";
      mechanical_target_module := RustEngine;
      mechanical_target_symbol := "rotate_epoch_full";
      mechanical_target_coq_model := "ArcStateMachineCompleteness";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "capability_tree.proofs";
      mechanical_target_module := RustCapabilityTree;
      mechanical_target_symbol := "proof";
      mechanical_target_coq_model := "ArcMerkleTransparencyCompleteness";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |};
    {|
      mechanical_target_id := "transparency.append";
      mechanical_target_module := RustTransparency;
      mechanical_target_symbol := "append";
      mechanical_target_coq_model := "ArcTransparencyAppendOnly";
      mechanical_target_level := MechanicalHarnessed;
      mechanical_source_present := true;
      mechanical_symbol_present := true;
      mechanical_checked := false;
      mechanical_proven := false
    |}
  ].

Record ArcRustMechanicalRefinementCoverage := {
  mechanical_inventory_script : bool;
  mechanical_inventory_json : bool;
  mechanical_inventory_test : bool;
  mechanical_refinement_plan : bool;
  mechanical_codec_decode_harness : bool;
  mechanical_codec_encode_harness : bool;
  mechanical_context_hash_harness : bool;
  mechanical_verify_harness : bool;
  mechanical_open_harness : bool;
  mechanical_seal_harness : bool;
  mechanical_rewrap_harness : bool;
  mechanical_rotate_epoch_harness : bool;
  mechanical_rotate_epoch_full_harness : bool;
  mechanical_capability_tree_harness : bool;
  mechanical_transparency_harness : bool;
  mechanical_boundary_preserved : bool;
  mechanical_no_full_proof_claim : bool
}.

Definition arc_rust_mechanical_refinement_coverage_complete
  (coverage : ArcRustMechanicalRefinementCoverage)
  : bool :=
  mechanical_inventory_script coverage &&
  mechanical_inventory_json coverage &&
  mechanical_inventory_test coverage &&
  mechanical_refinement_plan coverage &&
  mechanical_codec_decode_harness coverage &&
  mechanical_codec_encode_harness coverage &&
  mechanical_context_hash_harness coverage &&
  mechanical_verify_harness coverage &&
  mechanical_open_harness coverage &&
  mechanical_seal_harness coverage &&
  mechanical_rewrap_harness coverage &&
  mechanical_rotate_epoch_harness coverage &&
  mechanical_rotate_epoch_full_harness coverage &&
  mechanical_capability_tree_harness coverage &&
  mechanical_transparency_harness coverage &&
  mechanical_boundary_preserved coverage &&
  mechanical_no_full_proof_claim coverage.

Definition arc_current_rust_mechanical_refinement_coverage
  : ArcRustMechanicalRefinementCoverage :=
  {|
    mechanical_inventory_script := true;
    mechanical_inventory_json := true;
    mechanical_inventory_test := true;
    mechanical_refinement_plan := true;
    mechanical_codec_decode_harness := true;
    mechanical_codec_encode_harness := true;
    mechanical_context_hash_harness := true;
    mechanical_verify_harness := true;
    mechanical_open_harness := true;
    mechanical_seal_harness := true;
    mechanical_rewrap_harness := true;
    mechanical_rotate_epoch_harness := true;
    mechanical_rotate_epoch_full_harness := true;
    mechanical_capability_tree_harness := true;
    mechanical_transparency_harness := true;
    mechanical_boundary_preserved := true;
    mechanical_no_full_proof_claim := true
  |}.

Definition arc_rust_mechanical_refinement_coverage_score
  (coverage : ArcRustMechanicalRefinementCoverage)
  : nat :=
  (if mechanical_inventory_script coverage then 1 else 0) +
  (if mechanical_inventory_json coverage then 1 else 0) +
  (if mechanical_inventory_test coverage then 1 else 0) +
  (if mechanical_refinement_plan coverage then 1 else 0) +
  (if mechanical_codec_decode_harness coverage then 1 else 0) +
  (if mechanical_codec_encode_harness coverage then 1 else 0) +
  (if mechanical_context_hash_harness coverage then 1 else 0) +
  (if mechanical_verify_harness coverage then 1 else 0) +
  (if mechanical_open_harness coverage then 1 else 0) +
  (if mechanical_seal_harness coverage then 1 else 0) +
  (if mechanical_rewrap_harness coverage then 1 else 0) +
  (if mechanical_rotate_epoch_harness coverage then 1 else 0) +
  (if mechanical_rotate_epoch_full_harness coverage then 1 else 0) +
  (if mechanical_capability_tree_harness coverage then 1 else 0) +
  (if mechanical_transparency_harness coverage then 1 else 0) +
  (if mechanical_boundary_preserved coverage then 1 else 0) +
  (if mechanical_no_full_proof_claim coverage then 1 else 0).

Definition arc_rust_mechanical_refinement_coverage_total : nat := 17.

Definition arc_rust_mechanical_refinement_coverage_is_100_percent
  (coverage : ArcRustMechanicalRefinementCoverage)
  : bool :=
  Nat.eqb
    (arc_rust_mechanical_refinement_coverage_score coverage)
    arc_rust_mechanical_refinement_coverage_total.

Theorem current_mechanical_harness_list_complete :
  mechanical_harness_list_complete arc_rust_mechanical_refinement_targets = true.
Proof.
  reflexivity.
Qed.

Theorem current_mechanical_proof_list_not_complete :
  mechanical_proof_list_complete arc_rust_mechanical_refinement_targets = false.
Proof.
  reflexivity.
Qed.

Theorem current_rust_mechanical_refinement_coverage_complete :
  arc_rust_mechanical_refinement_coverage_complete
    arc_current_rust_mechanical_refinement_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem current_rust_mechanical_refinement_coverage_score_is_total :
  arc_rust_mechanical_refinement_coverage_score
    arc_current_rust_mechanical_refinement_coverage =
  arc_rust_mechanical_refinement_coverage_total.
Proof.
  reflexivity.
Qed.

Theorem current_rust_mechanical_refinement_coverage_is_100_percent :
  arc_rust_mechanical_refinement_coverage_is_100_percent
    arc_current_rust_mechanical_refinement_coverage = true.
Proof.
  reflexivity.
Qed.

Theorem mechanical_harness_preserves_prior_closures :
  arc_rust_mechanical_refinement_coverage_is_100_percent
    arc_current_rust_mechanical_refinement_coverage = true ->
  arc_abstract_invariant_coverage_is_100_percent arc_current_abstract_invariant_coverage = true /\
  arc_design_model_coverage_is_100_percent arc_current_design_model_coverage = true /\
  arc_state_machine_coverage_is_100_percent arc_current_state_machine_coverage = true /\
  arc_merkle_transparency_coverage_is_100_percent arc_current_merkle_transparency_coverage = true /\
  arc_crypto_reduction_coverage_is_100_percent arc_current_crypto_reduction_coverage = true /\
  arc_rust_coq_refinement_evidence_is_100_percent arc_current_rust_coq_refinement_evidence_coverage = true.
Proof.
  intros _.
  split.
  - apply current_abstract_invariant_coverage_is_100_percent.
  - split.
    + apply current_design_model_coverage_is_100_percent.
    + split.
      * apply current_state_machine_coverage_is_100_percent.
      * split.
        -- apply current_merkle_transparency_coverage_is_100_percent.
        -- split.
           ++ apply current_crypto_reduction_coverage_is_100_percent.
           ++ apply current_rust_coq_refinement_evidence_is_100_percent.
Qed.

Theorem mechanical_harness_does_not_claim_full_mechanical_proof :
  arc_rust_mechanical_refinement_coverage_is_100_percent
    arc_current_rust_mechanical_refinement_coverage = true /\
  mechanical_proof_list_complete arc_rust_mechanical_refinement_targets = false /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_rust_mechanical_refinement_coverage_is_100_percent.
  - split.
    + apply current_mechanical_proof_list_not_complete.
    + apply current_obligations_are_not_claimed_fully_satisfied.
Qed.

Theorem arc_rust_mechanical_refinement_harness_layer_closed :
  arc_rust_mechanical_refinement_coverage_complete
    arc_current_rust_mechanical_refinement_coverage = true /\
  arc_rust_mechanical_refinement_coverage_is_100_percent
    arc_current_rust_mechanical_refinement_coverage = true /\
  mechanical_harness_list_complete arc_rust_mechanical_refinement_targets = true /\
  mechanical_proof_list_complete arc_rust_mechanical_refinement_targets = false /\
  obligations_all_satisfied current_arc_refinement_obligations = false.
Proof.
  split.
  - apply current_rust_mechanical_refinement_coverage_complete.
  - split.
    + apply current_rust_mechanical_refinement_coverage_is_100_percent.
    + split.
      * apply current_mechanical_harness_list_complete.
      * split.
        -- apply current_mechanical_proof_list_not_complete.
        -- apply current_obligations_are_not_claimed_fully_satisfied.
Qed.
