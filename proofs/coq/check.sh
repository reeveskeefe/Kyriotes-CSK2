#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

coq_flags=(
  -Q core ArcProofs
  -Q merkle_transparency ArcProofs
  -Q security ArcProofs
  -Q lifecycle ArcProofs
  -Q completeness ArcProofs
  -Q rust_refinement ArcProofs
)

proofs=(
  core/ArcTypes.v
  merkle_transparency/ArcMerkle.v
  core/ArcAuthority.v
  core/ArcPolicy.v
  core/ArcVerify.v
  security/ArcSecurityGame.v
  security/ArcTheorems.v
  security/ArcStressProofs.v
  security/ArcDelegationProofs.v
  security/ArcCryptoReduction.v
  lifecycle/ArcTemporalProofs.v
  lifecycle/ArcTranscriptProofs.v
  lifecycle/ArcRevocationCompromiseProofs.v
  merkle_transparency/ArcTransparencyProofs.v
  lifecycle/ArcEncodingProofs.v
  lifecycle/ArcWrapperProofs.v
  security/ArcKemAeadAssumptions.v
  lifecycle/ArcEndToEndTheorems.v
  lifecycle/ArcStateTransitionProofs.v
  merkle_transparency/ArcConcreteMerkleProofs.v
  merkle_transparency/ArcTransparencyConsistencyProofs.v
  lifecycle/ArcProtocolStateMachineProofs.v
  lifecycle/ArcInvalidTransitionProofs.v
  security/ArcTightSecurityGameProofs.v
  security/ArcAssumptionReductionProofs.v
  rust_refinement/ArcRustRefinementMap.v
  completeness/ArcMasterInvariantProofs.v
  merkle_transparency/ArcMerkleConcreteTree.v
  merkle_transparency/ArcTransparencyAppendOnly.v
  lifecycle/ArcLifecycleProofs.v
  lifecycle/ArcPredicateRefinementProofs.v
  security/ArcAdversaryGame.v
  rust_refinement/ArcRustRefinementObligations.v
  completeness/ArcAbstractInvariantCompleteness.v
  completeness/ArcDesignModelCompleteness.v
  completeness/ArcStateMachineCompleteness.v
  merkle_transparency/ArcMerkleTransparencyCompleteness.v
  security/ArcCryptoReductionCompleteness.v
  rust_refinement/ArcRustRefinementEvidence.v
  rust_refinement/ArcRustMechanicalRefinement.v
  rust_refinement/ArcRustFullMechanicalProofGate.v
  rust_refinement/ArcContextHashRustRefinement.v
  rust_refinement/ArcDecodeArcObjectRustRefinement.v
  rust_refinement/ArcEncodeArcObjectRustRefinement.v
  rust_refinement/ArcVerifyRustRefinement.v
  rust_refinement/ArcSealRustRefinement.v
  rust_refinement/ArcOpenRustRefinement.v
  rust_refinement/ArcSealOpenModelCryptoEquivalence.v
  rust_refinement/ArcSealOpenCryptoSemanticContracts.v
  rust_refinement/ArcAddEpochWrapperRustRefinement.v
  rust_refinement/ArcRotateEpochRustRefinement.v
  rust_refinement/ArcRotateEpochFullRustRefinement.v
  rust_refinement/ArcCapabilityTreeRustRefinement.v
  rust_refinement/ArcTransparencyRustRefinement.v
  rust_refinement/ArcFullMechanicalProofEquivalence.v
)

for proof in "${proofs[@]}"; do
  coqc "${coq_flags[@]}" "$proof"
done

echo "ARC Coq proofs compiled successfully."
