#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v coqc >/dev/null 2>&1; then
  for rocq_bin in \
    /opt/homebrew/opt/rocq/bin \
    /opt/homebrew/Cellar/rocq/*/bin \
    /usr/local/opt/rocq/bin \
    /usr/local/Cellar/rocq/*/bin; do
    if [ -x "$rocq_bin/coqc" ]; then
      PATH="$rocq_bin:$PATH"
      break
    fi
  done
fi

coq_flags=(
  -Q core KyriotesCsk2Proofs
  -Q merkle_transparency KyriotesCsk2Proofs
  -Q security KyriotesCsk2Proofs
  -Q lifecycle KyriotesCsk2Proofs
  -Q completeness KyriotesCsk2Proofs
  -Q rust_refinement KyriotesCsk2Proofs
)

proofs=(
  core/KyriotesCsk2Types.v
  merkle_transparency/KyriotesCsk2Merkle.v
  core/KyriotesCsk2Authority.v
  core/KyriotesCsk2Policy.v
  core/KyriotesCsk2Verify.v
  security/KyriotesCsk2SecurityGame.v
  security/KyriotesCsk2Theorems.v
  security/KyriotesCsk2StressProofs.v
  security/KyriotesCsk2DelegationProofs.v
  security/KyriotesCsk2CryptoReduction.v
  lifecycle/KyriotesCsk2TemporalProofs.v
  lifecycle/KyriotesCsk2TranscriptProofs.v
  lifecycle/KyriotesCsk2RevocationCompromiseProofs.v
  merkle_transparency/KyriotesCsk2TransparencyProofs.v
  lifecycle/KyriotesCsk2EncodingProofs.v
  lifecycle/KyriotesCsk2WrapperProofs.v
  security/KyriotesCsk2KemAeadAssumptions.v
  lifecycle/KyriotesCsk2EndToEndTheorems.v
  lifecycle/KyriotesCsk2StateTransitionProofs.v
  merkle_transparency/KyriotesCsk2ConcreteMerkleProofs.v
  merkle_transparency/KyriotesCsk2TransparencyConsistencyProofs.v
  lifecycle/KyriotesCsk2ProtocolStateMachineProofs.v
  lifecycle/KyriotesCsk2InvalidTransitionProofs.v
  security/KyriotesCsk2TightSecurityGameProofs.v
  security/KyriotesCsk2AssumptionReductionProofs.v
  rust_refinement/KyriotesCsk2RustRefinementMap.v
  completeness/KyriotesCsk2MasterInvariantProofs.v
  merkle_transparency/KyriotesCsk2MerkleConcreteTree.v
  merkle_transparency/KyriotesCsk2TransparencyAppendOnly.v
  lifecycle/KyriotesCsk2LifecycleProofs.v
  lifecycle/KyriotesCsk2PredicateRefinementProofs.v
  security/KyriotesCsk2AdversaryGame.v
  rust_refinement/KyriotesCsk2RustRefinementObligations.v
  completeness/KyriotesCsk2AbstractInvariantCompleteness.v
  completeness/KyriotesCsk2DesignModelCompleteness.v
  completeness/KyriotesCsk2StateMachineCompleteness.v
  merkle_transparency/KyriotesCsk2MerkleTransparencyCompleteness.v
  security/KyriotesCsk2CryptoReductionCompleteness.v
  rust_refinement/KyriotesCsk2RustRefinementEvidence.v
  rust_refinement/KyriotesCsk2RustMechanicalRefinement.v
  rust_refinement/KyriotesCsk2RustFullMechanicalProofGate.v
  rust_refinement/KyriotesCsk2ContextHashRustRefinement.v
  rust_refinement/KyriotesCsk2DecodeKyriotesCsk2ObjectRustRefinement.v
  rust_refinement/KyriotesCsk2EncodeKyriotesCsk2ObjectRustRefinement.v
  rust_refinement/KyriotesCsk2VerifyRustRefinement.v
  rust_refinement/KyriotesCsk2SealRustRefinement.v
  rust_refinement/KyriotesCsk2OpenRustRefinement.v
  rust_refinement/KyriotesCsk2SealOpenModelCryptoEquivalence.v
  rust_refinement/KyriotesCsk2SealOpenCryptoSemanticContracts.v
  rust_refinement/KyriotesCsk2EncodeDecodeRoundTripRustRefinement.v
  rust_refinement/KyriotesCsk2CapabilityTreeWitnessSoundness.v
  rust_refinement/KyriotesCsk2AddEpochWrapperRustRefinement.v
  rust_refinement/KyriotesCsk2RotateEpochRustRefinement.v
  rust_refinement/KyriotesCsk2RotateEpochFullRustRefinement.v
  rust_refinement/KyriotesCsk2CapabilityTreeRustRefinement.v
  rust_refinement/KyriotesCsk2TransparencyRustRefinement.v
  rust_refinement/KyriotesCsk2FullMechanicalProofEquivalence.v
)

for proof in "${proofs[@]}"; do
  coqc "${coq_flags[@]}" "$proof"
done

echo "Kyriotēs-CSK2 Coq proofs compiled successfully."
