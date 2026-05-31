#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

coqc ArcTypes.v
coqc ArcMerkle.v
coqc ArcAuthority.v
coqc ArcPolicy.v
coqc ArcVerify.v
coqc ArcSecurityGame.v
coqc ArcTheorems.v
coqc ArcStressProofs.v
coqc ArcDelegationProofs.v
coqc ArcCryptoReduction.v
coqc ArcTemporalProofs.v
coqc ArcTranscriptProofs.v
coqc ArcRevocationCompromiseProofs.v
coqc ArcTransparencyProofs.v
coqc ArcEncodingProofs.v
coqc ArcWrapperProofs.v
coqc ArcKemAeadAssumptions.v
coqc ArcEndToEndTheorems.v
coqc ArcStateTransitionProofs.v
coqc ArcConcreteMerkleProofs.v
coqc ArcTransparencyConsistencyProofs.v
coqc ArcProtocolStateMachineProofs.v
coqc ArcInvalidTransitionProofs.v
coqc ArcTightSecurityGameProofs.v
coqc ArcAssumptionReductionProofs.v
coqc ArcRustRefinementMap.v
coqc ArcMasterInvariantProofs.v

coqc ArcMerkleConcreteTree.v
coqc ArcTransparencyAppendOnly.v
coqc ArcLifecycleProofs.v
coqc ArcPredicateRefinementProofs.v
coqc ArcAdversaryGame.v
coqc ArcRustRefinementObligations.v
coqc ArcAbstractInvariantCompleteness.v
coqc ArcDesignModelCompleteness.v
coqc ArcStateMachineCompleteness.v
echo "ARC Coq proofs compiled successfully."
