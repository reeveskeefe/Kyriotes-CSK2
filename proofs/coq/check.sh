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

echo "ARC Coq proofs compiled successfully."
