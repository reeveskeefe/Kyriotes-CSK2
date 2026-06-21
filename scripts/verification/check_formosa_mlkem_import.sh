#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKER_IMAGE="${FORMOSA_NIX_DOCKER_IMAGE:-nixos/nix:latest}"

cd "$ROOT"

if command -v nix-shell >/dev/null 2>&1; then
  echo "Using local nix-shell from third_party/formosa-mlkem/shell.nix"
  exec nix-shell third_party/formosa-mlkem/shell.nix --run \
    "make -C proofs/easycrypt check-formosa-mlkem-import FORMOSA_EASYCRYPT=easycrypt"
fi

if ! command -v docker >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: neither nix-shell nor docker is available.

Install Nix and run:
  nix-shell third_party/formosa-mlkem/shell.nix --run \
    "make -C proofs/easycrypt check-formosa-mlkem-import FORMOSA_EASYCRYPT=easycrypt"

Or install Docker and re-run this script.
EOF
  exit 127
fi

cat <<EOF
Using Docker fallback image: $DOCKER_IMAGE
This may take a while the first time because it enters Formosa's Nix shell.
Set FORMOSA_NIX_DOCKER_IMAGE to override the Docker image.
EOF

exec docker run --rm \
  -v "$ROOT:/repo" \
  -w /repo \
  "$DOCKER_IMAGE" \
  sh -lc 'nix-shell third_party/formosa-mlkem/shell.nix --run "make -C proofs/easycrypt check-formosa-mlkem-import FORMOSA_EASYCRYPT=easycrypt"'
