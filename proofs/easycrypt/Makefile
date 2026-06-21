# EasyCrypt proof checker for Kyriotēs-CSK2
#
# Usage:
#   make          — check all .ec files
#   make check    — same
#   make clean    — remove generated files
#   make check-formosa-mlkem-import-auto
#                 — optional Formosa ML-KEM import smoke via Nix/Docker
#
# Requires: easycrypt in PATH.
# Docker target: docker run --rm -v $(PWD):/work -w /work \
#                  easycryptpa/ec-test-box:latest make

EASYCRYPT ?= easycrypt
EC_FLAGS  ?=
FORMOSA_ROOT ?= ../../third_party/formosa-mlkem
FORMOSA_EASYCRYPT ?= $(EASYCRYPT)
FORMOSA_EC_FLAGS ?= \
  -I security \
  -I $(FORMOSA_ROOT)/proof/security \
  -I $(FORMOSA_ROOT)/proof/spec \
  -I $(FORMOSA_ROOT)/proof/eclib \
  -I Jasmin:$(FORMOSA_ROOT)/jasmin/eclib \
  -I Keccak:$(FORMOSA_ROOT)/formosa-keccak/proof/amd64/common \
  -I Keccak:$(FORMOSA_ROOT)/formosa-keccak/proof/amd64/ref \
  -I Keccak:$(FORMOSA_ROOT)/formosa-keccak/proof/amd64/avx2 \
  -I JazzEC:$(FORMOSA_ROOT)/formosa-keccak/proof/amd64/extracted \
  -I CryptoSpecs:$(FORMOSA_ROOT)/crypto-specs/arrays \
  -I CryptoSpecs:$(FORMOSA_ROOT)/crypto-specs/common \
  -I CryptoSpecs:$(FORMOSA_ROOT)/crypto-specs/fips202 \
  -I CryptoSpecs:$(FORMOSA_ROOT)/crypto-specs/ml-kem \
  -I JazzEC:$(FORMOSA_ROOT)/crypto-specs/arrays \
  -I JazzEC:$(FORMOSA_ROOT)/crypto-specs/common \
  -I JazzEC:$(FORMOSA_ROOT)/code/jasmin/768/ref/extraction \
  -I JazzEC:$(FORMOSA_ROOT)/code/jasmin/1024/ref/extraction \
  -I JazzEC:$(FORMOSA_ROOT)/code/jasmin/768/avx2/extraction \
  -I JazzEC:$(FORMOSA_ROOT)/code/jasmin/1024/avx2/extraction

# Files in dependency order
EC_FILES = \
  security/Csk2BaseTypes.ec \
  security/KemIndCca2.ec \
  security/KemRorCcaBridge.ec \
  security/KemFormosaAdapter.ec \
  security/AeadAeSecurity.ec \
  security/Csk2MerkleBinding.ec \
  security/Csk2CapabilityGame.ec \
  security/Csk2TwoGateGame.ec \
  security/KemReduction.ec \
  security/AeadCpaReduction.ec \
  security/AeadCtxtReduction.ec \
  security/KemAeadComposition.ec \
  security/Csk2FullSecurityComposition.ec

.PHONY: check check-formosa-mlkem-import check-formosa-mlkem-import-auto all clean

all: check

check: $(EC_FILES)
	@echo "── Kyriotēs-CSK2 EasyCrypt proof check ──"
	@failed=0; \
	for f in $(EC_FILES); do \
	  printf "  checking %-55s" "$$f"; \
	  if $(EASYCRYPT) compile $(EC_FLAGS) $$f > /dev/null 2>&1; then \
	    echo "OK"; \
	  else \
	    echo "FAILED"; \
	    $(EASYCRYPT) compile $(EC_FLAGS) $$f; \
	    failed=$$((failed + 1)); \
	  fi; \
	done; \
	if [ $$failed -gt 0 ]; then \
	  echo ""; \
	  echo "$$failed file(s) failed."; \
	  exit 1; \
	fi
	@echo "── All EasyCrypt files passed ──"

check-formosa-mlkem-import:
	@echo "── Formosa ML-KEM import smoke check ──"
	@echo "Using FORMOSA_EASYCRYPT=$(FORMOSA_EASYCRYPT)"
	@echo "Note: Formosa requires a newer EasyCrypt branch than easycryptpa/ec-test-box:r2022.04."
	$(FORMOSA_EASYCRYPT) compile $(FORMOSA_EC_FLAGS) security/KemFormosaImportSmoke.ec

check-formosa-mlkem-import-auto:
	../../scripts/verification/check_formosa_mlkem_import.sh

clean:
	find . -name "*.eco" -delete
