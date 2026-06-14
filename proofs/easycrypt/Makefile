# EasyCrypt proof checker for Kyriotēs-CSK2
#
# Usage:
#   make          — check all .ec files
#   make check    — same
#   make clean    — remove generated files
#
# Requires: easycrypt in PATH.
# Docker target: docker run --rm -v $(PWD):/work -w /work \
#                  easycryptpa/ec-test-box:latest make

EASYCRYPT ?= easycrypt
EC_FLAGS  ?=

# Files in dependency order
EC_FILES = \
  security/KemIndCca2.ec \
  security/AeadAeSecurity.ec \
  security/Csk2TwoGateGame.ec \
  security/KemReduction.ec \
  security/KemAeadComposition.ec

.PHONY: check all clean

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

clean:
	find . -name "*.eco" -delete
