# Rust-to-Coq Refinement Evidence

This directory stores deterministic evidence connecting ARC Rust implementation surfaces to Coq model concepts.

Generated file:

    rust_coq_refinement_evidence.json

Generate it with:

    ./scripts/refinement/generate_refinement_evidence.py

This evidence is not a full formal refinement proof. It is an executable witness layer that confirms the expected Rust source files and symbols exist and are tracked against the Coq model.
