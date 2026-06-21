# ML-KEM Numeric Policy

Kyriotēs-CSK2 keeps the ML-KEM primitive leaf in summary form:

```easycrypt
|Pr[Game_KEM_RoR_Real(A)] - Pr[Game_KEM_RoR_Rand(A)]| <= 2^-128
```

This is the bound consumed by `KemReduction.ec` and the composed CSK2 security
theorems.  It keeps the CSK2 composition readable:

```text
KEM hybrid step      <= 2^-128
AEAD CPA step        <= 2^-128
message hiding step  <= 2^-128
opening bound        <= 3 * 2^-128
full bad-event bound <= 10 * 2^-128
```

The summary leaf is intended to be discharged by the Formosa ML-KEM-768
EasyCrypt proof plus:

1. a branch-equivalence adapter from Formosa `SPEC_MODEL.CCA` to the local
   `RandomLR` game;
2. `KemRorCcaBridge.kem_randomlr_to_ror_bound`;
3. a concrete parameter audit showing the Formosa multi-term bound is at most
   `2^-128` for the selected ML-KEM-768 assumptions and query limits.

The current import smoke check for step 1 is:

```sh
scripts/verification/check_formosa_mlkem_import.sh
```

or:

```sh
make -C proofs/easycrypt check-formosa-mlkem-import-auto
```

Until those steps compile in this repository, `mlkem768_ror_secure` remains an
explicit primitive summary assumption.  We do not expose Formosa's full
multi-term bound in `KemIndCca2.ec` yet, because doing so would ripple through
the CSK2 composition without closing the external import.
