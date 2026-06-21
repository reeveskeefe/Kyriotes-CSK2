(* Import smoke test for the vendored Formosa ML-KEM-768 EasyCrypt theorem.
 *
 * This file is intentionally not part of the default CSK2 EasyCrypt suite.
 * Formosa currently requires a newer EasyCrypt branch than
 * easycryptpa/ec-test-box:r2022.04 supports; in particular, its vendored
 * Jasmin library uses syntax such as `hint [rigid]`.
 *
 * Compile with:
 *
 *   make check-formosa-mlkem-import FORMOSA_EASYCRYPT=<formosa-compatible easycrypt>
 *
 * The `require` below is non-importing on purpose: it checks that the Formosa
 * theorem file is loadable while avoiding accidental namespace collisions with
 * CSK2's own `pkey`, `skey`, `ctkem`, and `ss` names.
 *)

require import AllCore.
require import KemIndCca2.
require MLKEMSecurity768.

op formosa_mlkem_import_smoke : bool = true.
