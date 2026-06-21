(* Adapter skeleton for discharging the Kyriotēs-CSK2 ML-KEM-768 RoR leaf
 * against the vendored Formosa ML-KEM EasyCrypt development.
 *
 * This file intentionally does not prove or restate `mlkem768_ror_secure`.
 * The current Formosa theorem closest to the needed leaf is:
 *
 *   third_party/formosa-mlkem/proof/spec/MLKEMSecurity768.ec
 *     lemma mlkem_spec_security
 *
 * Its shape is bit-guessing IND-CCA in the ROM:
 *
 *   |Pr[SPEC_MODEL.CCA(SPEC_MODEL.RO.RO, MLKEM_Op, A)] - 1/2|
 *     <= concrete multi-term bound over MLWE, SHA-family PRG/PRF,
 *        correctness, query limits, and message-spread terms.
 *
 * Kyriotēs-CSK2 currently consumes the direct RoR form in KemIndCca2.ec:
 *
 *   |Pr[Game_KEM_RoR_Real(A)] - Pr[Game_KEM_RoR_Rand(A)]| <= 2^-128
 *
 * Required adapter work:
 *   1. Add Formosa and crypto-specs include paths to the EasyCrypt build.
 *   2. Import MLKEMSecurity768.ec.
 *   3. Use KemRorCcaBridge.ec for the generic bit-guessing/left-right to
 *      direct RoR factor accounting.
 *   4. Map Formosa publickey/secretkey/ciphertext/sharedsecret to
 *      Csk2BaseTypes pkey/skey/ctkem/ss.
 *   5. Derive the final 2^-128 numeric bound or expose the full concrete
 *      Formosa bound at the Kyriotēs-CSK2 primitive boundary.
 *
 * See docs/verification/MLKEM_FORMOSA_ADAPTER_INVENTORY.md for the current
 * theorem inventory and mismatch list.
 *
 * EasyCrypt version: r2022.04 (easycryptpa/ec-test-box:latest)
 *)

require import AllCore Distr Real.
require import Csk2BaseTypes.
require import KemIndCca2.
require import KemRorCcaBridge.

(* ── Intended proof pipeline ─────────────────────────────────────
 *
 * The adapter closure should be structured as:
 *
 *   Formosa `mlkem_spec_security`
 *     gives:
 *       |Pr[SPEC_MODEL.CCA(...).main] - 1/2| <= formosa_bound
 *
 *   Formosa-specific branch equivalence
 *     proves:
 *       Pr[SPEC_MODEL.CCA(...).main]
 *       =
 *       Pr[LR.RandomLR(KEM_RoR_Real_Unit(A), KEM_RoR_Rand_Unit(A)).main(witness)]
 *
 *   Local generic bridge from KemRorCcaBridge.ec
 *     applies:
 *       kem_randomlr_to_ror_bound
 *
 *   Numeric/policy bound
 *     proves:
 *       2 * formosa_bound <= inv (2^128)
 *
 *   Result:
 *       mlkem768_ror_secure_from_formosa
 *
 * Until all four steps compile, KemIndCca2.ec keeps `mlkem768_ror_secure`
 * as the explicit primitive leaf.
 *)

(* Deliberately local aliases: these make the intended adapter surface explicit
 * without pretending the external Formosa types have already been imported.
 *)
type formosa_publickey.
type formosa_secretkey.
type formosa_ciphertext.
type formosa_sharedsecret.
type formosa_ro_input.
type formosa_ro_output.

op formosa_pk_to_csk2 : formosa_publickey -> pkey.
op formosa_sk_to_csk2 : formosa_secretkey -> skey.
op formosa_ct_to_csk2 : formosa_ciphertext -> ctkem.
op formosa_ss_to_csk2 : formosa_sharedsecret -> ss.

op csk2_pk_to_formosa : pkey -> formosa_publickey.
op csk2_sk_to_formosa : skey -> formosa_secretkey.
op csk2_ct_to_formosa : ctkem -> formosa_ciphertext.
op csk2_ss_to_formosa : ss -> formosa_sharedsecret.

module type FormosaPOracle = {
  proc get(x : formosa_ro_input) : formosa_ro_output
}.

module type FormosaCCAOracle = {
  proc dec(c : formosa_ciphertext) : formosa_sharedsecret option
}.

(* Mirrors Formosa's ROM CCA adversary shape:
 *
 *   module type CCA_ADV (H : POracle, O : CCA_ORC) = {
 *     proc guess(pk : pkey, c : ciphertext, k : key) : bool
 *   }.
 *
 * The CSK2 adversary wrapper does not call H or O.  They are parameters only
 * because Formosa's theorem quantifies over adversaries in that richer oracle
 * context.
 *)
module type FormosaROMCCAAdversary = {
  proc guess(pk : formosa_publickey,
             c  : formosa_ciphertext,
             k  : formosa_sharedsecret) : bool
}.

module B_FormosaROMCCA
  (A : KEM_RoR_Adversary)
  (H : FormosaPOracle)
  (O : FormosaCCAOracle) : FormosaROMCCAAdversary = {
  proc guess(pk : formosa_publickey,
             c  : formosa_ciphertext,
             k  : formosa_sharedsecret) : bool = {
    var b : bool;
    b <@ A.run(formosa_pk_to_csk2 pk,
               formosa_ct_to_csk2 c,
               formosa_ss_to_csk2 k);
    return b;
  }
}.

(* Future theorem target, once Formosa imports, branch equivalence, and numeric
 * accounting are wired:
 *
 * lemma mlkem768_ror_secure_from_formosa &m :
 *   `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
 *      Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
 *   <= inv (2%r ^ 128).
 *
 * This must replace, not duplicate, the `mlkem768_ror_secure` axiom in
 * KemIndCca2.ec.
 *
 * Proof outline:
 *   1. Instantiate Formosa `mlkem_spec_security` with the adversary wrapper
 *      corresponding to `B_FormosaROMCCA(A)`.
 *   2. Rewrite the Formosa CCA game to the local `LR.RandomLR` game.
 *   3. Apply `kem_randomlr_to_ror_bound`.
 *   4. Discharge the concrete Formosa-bound-to-2^-128 arithmetic/policy step.
 *)
