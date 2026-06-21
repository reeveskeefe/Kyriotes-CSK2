(* KEM real-or-random advantage game for Kyriotēs-CSK2.
 *
 * Formalizes the direct real-or-random KEM game consumed by
 * KemReduction.ec.  The primitive theorem boundary is ML-KEM-768 RoR
 * security; importing a full ML-KEM EasyCrypt development should prove
 * `mlkem768_ror_secure`, after which `kem_csk2_ror_secure` is immediate.
 *
 * Types (pkey, skey, ctkem, ss) and primitive operators (encap, decap,
 * dss, dkeypair) are declared in Csk2BaseTypes.ec.
 *
 * EasyCrypt version: r2022.04 (easycryptpa/ec-test-box:latest)
 *)

require import AllCore Distr Real.
require import Csk2BaseTypes.

(* ── Direct real-or-random KEM worlds for hybrid reductions ───── *)

module type KEM_RoR_Adversary = {
  proc run(pk : pkey, ct_k : ctkem, ss_b : ss) : bool
}.

module Game_KEM_RoR_Real (A : KEM_RoR_Adversary) = {
  proc main() : bool = {
    var pk      : pkey;
    var sk      : skey;
    var ct_k    : ctkem;
    var ss_real : ss;
    var b'      : bool;

    (pk, sk)        <$ dkeypair;
    (ct_k, ss_real) <$ encap pk;
    b'              <@ A.run(pk, ct_k, ss_real);
    return b';
  }
}.

module Game_KEM_RoR_Rand (A : KEM_RoR_Adversary) = {
  proc main() : bool = {
    var pk      : pkey;
    var sk      : skey;
    var ct_k    : ctkem;
    var ss_ign  : ss;
    var ss_rand : ss;
    var b'      : bool;

    (pk, sk)       <$ dkeypair;
    (ct_k, ss_ign) <$ encap pk;
    ss_rand        <$ dss;
    b'             <@ A.run(pk, ct_k, ss_rand);
    return b';
  }
}.

(* ── Advantage and security statement ────────────────────────────
 *
 * Advantage is stated inside a section so A is a concrete module
 * variable (required by EasyCrypt's probability syntax).
 *
 * Security goal:
 *   For all PPT adversaries A, the real and random shared-secret worlds
 *   are indistinguishable.
 *   ML-KEM-768 targets >= 128-bit classical security.
 *
 * The ML-KEM-768 primitive security statement is imported here as a
 * standard-boundary assumption.  This repository models CSK2's use of
 * ML-KEM-768; it does not prove FIPS 203 / ML-KEM-768 security internally.
 *
 * Adapter status:
 *   - third_party/formosa-mlkem contains a Formosa EasyCrypt proof for
 *     ML-KEM-768.
 *   - The closest theorem is `mlkem_spec_security` in
 *     proof/spec/MLKEMSecurity768.ec.  It is a ROM bit-guessing IND-CCA
 *     theorem with a concrete multi-term reduction bound, not this direct
 *     RoR statement.
 *   - The adapter inventory is documented in
 *     docs/verification/MLKEM_FORMOSA_ADAPTER_INVENTORY.md.
 *   - The compile-safe adapter skeleton lives in KemFormosaAdapter.ec.
 *)

section KEM_RoR_Security.

declare module A <: KEM_RoR_Adversary { -Game_KEM_RoR_Real, -Game_KEM_RoR_Rand }.

(* Direct ML-KEM-768 real-or-random primitive boundary.  This is the
 * exact form consumed by KemReduction.ec.  It is stated separately from
 * the bit-guessing IND-CCA2 game to avoid hiding a factor-of-two or
 * convention conversion in the CSK2 hybrid proof.  Replace this axiom only
 * after KemFormosaAdapter.ec imports the Formosa theorem and proves the
 * CCA bit-guessing-to-RoR conversion with the concrete bound accounting. *)
axiom mlkem768_ror_secure &m :
  `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
     Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
  <= inv (2%r ^ 128).

lemma kem_csk2_ror_secure &m :
  `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
     Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof.
  exact (mlkem768_ror_secure &m).
qed.

end section KEM_RoR_Security.
