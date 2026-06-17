(* KEM+AEAD composition for Kyriotēs-CSK2.
 *
 * Assembles the three hybrid-step lemmas into the final concrete
 * KEM+AEAD bound.  Two primitive-security leaves remain axiomatized
 * in the primitive game files:
 * kem_csk2_ror_secure and aead_csk2_ind_cpa_lr_secure.
 *
 *   kem_hybrid_step  (KemReduction.ec)     : |Pr[G0] - Pr[G1]| <= 2^{-128}
 *   game1_game2_cpa  (AeadCpaReduction.ec) : |Pr[G1] - Pr[G2]| <= 2^{-128}
 *   game2_win_bound  (AeadCtxtReduction.ec): Pr[G2]             <= 2^{-128}
 *
 * Combining with the triangle inequality gives Pr[Game0(A)] <= 3 * 2^{-128}.
 *
 * Remaining primitive-security leaves (axioms in their files):
 *   kem_csk2_ror_secure         — direct KEM real-or-random hybrid bound
 *   aead_csk2_ind_cpa_lr_secure — direct AEAD left/right hybrid bound
 *
 * game2_win_bound is now proved in AeadCtxtReduction.ec from dmsg_bound.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Real.
require import Csk2BaseTypes.
require import Csk2TwoGateGame.
require import AeadAeSecurity.
require import KemReduction.
require import AeadCpaReduction.
require import AeadCtxtReduction.

section Composition.

declare module A <: Csk2Adv {
  -Game0, -Game1, -Game2,
  -B_CPA, -Game_CPA_Left, -Game_CPA_Right
}.

axiom A_attack_ll : islossless A.attack.

(*
 * csk2_concrete_bound
 *
 * Each have-step is discharged by a proved lemma from a reduction file;
 * smt() closes the arithmetic via the triangle inequality.
 *
 *   Pr[G0] - Pr[G1]  bounded by kem_hybrid_step    (KEM IND-CCA2)
 *   Pr[G1] - Pr[G2]  bounded by game1_game2_cpa    (AEAD IND-CPA)
 *   Pr[G2]           bounded by game2_win_bound     (message-space guessing)
 *)
lemma csk2_concrete_bound &m :
  Pr[Game0(A).main() @ &m : res] <= 3%r * inv (2%r ^ 128).
proof.
  have h01 := kem_hybrid_step A &m.
  have h12 := game1_game2_cpa A &m.
  have h2  := game2_win_bound A &m.
  smt().
qed.

lemma csk2_concrete_bound_phoare :
  phoare [Game0(A).main : true ==> !res] >= (1%r - 3%r * inv (2%r ^ 128)).
proof.
  bypr => &m _.
  have h := csk2_concrete_bound &m.
  have hll : Pr[Game0(A).main() @ &m : true] = 1%r.
  + byphoare (_ : true ==> true) => //; proc.
    call A_attack_ll.
    auto; smt(dkeypair_ll dmsg_ll encap_ll aenc_ll).
  rewrite Pr[mu_not] hll.
  smt().
qed.

end section Composition.
