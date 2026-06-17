(* KEM+AEAD composition for Kyriotēs-CSK2.
 *
 * Assembles the three proved hybrid-step lemmas into the final
 * concrete security bound — no axiom stubs.
 *
 *   kem_hybrid_step  (KemReduction.ec)     : |Pr[G0] - Pr[G1]| <= 2^{-128}
 *   game1_game2_cpa  (AeadCpaReduction.ec) : |Pr[G1] - Pr[G2]| <= 2^{-128}
 *   game2_win_bound  (AeadCtxtReduction.ec): Pr[G2]             <= 2^{-128}
 *
 * Combining with the triangle inequality gives Pr[Game0(A)] <= 3 * 2^{-128}.
 *
 * Remaining primitive-security leaves (axioms in their files):
 *   kem_ror      — KEM IND-CCA2 real-or-random (ML-KEM-768)
 *   aead_cpa_adv — AEAD IND-CPA (ChaCha20-Poly1305)
 *   aead_ow      — one-way / message-hiding bound on dmsg
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Real.
require import Csk2TwoGateGame.
require import KemReduction.
require import AeadCpaReduction.
require import AeadCtxtReduction.

section Composition.

declare module A <: Csk2Adv { -Game0, -Game1, -Game2 }.

(*
 * csk2_concrete_bound
 *
 * Each have-step is discharged by a proved lemma from a reduction file;
 * smt() closes the arithmetic via the triangle inequality.
 *
 *   Pr[G0] - Pr[G1]  bounded by kem_hybrid_step    (KEM IND-CCA2)
 *   Pr[G1] - Pr[G2]  bounded by game1_game2_cpa    (AEAD IND-CPA)
 *   Pr[G2]           bounded by game2_win_bound     (AEAD one-way)
 *)
lemma csk2_concrete_bound &m :
  Pr[Game0(A).main() @ &m : res] <= 3%r * inv (2%r ^ 128).
proof.
  have h01 := kem_hybrid_step A &m.
  have h12 := game1_game2_cpa A &m.
  have h2  := game2_win_bound A &m.
  smt().
qed.

end section Composition.
