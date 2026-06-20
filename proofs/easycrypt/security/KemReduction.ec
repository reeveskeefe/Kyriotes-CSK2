(* KEM reduction for Kyriotēs-CSK2 hybrid argument.
 *
 * Discharges the game0_game1_kem axiom stub from Csk2TwoGateGame.ec
 * by constructing B_KEM and embedding Game0/Game1 into the KEM
 * real-or-random worlds.
 *
 * Dependency chain:
 *   kem_hybrid_step
 *     ← game0_eq_kem_real  (byequiv: swap pure assignments, sim)
 *     ← game1_eq_kem_rand  (byequiv: swap pure assignments, sim)
 *     ← kem_csk2_ror_secure (wrapper over the ML-KEM-768 RoR primitive leaf)
 *
 * KemIndCca2.ec exposes the direct real-or-random worlds used by this
 * hybrid, so this file no longer carries a local KEM RoR axiom.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr Real.
require import Csk2BaseTypes.
require import Csk2TwoGateGame.
require import KemIndCca2.

(* ── B_KEM: CSK2 adversary → KEM adversary ──────────────────── *)
(*
 * B_KEM(A).run(pk, ct_k, ss_b):
 *   Derive k = hkdf(ss_b).  Sample AEAD ciphertext for the fixed
 *   witness plaintext.  Forward (pk, ct_k, ct_a, aad) to A.attack.
 *
 * Simulation argument:
 *   ss_b = ss_real  →  k from real KEM ss  →  identical to Game0
 *   ss_b = ss_rand  →  k from uniform ss   →  identical to Game1
 *)
module B_KEM (A : Csk2Adv) : KEM_RoR_Adversary = {
  proc run(pk : pkey, ct_k : ctkem, ss_b : ss) : bool = {
    var k     : key;
    var m     : msg;
    var a     : aad;
    var ct_a  : ctaead;
    var guess : msg option;
    m     <$ dmsg;
    a     <- witness;
    k     <- hkdf ss_b;
    ct_a  <$ aenc k a m;
    guess <@ A.attack(pk, ct_k, ct_a, a);
    return (guess = Some m);
  }
}.

(* ── Proof section ──────────────────────────────────────────── *)

section KemHybrid.

declare module A <: Csk2Adv { -Game0, -Game1, -Game2 }.

(*
 * Game0(A) ≡ Game_KEM_RoR_Real(B_KEM(A)).
 *
 * swap {1} [2..3] 1 aligns both programs:
 *   LHS: [dk, enc, m, a, hkdf, aenc, A, result]
 *   RHS: [dk, enc, m, a, hkdf, aenc, A, b', result]  (after inline)
 *
 * wp absorbs the trailing result/b'.  The abstract-module step is
 * discharged by establishing Hatt (equiv[A.attack ~ A.attack]) via sim,
 * then calling it to reduce to the concrete coupling subgoal
 * [dk, enc, m, a, hkdf, aenc].  auto => /# closes the coupling:
 * it drives wp (absorbs hkdf/a), rnd for aenc/m/enc/dk, and smt for the
 * deferred distribution-equality obligations.
 *)
lemma game0_eq_kem_real &m :
  Pr[Game0(A).main() @ &m : res] =
  Pr[Game_KEM_RoR_Real(B_KEM(A)).main() @ &m : res].
proof.
  byequiv => //; proc; inline B_KEM(A).run.
  swap {1} [2..3] 1.
  wp.
  have Hatt : equiv[A.attack ~ A.attack : ={glob A, arg} ==> ={glob A, res}] by sim.
  call Hatt.
  auto => /#.
qed.

(*
 * Game1(A) ≡ Game_KEM_RoR_Rand(B_KEM(A)).
 *
 * swap {1} [2..3] 2 aligns both programs:
 *   LHS: [dk, enc, dss, m, a, hkdf, aenc, A, result]
 *   RHS: [dk, enc, dss, m, a, hkdf, aenc, A, b', result]  (after inline)
 *
 * Same structural argument as game0_eq_kem_real.  wp absorbs the
 * trailing result/b'; Hatt (sim) closes the abstract-module step;
 * auto => /# closes the concrete coupling [dk, enc, dss, m, a, hkdf, aenc].
 *)
lemma game1_eq_kem_rand &m :
  Pr[Game1(A).main() @ &m : res] =
  Pr[Game_KEM_RoR_Rand(B_KEM(A)).main() @ &m : res].
proof.
  byequiv => //; proc; inline B_KEM(A).run.
  swap {1} [2..3] 2.
  wp.
  have Hatt : equiv[A.attack ~ A.attack : ={glob A, arg} ==> ={glob A, res}] by sim.
  call Hatt.
  auto => /#.
qed.

(*
 * Hybrid step: |Pr[Game0] - Pr[Game1]| <= inv(2^128).
 *
 * Substitute the two game-equivalence lemmas then apply the imported
 * KEM RoR security axiom.
 * This discharges the game0_game1_kem axiom stub in
 * Csk2TwoGateGame.ec.
 *)
lemma kem_hybrid_step &m :
  `| Pr[Game0(A).main() @ &m : res] - Pr[Game1(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof.
  rewrite (game0_eq_kem_real &m) (game1_eq_kem_rand &m).
  exact (kem_csk2_ror_secure (B_KEM(A)) &m).
qed.

end section KemHybrid.
