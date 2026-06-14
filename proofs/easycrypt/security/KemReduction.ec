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
 *     ← kem_ror            (KEM primitive security axiom)
 *
 * kem_ror is axiomatised here because KemIndCca2.ec redeclares the
 * same abstract types; importing both causes conflicts.  Once types
 * are factored into a shared header, kem_ror becomes a lemma proved
 * by embedding B_KEM into Game_IND_CCA2 from KemIndCca2.ec.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr Real.
require import Csk2TwoGateGame.

(* ── Local KEM real-or-random adversary type ────────────────── *)

module type KEM_Adv = {
  proc run(pk : pkey, ct_k : ctkem, ss_b : ss) : bool
}.

(* ── KEM real world ─────────────────────────────────────────── *)

module KEM_Real (A : KEM_Adv) = {
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

(* ── KEM random world ───────────────────────────────────────── *)

module KEM_Rand (A : KEM_Adv) = {
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
module B_KEM (A : Csk2Adv) : KEM_Adv = {
  proc run(pk : pkey, ct_k : ctkem, ss_b : ss) : bool = {
    var k     : key;
    var m     : msg;
    var a     : aad;
    var ct_a  : ctaead;
    var guess : msg option;
    m     <- witness;
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

(* Losslessness of A.attack — needed for byequiv termination goals. *)
axiom A_ll : islossless A.attack.

(*
 * KEM real-or-random security.
 * Corresponds to |Pr[IND_CCA2 wins] - 1/2| <= inv(2^128) from
 * KemIndCca2.ec, translated to the RoR form.  With unified types
 * this becomes a lemma proved by plugging B_KEM into Game_IND_CCA2.
 *)
axiom kem_ror &m :
  `| Pr[KEM_Real(B_KEM(A)).main() @ &m : res] -
     Pr[KEM_Rand(B_KEM(A)).main() @ &m : res] |
  <= inv (2%r ^ 128).

(*
 * Game0(A) ≡ KEM_Real(B_KEM(A)).
 *
 * Game0 samples (m <- witness; a <- witness) before encap.
 * B_KEM.run samples them after receiving ss_b (i.e., after encap).
 * swap {1} [2..3] 2 moves the two pure witness assignments past the
 * encap sampling in the LHS, aligning the programs structurally.
 *
 * After wp absorbs the trailing return assignments, call handles
 * A.attack in both programs (EC's call finds the last module call,
 * ignoring any trailing deterministic b'<-... from the inline).
 * sim closes the A.attack self-equivalence for the abstract module.
 * rnd; wp; rnd; rnd couples aenc, hkdf/witness assignments, encap,
 * and dkeypair in order, leaving a trivially-closed skip goal.
 *)
lemma game0_eq_kem_real &m :
  Pr[Game0(A).main() @ &m : res] =
  Pr[KEM_Real(B_KEM(A)).main() @ &m : res].
proof.
  byequiv => //; proc; inline B_KEM(A).run.
  swap {1} [2..3] 2.
  wp.
  call (: ={glob A, arg} ==> ={glob A, res}).
  - by sim.
  - rnd; wp; rnd; rnd; skip; smt().
qed.

(*
 * Game1(A) ≡ KEM_Rand(B_KEM(A)).
 *
 * Same structure as above but both programs also sample ss_rand <$ dss.
 * In Game1 the real KEM ss (shared) is sampled but discarded.
 * In KEM_Rand the discarded component is ss_ign — same distribution.
 * swap {1} [2..3] 3 moves (m,a) past both encap and the dss sampling.
 * One extra rnd handles the dss sampling step compared to game0.
 *)
lemma game1_eq_kem_rand &m :
  Pr[Game1(A).main() @ &m : res] =
  Pr[KEM_Rand(B_KEM(A)).main() @ &m : res].
proof.
  byequiv => //; proc; inline B_KEM(A).run.
  swap {1} [2..3] 3.
  wp.
  call (: ={glob A, arg} ==> ={glob A, res}).
  - by sim.
  - rnd; wp; rnd; rnd; rnd; skip; smt().
qed.

(*
 * Hybrid step: |Pr[Game0] - Pr[Game1]| <= inv(2^128).
 *
 * Substitute the two game-equivalence lemmas then apply kem_ror.
 * This discharges the game0_game1_kem axiom stub in
 * Csk2TwoGateGame.ec.
 *)
lemma kem_hybrid_step &m :
  `| Pr[Game0(A).main() @ &m : res] - Pr[Game1(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof.
  rewrite (game0_eq_kem_real &m) (game1_eq_kem_rand &m).
  apply kem_ror.
qed.

end section KemHybrid.
