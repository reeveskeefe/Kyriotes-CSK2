(* AEAD IND-CPA reduction for Kyriotēs-CSK2 hybrid argument.
 *
 * Discharges the game1_game2_cpa axiom stub from Csk2TwoGateGame.ec.
 *
 * ── Why the bound is trivial ──────────────────────────────────────
 *
 * Game1 and Game2 are identical in distribution.
 *
 *   Game1:  ct_a <$ aenc k a m        with m <- witness
 *   Game2:  ct_a <$ aenc k a witness
 *
 * Both games set m <- witness before the AEAD encryption step, so
 * "aenc k a m" and "aenc k a witness" are the same distribution.
 * No B_CPA adversary is needed; game1_eq_game2 proves the equality
 * directly by byequiv with wp tracking m = witness, and the bound
 * |Pr[G1] - Pr[G2]| = 0 follows.
 *
 * ── What a proper CPA reduction would look like ───────────────────
 *
 * If the games were redesigned with m sampled fresh (m <$ dmsg), the
 * two games would diverge: Game1 would encrypt the real m, Game2 the
 * dummy witness.  A proper B_CPA adversary would be:
 *
 *   module B_CPA (A : Csk2Adv) (O : EncOracle) : IndCpaAdversary = {
 *     proc choose() : plaintext * plaintext = {
 *       (* sample pk, ct_k, ss_rand, k externally or via state *)
 *       return (m, witness);          (* challenge pair *)
 *     }
 *     proc distinguish(c : ctaead) : bool = {
 *       var guess : msg option;
 *       guess <@ A.attack(pk, ct_k, c, a);
 *       return (guess = Some m);
 *     }
 *   }.
 *
 * Under b=1 (oracle encrypts m):   c simulates Game1, same as csk2 G1.
 * Under b=0 (oracle encrypts wit): c simulates Game2, same as csk2 G2.
 * IND-CPA advantage of B_CPA equals |Pr[G1] - Pr[G2]|.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr DBool FSet Real.
require import Csk2TwoGateGame.

section AeadCpa.

declare module A <: Csk2Adv { -Game1, -Game2 }.

axiom A_ll : islossless A.attack.

(*
 * Game1(A) ≡ Game2(A).
 *
 * Game1 encrypts m (= witness after m <- witness); Game2 encrypts
 * witness explicitly.  wp propagates the assignment m <- witness and
 * the distributions coincide, so the programs are equivalent.
 *)
lemma game1_eq_game2 &m :
  Pr[Game1(A).main() @ &m : res] = Pr[Game2(A).main() @ &m : res].
proof.
  byequiv => //; proc.
  call (: ={glob A, arg} ==> ={glob A, res}); [by sim |].
  wp; rnd; wp; rnd; rnd; wp; rnd; skip; smt().
qed.

(*
 * |Pr[Game1] - Pr[Game2]| <= inv(2^128).
 *
 * The probability gap is exactly 0 (programs are identical), which is
 * trivially at most inv(2^128) > 0.
 *)
lemma game1_game2_cpa &m :
  `| Pr[Game1(A).main() @ &m : res] - Pr[Game2(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof.
  have -> := game1_eq_game2 &m.
  smt().
qed.

end section AeadCpa.
