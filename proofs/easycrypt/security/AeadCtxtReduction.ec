(* AEAD one-way / message-hiding bound for Kyriotēs-CSK2 hybrid argument.
 *
 * Discharges the game2_win_bound axiom stub from Csk2TwoGateGame.ec.
 *
 * ── Why Game2 is hard ─────────────────────────────────────────────
 *
 * Game2:
 *   m    <$ dmsg;                        (* hidden target     *)
 *   ct_a <$ aenc k a witness;            (* dummy ciphertext  *)
 *   guess <@ A.attack(pk, ct_k, ct_a, a);
 *   return (guess = Some m);
 *
 * A's view (pk, ct_k, ct_a, a) is independent of m:
 *   - ct_a = aenc k a witness does not encode m
 *   - pk, ct_k come from dkeypair / encap, not m
 *   - a = witness is fixed
 *
 * So A's guess is fixed before m is sampled.  The win probability
 * equals mu1 dmsg (oget guess), bounded by inv(2^128) via dmsg_bound.
 *
 * ── Proof structure ────────────────────────────────────────────────
 *
 * 1. Game2swap: identical to Game2 but m <$ dmsg comes AFTER A.attack.
 * 2. game2_swap_eq: byequiv, swap {1} 2 6; sim.
 * 3. mu_guess: mu dmsg (fun m0 => g = Some m0) <= inv(2^128) for any g.
 * 4. game2swap_bound: byphoare; proc; seq 7 (split after A.attack);
 *    prefix is handled structurally, suffix is m <$ dmsg
 *    bounded by mu_guess applied to guess{hr}.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr DBool FSet Real Number.
require import Csk2BaseTypes.
require import Csk2TwoGateGame.

section AeadCtxt.

declare module A <: Csk2Adv { -Game2 }.

(* ── Game2swap: m sampled after A.attack ─────────────────────────── *)

local module Game2swap = {
  proc main() : bool = {
    var pk      : pkey;
    var sk      : skey;
    var ct_k    : ctkem;
    var shared  : ss;
    var ss_rand : ss;
    var k       : key;
    var m       : msg;
    var ct_a    : ctaead;
    var a       : aad;
    var guess   : msg option;

    (pk, sk)       <$ dkeypair;
    a              <- witness;
    (ct_k, shared) <$ encap pk;
    ss_rand        <$ dss;
    k              <- hkdf ss_rand;
    ct_a           <$ aenc k a witness;
    guess          <@ A.attack(pk, ct_k, ct_a, a);
    m              <$ dmsg;
    return (guess = Some m);
  }
}.

(* ── Equivalence: Game2 ≡ Game2swap ─────────────────────────────── *)

local lemma game2_swap_eq &m :
  Pr[Game2(A).main() @ &m : res] =
  Pr[Game2swap.main() @ &m : res].
proof.
  byequiv => //; proc.
  swap {1} 2 6.
  sim.
qed.

(* ── Helper: mu bound for any option guess ──────────────────────── *)
(*
 * None  → predicate is always false (pred0), mu = 0 <= inv(2^128).
 * Some m → predicate is pred1 m, mu = mu1 dmsg m <= inv(2^128).
 *)
local lemma mu_guess (g : msg option) :
  mu dmsg (fun m0 => g = Some m0) <= inv (2%r ^ 128).
proof.
  have inv_bound_ge0 : 0%r <= inv (2%r ^ 128).
  + have hle := dmsg_bound witness.
    have hge : 0%r <= mu1 dmsg witness by smt(mu_bounded).
    smt().
  case g.
  + (* None: predicate equals pred0, so mu = 0 <= inv(2^128) *)
    have h : mu dmsg (fun m0 => None = Some m0) = mu dmsg pred0.
    * congr; apply fun_ext => m0; by rewrite /pred0 /=.
    by rewrite h mu0.
  + (* Some m: predicate equals pred1 m, so mu = mu1 dmsg m *)
    move => m.
    have h : mu dmsg (fun m0 => Some m = Some m0) = mu1 dmsg m.
    * rewrite /mu1; congr; apply fun_ext => m0; by rewrite /pred1 /=; smt().
    by rewrite h; exact (dmsg_bound m).
qed.

(* ── Bound on Game2swap ────────────────────────────────────────────── *)
(*
 * Split the program right after A.attack (instruction 7).  The prefix
 * (instructions 1-7) trivially establishes `true` with probability 1
 * (abstract call plus lossless KEM/AEAD/key-derivation steps).  At that split
 * point `guess` is a normal local program variable, addressable as
 * `guess{hr}` once the memory is introduced by `skip`.  The suffix is
 * just `m <$ dmsg; return (guess = Some m)`, bounded directly by
 * mu_guess applied to `guess{hr}`.
 *)

local lemma game2swap_bound &m :
  Pr[Game2swap.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> _) => //; proc.
  rnd (fun m0 => guess = Some m0).
  call (: true ==> true); first by proc true.
  rnd; wp; rnd; rnd; wp; rnd.
  skip; move => &mem _.
  move => [pk sk] _ [ct_k shared] _ ss_rand _ ct_a _.
  move => result; split.
  + exact (mu_guess result).
  + by move => v Hv Hres.
qed.

(* ── Main result ─────────────────────────────────────────────────── *)

lemma game2_win_bound &m :
  Pr[Game2(A).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  rewrite (game2_swap_eq &m); exact (game2swap_bound &m).
qed.

end section AeadCtxt.
