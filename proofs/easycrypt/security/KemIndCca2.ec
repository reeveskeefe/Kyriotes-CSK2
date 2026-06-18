(* KEM IND-CCA2 advantage game for Kyriotēs-CSK2.
 *
 * Formalizes the probabilistic IND-CCA2 game that Coq approximates
 * with the functional OW-CCA axiom `kem_csk2_ct_authenticity`.
 * The Coq field `kem_indcca2_game_defined` in KemAeadSecurityStatus
 * points here as the authoritative probabilistic statement.
 *
 * Types (pkey, skey, ctkem, ss) and primitive operators (encap, decap,
 * dss, dkeypair) are declared in Csk2BaseTypes.ec.  This file adds
 * only the game-specific constructs:
 *   - keypair predicate (correctness relation for key generation)
 *   - dss_uni (uniformity of random shared secrets — security requirement)
 *   - kem_correctness axiom
 *   - IND-CCA2 game modules and adversary interface
 *
 * EasyCrypt version: r2022.04 (easycryptpa/ec-test-box:latest)
 *)

require import AllCore Distr DBool Real.
require import Csk2BaseTypes.

(* ── Key-pair relation ────────────────────────────────────────── *)

(* Correctness predicate: (pk, sk) is a valid key pair. *)
op keypair : pkey -> skey -> bool.

(* ── Additional KEM axioms ────────────────────────────────────── *)

(* Shared secrets are uniform — needed to argue that ss1 <$ dss is
   indistinguishable from ss0 in the IND-CCA2 game. *)
axiom dss_uni : is_uniform dss.

(* ── Correctness ──────────────────────────────────────────────── *)

axiom kem_correctness :
  forall (pk : pkey) (sk : skey) (ct : ctkem) (shared : ss),
    keypair pk sk =>
    (ct, shared) \in encap pk =>
    decap sk ct = Some shared.

(* ── Abstract KEM key-generation module ──────────────────────── *)

(* Key generation — probabilistic.  Concrete instantiation would use
   dkeypair from Csk2BaseTypes; KEM_KG abstracts this for the game. *)
module type KEM_KG = {
  proc kg() : pkey * skey
}.

(* Concrete ML-KEM-768 key-generation wrapper used by the CSK2 games.
 * The byte-level FIPS 203 algorithm is intentionally outside this file;
 * Csk2BaseTypes supplies the abstract distributions/operators that model
 * the ML-KEM-768 implementation boundary. *)
module MLKEM768_KG : KEM_KG = {
  proc kg() : pkey * skey = {
    var pk : pkey;
    var sk : skey;
    (pk, sk) <$ dkeypair;
    return (pk, sk);
  }
}.

(* ── IND-CCA2 game ────────────────────────────────────────────── *)

(*
 * The challenge ciphertext ct* is stored in a global so the decap
 * oracle can reject it.  After A.choose produces ct*, we encapsulate
 * a fresh (ct_ch, ss_real) pair; flip a bit b; give A either ss_real
 * (b=1) or a uniform random ss (b=0); A outputs a guess b'.
 * A wins if b' = b.
 *)

module IND_CCA2 (KG : KEM_KG) = {

  var sk     : skey
  var ct_ch  : ctkem   (* forbidden in decap oracle queries *)
  var b      : bool

  (* Decap oracle: reject the challenge ciphertext *)
  module DecapO = {
    proc query(ct : ctkem) : ss option = {
      var r : ss option;
      r <- if ct = ct_ch then None else decap sk ct;
      return r;
    }
  }

  proc main() : bool = {
    var pk    : pkey;
    var ct_st : ctkem;
    var ss0   : ss;    (* real shared secret  *)
    var ss1   : ss;    (* random shared secret *)
    var ss_b  : ss;
    var b'    : bool;

    (pk, sk) <@ KG.kg();

    (* Phase 1: adversary picks a challenge ciphertext target.
       We leave adversary interaction as an axiom stub — the full
       two-phase adversary module requires abstract module parameters
       which are stated in the section below. *)
    ct_ch  <- witness;
    (ct_st, ss0) <$ encap pk;
    ss1          <$ dss;
    b            <$ {0,1};
    ss_b         <- if b then ss0 else ss1;

    (* Phase 2: adversary sees ss_b and outputs a guess.
       Full adversary wiring is in section IND_CCA2_Section below. *)
    b' <- witness;
    return (b' = b);
  }
}.

(* ── Two-phase adversary interface ────────────────────────────── *)

module type DecapOracle = {
  proc query(ct : ctkem) : ss option
}.

module type KEM_Adversary (O : DecapOracle) = {
  proc choose(pk : pkey)  : ctkem    { O.query }
  proc guess (ss_b : ss)  : bool     { O.query }
}.

(* ── Full IND-CCA2 game with adversary ────────────────────────── *)

module Game_IND_CCA2 (KG : KEM_KG, A : KEM_Adversary) = {

  var sk     : skey
  var ct_ch  : ctkem
  var b      : bool

  module O = {
    proc query(ct : ctkem) : ss option = {
      return if ct = ct_ch then None else decap sk ct;
    }
  }

  module A' = A(O)

  proc main() : bool = {
    var pk    : pkey;
    var ct_st : ctkem;
    var ss0   : ss;
    var ss1   : ss;
    var ss_b  : ss;
    var b'    : bool;

    (pk, sk) <@ KG.kg();
    ct_ch    <@ A'.choose(pk);
    (ct_st, ss0) <$ encap pk;
    ss1      <$ dss;
    b        <$ {0,1};
    ss_b     <- if b then ss0 else ss1;
    b'       <@ A'.guess(ss_b);
    return (b' = b);
  }
}.

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
 *   For all PPT adversaries A, Adv^{IND-CCA2}(A) is negligible.
 *   ML-KEM-768 targets >= 128-bit classical security.
 *
 * The ML-KEM-768 primitive security statement is imported here as a
 * standard-boundary assumption.  This repository models CSK2's use of
 * ML-KEM-768; it does not prove FIPS 203 / ML-KEM-768 security internally.
 *)

section IND_CCA2_Security.

declare module KG <: KEM_KG.
declare module A  <: KEM_Adversary { -Game_IND_CCA2 }.

(* ML-KEM-768 IND-CCA2 primitive security boundary.
 * Advantage = |Pr[A wins Game_IND_CCA2] - 1/2| <= 2^{-128}. *)
axiom kem_csk2_indcca2_secure &m :
  `| Pr[Game_IND_CCA2(KG, A).main() @ &m : res] - 1%r / 2%r |
  <= inv (2%r ^ 128).

end section IND_CCA2_Security.

section KEM_RoR_Security.

declare module A <: KEM_RoR_Adversary { -Game_KEM_RoR_Real, -Game_KEM_RoR_Rand }.

(* Direct ML-KEM-768 real-or-random primitive boundary.  This is the
 * exact form consumed by KemReduction.ec.  It is stated separately from
 * the bit-guessing IND-CCA2 game to avoid hiding a factor-of-two or
 * convention conversion in the CSK2 hybrid proof. *)
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
