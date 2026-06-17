(* CSK2 two-gate game — concrete hybrid sequence.
 *
 * Defines the three hybrid games (Game0 → Game1 → Game2).  The final
 * concrete KEM+AEAD composition bound is proved in KemAeadComposition.ec.
 *
 * Game0: real CSK2 seal/open game
 * Game1: KEM shared secret replaced by uniform random
 * Game2: Game1 + AEAD encrypts a dummy plaintext
 *
 * Distinguishing adjacent games gives an adversary against a primitive.
 * In Game2 the challenge message is independent of A's view; the final
 * bound is proved in AeadCtxtReduction.ec from dmsg_bound.
 *
 * Types, primitive operators, and correctness axioms live in
 * Csk2BaseTypes.ec; this file only contains the game definitions.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr DBool FSet Real.
require import Csk2BaseTypes.

(* ── Adversary ────────────────────────────────────────────────── *)

(* The adversary sees the sealed object — (pk, kem ciphertext,
   aead ciphertext, aad) — but not the secret key, shared secret,
   or AEAD key.  It must output the original plaintext. *)
module type Csk2Adv = {
  proc attack (pk : pkey, ct_k : ctkem, ct_a : ctaead, a : aad) : msg option
}.

(* ── Game 0: Real CSK2 game ───────────────────────────────────── *)

module Game0 (A : Csk2Adv) = {
  proc main () : bool = {
    var pk    : pkey;
    var sk    : skey;
    var ct_k  : ctkem;
    var shared : ss;
    var k     : key;
    var m     : msg;
    var ct_a  : ctaead;
    var a     : aad;
    var guess : msg option;

    (pk, sk)       <$ dkeypair;
    m              <$ dmsg;
    a              <- witness;
    (ct_k, shared) <$ encap pk;
    k              <- hkdf shared;
    ct_a           <$ aenc k a m;
    guess          <@ A.attack(pk, ct_k, ct_a, a);
    return (guess = Some m);
  }
}.

(* ── Game 1: Uniform random shared secret ─────────────────────── *)
(*
 * Identical to Game0 except the AEAD key is derived from a fresh
 * uniform ss_rand rather than the real KEM output.  The KEM
 * ciphertext ct_k is still honest.
 *
 * Distinguishing Game0 and Game1 yields a KEM IND-CCA2 adversary:
 * if ss_b is the real ss, A wins with probability Pr[Game0];
 * if ss_b is random, A wins with probability Pr[Game1].
 *)
module Game1 (A : Csk2Adv) = {
  proc main () : bool = {
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
    m              <$ dmsg;
    a              <- witness;
    (ct_k, shared) <$ encap pk;
    ss_rand        <$ dss;
    k              <- hkdf ss_rand;
    ct_a           <$ aenc k a m;
    guess          <@ A.attack(pk, ct_k, ct_a, a);
    return (guess = Some m);
  }
}.

(* ── Game 2: Random ss + dummy AEAD plaintext ─────────────────── *)
(*
 * Game1 but AEAD now encrypts a dummy witness plaintext.
 * Distinguishing Game1 and Game2 yields an AEAD IND-CPA adversary:
 * submit (m, witness) as the challenge pair; use the oracle's choice
 * ciphertext as ct_a and observe whether A recovers m.
 *)
module Game2 (A : Csk2Adv) = {
  proc main () : bool = {
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
    m              <$ dmsg;
    a              <- witness;
    (ct_k, shared) <$ encap pk;
    ss_rand        <$ dss;
    k              <- hkdf ss_rand;
    ct_a           <$ aenc k a witness;  (* dummy plaintext; m is the hidden target *)
    guess          <@ A.attack(pk, ct_k, ct_a, a);
    return (guess = Some m);
  }
}.
