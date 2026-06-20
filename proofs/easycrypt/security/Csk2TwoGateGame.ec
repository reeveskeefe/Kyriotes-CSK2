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
require import Csk2CapabilityGame.

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

(* ── Unified opening + capability adversary ──────────────────── *)

module type Csk2FullAdversary = {
  proc attack (pk : pkey, ct_k : ctkem, ct_a : ctaead, a : aad) : msg option
  proc forge() : cap * capctx * capctx * root * root
}.

module B_OpenFull (A : Csk2FullAdversary) : Csk2Adv = {
  proc attack (pk : pkey, ct_k : ctkem, ct_a : ctaead, a : aad) : msg option = {
    var guess : msg option;
    guess <@ A.attack(pk, ct_k, ct_a, a);
    return guess;
  }
}.

module B_FieldFull (A : Csk2FullAdversary) : CapFieldAdversary = {
  proc forge() : cap * capctx * capctx * root * root = {
    var c  : cap;
    var x1 : capctx;
    var x2 : capctx;
    var r1 : root;
    var r2 : root;
    (c, x1, x2, r1, r2) <@ A.forge();
    return (c, x1, x2, r1, r2);
  }
}.

module Csk2FullBadEventGame (A : Csk2FullAdversary) = {
  var open_bad       : bool
  var object_bad     : bool
  var rights_bad     : bool
  var policy_bad     : bool
  var epoch_bad      : bool
  var subject_bad    : bool
  var recipient_bad  : bool
  var revocation_bad : bool

  proc main() : bool = {
    open_bad      <@ Game0(B_OpenFull(A)).main();
    object_bad    <@ WrongObjectGame(B_FieldFull(A)).main();
    rights_bad    <@ WrongRightsGame(B_FieldFull(A)).main();
    policy_bad    <@ WrongPolicyGame(B_FieldFull(A)).main();
    epoch_bad     <@ WrongEpochGame(B_FieldFull(A)).main();
    subject_bad   <@ WrongSubjectGame(B_FieldFull(A)).main();
    recipient_bad <@ WrongRecipientGame(B_FieldFull(A)).main();
    revocation_bad <@ WrongRevocationGame(B_FieldFull(A)).main();

    return (open_bad || object_bad || rights_bad || policy_bad
            || epoch_bad || subject_bad || recipient_bad || revocation_bad);
  }
}.

type flags8 = {
  f_open       : bool;
  f_object     : bool;
  f_rights     : bool;
  f_policy     : bool;
  f_epoch      : bool;
  f_subject    : bool;
  f_recipient  : bool;
  f_revocation : bool
}.

module Csk2FlagsGame (A : Csk2FullAdversary) = {
  proc main() : flags8 = {
    var b1 : bool;
    var b2 : bool;
    var b3 : bool;
    var b4 : bool;
    var b5 : bool;
    var b6 : bool;
    var b7 : bool;
    var b8 : bool;
    b1 <@ Game0(B_OpenFull(A)).main();
    b2 <@ WrongObjectGame(B_FieldFull(A)).main();
    b3 <@ WrongRightsGame(B_FieldFull(A)).main();
    b4 <@ WrongPolicyGame(B_FieldFull(A)).main();
    b5 <@ WrongEpochGame(B_FieldFull(A)).main();
    b6 <@ WrongSubjectGame(B_FieldFull(A)).main();
    b7 <@ WrongRecipientGame(B_FieldFull(A)).main();
    b8 <@ WrongRevocationGame(B_FieldFull(A)).main();
    return {|
      f_open       = b1;
      f_object     = b2;
      f_rights     = b3;
      f_policy     = b4;
      f_epoch      = b5;
      f_subject    = b6;
      f_recipient  = b7;
      f_revocation = b8
    |};
  }
}.
