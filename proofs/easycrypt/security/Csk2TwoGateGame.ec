(* CSK2 two-gate game — concrete hybrid sequence.
 *
 * Defines the three hybrid games (Game0 → Game1 → Game2) and proves
 * the final composition bound from the three hybrid-step axioms.
 * Each axiom stub becomes the proof obligation for one reduction
 * adversary (B_KEM, B_CPA, B_CTXT).
 *
 * Game0: real CSK2 seal/open game
 * Game1: KEM shared secret replaced by uniform random
 * Game2: Game1 + AEAD encrypts a dummy plaintext
 *
 * Distinguishing adjacent games gives an adversary against a primitive.
 * In Game2 no adversary can win → Pr[win] bounded by INT-CTXT advantage.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr DBool FSet Real.

(* ── Types ────────────────────────────────────────────────────── *)

type pkey.    (* ML-KEM-768 encapsulation key  *)
type skey.    (* ML-KEM-768 decapsulation key  *)
type ctkem.   (* ML-KEM-768 ciphertext         *)
type ss.      (* 32-byte shared secret         *)
type key.     (* 32-byte AEAD key (from HKDF)  *)
type aad.     (* additional authenticated data *)
type msg.     (* sealed payload                *)
type ctaead.  (* ChaCha20-Poly1305 ciphertext  *)

(* ── KEM operators ────────────────────────────────────────────── *)

op dkeypair : (pkey * skey) distr.
axiom dkeypair_ll : is_lossless dkeypair.

op encap : pkey -> (ctkem * ss) distr.
axiom encap_ll : forall pk, is_lossless (encap pk).

op decap : skey -> ctkem -> ss option.

(* Uniform distribution over shared secrets *)
op dss : ss distr.
axiom dss_ll : is_lossless dss.

(* Distribution over messages — models the sealed payload space.
   Sampling m <$ dmsg gives the adversary a hidden target to recover. *)
op dmsg : msg distr.
axiom dmsg_ll : is_lossless dmsg.

(* ── HKDF (abstracted as a deterministic function) ───────────── *)

op hkdf : ss -> key.

(* ── AEAD operators ───────────────────────────────────────────── *)

op aenc : key -> aad -> msg -> ctaead distr.
axiom aenc_ll : forall k a m, is_lossless (aenc k a m).

op adec : key -> aad -> ctaead -> msg option.

axiom aead_correct :
  forall (k : key) (a : aad) (m : msg) (c : ctaead),
    c \in aenc k a m => adec k a c = Some m.

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

(* ── Hybrid-step axiom stubs ──────────────────────────────────── *)
(*
 * Each stub is one proof obligation: write the reduction adversary,
 * set up the embedding argument, and replace `axiom` with `lemma`.
 *
 * The 2^{-128} bound comes from the concrete primitive security
 * statements in KemIndCca2.ec and AeadAeSecurity.ec.
 *)

section HybridBound.

declare module A <: Csk2Adv { -Game0, -Game1, -Game2 }.

(*
 * Obligation 1 — B_KEM reduction (→ KemIndCca2.ec):
 *   B_KEM.choose(pk) : run A with ss_real-derived ciphertext, return ct_k
 *   B_KEM.guess(ss_b): re-encrypt under hkdf(ss_b), check if A recovers m
 *)
axiom game0_game1_kem &m :
  `| Pr[Game0(A).main() @ &m : res] - Pr[Game1(A).main() @ &m : res] |
  <= inv (2%r ^ 128).

(*
 * Obligation 2 — B_CPA reduction (→ AeadAeSecurity.ec):
 *   B_CPA.choose()         : output (m, witness) as the challenge pair
 *   B_CPA.distinguish(c)   : run A.attack with c; return (guess = Some m)
 *)
axiom game1_game2_cpa &m :
  `| Pr[Game1(A).main() @ &m : res] - Pr[Game2(A).main() @ &m : res] |
  <= inv (2%r ^ 128).

(*
 * Obligation 3 — B_CTXT reduction (→ AeadAeSecurity.ec):
 *   ct_a encrypts witness; A wins only if it produces Some m where
 *   m ≠ witness.  Any valid forgery breaks INT-CTXT.
 *)
axiom game2_win_bound &m :
  Pr[Game2(A).main() @ &m : res] <= inv (2%r ^ 128).

(* ── Composition theorem ──────────────────────────────────────── *)
(*
 * Machine-checked from the three axiom stubs above.
 * Triangle inequality: Pr[G0] ≤ (Pr[G0]−Pr[G1]) + (Pr[G1]−Pr[G2]) + Pr[G2]
 *                               ≤ 1/2^128 + 1/2^128 + 1/2^128
 *                               = 3 × 2^{-128}
 *)
lemma csk2_concrete_bound &m :
  Pr[Game0(A).main() @ &m : res] <= 3%r * inv (2%r ^ 128).
proof.
  have h01 := game0_game1_kem &m.
  have h12 := game1_game2_cpa &m.
  have h2  := game2_win_bound &m.
  smt().
qed.

end section HybridBound.
