(* AEAD AE-security (INT-CTXT + IND-CPA) for Kyriotēs-CSK2.
 *
 * The Coq axiom `aead_csk2_int_ctxt` gives the functional consequence
 * (any authenticating ciphertext equals the honest encryption).  This
 * file states the full probabilistic AE game so advantage bounds can
 * be proved and composed with the KEM bound in KemAeadComposition.ec.
 *
 * EasyCrypt version: r2022.04 (easycryptpa/ec-test-box:latest)
 *
 * We follow the AEAD.ec stdlib convention: enc is probabilistic (a
 * Cph distr) so the nonce is modelled as internal randomness.  The
 * CSK2 instantiation uses a 12-byte explicit nonce passed by the
 * caller, but that is an instantiation detail — the game here is
 * stated at the abstract level.
 *)

require import AllCore Distr DBool FSet Real.

(* ── Abstract types ───────────────────────────────────────────── *)

type key.        (* AEAD symmetric key (derived via HKDF in CSK2) *)
type plaintext.
type ciphertext.
type aad.        (* additional authenticated data = policy_hash in CSK2 *)

(* ── Abstract AEAD operators ──────────────────────────────────── *)

(* Key generation *)
op dkey : key distr.
axiom dkey_ll : is_lossless dkey.

(* Encryption — probabilistic (nonce is internal randomness) *)
op enc : key -> aad -> plaintext -> ciphertext distr.
axiom enc_ll : forall k a m, is_lossless (enc k a m).

(* Decryption — deterministic *)
op dec : key -> aad -> ciphertext -> plaintext option.

(* ── Correctness ──────────────────────────────────────────────── *)

axiom aead_correctness :
  forall (k : key) (a : aad) (m : plaintext) (c : ciphertext),
    c \in enc k a m =>
    dec k a c = Some m.

(* Ciphertext uniqueness (deterministic INT-CTXT):
   any c that authenticates under (k, a) must equal the honest encryption.
   This is the probabilistic lift of the Coq `aead_csk2_int_ctxt` axiom. *)
axiom aead_unique_ciphertext :
  forall (k : key) (a : aad) (c : ciphertext) (m : plaintext),
    dec k a c = Some m =>
    c \in enc k a m.

(* ── Encryption oracle ────────────────────────────────────────── *)

module type EncOracle = {
  proc encrypt(a : aad, m : plaintext) : ciphertext
}.

(* ── INT-CTXT game ────────────────────────────────────────────── *)

(*
 * The adversary gets an encryption oracle.  It wins if it produces a
 * (ciphertext, aad) pair that (a) authenticates under the secret key
 * and (b) was not a direct output of the encryption oracle.
 * Tracking is by (aad, ciphertext) pairs.
 *)

module type IntCtxtAdversary (O : EncOracle) = {
  proc forge() : (aad * ciphertext) { O.encrypt }
}.

module Game_INT_CTXT (A : IntCtxtAdversary) = {

  var k       : key
  var queried : (aad * ciphertext) fset

  module O = {
    proc encrypt(a : aad, m : plaintext) : ciphertext = {
      var c : ciphertext;
      c <$ enc k a m;
      queried <- queried `|` fset1 (a, c);
      return c;
    }
  }

  module A' = A(O)

  proc main() : bool = {
    var a  : aad;
    var c  : ciphertext;
    var pt : plaintext option;

    k       <$ dkey;
    queried <- fset0;
    (a, c)  <@ A'.forge();
    pt      <- dec k a c;
    return (pt <> None /\ ! (a, c) \in queried);
  }
}.

(* ── IND-CPA game ─────────────────────────────────────────────── *)

(*
 * Left-or-right encryption oracle: adversary submits (m0, m1) pairs;
 * oracle encrypts one based on the hidden bit b.  Adversary must guess b.
 *)

module type IndCpaAdversary (O : EncOracle) = {
  proc choose()                     : plaintext * plaintext { O.encrypt }
  proc distinguish(c : ciphertext)  : bool                  { O.encrypt }
}.

module Game_IND_CPA (A : IndCpaAdversary) = {

  var k : key
  var b : bool

  module O = {
    proc encrypt(a : aad, m : plaintext) : ciphertext = {
      var c : ciphertext;
      c <$ enc k a m;
      return c;
    }
  }

  module A' = A(O)

  proc main() : bool = {
    var m0  : plaintext;
    var m1  : plaintext;
    var c   : ciphertext;
    var b'  : bool;
    var a_ch : aad;

    k  <$ dkey;
    b  <$ {0,1};
    a_ch <- witness;
    (m0, m1) <@ A'.choose();
    c        <$ enc k a_ch (if b then m0 else m1);
    b'       <@ A'.distinguish(c);
    return (b' = b);
  }
}.

(* ── Advantage and security statements ───────────────────────────
 *
 * Both games are stated with concrete module parameters inside
 * sections (required by EasyCrypt's probability syntax).
 *
 * Security goal: both advantages are negligible for CSK2's AEAD.
 * The axiom stubs below will be replaced by proofs once the concrete
 * ChaCha20-Poly1305 (or AES-256-GCM) instantiation is written.
 *)

section INT_CTXT_Security.

declare module A <: IntCtxtAdversary { -Game_INT_CTXT }.

axiom aead_csk2_int_ctxt_secure &m :
  Pr[Game_INT_CTXT(A).main() @ &m : res] <= inv (2%r ^ 128).

end section INT_CTXT_Security.

section IND_CPA_Security.

declare module A <: IndCpaAdversary { -Game_IND_CPA }.

axiom aead_csk2_ind_cpa_secure &m :
  `| Pr[Game_IND_CPA(A).main() @ &m : res] - 1%r / 2%r |
  <= inv (2%r ^ 128).

end section IND_CPA_Security.
