(* AEAD AE-security (INT-CTXT + IND-CPA) for Kyriotēs-CSK2.
 *
 * The Coq axiom `aead_csk2_int_ctxt` gives the functional consequence
 * (any authenticating ciphertext equals the honest encryption).  This
 * file states the full probabilistic AE game so advantage bounds can
 * be proved and composed with the KEM bound in KemAeadComposition.ec.
 *
 * EasyCrypt version: r2022.04 (easycryptpa/ec-test-box:latest)
 *
 * We follow the AEAD.ec stdlib convention: aenc is probabilistic (a
 * ctaead distr) so the nonce is modelled as internal randomness.  The
 * CSK2 instantiation uses a 12-byte explicit nonce passed by the
 * caller, but that is an instantiation detail — the game here is
 * stated at the abstract level.
 *
 * Types (key, aad, msg, ctaead) and correctness axioms (aead_correct,
 * aead_unique_ciphertext) live in Csk2BaseTypes.ec.  This file adds
 * only the game-specific constructs: the key distribution dkey, a
 * ChaCha20-Poly1305 game-level wrapper over the CSK2 AEAD operators,
 * and the INT-CTXT / IND-CPA game modules.
 *)

require import AllCore Distr DBool FSet Real.
require import Csk2BaseTypes.

(* ── Game key distribution ────────────────────────────────────── *)

(* AEAD key sampled for the security game.  In the CSK2 instantiation
   the key is derived as hkdf(ss_rand); dkey abstracts that here. *)
op dkey : key distr.
axiom dkey_ll : is_lossless dkey.

(* ── Concrete CSK2 AEAD instantiation boundary ───────────────── *)

(*
 * CSK2 instantiates AEAD with ChaCha20-Poly1305 in the implementation.
 * At this EasyCrypt layer, byte-level ChaCha20 block functions, nonce
 * encoding, and Poly1305 arithmetic are intentionally below the model
 * boundary; they are represented by the shared operators dkey/aenc/adec
 * and their correctness/security assumptions.
 *
 * The wrapper below makes that primitive boundary explicit.  Reduction
 * files reason about Game_CPA_Left/Game_CPA_Right over these operators;
 * the only external cryptographic leaf is the ChaCha20-Poly1305
 * left/right IND-CPA advantage bound stated near the end of this file.
 *)

module type AEAD_Scheme = {
  proc keygen() : key
  proc enc(k : key, a : aad, m : msg) : ctaead
  proc dec(k : key, a : aad, c : ctaead) : msg option
}.

module ChaCha20Poly1305_AEAD : AEAD_Scheme = {
  proc keygen() : key = {
    var k : key;
    k <$ dkey;
    return k;
  }

  proc enc(k : key, a : aad, m : msg) : ctaead = {
    var c : ctaead;
    c <$ aenc k a m;
    return c;
  }

  proc dec(k : key, a : aad, c : ctaead) : msg option = {
    var p : msg option;
    p <- adec k a c;
    return p;
  }
}.

(* ── Encryption oracle ────────────────────────────────────────── *)

module type EncOracle = {
  proc encrypt(a : aad, m : msg) : ctaead
}.

(* ── INT-CTXT game ────────────────────────────────────────────── *)

(*
 * The adversary gets an encryption oracle.  It wins if it produces a
 * (ctaead, aad) pair that (a) authenticates under the secret key
 * and (b) was not a direct output of the encryption oracle.
 * Tracking is by (aad, ctaead) pairs.
 *)

module type IntCtxtAdversary (O : EncOracle) = {
  proc forge() : (aad * ctaead) { O.encrypt }
}.

module Game_INT_CTXT (A : IntCtxtAdversary) = {

  var k       : key
  var queried : (aad * ctaead) fset

  module O = {
    proc encrypt(a : aad, m : msg) : ctaead = {
      var c : ctaead;
      c <$ aenc k a m;
      queried <- queried `|` fset1 (a, c);
      return c;
    }
  }

  module A' = A(O)

  proc main() : bool = {
    var a  : aad;
    var c  : ctaead;
    var pt : msg option;

    k       <$ dkey;
    queried <- fset0;
    (a, c)  <@ A'.forge();
    pt      <- adec k a c;
    return (pt <> None /\ ! (a, c) \in queried);
  }
}.

(* ── IND-CPA game ─────────────────────────────────────────────── *)

(*
 * Left-or-right encryption oracle: adversary submits (m0, m1) pairs;
 * oracle encrypts one based on the hidden bit b.  Adversary must guess b.
 *)

module type IndCpaAdversary (O : EncOracle) = {
  proc choose()               : msg * msg  { O.encrypt }
  proc distinguish(c : ctaead) : bool      { O.encrypt }
}.

module Game_IND_CPA (A : IndCpaAdversary) = {

  var k : key
  var b : bool

  module O = {
    proc encrypt(a : aad, m : msg) : ctaead = {
      var c : ctaead;
      c <$ aenc k a m;
      return c;
    }
  }

  module A' = A(O)

  proc main() : bool = {
    var m0   : msg;
    var m1   : msg;
    var c    : ctaead;
    var b'   : bool;
    var a_ch : aad;

    k  <$ dkey;
    b  <$ {0,1};
    a_ch <- witness;
    (m0, m1) <@ A'.choose();
    c        <$ aenc k a_ch (if b then m0 else m1);
    b'       <@ A'.distinguish(c);
    return (b' = b);
  }
}.

(* ── Direct left/right game for hybrid reductions ─────────────── *)

module type LrIndCpaAdversary = {
  proc choose() : msg * msg
  proc distinguish(c : ctaead) : bool
}.

module Game_CPA_Left (A : LrIndCpaAdversary) = {

  var k : key

  proc main() : bool = {
    var ss_rand : ss;
    var m0   : msg;
    var m1   : msg;
    var c    : ctaead;
    var b'   : bool;
    var a_ch : aad;

    (m0, m1) <@ A.choose();
    ss_rand  <$ dss;
    k        <- hkdf ss_rand;
    a_ch     <- witness;
    c        <$ aenc k a_ch m0;
    b'       <@ A.distinguish(c);
    return b';
  }
}.

module Game_CPA_Right (A : LrIndCpaAdversary) = {

  var k : key

  proc main() : bool = {
    var ss_rand : ss;
    var m0   : msg;
    var m1   : msg;
    var c    : ctaead;
    var b'   : bool;
    var a_ch : aad;

    (m0, m1) <@ A.choose();
    ss_rand  <$ dss;
    k        <- hkdf ss_rand;
    a_ch     <- witness;
    c        <$ aenc k a_ch m1;
    b'       <@ A.distinguish(c);
    return b';
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

section IND_CPA_LR_Security.

declare module A <: LrIndCpaAdversary { -Game_CPA_Left, -Game_CPA_Right }.

axiom chacha20poly1305_ind_cpa_lr_secure &m :
  `| Pr[Game_CPA_Left(A).main() @ &m : res] -
     Pr[Game_CPA_Right(A).main() @ &m : res] |
  <= inv (2%r ^ 128).

lemma aead_csk2_ind_cpa_lr_secure &m :
  `| Pr[Game_CPA_Left(A).main() @ &m : res] -
     Pr[Game_CPA_Right(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof.
  exact (chacha20poly1305_ind_cpa_lr_secure &m).
qed.

end section IND_CPA_LR_Security.
