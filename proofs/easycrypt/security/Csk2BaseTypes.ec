(* Shared abstract types and primitive operators for Kyriotēs-CSK2.
 *
 * All EasyCrypt files in the CSK2 proof stack require-import this
 * module so every type is declared exactly once.  KemIndCca2.ec and
 * AeadAeSecurity.ec use these types directly; connecting their game
 * statements to the CSK2 hybrid sequence is then a plain require-import
 * rather than a clone-with-renames.
 *
 * Type naming follows the CSK2 construction throughout.
 * AeadAeSecurity.ec was updated from its own (plaintext, ciphertext,
 * enc, dec) to the CSK2 names (msg, ctaead, aenc, adec) so that a
 * single import suffices.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr.

(* ── KEM types ────────────────────────────────────────────────── *)

type pkey.    (* ML-KEM-768 encapsulation key  *)
type skey.    (* ML-KEM-768 decapsulation key  *)
type ctkem.   (* ML-KEM-768 ciphertext         *)
type ss.      (* 32-byte shared secret         *)

(* ── Session types ────────────────────────────────────────────── *)

type key.     (* 32-byte AEAD key (derived from ss via HKDF) *)
type aad.     (* additional authenticated data               *)
type msg.     (* sealed payload                              *)
type ctaead.  (* ChaCha20-Poly1305 ciphertext                *)

(* ── KEM operators ────────────────────────────────────────────── *)

op dkeypair : (pkey * skey) distr.
axiom dkeypair_ll : is_lossless dkeypair.

op encap : pkey -> (ctkem * ss) distr.
axiom encap_ll : forall pk, is_lossless (encap pk).

op decap : skey -> ctkem -> ss option.

(* Uniform distribution over shared secrets *)
op dss : ss distr.
axiom dss_ll : is_lossless dss.

(* ── HKDF ─────────────────────────────────────────────────────── *)

op hkdf : ss -> key.

(* ── AEAD operators ───────────────────────────────────────────── *)

op aenc : key -> aad -> msg -> ctaead distr.
axiom aenc_ll : forall k a m, is_lossless (aenc k a m).

op adec : key -> aad -> ctaead -> msg option.

(* ── AEAD correctness ─────────────────────────────────────────── *)

axiom aead_correct :
  forall (k : key) (a : aad) (m : msg) (c : ctaead),
    c \in aenc k a m => adec k a c = Some m.

(* Converse: any authenticating ciphertext equals an honest encryption.
   Probabilistic lift of the Coq axiom aead_csk2_int_ctxt. *)
axiom aead_unique_ciphertext :
  forall (k : key) (a : aad) (c : ctaead) (m : msg),
    adec k a c = Some m => c \in aenc k a m.

(* ── Message distribution ─────────────────────────────────────── *)

(* Uniform distribution over sealed payloads.  The adversary must
   guess m drawn from dmsg without seeing it in Game2. *)
op dmsg : msg distr.
axiom dmsg_ll : is_lossless dmsg.
