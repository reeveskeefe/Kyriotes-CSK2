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
axiom dmsg_ll   : is_lossless dmsg.

(* dmsg is the uniform distribution over a 2^128-element message space. *)
axiom dmsg_uni   : is_uniform dmsg.
axiom dmsg_full  : is_full dmsg.

(* Any single message occurs with probability at most 2^{-128}.
   This is the key bound used by the Game2 one-way argument. *)
axiom dmsg_bound (m : msg) : mu1 dmsg m <= inv (2%r ^ 128).

(* ── Merkle / capability types ─────────────────────────────────── *)
(*
 * These types support the capability binding and Merkle transparency
 * games (Csk2MerkleBinding.ec, Csk2CapabilityGame.ec).
 *
 * In the CSK2 construction:
 *   hash   = SHA-256 output (Merkle leaf or node hash)
 *   root   = Merkle root (a hash conceptually; typed distinctly for clarity)
 *   cap    = capability token (signed by the authority)
 *   stamp  = per-capability revocation stamp (unique identifier)
 *
 * Mirrors KyriotesCsk2Types.v (Hash, Capability, cap_stamp) and
 * KyriotesCsk2Merkle.v (hash_capability, included_in_merkle_root,
 * not_in_revocation_root).
 *)

type hash.    (* SHA-256 output / Merkle leaf *)
type root.    (* Merkle root                  *)
type cap.     (* CSK2 capability token        *)
type stamp.   (* Capability revocation stamp  *)

type object_id.    (* Object namespace identifier          *)
type rights.       (* Capability rights / operation mask    *)
type policy_hash.  (* Hash of the governing access policy   *)
type epoch.        (* Authority-state or policy epoch       *)
type subject.      (* Principal authorized by a capability  *)
type recipient.    (* Recipient/opening principal           *)
type rev_status.   (* Revocation status carried by context  *)
type capctx.       (* Capability verification context       *)

(* Extract the revocation stamp from a capability *)
op cap_stamp : cap -> stamp.

(* Capability payload fields bound by the authority context. *)
op cap_object_id   : cap -> object_id.
op cap_rights      : cap -> rights.
op cap_policy_hash : cap -> policy_hash.
op cap_epoch       : cap -> epoch.
op cap_subject     : cap -> subject.
op cap_recipient   : cap -> recipient.

(* Verification-context fields supplied at open time. *)
op ctx_object_id   : capctx -> object_id.
op ctx_rights      : capctx -> rights.
op ctx_policy_hash : capctx -> policy_hash.
op ctx_epoch       : capctx -> epoch.
op ctx_subject     : capctx -> subject.
op ctx_recipient   : capctx -> recipient.
op ctx_rev_status  : capctx -> rev_status.

(* Revocation status binds a non-revocation witness to a concrete root. *)
op rev_stamp : rev_status -> stamp.
op rev_root  : rev_status -> root.

(* Hash a capability for Merkle tree inclusion (the authority tree leaf) *)
op hash_cap : cap -> hash.

(* Hash a revocation stamp for the revocation Merkle tree *)
op hash_stamp : stamp -> hash.

(* Merkle inclusion predicate: leaf h is included in root r *)
op merkle_include : hash -> root -> bool.

(* Non-revocation proof: a witness that stamp s is absent from root r.
   Corresponds to `not_in_revocation_root` in KyriotesCsk2Merkle.v. *)
op non_revoc_proof : stamp -> root -> bool.

(* Active means the context proves this capability stamp is absent from
   the concrete revocation Merkle root carried by the status. *)
op rev_active (s : stamp) (st : rev_status) : bool =
  (s = rev_stamp st) && non_revoc_proof s (rev_root st).

(*
 * Revocation soundness: a valid non-revocation proof guarantees that
 * the stamp's hash is absent from the Merkle root.
 *
 * Mirrors `revocation_soundness` from KyriotesCsk2Merkle.v:
 *   Axiom revocation_soundness : forall stamp root,
 *     not_in_revocation_root stamp root = true ->
 *     included_in_merkle_root (hash_revocation_stamp stamp) root = false.
 *)
axiom revocation_soundness (s : stamp) (r : root) :
  non_revoc_proof s r = true =>
  merkle_include (hash_stamp s) r = false.

lemma rev_active_excludes_revocation_leaf (s : stamp) (st : rev_status) :
  rev_active s st = true =>
  merkle_include (hash_stamp s) (rev_root st) = false.
proof.
  smt(revocation_soundness).
qed.
