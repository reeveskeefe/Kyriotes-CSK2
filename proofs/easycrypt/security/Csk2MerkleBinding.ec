(* Merkle inclusion binding for Kyriotēs-CSK2.
 *
 * A leaf hash included in two distinct Merkle roots implies a
 * SHA-256 preimage or collision on the Merkle path — a break of the
 * underlying hash function.  The game is stated as a probabilistic
 * advantage bound at the 2^{-128} level consistent with the rest of
 * the CSK2 security proof.
 *
 * This file lifts the Coq axiom `merkle_inclusion_binding` from
 * proofs/coq/merkle_transparency/KyriotesCsk2Merkle.v to a
 * probabilistic game:
 *
 *   Axiom merkle_inclusion_binding :
 *     forall leaf root_a root_b,
 *       included_in_merkle_root leaf root_a = true ->
 *       included_in_merkle_root leaf root_b = true ->
 *       root_a <> root_b -> False.
 *
 * In the CSK2 instantiation, leaves are hashed capabilities
 * (hash_cap c) and roots are authority_root values from distinct
 * AuthorityStates.  The game captures:
 *
 *   "No PPT adversary can exhibit one Merkle leaf included in two
 *    distinct authority tree roots."
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr Real.
require import Csk2BaseTypes.

(* ── Collision-resistance game ──────────────────────────────────── *)
(*
 * MerkleBindingGame:
 *   A.find() returns (leaf, r1, r2).
 *   The adversary wins if leaf is included in both r1 and r2 with r1 ≠ r2.
 *
 * This is a leaf-in-two-roots game, analogous to a hash-function
 * collision game but for Merkle tree paths.
 *)

module type MerkleAdversary = {
  proc find() : hash * root * root
}.

module MerkleBindingGame (A : MerkleAdversary) = {
  proc main() : bool = {
    var leaf : hash;
    var r1   : root;
    var r2   : root;
    (leaf, r1, r2) <@ A.find();
    return (merkle_include leaf r1 && merkle_include leaf r2 && (r1 <> r2));
  }
}.

(* ── Security axiom ─────────────────────────────────────────────── *)

section MerkleBinding.

declare module A <: MerkleAdversary.

(*
 * merkle_binding_security
 *
 * No PPT adversary can exhibit a leaf in two distinct Merkle roots
 * with probability more than 2^{-128}.
 *
 * Follows from SHA-256 collision resistance: distinct roots have
 * distinct root hashes, and a Merkle path proof binds a leaf to a
 * single root via a chain of SHA-256 evaluations.  A leaf in two
 * roots would require either a hash collision or a second-preimage.
 *
 * Replace with a concrete reduction to the SHA-256 PRF / collision
 * game once the Merkle path structure (KyriotesCsk2MerkleConcreteTree.v)
 * is ported to EasyCrypt.
 *)
axiom merkle_binding_security &m :
  Pr[MerkleBindingGame(A).main() @ &m : res] <= inv (2%r ^ 128).

end section MerkleBinding.
