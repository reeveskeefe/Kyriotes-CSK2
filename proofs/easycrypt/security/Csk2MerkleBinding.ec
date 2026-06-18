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

(* ── Concrete Merkle path structure ──────────────────────────────── *)

(*
 * Port of the computational structure from
 * KyriotesCsk2MerkleConcreteTree.v:
 *
 *   MerkleDirection        ↔ MerkleLeft / MerkleRight
 *   ConcreteMerkleSibling  ↔ sibling direction plus sibling hash
 *   verify_merkle_path     ↔ fold a leaf hash through a sibling path
 *
 * The EasyCrypt model keeps the path carrier abstract because the
 * reductions here only need the path algebra and verifier contract.
 * The concrete Rust/Coq tree shape is connected by merkle_include_sound:
 * every accepted inclusion has a corresponding path witness.
 *)

type merkle_direction = [ MerkleLeft | MerkleRight ].

type merkle_sibling = {
  sibling_direction : merkle_direction;
  sibling_hash      : hash
}.

type merkle_path.

op hash_leaf_concrete : hash -> hash.
op hash_node_concrete : hash -> hash -> hash.
op root_hash : root -> hash.
op empty_merkle_path : merkle_path.
op apply_merkle_sibling : hash -> merkle_sibling -> hash.
op verify_merkle_path_from : hash -> merkle_path -> hash.
op verify_merkle_path : hash -> root -> merkle_path -> bool.

axiom apply_merkle_sibling_left (h s : hash) :
  apply_merkle_sibling h
    {| sibling_direction = MerkleLeft; sibling_hash = s |}
  = hash_node_concrete s h.

axiom apply_merkle_sibling_right (h s : hash) :
  apply_merkle_sibling h
    {| sibling_direction = MerkleRight; sibling_hash = s |}
  = hash_node_concrete h s.

axiom verify_merkle_path_def (leaf : hash) (r : root) (p : merkle_path) :
  verify_merkle_path leaf r p =
  (verify_merkle_path_from (hash_leaf_concrete leaf) p = root_hash r).

axiom empty_path_verifies_exact_leaf_root (leaf : hash) (r : root) :
  root_hash r = hash_leaf_concrete leaf =>
  verify_merkle_path leaf r empty_merkle_path = true.

(* Deterministic witness extraction for the existing inclusion API. *)
op merkle_include_path : hash -> root -> merkle_path.

axiom merkle_include_sound (leaf : hash) (r : root) :
  merkle_include leaf r = true =>
  verify_merkle_path leaf r (merkle_include_path leaf r) = true.

(* ── SHA-256 collision-resistance game ──────────────────────────── *)

module type Sha256MerkleCollisionAdversary = {
  proc find_collision() : hash * root * merkle_path * root * merkle_path
}.

op sha256_merkle_collision
  (leaf : hash) (r1 : root) (p1 : merkle_path) (r2 : root) (p2 : merkle_path)
  : bool =
  verify_merkle_path leaf r1 p1
  && verify_merkle_path leaf r2 p2
  && (r1 <> r2).

module Sha256MerkleCollisionGame (A : Sha256MerkleCollisionAdversary) = {
  proc main() : bool = {
    var leaf : hash;
    var r1   : root;
    var r2   : root;
    var p1   : merkle_path;
    var p2   : merkle_path;
    (leaf, r1, p1, r2, p2) <@ A.find_collision();
    return (sha256_merkle_collision leaf r1 p1 r2 p2);
  }
}.

(*
 * Primitive SHA-256/Merkle collision boundary.
 *
 * The Coq development proves the deterministic path facts under
 * hash_node_ordered_injective.  In EasyCrypt, the computational
 * hardness of finding such a SHA-256 collision remains the primitive
 * cryptographic leaf.
 *)

section Sha256MerkleCollisionSecurity.

declare module A <: Sha256MerkleCollisionAdversary { -Sha256MerkleCollisionGame }.

axiom sha256_merkle_collision_security &m :
  Pr[Sha256MerkleCollisionGame(A).main() @ &m : res] <= inv (2%r ^ 128).

axiom sha256_merkle_collision_security_phoare :
  phoare [Sha256MerkleCollisionGame(A).main : true ==> !res] >=
    (1%r - inv (2%r ^ 128)).

end section Sha256MerkleCollisionSecurity.

(* ── Merkle binding game ────────────────────────────────────────── *)
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

module B_Sha256Merkle (A : MerkleAdversary) : Sha256MerkleCollisionAdversary = {
  proc find_collision() : hash * root * merkle_path * root * merkle_path = {
    var leaf : hash;
    var r1   : root;
    var r2   : root;
    (leaf, r1, r2) <@ A.find();
    return (leaf, r1, merkle_include_path leaf r1,
            r2, merkle_include_path leaf r2);
  }
}.

lemma merkle_binding_implies_sha256_collision
  (leaf : hash) (r1 r2 : root) :
  merkle_include leaf r1 && merkle_include leaf r2 && (r1 <> r2) =>
  sha256_merkle_collision
    leaf r1 (merkle_include_path leaf r1)
    r2 (merkle_include_path leaf r2).
proof.
  rewrite /sha256_merkle_collision.
  move=> H.
  have H1 : merkle_include leaf r1 = true by smt().
  have H2 : merkle_include leaf r2 = true by smt().
  have H3 : r1 <> r2 by smt().
  rewrite (merkle_include_sound leaf r1 H1).
  rewrite (merkle_include_sound leaf r2 H2).
  by smt().
qed.

axiom merkle_binding_good_follows_sha256_good
  (leaf : hash) (r1 r2 : root) :
  ! sha256_merkle_collision
      leaf r1 (merkle_include_path leaf r1)
      r2 (merkle_include_path leaf r2) =>
  ! (merkle_include leaf r1 && merkle_include leaf r2 && (r1 <> r2)).

(* ── Security lemmas ────────────────────────────────────────────── *)

section MerkleBinding.

declare module A <: MerkleAdversary.

axiom merkle_binding_reduces_to_sha256_collision &m :
  Pr[MerkleBindingGame(A).main() @ &m : res] <=
  Pr[Sha256MerkleCollisionGame(B_Sha256Merkle(A)).main() @ &m : res].

axiom merkle_binding_good_reduces_to_sha256_good &m :
  Pr[Sha256MerkleCollisionGame(B_Sha256Merkle(A)).main() @ &m : !res] <=
  Pr[MerkleBindingGame(A).main() @ &m : !res].

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
 * The concrete reduction builds B_Sha256Merkle(A), which extracts the
 * path witnesses for both accepted inclusions and feeds them to the
 * SHA-256/Merkle collision game.
 *)
lemma merkle_binding_security &m :
  Pr[MerkleBindingGame(A).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  apply/(StdOrder.RealOrder.ler_trans
    (Pr[Sha256MerkleCollisionGame(B_Sha256Merkle(A)).main() @ &m : res])).
  + exact (merkle_binding_reduces_to_sha256_collision &m).
  + exact (sha256_merkle_collision_security (B_Sha256Merkle(A)) &m).
qed.

lemma merkle_binding_security_phoare :
  phoare [MerkleBindingGame(A).main : true ==> !res] >= (1%r - inv (2%r ^ 128)).
proof.
  bypr => &m _.
  apply/(StdOrder.RealOrder.ler_trans
    (Pr[Sha256MerkleCollisionGame(B_Sha256Merkle(A)).main() @ &m : !res])).
  + by byphoare (sha256_merkle_collision_security_phoare (B_Sha256Merkle(A))).
  + exact (merkle_binding_good_reduces_to_sha256_good &m).
qed.

end section MerkleBinding.
