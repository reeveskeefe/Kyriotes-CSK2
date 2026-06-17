(* Capability authority-root binding for Kyriotēs-CSK2.
 *
 * This file formalizes the "second gate" of the CSK2 two-gate opening
 * model and connects it to the Merkle binding assumption.
 *
 * ── Two-gate opening model ────────────────────────────────────────
 *
 * CSK2 requires an adversary to hold BOTH gates to open a sealed object:
 *   Gate 1: KEM private key  → KEM IND-CCA2 (Game0 → Game1 → Game2)
 *   Gate 2: accepted capability context → capability binding game (here)
 *
 * The KEM gate is modelled by Csk2TwoGateGame.ec / KemReduction.ec.
 * This file models Gate 2: an adversary that obtains an accepted
 * capability for the wrong authority root.
 *
 * ── Game description ─────────────────────────────────────────────
 *
 * CapBindingGame:
 *   A.forge() returns (c, r1, r2).
 *   A wins if cap_in_root c r1 ∧ cap_in_root c r2 ∧ r1 ≠ r2.
 *
 * A win means the same capability is accepted under two distinct
 * authority roots — a cross-context authority-root binding violation.
 *
 * ── Reduction ────────────────────────────────────────────────────
 *
 * B_Merkle(A).find():
 *   (c, r1, r2) <@ A.forge()
 *   return (hash_cap c, r1, r2)
 *
 * If A wins CapBindingGame, then B_Merkle(A) wins MerkleBindingGame,
 * because cap_in_root c r = merkle_include (hash_cap c) r (cap_in_root_def).
 *
 * ── Coq correspondence ───────────────────────────────────────────
 *
 * Mirrors the following from KyriotesCsk2CapabilityBindingReduction.v:
 *
 *   Definition cross_context_wins_authority_root (v) :=
 *     verify_open_context obj_a cap state_a = true ∧
 *     verify_open_context obj_b cap state_b = true ∧
 *     authority_root state_a ≠ authority_root state_b.
 *
 *   Theorem cross_context_authority_root_requires_merkle_break :
 *     forall v, cross_context_wins_authority_root v -> False.
 *
 * Here the deterministic False is replaced by the probabilistic bound
 * Pr[CapBindingGame] <= inv(2^128), proved by reduction to MerkleBinding.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr Real.
require import Csk2BaseTypes.
require import Csk2MerkleBinding.

(* ── Capability-in-root predicate ──────────────────────────────── *)
(*
 * cap_in_root c r = true iff hash_cap(c) is a leaf in the Merkle
 * tree with root r.  In the CSK2 authority model, this is the check:
 *   "Is this capability committed to this authority state?"
 *
 * Mirrors:
 *   Definition capability_in_authority_root (cap : Capability) (state : AuthorityState) : bool :=
 *     included_in_merkle_root (hash_capability cap) (authority_root state).
 * from KyriotesCsk2Merkle.v.
 *)

op cap_in_root : cap -> root -> bool.

(*
 * cap_in_root_def: capability verification decomposes as Merkle
 * inclusion of the capability hash.  This is the interface lemma that
 * ties cap_in_root to the concrete Merkle predicate, enabling the
 * reduction to MerkleBindingGame.
 *)
axiom cap_in_root_def (c : cap) (r : root) :
  cap_in_root c r = merkle_include (hash_cap c) r.

(* ── Capability binding game ────────────────────────────────────── *)

module type CapBindAdversary = {
  proc forge() : cap * root * root
}.

(*
 * CapBindingGame:
 *   A.forge() returns (c, r1, r2).
 *   A wins if c is accepted in both r1 and r2 with r1 ≠ r2.
 *
 * A win is a cross-authority-root capability binding violation.
 *)
module CapBindingGame (A : CapBindAdversary) = {
  proc main() : bool = {
    var c  : cap;
    var r1 : root;
    var r2 : root;
    (c, r1, r2) <@ A.forge();
    return (cap_in_root c r1 && cap_in_root c r2 && (r1 <> r2));
  }
}.

(* ── B_Merkle: CapBindAdversary → MerkleAdversary ──────────────── *)
(*
 * B_Merkle(A).find() runs A.forge() and returns (hash_cap c, r1, r2).
 * A capability binding win for A immediately yields a Merkle binding
 * win for B_Merkle(A), because cap_in_root c r = merkle_include
 * (hash_cap c) r by cap_in_root_def.
 *)

module B_Merkle (A : CapBindAdversary) : MerkleAdversary = {
  proc find() : hash * root * root = {
    var c  : cap;
    var r1 : root;
    var r2 : root;
    (c, r1, r2) <@ A.forge();
    return (hash_cap c, r1, r2);
  }
}.

(* ── Reduction proof ────────────────────────────────────────────── *)

section CapBinding.

declare module A <: CapBindAdversary.

(*
 * cap_bind_eq_merkle
 *
 * The two games are equiprobable: A.forge() runs identically in both,
 * and the win conditions are propositionally equal via cap_in_root_def.
 *
 *   cap_in_root c r1 ∧ cap_in_root c r2 ∧ r1 ≠ r2
 *   = merkle_include (hash_cap c) r1 ∧ merkle_include (hash_cap c) r2 ∧ r1 ≠ r2
 *)
lemma cap_bind_eq_merkle &m :
  Pr[CapBindingGame(A).main() @ &m : res] =
  Pr[MerkleBindingGame(B_Merkle(A)).main() @ &m : res].
proof.
  byequiv => //; proc; inline B_Merkle(A).find; wp.
  call (: ={glob A} ==> ={glob A, res}); first by sim.
  by skip => />; smt(cap_in_root_def).
qed.

(*
 * cap_binding_security
 *
 * The advantage of any PPT adversary in CapBindingGame is at most
 * 2^{-128}, by reduction to merkle_binding_security.
 *
 * Corresponds to Coq's cross_context_authority_root_requires_merkle_break:
 * the deterministic impossibility in Coq is a negligible advantage bound
 * in EasyCrypt.
 *)
lemma cap_binding_security &m :
  Pr[CapBindingGame(A).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  rewrite (cap_bind_eq_merkle &m).
  exact (merkle_binding_security (B_Merkle(A)) &m).
qed.

end section CapBinding.
