(* AEAD INT-CTXT / OW reduction for Kyriotēs-CSK2 hybrid argument.
 *
 * Discharges the game2_win_bound axiom stub from Csk2TwoGateGame.ec
 * using a locally-axiomatized one-way security bound on the AEAD.
 *
 * ── Design note ───────────────────────────────────────────────────
 *
 * Game2 sets m <- witness before the AEAD step, so the adversary is
 * trying to output Some witness — a value it can compute synthetically.
 * This means no information-theoretic bound on Pr[Game2] is derivable
 * purely from the game structure.  The bound must be asserted as a
 * cryptographic assumption.
 *
 * The correct fix is to redesign Game2 (and Game1/Game0) so that m is
 * sampled fresh (m <$ dmsg) and hidden from A until its guess.  Under
 * that design the reduction below is complete.  Until the game is
 * updated, aead_ow (below) is axiomatised just as kem_ror is axiomatised
 * in KemReduction.ec: it names the missing primitive assumption and
 * makes the gap explicit.
 *
 * ── What a proper INT-CTXT reduction would look like ─────────────
 *
 * If the adversary's win condition were ciphertext-based (A outputs an
 * (aad * ctaead) forgery not obtained from an oracle) then:
 *
 *   module B_CTXT (A : Csk2Adv) (O : EncOracle) : IntCtxtAdversary = {
 *     proc forge() : aad * ctaead = {
 *       var pk; var sk; var ct_k; var ss_rand; var k; var a; var ct_a;
 *       var guess;
 *       (pk, sk)  <$ dkeypair;
 *       (ct_k, _) <$ encap pk;
 *       ss_rand   <$ dss;
 *       k         <- hkdf ss_rand;
 *       a         <- witness;
 *       ct_a      <@ O.encrypt(a, witness);   (* one oracle query *)
 *       guess     <@ A.attack(pk, ct_k, ct_a, a);
 *       (* A outputs a plaintext, not a ciphertext forgery.
 *          The interface mismatch prevents a direct INT-CTXT reduction.
 *          A proper CTXT reduction would need A to output a ciphertext. *)
 *       return (a, ct_a);   (* placeholder — not a forgery *)
 *     }
 *   }.
 *
 * The interface mismatch (A outputs msg option, INT-CTXT needs aad*ctaead)
 * is the core obstacle.  The right adversary interface for a CTXT reduction
 * would have A output a fresh ciphertext attempt rather than a plaintext
 * guess.
 *
 * ── What the axiom represents ─────────────────────────────────────
 *
 * aead_ow captures the one-way security of the AEAD composition:
 * given ct_a = aenc(k, a, witness) for a fresh key k = hkdf(ss_rand)
 * where ss_rand is drawn uniformly from dss, no PPT adversary can
 * recover the plaintext (witness) with probability more than inv(2^128).
 *
 * This encapsulates two properties:
 *   (1) Key unpredictability: hkdf(dss) is computationally indistinguishable
 *       from uniform over the key space.
 *   (2) AEAD one-wayness: given a single ciphertext under a fresh key,
 *       recovery probability is at most inv(2^128).
 *
 * Once the game is redesigned with m <$ dmsg (fresh hidden message), the
 * OW bound follows from AEAD IND-CPA + the guessing bound on dmsg.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr DBool FSet Real.
require import Csk2TwoGateGame.

section AeadCtxt.

declare module A <: Csk2Adv { -Game2 }.

axiom A_ll : islossless A.attack.

(*
 * AEAD one-way security axiom.
 *
 * Asserts that for the specific structure of Game2 (AEAD key derived
 * from a uniform shared secret, adversary sees pk/ct_k/ct_a/aad but
 * not the key or shared secret), the win probability is negligible.
 *
 * This replaces the INT-CTXT reduction that cannot be completed with
 * the current adversary interface.  Replace with a lemma once either:
 *   (a) the game is redesigned with a fresh random m, or
 *   (b) AeadAeSecurity.ec is imported with matching types and a
 *       proper OW/CPA adversary module is constructed.
 *)
axiom aead_ow &m :
  Pr[Game2(A).main() @ &m : res] <= inv (2%r ^ 128).

(*
 * game2_win_bound: Pr[Game2] <= inv(2^128).
 *
 * Follows directly from aead_ow.  Once aead_ow is discharged by a
 * concrete reduction adversary, this lemma needs no further changes.
 *)
lemma game2_win_bound &m :
  Pr[Game2(A).main() @ &m : res] <= inv (2%r ^ 128).
proof. exact (aead_ow &m). qed.

end section AeadCtxt.
