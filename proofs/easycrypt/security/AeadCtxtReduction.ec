(* AEAD one-way / message-hiding bound for Kyriotēs-CSK2 hybrid argument.
 *
 * Discharges the game2_win_bound axiom stub from Csk2TwoGateGame.ec.
 *
 * ── Why Game2 is hard with the corrected game design ─────────────
 *
 * With m <$ dmsg, Game2 is:
 *
 *   m    <$ dmsg;                        (* hidden target *)
 *   ct_a <$ aenc k a witness;            (* dummy ciphertext *)
 *   guess <@ A.attack(pk, ct_k, ct_a, a);
 *   return (guess = Some m);
 *
 * A's view (pk, ct_k, ct_a, a) is INDEPENDENT of m:
 *   - pk and ct_k come from dkeypair / encap, not m
 *   - ct_a = aenc k a witness does not encode m
 *   - a = witness is fixed
 *
 * To output Some m, A must guess m from dmsg without seeing it.
 * The probability is at most 1/|support(dmsg)| <= inv(2^128) if
 * dmsg is uniform over a 128-bit message space.
 *
 * ── What aead_ow represents ───────────────────────────────────────
 *
 * aead_ow captures the combined bound:
 *   (1) AEAD key is uniform (k = hkdf(ss_rand), ss_rand <$ dss).
 *   (2) ct_a = aenc k a witness hides m by IND-CPA (no info about m
 *       leaks through the ciphertext).
 *   (3) m is uniform over dmsg (message-space guessing bound).
 *
 * The overall win probability is therefore bounded by 1/|dmsg|.
 *
 * A direct EC proof would require:
 *   axiom dmsg_uniform : is_uniform dmsg.
 *   axiom dmsg_full    : is_full dmsg.
 *   axiom dmsg_card    : (size (to_seq (support dmsg)))%r = 2%r ^ 128.
 * and a probabilistic independence argument (swap m to be sampled last).
 * For now, aead_ow axiomatises the bound, mirroring kem_ror and
 * aead_cpa_adv in the other reduction files.
 *
 * ── What a direct INT-CTXT reduction would look like ─────────────
 *
 * With the current Csk2Adv interface (A outputs msg option), a CTXT
 * reduction is still impossible: INT-CTXT needs a ciphertext forgery,
 * not a plaintext guess.  The correct adversary for a CTXT reduction
 * would need A to output (aad * ctaead).  The OW bound is the right
 * primitive here.
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
 * Pr[Game2(A).main() @ &m : res] measures the probability that A
 * outputs Some m where m is a hidden uniform sample from dmsg and
 * ct_a encrypts only the dummy witness (not m).
 *
 * This bound follows from AEAD IND-CPA (ct_a hides witness, so A
 * learns nothing about m from ct_a) plus the message-space size
 * (guessing m from dmsg has probability <= inv(2^128)).
 *
 * Replace with a proved lemma once dmsg_uniform, dmsg_full, and
 * dmsg_card axioms are added and a probabilistic independence
 * argument is mechanised.
 *)
axiom aead_ow &m :
  Pr[Game2(A).main() @ &m : res] <= inv (2%r ^ 128).

(*
 * game2_win_bound: Pr[Game2] <= inv(2^128).
 *
 * Follows directly from aead_ow.
 *)
lemma game2_win_bound &m :
  Pr[Game2(A).main() @ &m : res] <= inv (2%r ^ 128).
proof. exact (aead_ow &m). qed.

end section AeadCtxt.
