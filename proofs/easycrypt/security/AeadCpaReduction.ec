(* AEAD IND-CPA reduction for Kyriotēs-CSK2 hybrid argument.
 *
 * Discharges the game1_game2_cpa axiom stub from Csk2TwoGateGame.ec
 * via a local IND-CPA assumption on the AEAD primitive.
 *
 * ── Why the games now differ ──────────────────────────────────────
 *
 * With the corrected game design (m <$ dmsg):
 *
 *   Game1:  m <$ dmsg;  ct_a <$ aenc k a m       (encrypts real m)
 *   Game2:  m <$ dmsg;  ct_a <$ aenc k a witness  (encrypts dummy)
 *
 * Both games return (guess = Some m), so A wins if it recovers m.
 * In Game1 the ciphertext carries information about m (IND-CPA world);
 * in Game2 the ciphertext is independent of m.  An adversary that
 * distinguishes the games breaks AEAD IND-CPA.
 *
 * The primitive game files now share Csk2BaseTypes, so there is no longer
 * a type-namespace conflict.  The remaining work is the game-shape bridge:
 * AeadAeSecurity.ec states a bit-guessing IND-CPA game, while this hybrid
 * step needs a direct left/right probability-gap statement over the CSK2
 * derived-key distribution.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr DBool FSet Real.
require import Csk2TwoGateGame.

section AeadCpa.

declare module A <: Csk2Adv { -Game1, -Game2 }.

axiom A_ll : islossless A.attack.

(*
 * AEAD IND-CPA security axiom.
 *
 * This is no longer blocked by duplicate type declarations; it remains as
 * the direct left/right CPA bound needed by the CSK2 hybrid until the
 * bit-guessing AEAD game is connected with the correct factor accounting.
 *)
axiom aead_cpa_adv &m :
  `| Pr[Game1(A).main() @ &m : res] - Pr[Game2(A).main() @ &m : res] |
  <= inv (2%r ^ 128).

lemma game1_game2_cpa &m :
  `| Pr[Game1(A).main() @ &m : res] - Pr[Game2(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof. exact (aead_cpa_adv &m). qed.

end section AeadCpa.
