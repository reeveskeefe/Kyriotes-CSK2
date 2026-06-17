(* Top-level EasyCrypt security composition for Kyriotēs-CSK2.
 *
 * This file gives the proof architecture a single spine.  It does not
 * introduce a richer two-gate game yet; instead it composes the currently
 * mechanized game lanes and exposes the primitive/security leaves that remain
 * below them.
 *
 * Current composed lanes:
 *   - KEM+AEAD opening game:
 *       Pr[Game0(A)] <= 3 * 2^{-128}
 *   - Capability authority-root binding game:
 *       Pr[CapBindingGame(C)] <= 2^{-128}
 *
 * The remaining leaves are explicit in imported files:
 *   - kem_csk2_ror_secure              (KEM direct real-or-random)
 *   - aead_csk2_ind_cpa_lr_secure      (AEAD direct left/right)
 *   - dmsg_bound                       (message guessing)
 *   - merkle_binding_security          (Merkle/hash binding)
 *
 * Next architectural step: replace this lane-wise theorem with a richer
 * two-gate game whose adversary has both a ciphertext-opening interface and a
 * capability/context-forgery interface.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Real.
require import Csk2TwoGateGame.
require import AeadAeSecurity.
require import AeadCpaReduction.
require import KemAeadComposition.
require import Csk2CapabilityGame.

section FullSecurityComposition.

declare module A <: Csk2Adv {
  -Game0, -Game1, -Game2,
  -B_CPA, -Game_CPA_Left, -Game_CPA_Right
}.

declare module C <: CapBindAdversary { -CapBindingGame, -B_Merkle }.

lemma csk2_opening_bound &m :
  Pr[Game0(A).main() @ &m : res] <= 3%r * inv (2%r ^ 128).
proof.
  exact (csk2_concrete_bound A &m).
qed.

lemma csk2_capability_binding_bound &m :
  Pr[CapBindingGame(C).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (cap_binding_security C &m).
qed.

lemma csk2_lane_sum_bound &m :
  Pr[Game0(A).main() @ &m : res] +
  Pr[CapBindingGame(C).main() @ &m : res]
  <= 4%r * inv (2%r ^ 128).
proof.
  have h_open := csk2_opening_bound &m.
  have h_cap  := csk2_capability_binding_bound &m.
  smt().
qed.

end section FullSecurityComposition.
