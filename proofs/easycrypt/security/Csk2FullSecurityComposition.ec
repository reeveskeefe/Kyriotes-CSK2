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
 *   - Field-aware capability games:
 *       object, rights, policy, epoch, subject, recipient, revocation
 *       are each bounded by 2^{-128}
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
require import Csk2BaseTypes.
require import Csk2TwoGateGame.
require import AeadAeSecurity.
require import AeadCpaReduction.
require import KemAeadComposition.
require import Csk2CapabilityGame.

(* ── Full CSK2 adversary interface ─────────────────────────────── *)

module type Csk2FullAdversary = {
  proc attack (pk : pkey, ct_k : ctkem, ct_a : ctaead, a : aad) : msg option
  proc forge() : cap * capctx * capctx * root * root
}.

module B_OpenFull (A : Csk2FullAdversary) : Csk2Adv = {
  proc attack (pk : pkey, ct_k : ctkem, ct_a : ctaead, a : aad) : msg option = {
    var guess : msg option;
    guess <@ A.attack(pk, ct_k, ct_a, a);
    return guess;
  }
}.

module B_FieldFull (A : Csk2FullAdversary) : CapFieldAdversary = {
  proc forge() : cap * capctx * capctx * root * root = {
    var c  : cap;
    var x1 : capctx;
    var x2 : capctx;
    var r1 : root;
    var r2 : root;
    (c, x1, x2, r1, r2) <@ A.forge();
    return (c, x1, x2, r1, r2);
  }
}.

section FullSecurityComposition.

declare module A <: Csk2Adv {
  -Game0, -Game1, -Game2,
  -B_CPA, -Game_CPA_Left, -Game_CPA_Right
}.

declare module C <: CapBindAdversary { -CapBindingGame, -B_Merkle }.

declare module F <: CapFieldAdversary {
  -CapBindingGame, -B_Merkle, -B_CapField,
  -WrongObjectGame, -WrongRightsGame, -WrongPolicyGame,
  -WrongEpochGame, -WrongSubjectGame, -WrongRecipientGame,
  -WrongRevocationGame
}.

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

lemma csk2_wrong_object_bound &m :
  Pr[WrongObjectGame(F).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (wrong_object_bound F &m).
qed.

lemma csk2_wrong_rights_bound &m :
  Pr[WrongRightsGame(F).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (wrong_rights_bound F &m).
qed.

lemma csk2_wrong_policy_bound &m :
  Pr[WrongPolicyGame(F).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (wrong_policy_bound F &m).
qed.

lemma csk2_wrong_epoch_bound &m :
  Pr[WrongEpochGame(F).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (wrong_epoch_bound F &m).
qed.

lemma csk2_wrong_subject_bound &m :
  Pr[WrongSubjectGame(F).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (wrong_subject_bound F &m).
qed.

lemma csk2_wrong_recipient_bound &m :
  Pr[WrongRecipientGame(F).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (wrong_recipient_bound F &m).
qed.

lemma csk2_wrong_revocation_bound &m :
  Pr[WrongRevocationGame(F).main() @ &m : res] <= inv (2%r ^ 128).
proof.
  exact (wrong_revocation_bound F &m).
qed.

lemma csk2_field_sum_bound &m :
  Pr[WrongObjectGame(F).main() @ &m : res] +
  Pr[WrongRightsGame(F).main() @ &m : res] +
  Pr[WrongPolicyGame(F).main() @ &m : res] +
  Pr[WrongEpochGame(F).main() @ &m : res] +
  Pr[WrongSubjectGame(F).main() @ &m : res] +
  Pr[WrongRecipientGame(F).main() @ &m : res] +
  Pr[WrongRevocationGame(F).main() @ &m : res]
  <= 7%r * inv (2%r ^ 128).
proof.
  have h_obj := csk2_wrong_object_bound &m.
  have h_rights := csk2_wrong_rights_bound &m.
  have h_policy := csk2_wrong_policy_bound &m.
  have h_epoch := csk2_wrong_epoch_bound &m.
  have h_subject := csk2_wrong_subject_bound &m.
  have h_recipient := csk2_wrong_recipient_bound &m.
  have h_revocation := csk2_wrong_revocation_bound &m.
  smt().
qed.

lemma csk2_opening_plus_field_sum_bound &m :
  Pr[Game0(A).main() @ &m : res] +
  Pr[WrongObjectGame(F).main() @ &m : res] +
  Pr[WrongRightsGame(F).main() @ &m : res] +
  Pr[WrongPolicyGame(F).main() @ &m : res] +
  Pr[WrongEpochGame(F).main() @ &m : res] +
  Pr[WrongSubjectGame(F).main() @ &m : res] +
  Pr[WrongRecipientGame(F).main() @ &m : res] +
  Pr[WrongRevocationGame(F).main() @ &m : res]
  <= 10%r * inv (2%r ^ 128).
proof.
  have h_open := csk2_opening_bound &m.
  have h_fields := csk2_field_sum_bound &m.
  smt().
qed.

end section FullSecurityComposition.

section FullAdversaryComposition.

declare module X <: Csk2FullAdversary {
  -Game0, -Game1, -Game2,
  -B_CPA, -Game_CPA_Left, -Game_CPA_Right,
  -CapBindingGame, -B_Merkle, -B_CapField,
  -WrongObjectGame, -WrongRightsGame, -WrongPolicyGame,
  -WrongEpochGame, -WrongSubjectGame, -WrongRecipientGame,
  -WrongRevocationGame,
  -B_OpenFull, -B_FieldFull
}.

lemma csk2_full_adversary_sum_bound &m :
  Pr[Game0(B_OpenFull(X)).main() @ &m : res] +
  Pr[WrongObjectGame(B_FieldFull(X)).main() @ &m : res] +
  Pr[WrongRightsGame(B_FieldFull(X)).main() @ &m : res] +
  Pr[WrongPolicyGame(B_FieldFull(X)).main() @ &m : res] +
  Pr[WrongEpochGame(B_FieldFull(X)).main() @ &m : res] +
  Pr[WrongSubjectGame(B_FieldFull(X)).main() @ &m : res] +
  Pr[WrongRecipientGame(B_FieldFull(X)).main() @ &m : res] +
  Pr[WrongRevocationGame(B_FieldFull(X)).main() @ &m : res]
  <= 10%r * inv (2%r ^ 128).
proof.
  exact (csk2_opening_plus_field_sum_bound (B_OpenFull(X)) (B_FieldFull(X)) &m).
qed.

end section FullAdversaryComposition.
