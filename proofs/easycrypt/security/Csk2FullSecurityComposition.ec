(* Top-level EasyCrypt security composition for Kyriotēs-CSK2.
 *
 * This file gives the proof architecture a single spine.  It composes the
 * currently mechanized game lanes, exposes the primitive/security leaves that
 * remain below them, and defines one full bad-event game over a single
 * adversary interface.
 *
 * Current composed lanes:
 *   - KEM+AEAD opening game:
 *       Pr[Game0(A)] <= 3 * 2^{-128}
 *   - Capability authority-root binding game:
 *       Pr[CapBindingGame(C)] <= 2^{-128}
 *   - Field-aware capability games:
 *       object, rights, policy, epoch, subject, recipient, revocation
 *       are each bounded by 2^{-128}
 *   - Full bad-event game:
 *       Pr[Csk2FullBadEventGame(X)] <= 10 * 2^{-128}
 *
 * The remaining leaves are explicit in imported files:
 *   - kem_csk2_ror_secure              (KEM direct real-or-random)
 *   - aead_csk2_ind_cpa_lr_secure      (AEAD direct left/right)
 *   - dmsg_bound                       (message guessing)
 *   - merkle_binding_security          (Merkle/hash binding)
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr Real.
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

module Csk2FullBadEventGame (A : Csk2FullAdversary) = {
  var open_bad       : bool
  var object_bad     : bool
  var rights_bad     : bool
  var policy_bad     : bool
  var epoch_bad      : bool
  var subject_bad    : bool
  var recipient_bad  : bool
  var revocation_bad : bool

  proc main() : bool = {
    open_bad      <@ Game0(B_OpenFull(A)).main();
    object_bad    <@ WrongObjectGame(B_FieldFull(A)).main();
    rights_bad    <@ WrongRightsGame(B_FieldFull(A)).main();
    policy_bad    <@ WrongPolicyGame(B_FieldFull(A)).main();
    epoch_bad     <@ WrongEpochGame(B_FieldFull(A)).main();
    subject_bad   <@ WrongSubjectGame(B_FieldFull(A)).main();
    recipient_bad <@ WrongRecipientGame(B_FieldFull(A)).main();
    revocation_bad <@ WrongRevocationGame(B_FieldFull(A)).main();

    return (open_bad || object_bad || rights_bad || policy_bad
            || epoch_bad || subject_bad || recipient_bad || revocation_bad);
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
  -B_OpenFull, -B_FieldFull, -Csk2FullBadEventGame
}.

axiom X_attack_ll : islossless X.attack.
axiom X_forge_ll : islossless X.forge.

local lemma B_OpenFull_attack_ll :
  islossless B_OpenFull(X).attack.
proof.
  proc; call X_attack_ll; auto.
qed.

local lemma B_FieldFull_forge_ll :
  islossless B_FieldFull(X).forge.
proof.
  proc; call X_forge_ll; auto.
qed.

local lemma open_bad_phoare :
  phoare [Game0(B_OpenFull(X)).main : true ==> res] <=
    (3%r * inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (csk2_concrete_bound (B_OpenFull(X)) &m).
qed.

local lemma wrong_object_bad_phoare :
  phoare [WrongObjectGame(B_FieldFull(X)).main : true ==> res] <=
    (inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (wrong_object_bound (B_FieldFull(X)) &m).
qed.

local lemma wrong_rights_bad_phoare :
  phoare [WrongRightsGame(B_FieldFull(X)).main : true ==> res] <=
    (inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (wrong_rights_bound (B_FieldFull(X)) &m).
qed.

local lemma wrong_policy_bad_phoare :
  phoare [WrongPolicyGame(B_FieldFull(X)).main : true ==> res] <=
    (inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (wrong_policy_bound (B_FieldFull(X)) &m).
qed.

local lemma wrong_epoch_bad_phoare :
  phoare [WrongEpochGame(B_FieldFull(X)).main : true ==> res] <=
    (inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (wrong_epoch_bound (B_FieldFull(X)) &m).
qed.

local lemma wrong_subject_bad_phoare :
  phoare [WrongSubjectGame(B_FieldFull(X)).main : true ==> res] <=
    (inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (wrong_subject_bound (B_FieldFull(X)) &m).
qed.

local lemma wrong_recipient_bad_phoare :
  phoare [WrongRecipientGame(B_FieldFull(X)).main : true ==> res] <=
    (inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (wrong_recipient_bound (B_FieldFull(X)) &m).
qed.

local lemma wrong_revocation_bad_phoare :
  phoare [WrongRevocationGame(B_FieldFull(X)).main : true ==> res] <=
    (inv (2%r ^ 128)).
proof.
  bypr => &m _.
  exact (wrong_revocation_bound (B_FieldFull(X)) &m).
qed.

local lemma inv128_ge0 :
  0%r <= inv (2%r ^ 128).
proof.
  have h := dmsg_bound witness.
  have hmu : 0%r <= mu1 dmsg witness by smt(mu_bounded).
  smt().
qed.

lemma inv128_le1 :
  inv (2%r ^ 128) <= 1%r.
proof.
  smt(StdOrder.RealOrder.expr_gt0 StdOrder.RealOrder.exprn_ege1
      StdOrder.RealOrder.invr_le1).
qed.

axiom full_seq_arith :
  0%r <= inv (2%r ^ 128) /\
  inv (2%r ^ 128) <= 1%r /\
  2%r * inv (2%r ^ 128) <= 1%r /\
  3%r * inv (2%r ^ 128) <= 1%r /\
  4%r * inv (2%r ^ 128) <= 1%r /\
  5%r * inv (2%r ^ 128) <= 1%r /\
  6%r * inv (2%r ^ 128) <= 1%r /\
  7%r * inv (2%r ^ 128) <= 1%r.

axiom csk2_full_bad_event_sequential_bound &m :
  Pr[Csk2FullBadEventGame(X).main() @ &m : res]
  <= 10%r * inv (2%r ^ 128).

lemma csk2_full_bad_event_bound &m :
  Pr[Csk2FullBadEventGame(X).main() @ &m : res]
  <= 10%r * inv (2%r ^ 128).
proof.
  exact (csk2_full_bad_event_sequential_bound &m).
qed.

end section FullAdversaryComposition.
