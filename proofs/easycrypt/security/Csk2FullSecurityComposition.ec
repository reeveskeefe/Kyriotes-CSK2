(* Top-level EasyCrypt security composition for Kyriotēs-CSK2.
 *
 * This file is the single spine of the CSK2 formal security proof.  All
 * game-hopping lanes are proved and composed here; no admit stubs remain.
 *
 * Proved lanes (all bounds at the 2^{-128} level):
 *
 *   KEM+AEAD opening game
 *     Game0 → Game1 → Game2 hybrid, three steps, each bounded by 2^{-128}
 *     Result: Pr[Game0(A)] <= 3 * 2^{-128}            (csk2_concrete_bound)
 *
 *   Field-aware capability games (seven wrong-field games)
 *     Each reduces to capability authority-root binding via cap_binding_security
 *     Result: Pr[WrongXGame(F)] <= 2^{-128} each       (wrong_X_bound)
 *
 *   Full bad-event composition
 *     Csk2FlagsGame intermediate game exposes per-flag marginal distributions;
 *     union-bound over 8 independent flags gives the 10 * 2^{-128} total.
 *     Result: Pr[Csk2FullBadEventGame(X)] <= 10 * 2^{-128}
 *             (csk2_full_bad_event_sequential_bound)
 *
 * Primitive security leaves (axioms in their respective files):
 *   mlkem768_ror_secure              — ML-KEM-768 real-or-random  (KemIndCca2.ec)
 *   chacha20poly1305_ind_cpa_lr_secure — ChaCha20-Poly1305 LR     (AeadAeSecurity.ec)
 *   sha256_merkle_collision_security — SHA-256 collision resistance (Csk2MerkleBinding.ec)
 *   dmsg_bound                       — message-space entropy       (Csk2BaseTypes.ec)
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

local lemma wrong_object_ll :
  islossless WrongObjectGame(B_FieldFull(X)).main.
proof.
  proc; call B_FieldFull_forge_ll; auto.
qed.

local lemma wrong_rights_ll :
  islossless WrongRightsGame(B_FieldFull(X)).main.
proof.
  proc; call B_FieldFull_forge_ll; auto.
qed.

local lemma wrong_policy_ll :
  islossless WrongPolicyGame(B_FieldFull(X)).main.
proof.
  proc; call B_FieldFull_forge_ll; auto.
qed.

local lemma wrong_epoch_ll :
  islossless WrongEpochGame(B_FieldFull(X)).main.
proof.
  proc; call B_FieldFull_forge_ll; auto.
qed.

local lemma wrong_subject_ll :
  islossless WrongSubjectGame(B_FieldFull(X)).main.
proof.
  proc; call B_FieldFull_forge_ll; auto.
qed.

local lemma wrong_recipient_ll :
  islossless WrongRecipientGame(B_FieldFull(X)).main.
proof.
  proc; call B_FieldFull_forge_ll; auto.
qed.

local lemma wrong_revocation_ll :
  islossless WrongRevocationGame(B_FieldFull(X)).main.
proof.
  proc; call B_FieldFull_forge_ll; auto.
qed.

local lemma game0_ll : islossless Game0(B_OpenFull(X)).main.
proof.
  proc; call B_OpenFull_attack_ll.
  by auto; smt(aenc_ll encap_ll dkeypair_ll dmsg_ll).
qed.

op flags_any (f : flags8) : bool =
  f_open f || f_object f || f_rights f || f_policy f ||
  f_epoch f || f_subject f || f_recipient f || f_revocation f.

local module OpenFlagGame = {
  proc main() : bool = {
    var b1 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    return b1;
  }
}.

local module ObjectFlagGame = {
  proc main() : bool = {
    var b1 : bool;
    var b2 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    b2 <@ WrongObjectGame(B_FieldFull(X)).main();
    return b2;
  }
}.

local module RightsFlagGame = {
  proc main() : bool = {
    var b1 : bool;
    var b2 : bool;
    var b3 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    b2 <@ WrongObjectGame(B_FieldFull(X)).main();
    b3 <@ WrongRightsGame(B_FieldFull(X)).main();
    return b3;
  }
}.

local module PolicyFlagGame = {
  proc main() : bool = {
    var b1 : bool; var b2 : bool; var b3 : bool; var b4 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    b2 <@ WrongObjectGame(B_FieldFull(X)).main();
    b3 <@ WrongRightsGame(B_FieldFull(X)).main();
    b4 <@ WrongPolicyGame(B_FieldFull(X)).main();
    return b4;
  }
}.

local module EpochFlagGame = {
  proc main() : bool = {
    var b1 : bool; var b2 : bool; var b3 : bool; var b4 : bool;
    var b5 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    b2 <@ WrongObjectGame(B_FieldFull(X)).main();
    b3 <@ WrongRightsGame(B_FieldFull(X)).main();
    b4 <@ WrongPolicyGame(B_FieldFull(X)).main();
    b5 <@ WrongEpochGame(B_FieldFull(X)).main();
    return b5;
  }
}.

local module SubjectFlagGame = {
  proc main() : bool = {
    var b1 : bool; var b2 : bool; var b3 : bool; var b4 : bool;
    var b5 : bool; var b6 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    b2 <@ WrongObjectGame(B_FieldFull(X)).main();
    b3 <@ WrongRightsGame(B_FieldFull(X)).main();
    b4 <@ WrongPolicyGame(B_FieldFull(X)).main();
    b5 <@ WrongEpochGame(B_FieldFull(X)).main();
    b6 <@ WrongSubjectGame(B_FieldFull(X)).main();
    return b6;
  }
}.

local module RecipientFlagGame = {
  proc main() : bool = {
    var b1 : bool; var b2 : bool; var b3 : bool; var b4 : bool;
    var b5 : bool; var b6 : bool; var b7 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    b2 <@ WrongObjectGame(B_FieldFull(X)).main();
    b3 <@ WrongRightsGame(B_FieldFull(X)).main();
    b4 <@ WrongPolicyGame(B_FieldFull(X)).main();
    b5 <@ WrongEpochGame(B_FieldFull(X)).main();
    b6 <@ WrongSubjectGame(B_FieldFull(X)).main();
    b7 <@ WrongRecipientGame(B_FieldFull(X)).main();
    return b7;
  }
}.

local module RevocationFlagGame = {
  proc main() : bool = {
    var b1 : bool; var b2 : bool; var b3 : bool; var b4 : bool;
    var b5 : bool; var b6 : bool; var b7 : bool; var b8 : bool;
    b1 <@ Game0(B_OpenFull(X)).main();
    b2 <@ WrongObjectGame(B_FieldFull(X)).main();
    b3 <@ WrongRightsGame(B_FieldFull(X)).main();
    b4 <@ WrongPolicyGame(B_FieldFull(X)).main();
    b5 <@ WrongEpochGame(B_FieldFull(X)).main();
    b6 <@ WrongSubjectGame(B_FieldFull(X)).main();
    b7 <@ WrongRecipientGame(B_FieldFull(X)).main();
    b8 <@ WrongRevocationGame(B_FieldFull(X)).main();
    return b8;
  }
}.

local lemma full_game_eq_flags &m :
  Pr[Csk2FullBadEventGame(X).main() @ &m : res] =
  Pr[Csk2FlagsGame(X).main() @ &m : flags_any res].
proof.
  byequiv => //; proc.
  wp.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  by skip => />.
qed.

local lemma flags_union_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : flags_any res] <=
  Pr[Csk2FlagsGame(X).main() @ &m : f_open res] +
  Pr[Csk2FlagsGame(X).main() @ &m : f_object res] +
  Pr[Csk2FlagsGame(X).main() @ &m : f_rights res] +
  Pr[Csk2FlagsGame(X).main() @ &m : f_policy res] +
  Pr[Csk2FlagsGame(X).main() @ &m : f_epoch res] +
  Pr[Csk2FlagsGame(X).main() @ &m : f_subject res] +
  Pr[Csk2FlagsGame(X).main() @ &m : f_recipient res] +
  Pr[Csk2FlagsGame(X).main() @ &m : f_revocation res].
proof.
  rewrite /flags_any.
  rewrite Pr[mu_or] Pr[mu_or] Pr[mu_or] Pr[mu_or].
  rewrite Pr[mu_or] Pr[mu_or] Pr[mu_or].
  smt(mu_bounded).
qed.

local lemma flags_open_eq_open_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_open res] =
  Pr[OpenFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_open res{1} = res{2}) => //.
  proc.
  seq 1 1 : (={glob X} /\ b1{1} = b1{2}).
  + call (: ={glob X} ==> ={glob X, res}); first by sim.
    by skip.
  wp.
  call{1} wrong_revocation_ll.
  call{1} wrong_recipient_ll.
  call{1} wrong_subject_ll.
  call{1} wrong_epoch_ll.
  call{1} wrong_policy_ll.
  call{1} wrong_rights_ll.
  call{1} wrong_object_ll.
  by skip => />.
qed.

local lemma open_flag_bound &m :
  Pr[OpenFlagGame.main() @ &m : res] <= 3%r * inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  call open_bad_phoare.
  auto.
qed.

local lemma flags_open_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_open res] <= 3%r * inv (2%r ^ 128).
proof.
  rewrite (flags_open_eq_open_flag &m).
  exact (open_flag_bound &m).
qed.

local lemma flags_object_eq_object_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_object res] =
  Pr[ObjectFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_object res{1} = res{2}) => //.
  proc.
  seq 2 2 : (={glob X} /\ b2{1} = b2{2}).
  + call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    by skip.
  wp.
  call{1} wrong_revocation_ll.
  call{1} wrong_recipient_ll.
  call{1} wrong_subject_ll.
  call{1} wrong_epoch_ll.
  call{1} wrong_policy_ll.
  call{1} wrong_rights_ll.
  by skip => />.
qed.

local lemma object_flag_bound &m :
  Pr[ObjectFlagGame.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  seq 1 : true 1%r (inv (2%r ^ 128)) 0%r 0%r true => //.
  + wp.
    call wrong_object_bad_phoare.
    auto.
qed.

local lemma flags_object_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_object res] <= inv (2%r ^ 128).
proof.
  rewrite (flags_object_eq_object_flag &m).
  exact (object_flag_bound &m).
qed.

local lemma flags_rights_eq_rights_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_rights res] =
  Pr[RightsFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_rights res{1} = res{2}) => //.
  proc.
  seq 3 3 : (={glob X} /\ b3{1} = b3{2}).
  + call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    by skip.
  wp.
  call{1} wrong_revocation_ll.
  call{1} wrong_recipient_ll.
  call{1} wrong_subject_ll.
  call{1} wrong_epoch_ll.
  call{1} wrong_policy_ll.
  by skip => />.
qed.

local lemma rights_flag_bound &m :
  Pr[RightsFlagGame.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  seq 2 : true 1%r (inv (2%r ^ 128)) 0%r 0%r true => //.
  + wp.
    call wrong_rights_bad_phoare.
    auto.
qed.

local lemma flags_rights_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_rights res] <= inv (2%r ^ 128).
proof.
  rewrite (flags_rights_eq_rights_flag &m).
  exact (rights_flag_bound &m).
qed.

local lemma flags_policy_eq_policy_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_policy res] =
  Pr[PolicyFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_policy res{1} = res{2}) => //.
  proc.
  seq 4 4 : (={glob X} /\ b4{1} = b4{2}).
  + call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    by skip.
  wp.
  call{1} wrong_revocation_ll.
  call{1} wrong_recipient_ll.
  call{1} wrong_subject_ll.
  call{1} wrong_epoch_ll.
  by skip => />.
qed.

local lemma policy_flag_bound &m :
  Pr[PolicyFlagGame.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  seq 3 : true 1%r (inv (2%r ^ 128)) 0%r 0%r true => //.
  + wp.
    call wrong_policy_bad_phoare.
    auto.
qed.

local lemma flags_policy_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_policy res] <= inv (2%r ^ 128).
proof.
  rewrite (flags_policy_eq_policy_flag &m).
  exact (policy_flag_bound &m).
qed.

local lemma flags_epoch_eq_epoch_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_epoch res] =
  Pr[EpochFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_epoch res{1} = res{2}) => //.
  proc.
  seq 5 5 : (={glob X} /\ b5{1} = b5{2}).
  + call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    by skip.
  wp.
  call{1} wrong_revocation_ll.
  call{1} wrong_recipient_ll.
  call{1} wrong_subject_ll.
  by skip => />.
qed.

local lemma epoch_flag_bound &m :
  Pr[EpochFlagGame.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  seq 4 : true 1%r (inv (2%r ^ 128)) 0%r 0%r true => //.
  + wp.
    call wrong_epoch_bad_phoare.
    auto.
qed.

local lemma flags_epoch_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_epoch res] <= inv (2%r ^ 128).
proof.
  rewrite (flags_epoch_eq_epoch_flag &m).
  exact (epoch_flag_bound &m).
qed.

local lemma flags_subject_eq_subject_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_subject res] =
  Pr[SubjectFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_subject res{1} = res{2}) => //.
  proc.
  seq 6 6 : (={glob X} /\ b6{1} = b6{2}).
  + call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    by skip.
  wp.
  call{1} wrong_revocation_ll.
  call{1} wrong_recipient_ll.
  by skip => />.
qed.

local lemma subject_flag_bound &m :
  Pr[SubjectFlagGame.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  seq 5 : true 1%r (inv (2%r ^ 128)) 0%r 0%r true => //.
  + wp.
    call wrong_subject_bad_phoare.
    auto.
qed.

local lemma flags_subject_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_subject res] <= inv (2%r ^ 128).
proof.
  rewrite (flags_subject_eq_subject_flag &m).
  exact (subject_flag_bound &m).
qed.

local lemma flags_recipient_eq_recipient_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_recipient res] =
  Pr[RecipientFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_recipient res{1} = res{2}) => //.
  proc.
  seq 7 7 : (={glob X} /\ b7{1} = b7{2}).
  + call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    call (: ={glob X} ==> ={glob X, res}); first by sim.
    by skip.
  wp.
  call{1} wrong_revocation_ll.
  by skip => />.
qed.

local lemma recipient_flag_bound &m :
  Pr[RecipientFlagGame.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  seq 6 : true 1%r (inv (2%r ^ 128)) 0%r 0%r true => //.
  + wp.
    call wrong_recipient_bad_phoare.
    auto.
qed.

local lemma flags_recipient_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_recipient res] <= inv (2%r ^ 128).
proof.
  rewrite (flags_recipient_eq_recipient_flag &m).
  exact (recipient_flag_bound &m).
qed.

local lemma flags_revocation_eq_revocation_flag &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_revocation res] =
  Pr[RevocationFlagGame.main() @ &m : res].
proof.
  byequiv (_ : ={glob X} ==> f_revocation res{1} = res{2}) => //.
  proc.
  wp.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  call (: ={glob X} ==> ={glob X, res}); first by sim.
  by skip => />.
qed.

local lemma revocation_flag_bound &m :
  Pr[RevocationFlagGame.main() @ &m : res] <= inv (2%r ^ 128).
proof.
  byphoare (: true ==> res) => //; proc.
  seq 7 : true 1%r (inv (2%r ^ 128)) 0%r 0%r true => //.
  + wp.
    call wrong_revocation_bad_phoare.
    auto.
qed.

local lemma flags_revocation_bound &m :
  Pr[Csk2FlagsGame(X).main() @ &m : f_revocation res] <= inv (2%r ^ 128).
proof.
  rewrite (flags_revocation_eq_revocation_flag &m).
  exact (revocation_flag_bound &m).
qed.

lemma csk2_full_bad_event_sequential_bound &m :
  Pr[Csk2FullBadEventGame(X).main() @ &m : res]
  <= 10%r * inv (2%r ^ 128).
proof.
  have heq  := full_game_eq_flags &m.
  have hsum := flags_union_bound &m.
  have h1   := flags_open_bound &m.
  have h2   := flags_object_bound &m.
  have h3   := flags_rights_bound &m.
  have h4   := flags_policy_bound &m.
  have h5   := flags_epoch_bound &m.
  have h6   := flags_subject_bound &m.
  have h7   := flags_recipient_bound &m.
  have h8   := flags_revocation_bound &m.
  smt().
qed.

lemma csk2_full_bad_event_bound &m :
  Pr[Csk2FullBadEventGame(X).main() @ &m : res]
  <= 10%r * inv (2%r ^ 128).
proof.
  exact (csk2_full_bad_event_sequential_bound &m).
qed.

end section FullAdversaryComposition.
