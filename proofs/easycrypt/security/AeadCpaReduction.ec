(* AEAD IND-CPA reduction for Kyriotēs-CSK2 hybrid argument.
 *
 * Discharges the Game1/Game2 hybrid step by constructing B_CPA and
 * embedding Game1/Game2 into the direct left/right CPA worlds from
 * AeadAeSecurity.ec.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Distr DBool FSet Real.
require import Csk2BaseTypes.
require import Csk2TwoGateGame.
require import AeadAeSecurity.

module B_CPA (A : Csk2Adv) : LrIndCpaAdversary = {

  var pk_st   : pkey
  var ct_k_st : ctkem
  var m_st    : msg

  proc choose() : msg * msg = {
    var sk     : skey;
    var shared : ss;

    (pk_st, sk)       <$ dkeypair;
    m_st              <$ dmsg;
    (ct_k_st, shared) <$ encap pk_st;
    return (m_st, witness);
  }

  proc distinguish(c : ctaead) : bool = {
    var guess : msg option;

    guess <@ A.attack(pk_st, ct_k_st, c, witness);
    return (guess = Some m_st);
  }
}.

section AeadCpa.

declare module A <: Csk2Adv { -Game1, -Game2, -B_CPA, -Game_CPA_Left, -Game_CPA_Right }.

axiom A_ll : islossless A.attack.

local lemma game1_eq_cpa_left &m :
  Pr[Game1(A).main() @ &m : res] =
  Pr[Game_CPA_Left(B_CPA(A)).main() @ &m : res].
proof.
  byequiv => //; proc; inline B_CPA(A).choose B_CPA(A).distinguish.
  swap {1} 3 3.
  swap {2} 4 3.
  wp.
  have Hatt : equiv[A.attack ~ A.attack : ={glob A, arg} ==> ={glob A, res}] by sim.
  call Hatt.
  wp; rnd; wp; rnd; wp; rnd; rnd; rnd.
  skip => /#.
qed.

local lemma game2_eq_cpa_right &m :
  Pr[Game2(A).main() @ &m : res] =
  Pr[Game_CPA_Right(B_CPA(A)).main() @ &m : res].
proof.
  byequiv => //; proc; inline B_CPA(A).choose B_CPA(A).distinguish.
  swap {1} 3 3.
  swap {2} 4 3.
  wp.
  have Hatt : equiv[A.attack ~ A.attack : ={glob A, arg} ==> ={glob A, res}] by sim.
  call Hatt.
  wp; rnd; wp; rnd; wp; rnd; rnd; rnd.
  skip => /#.
qed.

lemma game1_game2_cpa &m :
  `| Pr[Game1(A).main() @ &m : res] - Pr[Game2(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof.
  rewrite (game1_eq_cpa_left &m) (game2_eq_cpa_right &m).
  exact (aead_csk2_ind_cpa_lr_secure (B_CPA(A)) &m).
qed.

end section AeadCpa.
