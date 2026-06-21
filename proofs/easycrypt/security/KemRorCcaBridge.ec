(* Generic KEM bit-guessing ↔ real-or-random bridge.
 *
 * This file is independent of ML-KEM internals.  It proves the accounting
 * convention needed to connect bit-guessing KEM IND-CCA/CPA statements to the
 * direct real-or-random left/right form consumed by KemReduction.ec.
 *
 * EasyCrypt version: r2022.04 (easycryptpa/ec-test-box:latest)
 *)

require import AllCore Distr DBool Real.
require import Csk2BaseTypes.
require import KemIndCca2.
require (****) LorR.

type kem_bridge_input.

clone import LorR as LR with
  type input <- kem_bridge_input.

module KEM_RoR_Real_Unit (A : KEM_RoR_Adversary) : LR.A = {
  proc main(x : kem_bridge_input) : bool = {
    var b : bool;
    b <@ Game_KEM_RoR_Real(A).main();
    return b;
  }
}.

module KEM_RoR_Rand_Unit (A : KEM_RoR_Adversary) : LR.A = {
  proc main(x : kem_bridge_input) : bool = {
    var b : bool;
    b <@ Game_KEM_RoR_Rand(A).main();
    return b;
  }
}.

section KEM_RoR_CCA_Bridge.

declare module A <: KEM_RoR_Adversary {
  -Game_KEM_RoR_Real, -Game_KEM_RoR_Rand,
  -KEM_RoR_Real_Unit, -KEM_RoR_Rand_Unit
}.

axiom A_ll : islossless A.run.

local lemma kem_ror_rand_ll :
  islossless Game_KEM_RoR_Rand(A).main.
proof.
  proc; call A_ll.
  by auto; smt(dkeypair_ll encap_ll dss_ll).
qed.

local lemma kem_ror_rand_unit_ll &m :
  Pr[KEM_RoR_Rand_Unit(A).main(witness) @ &m : true] = 1%r.
proof.
  byphoare => //; proc.
  call kem_ror_rand_ll.
  auto.
qed.

lemma kem_randomlr_ror_factor &m :
  `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
     Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
  =
  2%r *
  `| Pr[LR.RandomLR(KEM_RoR_Real_Unit(A), KEM_RoR_Rand_Unit(A)).main(witness) @ &m : res] -
     1%r / 2%r |.
proof.
  have hfactor :=
    LR.pr_AdvLR_AdvRndLR
      (KEM_RoR_Real_Unit(A)) (KEM_RoR_Rand_Unit(A)) &m witness
      (kem_ror_rand_unit_ll &m).
  have hreal :
    Pr[KEM_RoR_Real_Unit(A).main(witness) @ &m : res] =
    Pr[Game_KEM_RoR_Real(A).main() @ &m : res].
  + by byequiv => //; proc; inline *; sim.
  have hrand :
    Pr[KEM_RoR_Rand_Unit(A).main(witness) @ &m : res] =
    Pr[Game_KEM_RoR_Rand(A).main() @ &m : res].
  + by byequiv => //; proc; inline *; sim.
  by rewrite -hreal -hrand.
qed.

lemma kem_randomlr_to_ror_bound &m (eps : real) :
  2%r *
  `| Pr[LR.RandomLR(KEM_RoR_Real_Unit(A), KEM_RoR_Rand_Unit(A)).main(witness) @ &m : res] -
     1%r / 2%r | <= eps =>
  `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
     Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
  <= eps.
proof.
  move=> h.
  rewrite (kem_randomlr_ror_factor &m).
  exact h.
qed.

end section KEM_RoR_CCA_Bridge.
