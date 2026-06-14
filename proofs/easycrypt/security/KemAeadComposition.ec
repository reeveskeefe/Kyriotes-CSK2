(* KEM+AEAD composition for Kyriotēs-CSK2 — proof roadmap.
 *
 * The concrete hybrid game sequence and the machine-checked composition
 * theorem live in Csk2TwoGateGame.ec.  This file documents the three
 * remaining proof obligations (one reduction per hybrid step) and will
 * host the reduction adversary modules once they are written.
 *
 * EasyCrypt version: r2022.04
 *)

require import AllCore Real.
require import Csk2TwoGateGame.

(* ── Summary of what is already machine-checked ──────────────────
 *
 * In Csk2TwoGateGame.ec (assuming the three axiom stubs hold):
 *
 *   csk2_concrete_bound:
 *     forall (A : Csk2Adv) &m,
 *       Pr[Game0(A).main() @ &m : res] <= 3%r * inv (2%r ^ 128)
 *
 * ── Three open proof obligations ─────────────────────────────────
 *
 * 1. game0_game1_kem  →  B_KEM reduction to KemIndCca2.Game_IND_CCA2
 *
 *    Construct module B_KEM (A : Csk2Adv) : KEM_Adversary such that:
 *      Adv^{IND-CCA2}(B_KEM(A)) =
 *        |Pr[Game0(A).main()] - Pr[Game1(A).main()]|
 *
 *    Proof sketch:
 *      - B_KEM.choose(pk): sample a random aad, run
 *          (ct_k, _) <$ encap pk
 *        Return ct_k.
 *      - B_KEM.guess(ss_b): derive k = hkdf(ss_b), sample
 *          ct_a <$ aenc k aad m
 *        Run A.attack(pk, ct_k, ct_a, aad); output (guess = Some m).
 *      When ss_b is real (b=1): simulates Game0, so b' = b iff A wins G0.
 *      When ss_b is random (b=0): simulates Game1, so b' = b iff A wins G1.
 *
 * 2. game1_game2_cpa  →  B_CPA reduction to AeadAeSecurity.Game_IND_CPA
 *
 *    Construct module B_CPA (A : Csk2Adv) : IndCpaAdversary such that:
 *      Adv^{IND-CPA}(B_CPA(A)) =
 *        |Pr[Game1(A).main()] - Pr[Game2(A).main()]|
 *
 *    Proof sketch:
 *      - B_CPA.choose(): sample (pk, sk), (ct_k, ss_r), k = hkdf(ss_r).
 *        Output (m, witness) as the challenge plaintext pair.
 *      - B_CPA.distinguish(c): run A.attack(pk, ct_k, c, aad);
 *        output (guess = Some m).
 *      When the oracle chose m (b=1): c encrypts m   → simulates Game1.
 *      When the oracle chose witness (b=0): c encrypts dummy → simulates Game2.
 *
 * 3. game2_win_bound  →  B_CTXT reduction to AeadAeSecurity.Game_INT_CTXT
 *
 *    Construct module B_CTXT (A : Csk2Adv) : IntCtxtAdversary such that:
 *      Pr[Game2(A).main()] <= Adv^{INT-CTXT}(B_CTXT(A))
 *
 *    Proof sketch:
 *      In Game2, ct_a encrypts witness.  The real plaintext m is also
 *      witness (m <- witness in the game).  So A wins iff
 *        guess = Some witness
 *      which requires adec k a ct_a = Some witness.  But by aead_correct,
 *      ct_a <$ aenc k a witness already satisfies this, so A cannot
 *      win by producing a *different* ciphertext.  B_CTXT forwards
 *      A's winning ciphertext as a forgery.
 *
 * ── File structure once reductions are written ───────────────────
 *
 *   security/
 *     KemIndCca2.ec          — KEM IND-CCA2 game + axiom stub
 *     AeadAeSecurity.ec      — INT-CTXT + IND-CPA games + axiom stubs
 *     Csk2TwoGateGame.ec     — Game0/Game1/Game2 + composition theorem
 *     KemReduction.ec        — B_KEM module + proof of game0_game1_kem
 *     AeadCpaReduction.ec    — B_CPA module + proof of game1_game2_cpa
 *     AeadCtxtReduction.ec   — B_CTXT module + proof of game2_win_bound
 *     KemAeadComposition.ec  — (this file) pulls everything together
 *)
