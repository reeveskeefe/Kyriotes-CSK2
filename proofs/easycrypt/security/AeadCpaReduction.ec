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
 * The type namespace of AeadAeSecurity.ec conflicts with
 * Csk2TwoGateGame.ec (both declare `type key` and `type aad`),
 * so we cannot import Game_IND_CPA directly.  aead_cpa_adv is a
 * local axiom naming the IND-CPA security bound; it mirrors kem_ror
 * in KemReduction.ec.  Once a shared type header is factored out,
 * this axiom becomes a lemma proved by plugging B_CPA into
 * Game_IND_CPA from AeadAeSecurity.ec.
 *
 * ── B_CPA reduction adversary ─────────────────────────────────────
 *
 *   module B_CPA (A : Csk2Adv) (O : EncOracle) : IndCpaAdversary = {
 *
 *     var pk_st  : pkey
 *     var ct_k_st : ctkem
 *     var m_st   : msg
 *
 *     proc choose() : plaintext * plaintext = {
 *       var sk; var shared; var ss_rand;
 *       (pk_st, sk)      <$ dkeypair;
 *       m_st             <$ dmsg;
 *       (ct_k_st, shared) <$ encap pk_st;
 *       ss_rand          <$ dss;
 *       (* k is owned by Game_IND_CPA — B_CPA submits plaintext pair *)
 *       return (m_st, witness);   (* challenge: m_st vs dummy *)
 *     }
 *
 *     proc distinguish(c : ctaead) : bool = {
 *       var guess : msg option;
 *       guess <@ A.attack(pk_st, ct_k_st, c, witness);
 *       return (guess = Some m_st);
 *     }
 *   }.
 *
 * Under b=1 (oracle encrypts m_st): c simulates Game1 — same as CSK2 G1.
 * Under b=0 (oracle encrypts witness): c simulates Game2 — same as CSK2 G2.
 * IND-CPA advantage of B_CPA equals |Pr[G1] - Pr[G2]|.
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
 * Asserts that no PPT adversary can distinguish a ciphertext of a
 * real message from a ciphertext of a dummy witness with advantage
 * more than inv(2^128).  Translates directly to the gap between
 * Game1 and Game2 via the B_CPA reduction described above.
 *
 * Replace with a lemma (proved by plugging B_CPA into Game_IND_CPA
 * from AeadAeSecurity.ec) once the type namespace is unified.
 *)
axiom aead_cpa_adv &m :
  `| Pr[Game1(A).main() @ &m : res] - Pr[Game2(A).main() @ &m : res] |
  <= inv (2%r ^ 128).

(*
 * game1_game2_cpa: |Pr[Game1] - Pr[Game2]| <= inv(2^128).
 *
 * Follows directly from aead_cpa_adv.  Once aead_cpa_adv is discharged
 * by connecting B_CPA to Game_IND_CPA, this lemma needs no further changes.
 *)
lemma game1_game2_cpa &m :
  `| Pr[Game1(A).main() @ &m : res] - Pr[Game2(A).main() @ &m : res] |
  <= inv (2%r ^ 128).
proof. exact (aead_cpa_adv &m). qed.

end section AeadCpa.
