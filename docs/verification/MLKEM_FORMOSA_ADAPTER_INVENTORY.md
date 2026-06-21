# Formosa ML-KEM Adapter Inventory

This note records the current mapping between Kyriotēs-CSK2's direct KEM
real-or-random leaf and the vendored Formosa ML-KEM EasyCrypt development.

Numeric-bound policy is recorded separately in
[MLKEM_NUMERIC_POLICY.md](MLKEM_NUMERIC_POLICY.md).  In short, CSK2 keeps the
`2^-128` RoR summary leaf until the Formosa concrete multi-term bound is
imported and parameter-audited inside this repository.

## Candidate Formosa Theorems

Vendored repository:

```text
third_party/formosa-mlkem
```

Relevant files:

```text
third_party/formosa-mlkem/proof/security/KEM_ROM.ec
third_party/formosa-mlkem/proof/security/FO_MLKEM.ec
third_party/formosa-mlkem/proof/spec/MLKEMSecurity768.ec
```

Import smoke target:

```sh
scripts/verification/check_formosa_mlkem_import.sh
```

Equivalent Makefile convenience target:

```sh
make -C proofs/easycrypt check-formosa-mlkem-import-auto
```

The script uses local `nix-shell` when available.  If Nix is not installed but
Docker is available, it runs the same command inside `nixos/nix:latest`.  The
Docker fallback image can be overridden with:

```sh
FORMOSA_NIX_DOCKER_IMAGE=<image> scripts/verification/check_formosa_mlkem_import.sh
```

GitHub CI also has an allow-failure evidence job:

```text
CI / Formosa ML-KEM import smoke
```

It checks out submodules recursively, enters
`third_party/formosa-mlkem/shell.nix`, and runs the same smoke target through
`scripts/verification/check_formosa_mlkem_import.sh`.

The target uses `proofs/easycrypt/security/KemFormosaImportSmoke.ec`, which
requires `MLKEMSecurity768` without importing its namespace.  This avoids
accidental collisions with CSK2's own `pkey`, `skey`, `ctkem`, and `ss` names.

Current toolchain note: the standard CSK2 Docker checker
`easycryptpa/ec-test-box:r2022.04` is too old for the Formosa proof scripts.
With the Formosa include paths wired, it reaches `MLKEMSecurity768.ec` but
fails on newer tactic syntax such as:

```easycrypt
case <- {1} 12.
```

Formosa's README records that their proof currently relies on EasyCrypt branch
`bdep_ecCircuitsRefactor`; their Dockerfile pins EasyCrypt commit
`c299bbd5adb0d7e8f688a3fad94d3fa969e20baf`.

Local machine note: this repository's usual Docker check remains useful for the
CSK2 EasyCrypt files, but it is not sufficient for the Formosa import smoke.
Use Formosa's Nix shell or a Docker image built from Formosa's pinned
EasyCrypt commit.

Closest theorem:

```easycrypt
lemma mlkem_spec_security &m (failprob hsadv prfadv : real) : ...
```

Defined in:

```text
third_party/formosa-mlkem/proof/spec/MLKEMSecurity768.ec
```

Bound shape:

```easycrypt
`| Pr[SPEC_MODEL.CCA(SPEC_MODEL.RO.RO, MLKEM_Op, A).main() @ &m : res]
   - 1%r / 2%r |
<= concrete expression over MLWE, hash-sponge, PRF, correctness,
   random-oracle query bounds, and message-spread terms.
```

This is a bit-guessing IND-CCA style theorem in the random-oracle model, not
the direct real-or-random left/right form currently consumed by
`KemReduction.ec`.

Generic conversion theorem:

```easycrypt
lemma pr_CPA_LR &m :
  islossless S.kg => islossless S.enc => islossless A.guess =>
  `| Pr[CPA_L(S,A).main() @ &m : res] -
     Pr[CPA_R(S,A).main() @ &m : res] |
  =
  2%r * `| Pr[CPA(S,A).main() @ &m : res] - 1%r / 2%r |.
```

Defined in:

```text
third_party/formosa-mlkem/proof/security/KEM_ROM.ec
```

That theorem is for CPA left/right games. Kyriotēs-CSK2 now has a local generic
left/right-to-RoR factor bridge in:

```text
proofs/easycrypt/security/KemRorCcaBridge.ec
```

The proved local bridge exposes:

```easycrypt
lemma kem_randomlr_ror_factor &m :
  `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
     Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
  =
  2%r *
  `| Pr[LR.RandomLR(KEM_RoR_Real_Unit(A), KEM_RoR_Rand_Unit(A)).main(witness)
        @ &m : res] -
     1%r / 2%r |.

lemma kem_randomlr_to_ror_bound &m (eps : real) :
  2%r *
  `| Pr[LR.RandomLR(KEM_RoR_Real_Unit(A), KEM_RoR_Rand_Unit(A)).main(witness)
        @ &m : res] -
     1%r / 2%r | <= eps =>
  `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
     Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
  <= eps.
```

Remaining bridge work is Formosa-specific: connect `SPEC_MODEL.CCA` branches
to the local `RandomLR` shape and carry the ROM oracle/query obligations.

## Type And Operator Mapping

Kyriotēs-CSK2 leaf in `KemIndCca2.ec`:

```easycrypt
type pkey
type skey
type ctkem
type ss

op dkeypair : (pkey * skey) distr
op encap    : pkey -> (ctkem * ss) distr
op dss      : ss distr
```

Formosa abstract ROM KEM in `KEM_ROM.ec`:

```easycrypt
type pkey
type skey
type key
type ciphertext

op dkey : key distr

module type Scheme(O : POracle) = {
  proc kg() : pkey * skey
  proc enc(pk : pkey) : ciphertext * key
  proc dec(sk : skey, c : ciphertext) : key option
}.

module type CCA_ORC = {
  proc dec(c : ciphertext) : key option
}.

module type CCA_ADV(H : POracle, O : CCA_ORC) = {
  proc guess(pk : pkey, c : ciphertext, k : key) : bool
}.
```

Formosa ML-KEM-768 instantiation in `MLKEMSecurity768.ec`:

```easycrypt
clone import KEM_ROM as SPEC_MODEL with
  type pkey       <- publickey,
  type skey       <- secretkey,
  type key        <- sharedsecret,
  type ciphertext <- ciphertext,
  op dkey         <- srand,
  ...

module (MLKEM_Op : Scheme) (O : POracle) = {
  proc kg()  : publickey * secretkey
  proc enc(pk : publickey) : ciphertext * sharedsecret
  proc dec(sk : secretkey, cph : ciphertext) : sharedsecret option
}.
```

Direct intended mapping:

| Kyriotēs-CSK2 | Formosa ML-KEM-768 |
| --- | --- |
| `pkey` | `publickey` |
| `skey` | `secretkey` |
| `ctkem` | `ciphertext` |
| `ss` | `sharedsecret` |
| `dkeypair` | distribution induced by `MLKEM_Op(SPEC_MODEL.RO.RO).kg` |
| `encap pk` | distribution induced by `MLKEM_Op(SPEC_MODEL.RO.RO).enc pk` |
| `dss` | `srand` / `SPEC_MODEL.dkey` |
| `decap sk ct` | `MLKEM_Op(SPEC_MODEL.RO.RO).dec sk ct` |

The local adapter skeleton mirrors the ROM adversary interface as
`B_FormosaROMCCA(A)(H)(O)`.  The wrapper forwards only:

```easycrypt
A.run(formosa_pk_to_csk2 pk,
      formosa_ct_to_csk2 c,
      formosa_ss_to_csk2 k)
```

It intentionally does not call Formosa's random oracle `H` or CCA decryption
oracle `O`.  This is the right shape for a CSK2 one-shot RoR adversary embedded
inside Formosa's richer IND-CCA theorem: oracle access is available at the
Formosa theorem boundary, but the CSK2 hybrid adversary does not need it.

## Mismatch Points

- Kyriotēs-CSK2 currently consumes a direct RoR statement:

  ```easycrypt
  `| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
     Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
  <= inv (2%r ^ 128)
  ```

- Formosa exposes a bit-guessing `CCA` theorem:

  ```easycrypt
  `| Pr[SPEC_MODEL.CCA(SPEC_MODEL.RO.RO, MLKEM_Op, A).main() @ &m : res]
     - 1%r / 2%r |
  <= ...
  ```

- The Formosa theorem has a concrete multi-term reduction bound, not a single
  `2^-128` numerical bound. Closing Kyriotēs-CSK2's current leaf requires an
  additional policy theorem or assumption showing the Formosa bound is at most
  `inv (2^128)` for the chosen query limits and primitive assumptions.

- Formosa adversaries are oracle-parameterized:

  ```easycrypt
  module type CCA_ADV (H : POracle, O : CCA_ORC) = {
    proc guess(pk : pkey, c : ciphertext, k : key) : bool
  }.
  ```

  Kyriotēs-CSK2's direct leaf adversary is not oracle-parameterized:

  ```easycrypt
  module type KEM_RoR_Adversary = {
    proc run(pk : pkey, ct_k : ctkem, ss_b : ss) : bool
  }.
  ```

- Formosa's game initializes and uses a random oracle. The adapter must preserve
  RO state and query-bound obligations when embedding a CSK2 RoR adversary.

## Adapter Work Items

1. Add EasyCrypt include paths for Formosa security/spec files and its
   `crypto-specs` submodule.
2. Connect Formosa's bit-guessing `SPEC_MODEL.CCA` theorem to the local
   `KemRorCcaBridge.ec` `RandomLR` bridge.
3. Define a Formosa adversary wrapper from `KEM_RoR_Adversary` to
   `SPEC_MODEL.CCA_ADV`.
4. Prove equivalence between Kyriotēs-CSK2's `Game_KEM_RoR_Real/Rand` and the
   corresponding Formosa left/right or CCA branches.
5. Add the concrete numeric step from Formosa's multi-term bound to
   `inv (2^128)` or weaken the Kyriotēs-CSK2 theorem to expose the full
   concrete Formosa bound.
