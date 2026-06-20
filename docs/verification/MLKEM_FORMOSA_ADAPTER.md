# ML-KEM Formosa Adapter Plan

This repository vendors the Formosa ML-KEM EasyCrypt development as:

```text
third_party/formosa-mlkem
```

The intended external theorem target is:

```text
third_party/formosa-mlkem/proof/spec/MLKEMSecurity768.ec
```

Relevant Formosa declarations:

```text
SPEC_MODEL.CCA(SPEC_MODEL.RO.RO, MLKEM_Op, A).main
mlkem_spec_security_pre
mlkem_spec_security
```

`mlkem_spec_security` proves an IND-CCA bound for the FIPS 203 ML-KEM-768
specification, under MLWE, PRG/PRF, correctness-failure, query-count, and
losslessness side conditions. It is not a direct theorem of the shape used by
CSK2:

```easycrypt
`| Pr[Game_KEM_RoR_Real(A).main() @ &m : res] -
   Pr[Game_KEM_RoR_Rand(A).main() @ &m : res] |
<= inv (2%r ^ 128)
```

So `mlkem768_ror_secure` cannot be replaced by a one-line `exact
mlkem_spec_security`. The adapter has three required steps.

## Step 1: Type And Operator Mapping

Map Formosa ML-KEM-768 types to the CSK2 abstract boundary:

```text
Formosa publickey      -> pkey
Formosa secretkey      -> skey
Formosa ciphertext     -> ctkem
Formosa sharedsecret   -> ss
Formosa MLKEM_Op.kg    -> dkeypair
Formosa MLKEM_Op.enc   -> encap
Formosa sharedsecret distribution -> dss
```

The mapping should be implemented in an EasyCrypt adapter file only after the
Formosa include paths are available in CI. Formosa currently depends on nested
submodules including `crypto-specs`, `jasmin`, and `formosa-keccak`, and its
`easycrypt.project` uses include namespaces not present in this repository's
minimal EasyCrypt Docker setup.

## Step 2: Game Conversion

Formosa's theorem is stated over a ROM IND-CCA game:

```easycrypt
SPEC_MODEL.CCA(SPEC_MODEL.RO.RO, MLKEM_Op, A).main
```

CSK2 consumes direct real-or-random games:

```easycrypt
Game_KEM_RoR_Real(A).main
Game_KEM_RoR_Rand(A).main
```

The adapter must prove a bit-guessing-to-RoR conversion with the correct factor
accounting, then align the Formosa CCA adversary interface with CSK2's
`KEM_RoR_Adversary`.

## Step 3: Concrete Bound Specialization

Formosa's theorem gives a symbolic bound involving:

```text
failprob
hsadv
prfadv
MLWE advantages
query-count terms
message-space terms
```

To prove CSK2's current leaf:

```easycrypt
mlkem768_ror_secure <= 2^-128
```

we need a specialization lemma showing that the chosen ML-KEM-768 parameter
instantiation and adversary class make the Formosa symbolic bound no larger
than `inv (2^128)`. Without that specialization, replacing the axiom would
overclaim what the imported theorem proves.

## Current Status

`KemIndCca2.ec` has been narrowed so the only KEM security axiom left is:

```easycrypt
mlkem768_ror_secure
```

`kem_csk2_ror_secure` is a proved wrapper over that leaf. The local CSK2 KEM
game plumbing is complete; the remaining work is external proof integration and
bound specialization.
