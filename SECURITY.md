# Security Policy

## Project Status

Kyriotēs-CSK2 is currently an experimental cryptographic construction.

It is becoming ready to be showcased, reviewed, audited, and battle-tested, but it still requires public audit, continued verification work, and independent security review before it should be trusted in production environments.

Until that process is complete, I do **not** recommend using Kyriotēs-CSK2 to protect production secrets, regulated data, irreversible access-control systems, or security-critical infrastructure.

The project has made significant verification progress, including Coq modeling, Rust implementation checks, fuzzing, tests, Kani proof lanes, and explicit proof-boundary documentation. Transparency append and Merkle owned-composition soundness is complete under explicit SHA-256 assumptions. Capability-tree non-empty witness soundness is mechanically refined within a scoped proof boundary. Encode/decode canonical round-trip equivalence is now evidenced by production-function Kani harnesses and Coq axiom-backed correspondence in `KyriotesCsk2RustCoqFormalCorrespondence.v`. Seal/open cryptographic semantic equivalence has been mechanically formalized via model contracts, mechanically proven implications, and Kani-backed axioms in that same file. Remaining future targets are computational game-based reductions: the two-gate opening hybrid reduction is formalized in `KyriotesCsk2TwoGateHybridReduction.v`; extending capability-tree witness refinement into a full computational binding reduction and adding concrete advantage accounting to the seal/open composition claims remain open.

## Supported Versions

Kyriotēs-CSK2 is still pre-stable. Security fixes are expected to target the latest published crate version and the current `main` branch unless otherwise stated.

| Version | Status |
|---|---|
| `0.1.x` | Experimental / research preview |
| `< 0.1.0` | Unsupported |

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report suspected vulnerabilities privately by email:

**reeveskeefe@gmail.com**

Use the following link to open a prefilled email report:

<a href="mailto:reeveskeefe@gmail.com?subject=Kyriotes-CSK2%20Security%20Report&body=Security%20report%20for%20Kyriotes-CSK2%0A%0ASummary%3A%0A%0AAffected%20version%20or%20commit%3A%0A%0AAffected%20component%20or%20file%3A%0A%0AImpact%3A%0A%0ASteps%20to%20reproduce%3A%0A%0AExpected%20behavior%3A%0A%0AActual%20behavior%3A%0A%0AProof%20of%20concept%20or%20test%20case%3A%0A%0ASuggested%20fix%20if%20known%3A%0A%0AReporter%20name%20or%20handle%3A%0A%0ADisclosure%20preference%3A%0A">Submit a Kyriotēs-CSK2 vulnerability report by email</a>

If the email link does not work, copy and paste this template manually:

```text
Security report for Kyriotēs-CSK2

Summary:

Affected version or commit:

Affected component or file:

Impact:

Steps to reproduce:

Expected behavior:

Actual behavior:

Proof of concept or test case:

Suggested fix if known:

Reporter name or handle:

Disclosure preference:
```

## What to Report

Please report anything that could affect the confidentiality, integrity, verification correctness, or fail-closed behavior of Kyriotēs-CSK2.

Examples include:

- A way to open ciphertext without valid key material.
- A way to open ciphertext without valid authority evidence.
- A way to bypass capability checks, non-revocation checks, policy checks, epoch checks, or context binding.
- A case where raw caller-controlled data is treated as already verified.
- A panic, crash, or unsafe behavior caused by malformed input.
- Parser or decoder behavior that accepts malformed wire data as valid.
- A failure path that leaks plaintext, key material, wrapped DEKs, or sensitive internal state.
- A mismatch between documented proof boundaries and implementation behavior.
- A flaw in the verified-state boundary, authority verification flow, Kani harness assumptions, or fuzzing/test coverage.

## Current Security Boundary

Kyriotēs-CSK2 is designed around a two-gate opening predicate:

```text
Open succeeds ⇔ Key Gate · Authority Gate = 1
```

The key gate verifies that the opener has the correct cryptographic key material.

The authority gate verifies capability evidence, non-revocation evidence, rights, policy binding, epoch validity, transparency context, and transcript binding.

The value `1` is not an access code and is not user-supplied. It is the verifier-computed result of all required predicates passing. A correct implementation must derive this result internally from cryptographic verification, not accept it from caller-controlled input.

## Disclosure Process

I will try to acknowledge security reports as soon as possible.

For serious reports, please include enough detail to reproduce the issue locally. Minimal reproduction cases, failing tests, proof-of-concept inputs, or precise file/function references are very helpful.

I prefer coordinated disclosure. Please give reasonable time for triage and remediation before public disclosure.

## Out of Scope

The following are generally out of scope unless they demonstrate a direct security impact:

- Reports about the project being experimental.
- Missing production-readiness guarantees already documented in this policy.
- Social engineering or phishing.
- Denial-of-service reports that only affect a local developer machine without a security boundary impact.
- Reports requiring physical access to a developer’s machine.
- Issues caused by intentionally modifying the local source code to disable verification.

## Cryptographic Disclaimer

Kyriotēs-CSK2 is experimental cryptographic software.

Do not rely on it for production security until it has received substantial public review, independent audit, and further semantic verification. The project’s current verification work is meaningful, but it should not be interpreted as a complete proof of end-to-end cryptographic security.