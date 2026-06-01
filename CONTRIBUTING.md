# Contributing

I welcome all contribution attempts to this project under the MIT license. 

However all
Contributions to Kyriotēs-CSK2 must uphold high technical standards, including passing Rust idiom checks, updating formal Rocq/Coq proofs, and expanding Kani model checking for memory safety. 

Ethical guidelines strictly prohibit weakened primitives, hidden telemetry, or intellectual property violations, ensuring a secure and transparent cryptographic project.

Modifications to core cryptographic primitives require corresponding updates or new proofs in Rocq/Coq. The ./proofs/coq/check.sh script must pass cleanly.

New execution paths must be covered by Kani Rust verification harnesses to mathematically guarantee memory safety and boundary correctness.

On top of that, they must maintain concrete payload testing within the test harness, ensuring all tamper and rejection guards function as intended. 

## Ethical principles; Your [DO NOTS]

Do not introduce backdoor access mechanisms, weakened cryptographic primitives, or hidden logic.

Do not introduce telemetry, user tracking, or data collection mechanisms.

Do not submit un-original work or code not covered by a compatible open-source license. Always provide clear attribution for derivative works.

Do not submit new primitives, or roll out entirely new cryptography 

>Non intrusive Janoitoral organizational edits, non intrusive code syntax best practices, further proof work that correctly aligns with the current state of the project will take priority review. 

>Introducing new strenghtening mechanisms or execution paths will take secondary priority and larger time to review and more likelyhood of unacceptance. 

## Professional Behaviour within the projects perceptive bounds

Keep all discussions on issues, pull requests, and code reviews strictly focused on development, engineering, mathematics, and project goals.

Frame all feedback, critiques, and reviews around technical solutions, performance, safety, and architecture. Focus comments entirely on the code, never on the person.

Personal attacks, insults, and harassment are strictly prohibited. Treat all collaborators with professional courtesy.

Resolve technical differences through data, cryptographic theory, benchmarking, and formal proof verification rather than ideological arguments.

## How to Submit a Contribution

1. Review existing issues or open a new issue to discuss your proposed engineering changes.
2. Fork the repository and create a distinct feature branch.
3. Verify your work locally using the Rust test suite, Coq proof checkers, and Kani harnesses.
4. Open a pull request containing a clear description of your changes, your testing methodology, and how the changes impact the existing threat model.
5. Respond objectively to the technical feedback provided by project maintainers to finalize the merge process.


