# ARC crate publishing

This repository publishes the crate package `ARCencryption` (library name `arc_core`) to crates.io.

## One-time setup

- Set the repository secret `CARGO_REGISTRY_TOKEN` with a valid crates.io API token.
- Keep the token scoped to publish rights only.

## Release steps

1. Update `Cargo.toml` version.
2. Run local preflight checks:

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo publish --dry-run --locked
```

3. Commit and push changes.
4. Create and push a tag in `vX.Y.Z` format that matches `Cargo.toml`:

```bash
git tag v0.1.1
git push origin v0.1.1
```

5. Confirm the Publish workflow succeeds.

## Workflow behavior

- File: `.github/workflows/publish.yml`
- Trigger: tag push matching `v*` or manual run
- Guardrail: fails if tag version does not match `Cargo.toml`
- Publish command: `cargo publish --locked`
