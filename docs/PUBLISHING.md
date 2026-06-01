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
4. In GitHub Actions, manually run the `Publish` workflow from the branch/commit you want to release.
5. Confirm the Publish workflow succeeds.

## Workflow behavior

- File: `.github/workflows/publish.yml`
- Trigger: manual run (`workflow_dispatch`) only
- Publish command: `cargo publish --locked`
