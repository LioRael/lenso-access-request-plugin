# Release process

This repository publishes four crates in dependency order:

1. `lenso-capability-access-request-requester`
2. `lenso-capability-access-request-admin`
3. `lenso-capability-access-request-worker`
4. `lenso-access-request-postgres-plugin`

Publication is manual-only from a clean, reviewed `main` checkout through
`.github/workflows/release-plz.yml`. A push may refresh a Release-plz PR but does
not publish. Live publication requires `main`, `live=true`, and literal
confirmation `publish`.

## Trusted Publisher

Configure one crates.io Trusted Publisher per crate:

- owner: `LioRael`
- repository: `lenso-access-request-plugin`
- workflow: `release-plz.yml`
- environment: unset

The workflow requests `id-token: write` only in the confirmed live job and has
no Cargo registry token fallback. Trusted Publishing cannot allocate a new
crate name. For the first release, allocate each unowned name in dependency
order with a temporary, tightly scoped crates.io token, revoke it immediately,
then use only OIDC for later releases.

## Required evidence

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
lenso-contract-codegen workspace check --manifest-path Cargo.toml
./scripts/check-public-packages.sh
./scripts/check-repository-boundary.sh
```

Run the real PostgreSQL acceptance command from
`docs/postgresql-operations.md`. Confirm `Cargo.lock` resolves Notification to
merged commit `b001dffea970789858499efa2049853d37bc3e0f`, Organization to
`9572afd465ba2f952b646ec16935c0274f66c82a`, Access Control to
`de1e1f1ec61232b13fc90a05f1cb4e3fc96ba420`, and Auth to
`b4a2f53df882ae51021aa3d5922d8ee41bf97c72`.
