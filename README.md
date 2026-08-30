# Lenso Access Request Plugin

Add a reviewable, organization-scoped access-request workflow without moving
Organization, Auth, Access Control, or Notification policy into one module.
Requesters submit one operator-approved permission bundle; reviewers approve or
deny it; a fenced worker applies the exact role definition and binding through
Access Control.

## Capabilities

| Capability | Operations | Intended caller |
| --- | --- | --- |
| `lenso.access-request.requester@1` | `create`, `get`, `list`, `cancel` | product/API ingress with an exact user Actor assertion |
| `lenso.access-request.admin@1` | `get_request`, `list_requests`, `approve`, `deny`, `inspect_effect`, `resolve_effect` | review UI/API with organization membership and independent Access Control permission |
| `lenso.access-request.worker@1` | `claim_due`, `process`, `expire`, `retry` | one exact worker Instance allowlist |

The implementation Plugin is `lenso.access-request.postgres`, with root slot
`access-requests`. All three contracts are portable and use checked generated
Rust projections.

## Configuration

```json
{
  "schema": "access_request",
  "database_url_secret": "access-request/database-url",
  "auth_issuer": "auth.users",
  "auth_assertion_public_key": "<base64 Ed25519 public key>",
  "requester_callers": ["app.access-request-api"],
  "admin_callers": ["app.access-request-admin"],
  "worker_callers": ["app.access-request-worker"],
  "requestable_bundles": [
    {
      "bundle_id": "project-reader",
      "role_mode": "existing",
      "role_id": "project_reader",
      "role_name": "Project reader",
      "scope_kind": "project",
      "permissions": ["project.read"],
      "allow_non_members": false
    },
    {
      "bundle_id": "organization-guest",
      "role_mode": "managed",
      "role_id": "access_request_guest",
      "role_name": "Guest",
      "scope_kind": "organization",
      "permissions": ["organization.read"],
      "allow_non_members": true
    }
  ]
}
```

Bundle permissions must be sorted and unique. The submitted request stores the
exact role, scope, and permission snapshot. Approval fails closed if that
snapshot no longer matches immutable Plugin configuration. For an existing
role, the worker calls `set_role_permissions` before `assign_role`; for a
managed role it calls `create_role`, `set_role_permissions`, then
`assign_role`. This prevents approval from silently granting a broader
configured role. Because `existing` deliberately replaces that role's complete
permission set, point it only at a role dedicated to this bundle; configuration
rejects two bundles that target the same scope-kind/role pair.

## Membership rules

- An active organization member may request an additional configured bundle on
  the bundle's configured scope kind.
- A non-member may request only a bundle with `allow_non_members=true`, and
  only at the exact organization root scope (`kind=organization`,
  `id=organization_id`).
- This Plugin does not create Organization membership. A non-member binding is
  useful only where the consuming product intentionally recognizes an external
  subject through Access Control.
- If an active member already has every permission in the requested bundle,
  creation returns `access_already_granted`.

## State and side effects

`pending` requests may be denied, cancelled, or expired. Approval first commits
`provisioning` and a durable, ordered effect plan; it does not report the grant
as complete. Only successful Access Control effects transition the request to
`approved`.

Each effect has a lease token and monotonic fence. A known, pre-effect rejection
may be explicitly retried. A runtime error, unknown domain response, or expired
lease after dispatch is recorded as `unknown`, moves the request to
`intervention_required`, and is never automatically dispatched again. An
authorized reviewer must inspect and resolve that exact effect with an external
evidence reference.

Access Control Admin independently requires a live Auth Actor assertion for
each mutation. Therefore a `process` invocation for an `access_effect` must
carry a user assertion whose audience includes the exact downstream
`lenso.access-control-admin@1` operation and whose subject holds the relevant
Access Control administration grant. A missing or denied authority is a known,
pre-effect failure: it may be retried explicitly with fresh authority, but is
never looped automatically. Notification jobs need only the exact worker caller.

The underlying `lenso.access-control-admin@1` contract has no caller-supplied
idempotency key or read-back operation, so this terminal uncertainty seam is
intentional. It preserves at-most-one automatic dispatch when an external
outcome cannot be proved.

## Notifications and deadlines

The Plugin durably schedules `submitted`, `approved`, `denied`, and `expiring`
intents through `lenso.notification.transactional@1` 1.1. Notification
acceptance is not business completion and delivery failure never rolls back a
request decision or grant. The stable key is
`access-request:<request_id>:<event>`; reasons and reviewer notes never enter a
notification payload.

`expires_at` is the decision deadline for a pending request. The `expiring`
intent is due before that deadline, and `expire` fails unless the deadline has
passed. v1 does not model a time-limited approved grant or revoke an approved
role binding automatically; products that need temporary grants should add a
separate grant-lifecycle Capability rather than reinterpret this field.

## PostgreSQL setup

DDL is operator-managed. Activation only validates the authored migration
ledger and opens the owned schema.

```rust,no_run
use lenso_access_request_postgres_plugin::AccessRequestOperator;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
AccessRequestOperator::setup(
    "postgres://postgres@127.0.0.1:5432/app",
    "access_request",
).await?;
# Ok(())
# }
```

See `docs/postgresql-operations.md` for upgrade, backup, and intervention
procedures. The database URL is resolved through `lenso.secrets@1`; it is never
part of Plugin configuration or diagnostics.

## Validation

```sh
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo fmt --all -- --check
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check --locked --workspace --all-targets --all-features
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test --locked --workspace --all-targets
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
lenso-contract-codegen workspace check --manifest-path Cargo.toml
./scripts/check-public-packages.sh
./scripts/check-repository-boundary.sh
```
