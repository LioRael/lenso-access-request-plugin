# PostgreSQL operations

## Setup and upgrade

Run `AccessRequestOperator::setup` once for a new owned schema. Run
`AccessRequestOperator::upgrade` from an operator-controlled release step before
activating a Plugin version with new migrations. Activation performs no DDL.

The database role needs ordinary DML on the owned schema at runtime. Do not give
the Plugin runtime role `CREATE DATABASE`, broad schema ownership, or access to
Organization/Auth/Access Control schemas.

## Backup and restore

Back up these tables and the Postgres Kit migration ledger consistently:

- `access_requests`
- `access_request_effects`
- `access_request_notifications`
- `access_request_commands`
- `access_request_activity`

The schema contains reasons, review notes, actor subjects, and notification
recipient PII. Apply the same retention and access controls as the product's
organization audit data.

After restore, activate against the restored schema and verify that the
migration ledger matches the binary. Do not delete command receipts: they are
part of caller/actor/operation idempotency.

## Uncertain Access Control effects

An effect becomes `unknown` after a runtime/unknown dependency outcome or when
its post-dispatch lease expires. Automatic workers must leave it untouched.

1. Use the Admin `inspect_effect` operation; do not query or mutate the table
   from an application path.
2. Inspect the exact role definition and subject binding in the authoritative
   Access Control implementation.
3. Record an external, non-secret evidence reference.
4. Call `resolve_effect` with the effect's current revision and either
   `succeeded` or `failed`.
5. If resolved succeeded, the next ordered effect becomes eligible. If it was
   the final effect, the request becomes `approved`. A failed resolution remains
   `intervention_required`.

Never treat `role already exists` for a managed role as success: the Plugin
cannot prove that an externally created role belongs to this request.

Access Control effects must be processed with a fresh user Actor assertion
covering the exact downstream Access Control Admin operation. The processing
subject must already hold the required scoped administration grant. An
unauthenticated or forbidden downstream response is known to occur before the
mutation and is therefore eligible only for an explicit retry with fresh
authority. Do not attach or persist Actor assertions in this database.

## Notification failures

Notification jobs use stable downstream idempotency and bounded retry attempts.
Their failure does not roll back a request or access grant. Investigate the
Notification Plugin delivery ledger for delivery state; this schema proves only
whether the intent was accepted.

## Acceptance test

The test role must be able to create and drop one UUID-named isolated database.

```sh
LENSO_ACCESS_REQUEST_TEST_DATABASE_URL=postgres://postgres:password@127.0.0.1:5432/postgres \
  cargo test --locked -p lenso-access-request-postgres-plugin \
  --features postgres-acceptance \
  postgres_restart_concurrency_cas_expiry_and_effect_fencing -- --nocapture
```

The suite drops its isolated database on success. If a test process is killed,
an operator may remove only databases with the exact
`lenso_access_request_test_<uuidhex>` name after checking active sessions.
