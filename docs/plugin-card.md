# Plugin card: PostgreSQL Access Request

## Job

Let a known user request one pre-approved access bundle and let an authorized
reviewer decide it without granting RBAC authority to the request-facing API.

## Owns

- access-request records, exact target snapshots, reasons, deadlines, decisions,
  revisions, and audit activity;
- caller/actor/operation-scoped idempotency receipts;
- ordered Access Control effect and Notification intent ledgers;
- worker leases, fences, retry classification, and manual uncertainty evidence.

## Does not own

- Auth subjects or Actor assertion signing;
- organizations or membership;
- roles, permissions, policy evaluation, or role bindings;
- notification rendering, transport, or delivery status;
- application ingress, reviewer UI, or temporary-grant revocation.

## Required typed ports

- `lenso.secrets@1`
- `lenso.organization-directory@1`
- `lenso.organization-membership@1`
- `lenso.access-control@1`
- `lenso.access-control-admin@1`
- `lenso.notification.transactional@1` descriptor 1.1.0

## Failure policy

Business decisions commit independently of Notification acceptance. Access
Control runtime/unknown outcomes and expired post-dispatch leases become
terminal `unknown` effects and require `inspect_effect` plus `resolve_effect`.
No automatic replay crosses that boundary.
