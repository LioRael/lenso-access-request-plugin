# Security policy

Report suspected vulnerabilities privately to the Lenso maintainers. Do not
put database URLs, Actor assertions, notification recipients, lease tokens, or
organization policy details in a public issue.

## Boundary

- Requester and administrator operations require exact caller allowlists and an
  Auth-issued user Actor assertion bound to the exact Capability operation.
- Administrator operations additionally require active Organization membership
  and a separate Access Control decision for `access-request.read`,
  `access-request.decide`, or `access-request.recover`.
- Worker operations use a disjoint exact caller allowlist and never inherit an
  administrator Actor's ambient authority.
- The Plugin stores notification recipient routing data as PII, not as a
  credential. Restrict database and backup access accordingly. Generated
  request and lease-token `Debug` implementations redact sensitive values.
- Never reset a leased or `unknown` Access Control effect to `pending` directly.
  Resolve uncertain outcomes only after verifying the external Access Control
  state and recording a bounded evidence reference.
- Back up the owned schema and the Postgres Kit migration ledger together.

The Plugin does not accept arbitrary templates or HTML. Notification rendering
is owned by the bounded Transactional Notification operation; request reasons
and review notes never cross that Port.
