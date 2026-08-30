# ADR 0001: Keep Access Request policy independent

Status: accepted

## Decision

Access Request is a separate Plugin with three role Capabilities. It uses Auth
for exact Actor assertions, Organization for directory and membership truth,
Access Control for reviewer authorization and grant effects, and Notification
for bounded lifecycle intents. It does not copy RBAC tables or become an
Organization submodule.

Requestable bundles are immutable operator configuration. Each request freezes
the role, scope, and permission set; approval compares that snapshot to current
configuration before writing a durable effect plan. Existing roles are reset to
the exact configured permission set before binding.

## Consequences

- Request APIs cannot grant access directly.
- Products can replace the workflow without replacing Organization or Access
  Control.
- A non-idempotent/opaque Access Control outcome must stop automatic work and
  require evidence-backed resolution.
- Grant expiry is intentionally outside v1; request expiry is a decision
  deadline, not an automatic revocation policy.
