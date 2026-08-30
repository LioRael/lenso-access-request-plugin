# Access Request context

This repository owns the removable PostgreSQL implementation for organization-scoped access requests. It does not own Organization membership, Access Control policy, Auth actor assertions, or Notification delivery.

The Access Control administrative dependency's stable Capability ID is `lenso.access-control-admin@1` (hyphen), as authored by the Access Control repository. The Notification dependency is pinned to merged commit `b001dffea970789858499efa2049853d37bc3e0f`, which adds the bounded access-request lifecycle operation to `lenso.notification.transactional@1`.
