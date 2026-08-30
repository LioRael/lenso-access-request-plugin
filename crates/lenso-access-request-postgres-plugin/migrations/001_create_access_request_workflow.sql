CREATE TABLE access_requests (
    request_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    requester_subject TEXT NOT NULL,
    requester_was_member BOOLEAN NOT NULL,
    bundle_id TEXT NOT NULL,
    role_mode TEXT NOT NULL CHECK (role_mode IN ('existing', 'managed')),
    role_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    scope_name TEXT,
    permissions JSONB NOT NULL,
    reason TEXT NOT NULL,
    recipient_address TEXT NOT NULL,
    recipient_display_name TEXT,
    recipient_locale TEXT NOT NULL CHECK (recipient_locale IN ('en', 'en-US')),
    request_fingerprint BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'provisioning', 'approved', 'denied', 'cancelled', 'expired', 'intervention_required')),
    effect_status TEXT NOT NULL CHECK (effect_status IN ('none', 'pending', 'leased', 'succeeded', 'failed', 'unknown')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    decided_by TEXT,
    decision_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX access_requests_active_target_idx
    ON access_requests (organization_id, requester_subject, bundle_id, scope_kind, scope_id)
    WHERE status IN ('pending', 'provisioning', 'intervention_required');
CREATE INDEX access_requests_requester_page_idx
    ON access_requests (organization_id, requester_subject, created_at DESC, request_id DESC);
CREATE INDEX access_requests_admin_page_idx
    ON access_requests (organization_id, created_at DESC, request_id DESC);
CREATE INDEX access_requests_expiry_idx
    ON access_requests (expires_at, request_id)
    WHERE status = 'pending';

CREATE TABLE access_request_effects (
    effect_id UUID PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES access_requests(request_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 8),
    kind TEXT NOT NULL CHECK (kind IN ('create_role', 'set_role_permissions', 'assign_role')),
    request_digest BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'succeeded', 'failed', 'unknown')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    automatic_retry_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    lease_token UUID,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    fence BIGINT NOT NULL DEFAULT 0 CHECK (fence >= 0),
    error_code TEXT,
    policy_revision TEXT,
    evidence_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (request_id, sequence)
);

CREATE INDEX access_request_effects_due_idx
    ON access_request_effects (status, request_id, sequence, updated_at)
    WHERE status IN ('pending', 'failed', 'leased');

CREATE TABLE access_request_notifications (
    notification_id UUID PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES access_requests(request_id) ON DELETE CASCADE,
    event TEXT NOT NULL CHECK (event IN ('submitted', 'approved', 'denied', 'expiring')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'accepted', 'failed')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    lease_token UUID,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    fence BIGINT NOT NULL DEFAULT 0 CHECK (fence >= 0),
    due_at TIMESTAMPTZ NOT NULL,
    error_code TEXT,
    intent_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (request_id, event)
);

CREATE INDEX access_request_notifications_due_idx
    ON access_request_notifications (due_at, notification_id)
    WHERE status IN ('pending', 'failed', 'leased');

CREATE TABLE access_request_commands (
    caller_instance TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('started', 'completed')),
    response JSONB,
    request_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (caller_instance, actor_subject, operation, idempotency_key)
);

CREATE INDEX access_request_commands_request_idx
    ON access_request_commands (request_id, created_at);

CREATE TABLE access_request_activity (
    activity_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    request_id UUID NOT NULL REFERENCES access_requests(request_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    caller_instance TEXT NOT NULL,
    request_revision BIGINT NOT NULL CHECK (request_revision > 0),
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX access_request_activity_request_idx
    ON access_request_activity (request_id, created_at, activity_id);
