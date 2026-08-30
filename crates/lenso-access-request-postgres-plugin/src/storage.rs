use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow, types::Json};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct RequestRecord {
    pub(crate) request_id: Uuid,
    pub(crate) organization_id: String,
    pub(crate) requester_subject: String,
    pub(crate) requester_was_member: bool,
    pub(crate) bundle_id: String,
    pub(crate) role_mode: String,
    pub(crate) role_id: String,
    pub(crate) role_name: String,
    pub(crate) scope_kind: String,
    pub(crate) scope_id: String,
    pub(crate) scope_name: Option<String>,
    pub(crate) permissions: Vec<String>,
    pub(crate) reason: String,
    pub(crate) recipient_address: String,
    pub(crate) recipient_display_name: Option<String>,
    pub(crate) recipient_locale: String,
    pub(crate) status: String,
    pub(crate) effect_status: String,
    #[serde(with = "decimal_i64")]
    pub(crate) revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) decided_by: Option<String>,
    pub(crate) decision_note: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EffectRecord {
    pub(crate) effect_id: Uuid,
    pub(crate) request_id: Uuid,
    pub(crate) sequence: i32,
    pub(crate) kind: String,
    pub(crate) status: String,
    #[serde(with = "decimal_i64")]
    pub(crate) revision: i64,
    pub(crate) attempts: i32,
    pub(crate) automatic_retry_allowed: bool,
    pub(crate) error_code: Option<String>,
    pub(crate) policy_revision: Option<String>,
    pub(crate) evidence_reference: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) lease_until: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct JobRecord {
    pub(crate) job_id: Uuid,
    pub(crate) request_id: Uuid,
    pub(crate) organization_id: String,
    pub(crate) kind: String,
    pub(crate) event_or_effect: String,
    #[serde(with = "decimal_i64")]
    pub(crate) fence: i64,
    pub(crate) lease_token: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) lease_until: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProcessResult {
    pub(crate) request_id: Uuid,
    pub(crate) request_status: String,
    #[serde(with = "decimal_i64")]
    pub(crate) request_revision: i64,
    pub(crate) job_status: String,
    pub(crate) automatic_retry_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProcessStart {
    Execute,
    Replay(ProcessResult),
}

#[derive(Clone, Debug)]
pub(crate) enum ClaimedWork {
    Effect {
        job: JobRecord,
        effect: EffectRecord,
        request: RequestRecord,
    },
    Notification {
        job: JobRecord,
        event: String,
        request: RequestRecord,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Cursor {
    pub(crate) created_at: OffsetDateTime,
    pub(crate) request_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct CreateInput<'a> {
    pub(crate) caller: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) idempotency_key: &'a str,
    pub(crate) request_hash: &'a [u8],
    pub(crate) fingerprint: &'a [u8],
    pub(crate) organization_id: &'a str,
    pub(crate) requester_was_member: bool,
    pub(crate) bundle_id: &'a str,
    pub(crate) role_mode: &'a str,
    pub(crate) role_id: &'a str,
    pub(crate) role_name: &'a str,
    pub(crate) scope_kind: &'a str,
    pub(crate) scope_id: &'a str,
    pub(crate) scope_name: Option<&'a str>,
    pub(crate) permissions: &'a [String],
    pub(crate) reason: &'a str,
    pub(crate) recipient_address: &'a str,
    pub(crate) recipient_display_name: Option<&'a str>,
    pub(crate) recipient_locale: &'a str,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) expiring_lead_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct CreateResult {
    pub(crate) request: RequestRecord,
    pub(crate) created: bool,
    pub(crate) merged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    NotFound,
    EffectNotFound,
    RevisionConflict,
    IdempotencyConflict,
    InvalidTransition,
    ActiveRequestConflict,
    RequestExpired,
    RequestNotExpired,
    LeaseLost,
    OperationInProgress,
    EffectUnknown,
    RetryNotAllowed,
    EffectNotUncertain,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("stored Access Request data is invalid: {detail}")]
    InvalidStoredData { detail: String },
    #[error("Access Request command serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn create_request(
    postgres: &OwnedPostgres,
    input: &CreateInput<'_>,
) -> Result<Result<CreateResult, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access request creation").await?;
    advisory_lock(
        &mut transaction,
        &format!(
            "target|{}|{}|{}|{}|{}",
            input.organization_id, input.actor, input.bundle_id, input.scope_kind, input.scope_id
        ),
    )
    .await?;
    if let Some(replay) = command_replay::<CreateResult>(
        &mut transaction,
        input.caller,
        input.actor,
        "create",
        input.idempotency_key,
        input.request_hash,
    )
    .await?
    {
        let replay = match replay {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        };
        commit(transaction, "commit access request creation replay").await?;
        return Ok(Ok(replay));
    }

    let existing = sqlx::query(
        "SELECT request_id,request_fingerprint FROM access_requests WHERE organization_id=$1 AND requester_subject=$2 AND bundle_id=$3 AND scope_kind=$4 AND scope_id=$5 AND status IN ('pending','provisioning','intervention_required') FOR UPDATE",
    )
    .bind(input.organization_id)
    .bind(input.actor)
    .bind(input.bundle_id)
    .bind(input.scope_kind)
    .bind(input.scope_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("find active access request", source))?;
    if let Some(existing) = existing {
        let fingerprint = existing
            .try_get::<Vec<u8>, _>("request_fingerprint")
            .map_err(|error| invalid_column("request_fingerprint", error))?;
        if fingerprint != input.fingerprint {
            return Ok(Err(DomainFailure::ActiveRequestConflict));
        }
        let request_id = existing
            .try_get::<Uuid, _>("request_id")
            .map_err(|error| invalid_column("request_id", error))?;
        let result = CreateResult {
            request: load_request_tx(&mut transaction, request_id).await?,
            created: false,
            merged: true,
        };
        insert_command(
            &mut transaction,
            input.caller,
            input.actor,
            "create",
            input.idempotency_key,
            input.request_hash,
            Some(request_id),
            &result,
        )
        .await?;
        commit(transaction, "commit merged access request").await?;
        return Ok(Ok(result));
    }

    let request_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    sqlx::query(
        "INSERT INTO access_requests(request_id,organization_id,requester_subject,requester_was_member,bundle_id,role_mode,role_id,role_name,scope_kind,scope_id,scope_name,permissions,reason,recipient_address,recipient_display_name,recipient_locale,request_fingerprint,status,effect_status,revision,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'pending','none',1,$18,$19,$19)",
    )
    .bind(request_id)
    .bind(input.organization_id)
    .bind(input.actor)
    .bind(input.requester_was_member)
    .bind(input.bundle_id)
    .bind(input.role_mode)
    .bind(input.role_id)
    .bind(input.role_name)
    .bind(input.scope_kind)
    .bind(input.scope_id)
    .bind(input.scope_name)
    .bind(Json(input.permissions))
    .bind(input.reason)
    .bind(input.recipient_address)
    .bind(input.recipient_display_name)
    .bind(input.recipient_locale)
    .bind(input.fingerprint)
    .bind(input.expires_at)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("insert access request", source))?;

    insert_notification(&mut transaction, request_id, "submitted", now).await?;
    let expiring_at = input.expires_at - Duration::seconds(input.expiring_lead_seconds);
    insert_notification(
        &mut transaction,
        request_id,
        "expiring",
        expiring_at.max(now),
    )
    .await?;
    insert_activity(
        &mut transaction,
        input.organization_id,
        request_id,
        "request.submitted",
        input.actor,
        input.caller,
        1,
        json!({"bundle_id": input.bundle_id, "scope_kind": input.scope_kind, "scope_id": input.scope_id, "requester_was_member": input.requester_was_member}),
    )
    .await?;
    let result = CreateResult {
        request: load_request_tx(&mut transaction, request_id).await?,
        created: true,
        merged: false,
    };
    insert_command(
        &mut transaction,
        input.caller,
        input.actor,
        "create",
        input.idempotency_key,
        input.request_hash,
        Some(request_id),
        &result,
    )
    .await?;
    commit(transaction, "commit access request creation").await?;
    Ok(Ok(result))
}

pub(crate) async fn get_request(
    postgres: &OwnedPostgres,
    organization_id: &str,
    request_id: Uuid,
) -> Result<Option<RequestRecord>, StorageError> {
    let row =
        sqlx::query("SELECT * FROM access_requests WHERE request_id=$1 AND organization_id=$2")
            .bind(request_id)
            .bind(organization_id)
            .fetch_optional(postgres.pool())
            .await
            .map_err(|source| database("get access request", source))?;
    row.map(|row| request_from_row(&row)).transpose()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn list_requests(
    postgres: &OwnedPostgres,
    organization_id: &str,
    requester_subject: Option<&str>,
    status: Option<&str>,
    bundle_id: Option<&str>,
    cursor: Option<&Cursor>,
    limit: i64,
) -> Result<(Vec<RequestRecord>, Option<Cursor>), StorageError> {
    let mut rows = sqlx::query(
        "SELECT * FROM access_requests WHERE organization_id=$1 AND ($2::TEXT IS NULL OR requester_subject=$2) AND ($3::TEXT IS NULL OR status=$3) AND ($4::TEXT IS NULL OR bundle_id=$4) AND ($5::TIMESTAMPTZ IS NULL OR (created_at,request_id)<($5,$6)) ORDER BY created_at DESC,request_id DESC LIMIT $7",
    )
    .bind(organization_id)
    .bind(requester_subject)
    .bind(status)
    .bind(bundle_id)
    .bind(cursor.map(|value| value.created_at))
    .bind(cursor.map(|value| value.request_id))
    .bind(limit + 1)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list access requests", source))?;
    let has_more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        rows.pop();
    }
    let records = rows
        .iter()
        .map(request_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let next = has_more
        .then(|| records.last())
        .flatten()
        .map(|record| Cursor {
            created_at: record.created_at,
            request_id: record.request_id,
        });
    Ok((records, next))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn cancel_request(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    expected_revision: i64,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    mutate_pending(
        postgres,
        caller,
        actor,
        "cancel",
        idempotency_key,
        request_hash,
        organization_id,
        request_id,
        expected_revision,
        "cancelled",
        None,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn deny_request(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    expected_revision: i64,
    note: Option<&str>,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    mutate_pending(
        postgres,
        caller,
        actor,
        "deny",
        idempotency_key,
        request_hash,
        organization_id,
        request_id,
        expected_revision,
        "denied",
        note,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn expire_request(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    expected_revision: i64,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access request expiry").await?;
    if let Some(replay) = command_replay::<RequestRecord>(
        &mut transaction,
        caller,
        "$worker",
        "expire",
        idempotency_key,
        request_hash,
    )
    .await?
    {
        let replay = match replay {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        };
        commit(transaction, "commit access request expiry replay").await?;
        return Ok(Ok(replay));
    }
    let request = lock_request(&mut transaction, organization_id, request_id).await?;
    let Some(request) = request else {
        return Ok(Err(DomainFailure::NotFound));
    };
    if request.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if request.status != "pending" {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    if request.expires_at > OffsetDateTime::now_utc() {
        return Ok(Err(DomainFailure::RequestNotExpired));
    }
    let revision = request.revision + 1;
    sqlx::query("UPDATE access_requests SET status='expired',revision=$2,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
        .bind(request_id)
        .bind(revision)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("expire access request", source))?;
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        "request.expired",
        "$worker",
        caller,
        revision,
        json!({}),
    )
    .await?;
    let result = load_request_tx(&mut transaction, request_id).await?;
    insert_command(
        &mut transaction,
        caller,
        "$worker",
        "expire",
        idempotency_key,
        request_hash,
        Some(request_id),
        &result,
    )
    .await?;
    commit(transaction, "commit access request expiry").await?;
    Ok(Ok(result))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn approve_request(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    expected_revision: i64,
    note: Option<&str>,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access request approval").await?;
    if let Some(replay) = command_replay::<RequestRecord>(
        &mut transaction,
        caller,
        actor,
        "approve",
        idempotency_key,
        request_hash,
    )
    .await?
    {
        let replay = match replay {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        };
        commit(transaction, "commit access request approval replay").await?;
        return Ok(Ok(replay));
    }
    let request = lock_request(&mut transaction, organization_id, request_id).await?;
    let Some(request) = request else {
        return Ok(Err(DomainFailure::NotFound));
    };
    if request.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if request.status != "pending" {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    if request.expires_at <= OffsetDateTime::now_utc() {
        return Ok(Err(DomainFailure::RequestExpired));
    }
    let revision = request.revision + 1;
    sqlx::query("UPDATE access_requests SET status='provisioning',effect_status='pending',decided_by=$2,decision_note=$3,revision=$4,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
        .bind(request_id)
        .bind(actor)
        .bind(note)
        .bind(revision)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("record access request approval", source))?;

    let kinds: &[&str] = if request.role_mode == "managed" {
        &["create_role", "set_role_permissions", "assign_role"]
    } else {
        // Existing roles are made exact immediately before binding. This prevents a stale or
        // expanded role definition from being granted silently.
        &["set_role_permissions", "assign_role"]
    };
    for (index, kind) in kinds.iter().enumerate() {
        let mut digest = Sha256::new();
        digest.update(request_hash);
        digest.update(kind.as_bytes());
        digest.update(request.role_id.as_bytes());
        digest.update(request.scope_kind.as_bytes());
        digest.update(request.scope_id.as_bytes());
        digest.update(request.requester_subject.as_bytes());
        for permission in &request.permissions {
            digest.update(permission.as_bytes());
            digest.update([0]);
        }
        sqlx::query("INSERT INTO access_request_effects(effect_id,request_id,sequence,kind,request_digest,status,revision) VALUES($1,$2,$3,$4,$5,'pending',1)")
            .bind(Uuid::new_v4())
            .bind(request_id)
            .bind(i32::try_from(index + 1).unwrap_or(i32::MAX))
            .bind(*kind)
            .bind(digest.finalize().to_vec())
            .execute(&mut *transaction)
            .await
            .map_err(|source| database("plan access-control effect", source))?;
    }
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        "request.approved_for_provisioning",
        actor,
        caller,
        revision,
        json!({"effect_count": kinds.len()}),
    )
    .await?;
    let result = load_request_tx(&mut transaction, request_id).await?;
    insert_command(
        &mut transaction,
        caller,
        actor,
        "approve",
        idempotency_key,
        request_hash,
        Some(request_id),
        &result,
    )
    .await?;
    commit(transaction, "commit access request approval").await?;
    Ok(Ok(result))
}

#[allow(clippy::too_many_arguments)]
async fn mutate_pending(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    expected_revision: i64,
    next_status: &str,
    note: Option<&str>,
    require_owner: bool,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access request mutation").await?;
    if let Some(replay) = command_replay::<RequestRecord>(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        request_hash,
    )
    .await?
    {
        let replay = match replay {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        };
        commit(transaction, "commit access request mutation replay").await?;
        return Ok(Ok(replay));
    }
    let request = lock_request(&mut transaction, organization_id, request_id).await?;
    let Some(request) = request else {
        return Ok(Err(DomainFailure::NotFound));
    };
    if require_owner && request.requester_subject != actor {
        return Ok(Err(DomainFailure::NotFound));
    }
    if request.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if request.status != "pending" {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    if request.expires_at <= OffsetDateTime::now_utc() {
        return Ok(Err(DomainFailure::RequestExpired));
    }
    let revision = request.revision + 1;
    sqlx::query("UPDATE access_requests SET status=$2,decided_by=CASE WHEN $2='denied' THEN $3 ELSE decided_by END,decision_note=CASE WHEN $2='denied' THEN $4 ELSE decision_note END,revision=$5,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
        .bind(request_id)
        .bind(next_status)
        .bind(actor)
        .bind(note)
        .bind(revision)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("mutate pending access request", source))?;
    if next_status == "denied" {
        insert_notification(
            &mut transaction,
            request_id,
            "denied",
            OffsetDateTime::now_utc(),
        )
        .await?;
    }
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        if next_status == "denied" {
            "request.denied"
        } else {
            "request.cancelled"
        },
        actor,
        caller,
        revision,
        json!({}),
    )
    .await?;
    let result = load_request_tx(&mut transaction, request_id).await?;
    insert_command(
        &mut transaction,
        caller,
        actor,
        operation,
        idempotency_key,
        request_hash,
        Some(request_id),
        &result,
    )
    .await?;
    commit(transaction, "commit access request mutation").await?;
    Ok(Ok(result))
}

pub(crate) async fn inspect_effect(
    postgres: &OwnedPostgres,
    organization_id: &str,
    request_id: Uuid,
    effect_id: Uuid,
) -> Result<Option<EffectRecord>, StorageError> {
    let row = sqlx::query(
        "SELECT e.* FROM access_request_effects e JOIN access_requests r ON r.request_id=e.request_id WHERE e.effect_id=$1 AND e.request_id=$2 AND r.organization_id=$3",
    )
    .bind(effect_id)
    .bind(request_id)
    .bind(organization_id)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|source| database("inspect access request effect", source))?;
    row.map(|row| effect_from_row(&row)).transpose()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_effect(
    postgres: &OwnedPostgres,
    caller: &str,
    actor: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    effect_id: Uuid,
    expected_revision: i64,
    succeeded: bool,
    evidence_reference: &str,
) -> Result<Result<EffectRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access effect resolution").await?;
    if let Some(replay) = command_replay::<EffectRecord>(
        &mut transaction,
        caller,
        actor,
        "resolve_effect",
        idempotency_key,
        request_hash,
    )
    .await?
    {
        let replay = match replay {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        };
        commit(transaction, "commit access effect resolution replay").await?;
        return Ok(Ok(replay));
    }
    let Some(effect) =
        lock_effect(&mut transaction, organization_id, request_id, effect_id).await?
    else {
        return Ok(Err(DomainFailure::EffectNotFound));
    };
    if effect.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if effect.status != "unknown" {
        return Ok(Err(DomainFailure::EffectNotUncertain));
    }
    let status = if succeeded { "succeeded" } else { "failed" };
    sqlx::query("UPDATE access_request_effects SET status=$2,revision=revision+1,automatic_retry_allowed=FALSE,error_code=CASE WHEN $2='failed' THEN 'operator_resolved_failed' ELSE NULL END,evidence_reference=$3,lease_token=NULL,lease_owner=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE effect_id=$1")
        .bind(effect_id)
        .bind(status)
        .bind(evidence_reference)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("resolve uncertain access effect", source))?;
    if succeeded {
        advance_request_after_effect(&mut transaction, request_id, actor, caller).await?;
    } else {
        mark_request_intervention(&mut transaction, request_id, "failed").await?;
    }
    let request = load_request_tx(&mut transaction, request_id).await?;
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        if succeeded {
            "effect.resolved_succeeded"
        } else {
            "effect.resolved_failed"
        },
        actor,
        caller,
        request.revision,
        json!({"effect_id": effect_id.to_string(), "evidence_reference": evidence_reference}),
    )
    .await?;
    let result = load_effect_tx(&mut transaction, effect_id).await?;
    insert_command(
        &mut transaction,
        caller,
        actor,
        "resolve_effect",
        idempotency_key,
        request_hash,
        Some(request_id),
        &result,
    )
    .await?;
    commit(transaction, "commit access effect resolution").await?;
    Ok(Ok(result))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn retry_effect(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    effect_id: Uuid,
    expected_revision: i64,
) -> Result<Result<EffectRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access effect retry").await?;
    if let Some(replay) = command_replay::<EffectRecord>(
        &mut transaction,
        caller,
        "$worker",
        "retry",
        idempotency_key,
        request_hash,
    )
    .await?
    {
        let replay = match replay {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        };
        commit(transaction, "commit access effect retry replay").await?;
        return Ok(Ok(replay));
    }
    let Some(effect) =
        lock_effect(&mut transaction, organization_id, request_id, effect_id).await?
    else {
        return Ok(Err(DomainFailure::EffectNotFound));
    };
    if effect.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if effect.status == "unknown" {
        return Ok(Err(DomainFailure::EffectUnknown));
    }
    if effect.status != "failed" || !effect.automatic_retry_allowed {
        return Ok(Err(DomainFailure::RetryNotAllowed));
    }
    sqlx::query("UPDATE access_request_effects SET status='pending',revision=revision+1,automatic_retry_allowed=FALSE,error_code=NULL,lease_token=NULL,lease_owner=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE effect_id=$1")
        .bind(effect_id)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("retry access effect", source))?;
    sqlx::query("UPDATE access_requests SET status='provisioning',effect_status='pending',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1 AND status='intervention_required'")
        .bind(request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("resume access request provisioning", source))?;
    let request = load_request_tx(&mut transaction, request_id).await?;
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        "effect.retry_requested",
        "$worker",
        caller,
        request.revision,
        json!({"effect_id": effect_id.to_string()}),
    )
    .await?;
    let result = load_effect_tx(&mut transaction, effect_id).await?;
    insert_command(
        &mut transaction,
        caller,
        "$worker",
        "retry",
        idempotency_key,
        request_hash,
        Some(request_id),
        &result,
    )
    .await?;
    commit(transaction, "commit access effect retry").await?;
    Ok(Ok(result))
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn claim_due(
    postgres: &OwnedPostgres,
    caller: &str,
    worker_id: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    lease_seconds: i64,
    max_notification_attempts: i32,
) -> Result<Result<Option<JobRecord>, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access request work claim").await?;
    if let Some(replay) = command_replay::<Option<JobRecord>>(
        &mut transaction,
        caller,
        "$worker",
        "claim_due",
        idempotency_key,
        request_hash,
    )
    .await?
    {
        let replay = match replay {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        };
        commit(transaction, "commit access request work claim replay").await?;
        return Ok(Ok(replay));
    }

    // An expired access-effect lease is an unknown external outcome. It is never replayed.
    let uncertain = sqlx::query(
        "UPDATE access_request_effects SET status='unknown',revision=revision+1,automatic_retry_allowed=FALSE,error_code='lease_expired_after_dispatch',lease_token=NULL,lease_owner=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE status='leased' AND lease_until<=CURRENT_TIMESTAMP RETURNING request_id",
    )
    .fetch_all(&mut *transaction)
    .await
    .map_err(|source| database("terminate expired access effect leases", source))?;
    for row in uncertain {
        let request_id = row
            .try_get::<Uuid, _>("request_id")
            .map_err(|error| invalid_column("request_id", error))?;
        mark_request_intervention(&mut transaction, request_id, "unknown").await?;
    }

    let lease_token = Uuid::new_v4();
    let lease_until = OffsetDateTime::now_utc() + Duration::seconds(lease_seconds);
    let effect_row = sqlx::query(
        "SELECT e.effect_id,e.request_id,r.organization_id,e.kind FROM access_request_effects e JOIN access_requests r ON r.request_id=e.request_id WHERE e.status='pending' AND r.status='provisioning' AND NOT EXISTS (SELECT 1 FROM access_request_effects prior WHERE prior.request_id=e.request_id AND prior.sequence<e.sequence AND prior.status<>'succeeded') ORDER BY r.created_at,e.sequence FOR UPDATE OF e SKIP LOCKED LIMIT 1",
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("select due access effect", source))?;
    let job = if let Some(row) = effect_row {
        let job_id = row
            .try_get::<Uuid, _>("effect_id")
            .map_err(|error| invalid_column("effect_id", error))?;
        let request_id = row
            .try_get::<Uuid, _>("request_id")
            .map_err(|error| invalid_column("request_id", error))?;
        let organization_id = row
            .try_get::<String, _>("organization_id")
            .map_err(|error| invalid_column("organization_id", error))?;
        let event_or_effect = row
            .try_get::<String, _>("kind")
            .map_err(|error| invalid_column("kind", error))?;
        let updated = sqlx::query("UPDATE access_request_effects SET status='leased',revision=revision+1,attempts=attempts+1,lease_token=$2,lease_owner=$3,lease_until=$4,fence=fence+1,updated_at=CURRENT_TIMESTAMP WHERE effect_id=$1 RETURNING fence")
            .bind(job_id)
            .bind(lease_token)
            .bind(worker_id)
            .bind(lease_until)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|source| database("lease access effect", source))?;
        let fence = updated
            .try_get::<i64, _>("fence")
            .map_err(|error| invalid_column("fence", error))?;
        sqlx::query("UPDATE access_requests SET effect_status='leased',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
            .bind(request_id)
            .execute(&mut *transaction)
            .await
            .map_err(|source| database("mark request effect leased", source))?;
        Some(JobRecord {
            job_id,
            request_id,
            organization_id,
            kind: "access_effect".to_owned(),
            event_or_effect,
            fence,
            lease_token,
            lease_until,
        })
    } else {
        claim_notification(
            &mut transaction,
            worker_id,
            lease_token,
            lease_until,
            max_notification_attempts,
        )
        .await?
    };
    insert_command(
        &mut transaction,
        caller,
        "$worker",
        "claim_due",
        idempotency_key,
        request_hash,
        job.as_ref().map(|value| value.request_id),
        &job,
    )
    .await?;
    commit(transaction, "commit access request work claim").await?;
    Ok(Ok(job))
}

pub(crate) async fn load_claimed_work(
    postgres: &OwnedPostgres,
    job_id: Uuid,
    lease_token: Uuid,
    fence: i64,
) -> Result<Result<ClaimedWork, DomainFailure>, StorageError> {
    let effect = sqlx::query("SELECT e.*,r.organization_id FROM access_request_effects e JOIN access_requests r ON r.request_id=e.request_id WHERE e.effect_id=$1")
        .bind(job_id)
        .fetch_optional(postgres.pool())
        .await
        .map_err(|source| database("load claimed access effect", source))?;
    if let Some(row) = effect {
        if !lease_matches(&row, lease_token, fence)? {
            return Ok(Err(DomainFailure::LeaseLost));
        }
        let request_id = row
            .try_get::<Uuid, _>("request_id")
            .map_err(|error| invalid_column("request_id", error))?;
        let organization_id = row
            .try_get::<String, _>("organization_id")
            .map_err(|error| invalid_column("organization_id", error))?;
        let event_or_effect = row
            .try_get::<String, _>("kind")
            .map_err(|error| invalid_column("kind", error))?;
        let lease_until = row
            .try_get::<OffsetDateTime, _>("lease_until")
            .map_err(|error| invalid_column("lease_until", error))?;
        return Ok(Ok(ClaimedWork::Effect {
            job: JobRecord {
                job_id,
                request_id,
                organization_id,
                kind: "access_effect".to_owned(),
                event_or_effect,
                fence,
                lease_token,
                lease_until,
            },
            effect: effect_from_row(&row)?,
            request: get_request(
                postgres,
                &row.try_get::<String, _>("organization_id")
                    .map_err(|error| invalid_column("organization_id", error))?,
                request_id,
            )
            .await?
            .ok_or(StorageError::InvalidStoredData {
                detail: "effect references a missing request".to_owned(),
            })?,
        }));
    }
    let notification = sqlx::query("SELECT n.*,r.organization_id FROM access_request_notifications n JOIN access_requests r ON r.request_id=n.request_id WHERE n.notification_id=$1")
        .bind(job_id)
        .fetch_optional(postgres.pool())
        .await
        .map_err(|source| database("load claimed notification", source))?;
    let Some(row) = notification else {
        return Ok(Err(DomainFailure::NotFound));
    };
    if !lease_matches(&row, lease_token, fence)? {
        return Ok(Err(DomainFailure::LeaseLost));
    }
    let request_id = row
        .try_get::<Uuid, _>("request_id")
        .map_err(|error| invalid_column("request_id", error))?;
    let organization_id = row
        .try_get::<String, _>("organization_id")
        .map_err(|error| invalid_column("organization_id", error))?;
    let event = row
        .try_get::<String, _>("event")
        .map_err(|error| invalid_column("event", error))?;
    let lease_until = row
        .try_get::<OffsetDateTime, _>("lease_until")
        .map_err(|error| invalid_column("lease_until", error))?;
    let request = get_request(postgres, &organization_id, request_id)
        .await?
        .ok_or(StorageError::InvalidStoredData {
            detail: "notification references a missing request".to_owned(),
        })?;
    Ok(Ok(ClaimedWork::Notification {
        job: JobRecord {
            job_id,
            request_id,
            organization_id,
            kind: "notification".to_owned(),
            event_or_effect: event.clone(),
            fence,
            lease_token,
            lease_until,
        },
        event,
        request,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EffectOutcome {
    Succeeded {
        policy_revision: String,
    },
    Failed {
        error_code: String,
        retry_allowed: bool,
    },
    Unknown {
        error_code: String,
    },
}

pub(crate) async fn complete_effect(
    postgres: &OwnedPostgres,
    caller: &str,
    job_id: Uuid,
    lease_token: Uuid,
    fence: i64,
    outcome: &EffectOutcome,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin access effect completion").await?;
    let row = sqlx::query("SELECT e.*,r.organization_id FROM access_request_effects e JOIN access_requests r ON r.request_id=e.request_id WHERE e.effect_id=$1 FOR UPDATE OF e")
        .bind(job_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|source| database("lock completing access effect", source))?;
    let Some(row) = row else {
        return Ok(Err(DomainFailure::EffectNotFound));
    };
    if !lease_matches(&row, lease_token, fence)? {
        return Ok(Err(DomainFailure::LeaseLost));
    }
    let request_id = row
        .try_get::<Uuid, _>("request_id")
        .map_err(|error| invalid_column("request_id", error))?;
    let organization_id = row
        .try_get::<String, _>("organization_id")
        .map_err(|error| invalid_column("organization_id", error))?;
    let (status, retry_allowed, error_code, policy_revision) = match outcome {
        EffectOutcome::Succeeded { policy_revision } => {
            ("succeeded", false, None, Some(policy_revision.as_str()))
        }
        EffectOutcome::Failed {
            error_code,
            retry_allowed,
        } => ("failed", *retry_allowed, Some(error_code.as_str()), None),
        EffectOutcome::Unknown { error_code } => {
            ("unknown", false, Some(error_code.as_str()), None)
        }
    };
    sqlx::query("UPDATE access_request_effects SET status=$2,revision=revision+1,automatic_retry_allowed=$3,error_code=$4,policy_revision=$5,lease_token=NULL,lease_owner=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE effect_id=$1")
        .bind(job_id)
        .bind(status)
        .bind(retry_allowed)
        .bind(error_code)
        .bind(policy_revision)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("complete access effect", source))?;
    match outcome {
        EffectOutcome::Succeeded { .. } => {
            advance_request_after_effect(&mut transaction, request_id, "$worker", caller).await?;
        }
        EffectOutcome::Failed { .. } => {
            mark_request_intervention(&mut transaction, request_id, "failed").await?;
        }
        EffectOutcome::Unknown { .. } => {
            mark_request_intervention(&mut transaction, request_id, "unknown").await?;
        }
    }
    let request = load_request_tx(&mut transaction, request_id).await?;
    insert_activity(
        &mut transaction,
        &organization_id,
        request_id,
        match outcome {
            EffectOutcome::Succeeded { .. } => "effect.succeeded",
            EffectOutcome::Failed { .. } => "effect.failed",
            EffectOutcome::Unknown { .. } => "effect.outcome_unknown",
        },
        "$worker",
        caller,
        request.revision,
        json!({"effect_id": job_id.to_string(), "fence": fence.to_string(), "error_code": error_code}),
    )
    .await?;
    commit(transaction, "commit access effect completion").await?;
    Ok(Ok(request))
}

pub(crate) async fn complete_notification(
    postgres: &OwnedPostgres,
    job_id: Uuid,
    lease_token: Uuid,
    fence: i64,
    accepted_intent_id: Option<&str>,
    error_code: Option<&str>,
    retry_seconds: i64,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin notification intent completion").await?;
    let row = sqlx::query("SELECT n.*,r.organization_id FROM access_request_notifications n JOIN access_requests r ON r.request_id=n.request_id WHERE n.notification_id=$1 FOR UPDATE OF n")
        .bind(job_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|source| database("lock completing notification intent", source))?;
    let Some(row) = row else {
        return Ok(Err(DomainFailure::NotFound));
    };
    if !lease_matches(&row, lease_token, fence)? {
        return Ok(Err(DomainFailure::LeaseLost));
    }
    let request_id = row
        .try_get::<Uuid, _>("request_id")
        .map_err(|error| invalid_column("request_id", error))?;
    if let Some(intent_id) = accepted_intent_id {
        sqlx::query("UPDATE access_request_notifications SET status='accepted',revision=revision+1,intent_id=$2,error_code=NULL,lease_token=NULL,lease_owner=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE notification_id=$1")
            .bind(job_id)
            .bind(intent_id)
            .execute(&mut *transaction)
            .await
            .map_err(|source| database("accept notification intent", source))?;
    } else {
        sqlx::query("UPDATE access_request_notifications SET status='failed',revision=revision+1,error_code=$2,due_at=CURRENT_TIMESTAMP+($3::BIGINT*INTERVAL '1 second'),lease_token=NULL,lease_owner=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE notification_id=$1")
            .bind(job_id)
            .bind(error_code.unwrap_or("notification_rejected"))
            .bind(retry_seconds)
            .execute(&mut *transaction)
            .await
            .map_err(|source| database("record notification intent failure", source))?;
    }
    let request = load_request_tx(&mut transaction, request_id).await?;
    commit(transaction, "commit notification intent completion").await?;
    Ok(Ok(request))
}

async fn advance_request_after_effect(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    actor: &str,
    caller: &str,
) -> Result<(), StorageError> {
    let pending = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM access_request_effects WHERE request_id=$1 AND status<>'succeeded'",
    )
    .bind(request_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|source| database("count unfinished access effects", source))?;
    if pending == 0 {
        let row = sqlx::query("UPDATE access_requests SET status='approved',effect_status='succeeded',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1 RETURNING organization_id,revision")
            .bind(request_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|source| database("finalize approved access request", source))?;
        let organization_id = row
            .try_get::<String, _>("organization_id")
            .map_err(|error| invalid_column("organization_id", error))?;
        let revision = row
            .try_get::<i64, _>("revision")
            .map_err(|error| invalid_column("revision", error))?;
        insert_notification(
            transaction,
            request_id,
            "approved",
            OffsetDateTime::now_utc(),
        )
        .await?;
        insert_activity(
            transaction,
            &organization_id,
            request_id,
            "request.provisioned",
            actor,
            caller,
            revision,
            json!({}),
        )
        .await?;
    } else {
        sqlx::query("UPDATE access_requests SET status='provisioning',effect_status='pending',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
            .bind(request_id)
            .execute(&mut **transaction)
            .await
            .map_err(|source| database("advance access request provisioning", source))?;
    }
    Ok(())
}

async fn mark_request_intervention(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    effect_status: &str,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE access_requests SET status='intervention_required',effect_status=$2,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
        .bind(request_id)
        .bind(effect_status)
        .execute(&mut **transaction)
        .await
        .map_err(|source| database("mark access request intervention required", source))?;
    Ok(())
}

async fn claim_notification(
    transaction: &mut Transaction<'_, Postgres>,
    worker_id: &str,
    lease_token: Uuid,
    lease_until: OffsetDateTime,
    max_attempts: i32,
) -> Result<Option<JobRecord>, StorageError> {
    let row = sqlx::query(
        "SELECT n.notification_id,n.request_id,n.event,r.organization_id FROM access_request_notifications n JOIN access_requests r ON r.request_id=n.request_id WHERE n.attempts<$1 AND n.due_at<=CURRENT_TIMESTAMP AND (n.status IN ('pending','failed') OR (n.status='leased' AND n.lease_until<=CURRENT_TIMESTAMP)) AND ((n.event='submitted') OR (n.event='approved' AND r.status='approved') OR (n.event='denied' AND r.status='denied') OR (n.event='expiring' AND r.status='pending')) ORDER BY n.due_at,n.notification_id FOR UPDATE OF n SKIP LOCKED LIMIT 1",
    )
    .bind(max_attempts)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|source| database("select due access request notification", source))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let job_id = row
        .try_get::<Uuid, _>("notification_id")
        .map_err(|error| invalid_column("notification_id", error))?;
    let request_id = row
        .try_get::<Uuid, _>("request_id")
        .map_err(|error| invalid_column("request_id", error))?;
    let organization_id = row
        .try_get::<String, _>("organization_id")
        .map_err(|error| invalid_column("organization_id", error))?;
    let event = row
        .try_get::<String, _>("event")
        .map_err(|error| invalid_column("event", error))?;
    let updated = sqlx::query("UPDATE access_request_notifications SET status='leased',revision=revision+1,attempts=attempts+1,lease_token=$2,lease_owner=$3,lease_until=$4,fence=fence+1,updated_at=CURRENT_TIMESTAMP WHERE notification_id=$1 RETURNING fence")
        .bind(job_id)
        .bind(lease_token)
        .bind(worker_id)
        .bind(lease_until)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|source| database("lease access request notification", source))?;
    let fence = updated
        .try_get::<i64, _>("fence")
        .map_err(|error| invalid_column("fence", error))?;
    Ok(Some(JobRecord {
        job_id,
        request_id,
        organization_id,
        kind: "notification".to_owned(),
        event_or_effect: event,
        fence,
        lease_token,
        lease_until,
    }))
}

async fn insert_notification(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    event: &str,
    due_at: OffsetDateTime,
) -> Result<(), StorageError> {
    sqlx::query("INSERT INTO access_request_notifications(notification_id,request_id,event,status,revision,due_at) VALUES($1,$2,$3,'pending',1,$4) ON CONFLICT(request_id,event) DO NOTHING")
        .bind(Uuid::new_v4())
        .bind(request_id)
        .bind(event)
        .bind(due_at)
        .execute(&mut **transaction)
        .await
        .map_err(|source| database("schedule access request notification", source))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_activity(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    request_id: Uuid,
    kind: &str,
    actor: &str,
    caller: &str,
    revision: i64,
    evidence: Value,
) -> Result<(), StorageError> {
    sqlx::query("INSERT INTO access_request_activity(activity_id,organization_id,request_id,kind,actor_subject,caller_instance,request_revision,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::new_v4())
        .bind(organization_id)
        .bind(request_id)
        .bind(kind)
        .bind(actor)
        .bind(caller)
        .bind(revision)
        .bind(Json(evidence))
        .execute(&mut **transaction)
        .await
        .map_err(|source| database("append access request activity", source))?;
    Ok(())
}

async fn command_replay<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
) -> Result<Option<Result<T, DomainFailure>>, StorageError> {
    advisory_lock(
        transaction,
        &format!("command|{caller}|{actor}|{operation}|{idempotency_key}"),
    )
    .await?;
    let row = sqlx::query("SELECT request_hash,status,response FROM access_request_commands WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4")
        .bind(caller)
        .bind(actor)
        .bind(operation)
        .bind(idempotency_key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|source| database("read access request idempotency receipt", source))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_hash = row
        .try_get::<Vec<u8>, _>("request_hash")
        .map_err(|error| invalid_column("request_hash", error))?;
    if stored_hash != request_hash {
        return Ok(Some(Err(DomainFailure::IdempotencyConflict)));
    }
    let status = row
        .try_get::<String, _>("status")
        .map_err(|error| invalid_column("status", error))?;
    if status == "started" {
        return Ok(Some(Err(DomainFailure::OperationInProgress)));
    }
    let Json(response) = row
        .try_get::<Option<Json<Value>>, _>("response")
        .map_err(|error| invalid_column("response", error))?
        .ok_or_else(|| StorageError::InvalidStoredData {
            detail: "completed command is missing a response".to_owned(),
        })?;
    Ok(Some(Ok(serde_json::from_value(response)?)))
}

#[allow(clippy::too_many_arguments)]
async fn insert_command<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    actor: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    request_id: Option<Uuid>,
    response: &T,
) -> Result<(), StorageError> {
    sqlx::query("INSERT INTO access_request_commands(caller_instance,actor_subject,operation,idempotency_key,request_hash,status,response,request_id) VALUES($1,$2,$3,$4,$5,'completed',$6,$7)")
        .bind(caller)
        .bind(actor)
        .bind(operation)
        .bind(idempotency_key)
        .bind(request_hash)
        .bind(Json(serde_json::to_value(response)?))
        .bind(request_id)
        .execute(&mut **transaction)
        .await
        .map_err(|source| database("write access request idempotency receipt", source))?;
    Ok(())
}

pub(crate) async fn begin_process(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
) -> Result<Result<ProcessStart, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin worker process command").await?;
    advisory_lock(
        &mut transaction,
        &format!("command|{caller}|$worker|process|{idempotency_key}"),
    )
    .await?;
    let row = sqlx::query("SELECT request_hash,status,response FROM access_request_commands WHERE caller_instance=$1 AND actor_subject='$worker' AND operation='process' AND idempotency_key=$2")
        .bind(caller)
        .bind(idempotency_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|source| database("read worker process receipt", source))?;
    if let Some(row) = row {
        let stored_hash = row
            .try_get::<Vec<u8>, _>("request_hash")
            .map_err(|error| invalid_column("request_hash", error))?;
        if stored_hash != request_hash {
            return Ok(Err(DomainFailure::IdempotencyConflict));
        }
        let status = row
            .try_get::<String, _>("status")
            .map_err(|error| invalid_column("status", error))?;
        if status == "started" {
            return Ok(Err(DomainFailure::OperationInProgress));
        }
        let Json(value) = row
            .try_get::<Option<Json<Value>>, _>("response")
            .map_err(|error| invalid_column("response", error))?
            .ok_or_else(|| StorageError::InvalidStoredData {
                detail: "completed process command is missing its response".to_owned(),
            })?;
        let result = serde_json::from_value(value)?;
        commit(transaction, "commit worker process replay").await?;
        return Ok(Ok(ProcessStart::Replay(result)));
    }
    sqlx::query("INSERT INTO access_request_commands(caller_instance,actor_subject,operation,idempotency_key,request_hash,status,response,request_id) VALUES($1,'$worker','process',$2,$3,'started',NULL,NULL)")
        .bind(caller)
        .bind(idempotency_key)
        .bind(request_hash)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("start worker process command", source))?;
    commit(transaction, "commit worker process start").await?;
    Ok(Ok(ProcessStart::Execute))
}

pub(crate) async fn finish_process(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    result: &ProcessResult,
) -> Result<(), StorageError> {
    let changed = sqlx::query("UPDATE access_request_commands SET status='completed',response=$4,request_id=$5 WHERE caller_instance=$1 AND actor_subject='$worker' AND operation='process' AND idempotency_key=$2 AND request_hash=$3 AND status='started'")
        .bind(caller)
        .bind(idempotency_key)
        .bind(request_hash)
        .bind(Json(serde_json::to_value(result)?))
        .bind(result.request_id)
        .execute(postgres.pool())
        .await
        .map_err(|source| database("complete worker process receipt", source))?;
    if changed.rows_affected() != 1 {
        return Err(StorageError::InvalidStoredData {
            detail: "worker process receipt lost its started fence".to_owned(),
        });
    }
    Ok(())
}

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<(), StorageError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(key)
        .execute(&mut **transaction)
        .await
        .map_err(|source| database("acquire access request command lock", source))?;
    Ok(())
}

async fn lock_request(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    request_id: Uuid,
) -> Result<Option<RequestRecord>, StorageError> {
    let row = sqlx::query(
        "SELECT * FROM access_requests WHERE request_id=$1 AND organization_id=$2 FOR UPDATE",
    )
    .bind(request_id)
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|source| database("lock access request", source))?;
    row.map(|row| request_from_row(&row)).transpose()
}

async fn lock_effect(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    request_id: Uuid,
    effect_id: Uuid,
) -> Result<Option<EffectRecord>, StorageError> {
    let row = sqlx::query("SELECT e.* FROM access_request_effects e JOIN access_requests r ON r.request_id=e.request_id WHERE e.effect_id=$1 AND e.request_id=$2 AND r.organization_id=$3 FOR UPDATE OF e")
        .bind(effect_id)
        .bind(request_id)
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|source| database("lock access request effect", source))?;
    row.map(|row| effect_from_row(&row)).transpose()
}

async fn load_request_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<RequestRecord, StorageError> {
    let row = sqlx::query("SELECT * FROM access_requests WHERE request_id=$1")
        .bind(request_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|source| database("load access request", source))?;
    request_from_row(&row)
}

async fn load_effect_tx(
    transaction: &mut Transaction<'_, Postgres>,
    effect_id: Uuid,
) -> Result<EffectRecord, StorageError> {
    let row = sqlx::query("SELECT * FROM access_request_effects WHERE effect_id=$1")
        .bind(effect_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|source| database("load access request effect", source))?;
    effect_from_row(&row)
}

fn request_from_row(row: &PgRow) -> Result<RequestRecord, StorageError> {
    let Json(permissions) = row
        .try_get::<Json<Vec<String>>, _>("permissions")
        .map_err(|error| invalid_column("permissions", error))?;
    Ok(RequestRecord {
        request_id: column(row, "request_id")?,
        organization_id: column(row, "organization_id")?,
        requester_subject: column(row, "requester_subject")?,
        requester_was_member: column(row, "requester_was_member")?,
        bundle_id: column(row, "bundle_id")?,
        role_mode: column(row, "role_mode")?,
        role_id: column(row, "role_id")?,
        role_name: column(row, "role_name")?,
        scope_kind: column(row, "scope_kind")?,
        scope_id: column(row, "scope_id")?,
        scope_name: column(row, "scope_name")?,
        permissions,
        reason: column(row, "reason")?,
        recipient_address: column(row, "recipient_address")?,
        recipient_display_name: column(row, "recipient_display_name")?,
        recipient_locale: column(row, "recipient_locale")?,
        status: column(row, "status")?,
        effect_status: column(row, "effect_status")?,
        revision: column(row, "revision")?,
        expires_at: column(row, "expires_at")?,
        decided_by: column(row, "decided_by")?,
        decision_note: column(row, "decision_note")?,
        created_at: column(row, "created_at")?,
        updated_at: column(row, "updated_at")?,
    })
}

fn effect_from_row(row: &PgRow) -> Result<EffectRecord, StorageError> {
    Ok(EffectRecord {
        effect_id: column(row, "effect_id")?,
        request_id: column(row, "request_id")?,
        sequence: column(row, "sequence")?,
        kind: column(row, "kind")?,
        status: column(row, "status")?,
        revision: column(row, "revision")?,
        attempts: column(row, "attempts")?,
        automatic_retry_allowed: column(row, "automatic_retry_allowed")?,
        error_code: column(row, "error_code")?,
        policy_revision: column(row, "policy_revision")?,
        evidence_reference: column(row, "evidence_reference")?,
        lease_until: column(row, "lease_until")?,
        created_at: column(row, "created_at")?,
        updated_at: column(row, "updated_at")?,
    })
}

fn lease_matches(row: &PgRow, lease_token: Uuid, fence: i64) -> Result<bool, StorageError> {
    let status = column::<String>(row, "status")?;
    let stored_token = column::<Option<Uuid>>(row, "lease_token")?;
    let stored_fence = column::<i64>(row, "fence")?;
    let lease_until = column::<Option<OffsetDateTime>>(row, "lease_until")?;
    Ok(status == "leased"
        && stored_token == Some(lease_token)
        && stored_fence == fence
        && lease_until.is_some_and(|value| value > OffsetDateTime::now_utc()))
}

fn column<T>(row: &PgRow, name: &'static str) -> Result<T, StorageError>
where
    for<'value> T: sqlx::Decode<'value, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(name)
        .map_err(|error| invalid_column(name, error))
}

pub(crate) fn encode_cursor(cursor: &Cursor) -> Result<String, StorageError> {
    let timestamp =
        cursor
            .created_at
            .format(&Rfc3339)
            .map_err(|error| StorageError::InvalidStoredData {
                detail: format!("cursor timestamp cannot be formatted: {error}"),
            })?;
    Ok(format!("{timestamp}|{}", cursor.request_id))
}

pub(crate) fn decode_cursor(value: &str) -> Option<Cursor> {
    let (timestamp, request_id) = value.rsplit_once('|')?;
    Some(Cursor {
        created_at: OffsetDateTime::parse(timestamp, &Rfc3339).ok()?,
        request_id: Uuid::parse_str(request_id).ok()?,
    })
}

pub(crate) fn request_id(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value.strip_prefix("ar_")?).ok()
}

pub(crate) fn effect_id(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value.strip_prefix("are_")?).ok()
}

pub(crate) fn job_id(value: &str) -> Option<Uuid> {
    let value = value
        .strip_prefix("are_")
        .or_else(|| value.strip_prefix("arn_"))?;
    Uuid::parse_str(value).ok()
}

pub(crate) fn wire_request_id(value: Uuid) -> String {
    format!("ar_{value}")
}

pub(crate) fn wire_effect_id(value: Uuid) -> String {
    format!("are_{value}")
}

pub(crate) fn wire_job_id(value: &JobRecord) -> String {
    if value.kind == "access_effect" {
        wire_effect_id(value.job_id)
    } else {
        format!("arn_{}", value.job_id)
    }
}

async fn begin<'a>(
    postgres: &'a OwnedPostgres,
    operation: &'static str,
) -> Result<Transaction<'a, Postgres>, StorageError> {
    postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database(operation, source))
}

async fn commit(
    transaction: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), StorageError> {
    transaction
        .commit()
        .await
        .map_err(|source| database(operation, source))
}

fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}

#[allow(clippy::needless_pass_by_value)]
fn invalid_column(column: &'static str, error: sqlx::Error) -> StorageError {
    StorageError::InvalidStoredData {
        detail: format!("column `{column}` is invalid: {error}"),
    }
}

mod decimal_i64 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(super) fn serialize<S: Serializer>(value: &i64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}
