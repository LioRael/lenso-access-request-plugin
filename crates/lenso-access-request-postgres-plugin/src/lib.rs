//! PostgreSQL-backed organization Access Request workflow.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control::{
    AccessControlInvocationError, CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_access_control_admin as access_admin;
use lenso_capability_access_request_admin as admin;
use lenso_capability_access_request_requester as requester;
use lenso_capability_access_request_worker as worker;
use lenso_capability_notification_transactional as notification;
use lenso_capability_organization_directory as directory;
use lenso_capability_organization_membership as membership;
use lenso_capability_organization_membership::{
    CheckMembershipRequest, OrganizationMembershipInvocationError,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use operator::{AccessRequestOperator, AccessRequestOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_BUNDLES: usize = 128;
const MAX_ID_BYTES: usize = 240;
const MAX_REASON_BYTES: usize = 2_000;
const MAX_NOTE_BYTES: usize = 2_000;
const MAX_REFERENCE_BYTES: usize = 1_000;
const MAX_IDEMPOTENCY_BYTES: usize = 200;
const DEFAULT_EXPIRING_LEAD_SECONDS: i64 = 24 * 60 * 60;
const DEFAULT_MAX_NOTIFICATION_ATTEMPTS: i32 = 10;
const DEFAULT_NOTIFICATION_RETRY_SECONDS: i64 = 60;

const ADMIN_READ: &str = "access-request.read";
const ADMIN_DECIDE: &str = "access-request.decide";
const ADMIN_RECOVER: &str = "access-request.recover";

/// Whether a configured bundle binds an existing role or a role managed by this Plugin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleRoleMode {
    Existing,
    Managed,
}

impl BundleRoleMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Existing => "existing",
            Self::Managed => "managed",
        }
    }
}

/// One immutable, operator-approved requestable permission bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestableBundle {
    bundle_id: String,
    role_mode: BundleRoleMode,
    role_id: String,
    role_name: String,
    scope_kind: String,
    permissions: Vec<String>,
    allow_non_members: bool,
}

/// Immutable configuration for one Access Request Plugin Instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequestConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    requester_callers: Vec<String>,
    admin_callers: Vec<String>,
    worker_callers: Vec<String>,
    requestable_bundles: Vec<RequestableBundle>,
    #[serde(default = "default_expiring_lead_seconds")]
    expiring_lead_seconds: i64,
    #[serde(default = "default_max_notification_attempts")]
    max_notification_attempts: i32,
    #[serde(default = "default_notification_retry_seconds")]
    notification_retry_seconds: i64,
}

impl AccessRequestConfig {
    fn validate(&self) -> Result<(), AccessRequestConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| AccessRequestConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(AccessRequestConfigError::InvalidSecretReference);
        }
        if !valid_identifier(&self.auth_issuer, MAX_ID_BYTES) {
            return Err(AccessRequestConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| AccessRequestConfigError::InvalidAuthPublicKey)?;
        validate_callers(&self.requester_callers)
            .map_err(|()| AccessRequestConfigError::InvalidRequesterCallers)?;
        validate_callers(&self.admin_callers)
            .map_err(|()| AccessRequestConfigError::InvalidAdminCallers)?;
        validate_callers(&self.worker_callers)
            .map_err(|()| AccessRequestConfigError::InvalidWorkerCallers)?;
        let all_callers = self
            .requester_callers
            .iter()
            .chain(&self.admin_callers)
            .chain(&self.worker_callers)
            .collect::<BTreeSet<_>>();
        if all_callers.len()
            != self.requester_callers.len() + self.admin_callers.len() + self.worker_callers.len()
        {
            return Err(AccessRequestConfigError::OverlappingCallers);
        }
        if self.requestable_bundles.is_empty() || self.requestable_bundles.len() > MAX_BUNDLES {
            return Err(AccessRequestConfigError::InvalidBundles);
        }
        let mut bundle_ids = BTreeSet::new();
        let mut role_targets = BTreeSet::new();
        for bundle in &self.requestable_bundles {
            let permissions = bundle.permissions.iter().collect::<BTreeSet<_>>();
            if !bundle_ids.insert(&bundle.bundle_id)
                || !role_targets.insert((&bundle.scope_kind, &bundle.role_id))
                || !valid_identifier(&bundle.bundle_id, 160)
                || !valid_identifier(&bundle.role_id, 160)
                || !valid_text(&bundle.role_name, 160, false)
                || !valid_identifier(&bundle.scope_kind, 160)
                || bundle.permissions.is_empty()
                || bundle.permissions.len() > 64
                || permissions.len() != bundle.permissions.len()
                || !bundle
                    .permissions
                    .iter()
                    .all(|permission| valid_identifier(permission, 160))
                || !bundle.permissions.windows(2).all(|pair| pair[0] < pair[1])
            {
                return Err(AccessRequestConfigError::InvalidBundles);
            }
        }
        if !(60..=7 * 24 * 60 * 60).contains(&self.expiring_lead_seconds)
            || !(1..=20).contains(&self.max_notification_attempts)
            || !(10..=3_600).contains(&self.notification_retry_seconds)
        {
            return Err(AccessRequestConfigError::InvalidWorkerBounds);
        }
        Ok(())
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Access Request Auth verification key is invalid".to_owned(),
        })
    }

    fn bundle(&self, bundle_id: &str) -> Option<&RequestableBundle> {
        self.requestable_bundles
            .iter()
            .find(|bundle| bundle.bundle_id == bundle_id)
    }
}

/// Invalid immutable Access Request configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AccessRequestConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("requester_callers must contain unique exact Instance keys")]
    InvalidRequesterCallers,
    #[error("admin_callers must contain unique exact Instance keys")]
    InvalidAdminCallers,
    #[error("worker_callers must contain unique exact Instance keys")]
    InvalidWorkerCallers,
    #[error("caller role allowlists must not overlap")]
    OverlappingCallers,
    #[error("requestable bundles must be unique, bounded, canonical, and non-empty")]
    InvalidBundles,
    #[error("worker and notification retry bounds are invalid")]
    InvalidWorkerBounds,
}

fn validate_config(config: &AccessRequestConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Access Request configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedAccessRequest {
    postgres: OwnedPostgres,
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct PostgresAccessRequestPlugin {
    #[config]
    config: AccessRequestConfig,
    secrets: Port<secrets::SecretsClient>,
    directory: Port<directory::OrganizationDirectoryClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    access_admin: Port<access_admin::AccessControlAdminClient>,
    notification: Port<notification::TransactionalClient>,
    prepared: Rc<RefCell<Option<PreparedAccessRequest>>>,
}

impl fmt::Debug for PostgresAccessRequestPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresAccessRequestPlugin")
            .field("schema", &self.config.schema)
            .field("bundle_count", &self.config.requestable_bundles.len())
            .field("prepared", &self.prepared.borrow().is_some())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(requester::Requester, admin::Admin, worker::Worker)]
impl PostgresAccessRequestPlugin {}

impl PostgresAccessRequestPlugin {
    #[allow(clippy::too_many_lines)]
    async fn create(
        &self,
        context: Ctx,
        request: requester::CreateRequest,
    ) -> PluginResult<requester::CreateResponse, requester::CreateError> {
        let (caller, actor) =
            self.requester_actor::<requester::CreateError>(&context, requester::CREATE_OPERATION)?;
        if !valid_identifier(&request.organization_id, MAX_ID_BYTES)
            || !valid_identifier(&request.bundle_id, 160)
            || !valid_identifier(&request.scope.kind, 160)
            || !valid_identifier(&request.scope.id, MAX_ID_BYTES)
            || request
                .scope
                .display_name
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_ID_BYTES, true))
            || !valid_text(&request.reason, MAX_REASON_BYTES, false)
            || !valid_email(&request.recipient.address)
            || request
                .recipient
                .display_name
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_ID_BYTES, true))
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(requester::CreateError::InvalidRequest));
        }
        let expires_at = parse_timestamp(&request.expires_at)
            .ok_or_else(|| PluginError::domain(requester::CreateError::InvalidRequest))?;
        let now = OffsetDateTime::now_utc();
        if expires_at < now + time::Duration::minutes(5)
            || expires_at > now + time::Duration::days(365)
        {
            return Err(PluginError::domain(requester::CreateError::InvalidRequest));
        }
        let bundle = self
            .config
            .bundle(&request.bundle_id)
            .cloned()
            .ok_or_else(|| PluginError::domain(requester::CreateError::BundleNotRequestable))?;
        if bundle.scope_kind != request.scope.kind
            || (request.scope.kind == "organization" && request.scope.id != request.organization_id)
        {
            return Err(PluginError::domain(
                requester::CreateError::ScopeNotRequestable,
            ));
        }
        self.require_active_organization::<requester::CreateError>(
            &context,
            &request.organization_id,
        )
        .await?;
        let active_member = self
            .membership_state::<requester::CreateError>(&context, &request.organization_id, &actor)
            .await?;
        if !active_member
            && (!bundle.allow_non_members
                || request.scope.kind != "organization"
                || request.scope.id != request.organization_id)
        {
            return Err(PluginError::domain(
                requester::CreateError::ScopeNotRequestable,
            ));
        }
        if active_member
            && self
                .already_has_bundle(
                    &context,
                    &actor,
                    &request.scope.kind,
                    &request.scope.id,
                    &bundle.permissions,
                )
                .await
                .map_err(PluginError::runtime)?
        {
            return Err(PluginError::domain(
                requester::CreateError::AccessAlreadyGranted,
            ));
        }
        let locale = match request.recipient.locale {
            requester::CreateRequestRecipientLocale::En => "en",
            requester::CreateRequestRecipientLocale::EnUS => "en-US",
        };
        let request_hash = hash_value(&(&actor, &request)).map_err(PluginError::runtime)?;
        let fingerprint = hash_value(&json!({
            "organization_id": request.organization_id,
            "requester_subject": actor,
            "bundle_id": bundle.bundle_id,
            "role_mode": bundle.role_mode.as_str(),
            "role_id": bundle.role_id,
            "role_name": bundle.role_name,
            "scope_kind": request.scope.kind,
            "scope_id": request.scope.id,
            "scope_name": request.scope.display_name,
            "permissions": bundle.permissions,
            "reason": request.reason,
            "expires_at": request.expires_at,
            "recipient_address": request.recipient.address,
            "recipient_display_name": request.recipient.display_name,
            "recipient_locale": locale,
        }))
        .map_err(PluginError::runtime)?;
        let postgres = self.prepared().map_err(PluginError::runtime)?.postgres;
        let result = storage::create_request(
            &postgres,
            &storage::CreateInput {
                caller: &caller,
                actor: &actor,
                idempotency_key: &request.idempotency_key,
                request_hash: &request_hash,
                fingerprint: &fingerprint,
                organization_id: &request.organization_id,
                requester_was_member: active_member,
                bundle_id: &bundle.bundle_id,
                role_mode: bundle.role_mode.as_str(),
                role_id: &bundle.role_id,
                role_name: &bundle.role_name,
                scope_kind: &request.scope.kind,
                scope_id: &request.scope.id,
                scope_name: request.scope.display_name.as_deref(),
                permissions: &bundle.permissions,
                reason: &request.reason,
                recipient_address: &request.recipient.address,
                recipient_display_name: request.recipient.display_name.as_deref(),
                recipient_locale: locale,
                expires_at,
                expiring_lead_seconds: self.config.expiring_lead_seconds,
            },
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(requester_failure(failure)))?;
        Ok(requester::CreateResponse {
            created: result.created,
            merged: result.merged,
            request: project_request(&result.request)?,
        })
    }

    async fn get(
        &self,
        context: Ctx,
        request: requester::GetRequest,
    ) -> PluginResult<requester::GetResponse, requester::GetError> {
        let (_, actor) =
            self.requester_actor::<requester::GetError>(&context, requester::GET_OPERATION)?;
        let request_id = parse_request_identity::<requester::GetError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let record = storage::get_request(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            request_id,
        )
        .await
        .map_err(storage_runtime)?
        .filter(|record| record.requester_subject == actor)
        .ok_or_else(|| PluginError::domain(requester::GetError::RequestNotFound))?;
        project_request(&record)
    }

    async fn list(
        &self,
        context: Ctx,
        request: requester::ListRequest,
    ) -> PluginResult<requester::ListResponse, requester::ListError> {
        let (_, actor) =
            self.requester_actor::<requester::ListError>(&context, requester::LIST_OPERATION)?;
        let cursor = parse_cursor::<requester::ListError>(request.cursor.as_deref())?;
        if !valid_identifier(&request.organization_id, MAX_ID_BYTES)
            || !(1..=200).contains(&request.limit)
        {
            return Err(PluginError::domain(requester::ListError::InvalidRequest));
        }
        let status = request.status.as_ref().map(enum_wire).transpose()?;
        let (records, next) = storage::list_requests(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            Some(&actor),
            status.as_deref(),
            None,
            cursor.as_ref(),
            request.limit,
        )
        .await
        .map_err(storage_runtime)?;
        Ok(requester::ListResponse {
            requests: records
                .iter()
                .map(project_request)
                .collect::<PluginResult<Vec<_>, _>>()?,
            next_cursor: next
                .as_ref()
                .map(storage::encode_cursor)
                .transpose()
                .map_err(storage_runtime)?,
        })
    }

    async fn cancel(
        &self,
        context: Ctx,
        request: requester::CancelRequest,
    ) -> PluginResult<requester::CancelResponse, requester::CancelError> {
        let (caller, actor) =
            self.requester_actor::<requester::CancelError>(&context, requester::CANCEL_OPERATION)?;
        let request_id = parse_request_identity::<requester::CancelError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let revision = parse_revision::<requester::CancelError>(&request.expected_revision)?;
        if !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(requester::CancelError::InvalidRequest));
        }
        let hash = hash_value(&(&actor, &request)).map_err(PluginError::runtime)?;
        let record = storage::cancel_request(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &actor,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            revision,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(requester_failure(failure)))?;
        project_request(&record)
    }

    async fn get_request(
        &self,
        context: Ctx,
        request: admin::GetRequestRequest,
    ) -> PluginResult<admin::GetRequestResponse, admin::GetRequestError> {
        self.authorize_admin::<admin::GetRequestError>(
            &context,
            admin::GET_REQUEST_OPERATION,
            &request.organization_id,
            ADMIN_READ,
        )
        .await?;
        let request_id = parse_request_identity::<admin::GetRequestError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let record = storage::get_request(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            request_id,
        )
        .await
        .map_err(storage_runtime)?
        .ok_or_else(|| PluginError::domain(admin::GetRequestError::RequestNotFound))?;
        project_request(&record)
    }

    async fn list_requests(
        &self,
        context: Ctx,
        request: admin::ListRequestsRequest,
    ) -> PluginResult<admin::ListRequestsResponse, admin::ListRequestsError> {
        self.authorize_admin::<admin::ListRequestsError>(
            &context,
            admin::LIST_REQUESTS_OPERATION,
            &request.organization_id,
            ADMIN_READ,
        )
        .await?;
        let cursor = parse_cursor::<admin::ListRequestsError>(request.cursor.as_deref())?;
        if !(1..=200).contains(&request.limit)
            || request
                .requester_subject
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, MAX_ID_BYTES))
            || request
                .bundle_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, 160))
        {
            return Err(PluginError::domain(
                admin::ListRequestsError::InvalidRequest,
            ));
        }
        let status = request.status.as_ref().map(enum_wire).transpose()?;
        let (records, next) = storage::list_requests(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            request.requester_subject.as_deref(),
            status.as_deref(),
            request.bundle_id.as_deref(),
            cursor.as_ref(),
            request.limit,
        )
        .await
        .map_err(storage_runtime)?;
        Ok(admin::ListRequestsResponse {
            requests: records
                .iter()
                .map(project_request)
                .collect::<PluginResult<Vec<_>, _>>()?,
            next_cursor: next
                .as_ref()
                .map(storage::encode_cursor)
                .transpose()
                .map_err(storage_runtime)?,
        })
    }

    async fn approve(
        &self,
        context: Ctx,
        request: admin::ApproveRequest,
    ) -> PluginResult<admin::ApproveResponse, admin::ApproveError> {
        let (caller, actor) = self
            .authorize_admin::<admin::ApproveError>(
                &context,
                admin::APPROVE_OPERATION,
                &request.organization_id,
                ADMIN_DECIDE,
            )
            .await?;
        let request_id = parse_request_identity::<admin::ApproveError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let expected_revision = parse_revision::<admin::ApproveError>(&request.expected_revision)?;
        if request
            .note
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_NOTE_BYTES, true))
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(admin::ApproveError::InvalidRequest));
        }
        let postgres = self.prepared().map_err(PluginError::runtime)?.postgres;
        let existing = storage::get_request(&postgres, &request.organization_id, request_id)
            .await
            .map_err(storage_runtime)?
            .ok_or_else(|| PluginError::domain(admin::ApproveError::RequestNotFound))?;
        if existing.requester_subject == actor {
            return Err(PluginError::domain(admin::ApproveError::SelfApproval));
        }
        if !self.target_policy_matches(&existing) {
            return Err(PluginError::domain(
                admin::ApproveError::TargetPolicyConflict,
            ));
        }
        let hash = hash_value(&(&actor, &request)).map_err(PluginError::runtime)?;
        let record = storage::approve_request(
            &postgres,
            &caller,
            &actor,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            expected_revision,
            request.note.as_deref(),
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(admin_failure(failure)))?;
        project_request(&record)
    }

    async fn deny(
        &self,
        context: Ctx,
        request: admin::DenyRequest,
    ) -> PluginResult<admin::DenyResponse, admin::DenyError> {
        let (caller, actor) = self
            .authorize_admin::<admin::DenyError>(
                &context,
                admin::DENY_OPERATION,
                &request.organization_id,
                ADMIN_DECIDE,
            )
            .await?;
        let request_id = parse_request_identity::<admin::DenyError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let expected_revision = parse_revision::<admin::DenyError>(&request.expected_revision)?;
        if request
            .note
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_NOTE_BYTES, true))
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(admin::DenyError::InvalidRequest));
        }
        let postgres = self.prepared().map_err(PluginError::runtime)?.postgres;
        let existing = storage::get_request(&postgres, &request.organization_id, request_id)
            .await
            .map_err(storage_runtime)?
            .ok_or_else(|| PluginError::domain(admin::DenyError::RequestNotFound))?;
        if existing.requester_subject == actor {
            return Err(PluginError::domain(admin::DenyError::SelfApproval));
        }
        let hash = hash_value(&(&actor, &request)).map_err(PluginError::runtime)?;
        let record = storage::deny_request(
            &postgres,
            &caller,
            &actor,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            expected_revision,
            request.note.as_deref(),
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(admin_failure(failure)))?;
        project_request(&record)
    }

    async fn inspect_effect(
        &self,
        context: Ctx,
        request: admin::InspectEffectRequest,
    ) -> PluginResult<admin::InspectEffectResponse, admin::InspectEffectError> {
        self.authorize_admin::<admin::InspectEffectError>(
            &context,
            admin::INSPECT_EFFECT_OPERATION,
            &request.organization_id,
            ADMIN_RECOVER,
        )
        .await?;
        let request_id = parse_request_identity::<admin::InspectEffectError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let effect_id = parse_effect_identity::<admin::InspectEffectError>(&request.effect_id)?;
        let record = storage::inspect_effect(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            request_id,
            effect_id,
        )
        .await
        .map_err(storage_runtime)?
        .ok_or_else(|| PluginError::domain(admin::InspectEffectError::EffectNotFound))?;
        project_effect(&record)
    }

    async fn resolve_effect(
        &self,
        context: Ctx,
        request: admin::ResolveEffectRequest,
    ) -> PluginResult<admin::ResolveEffectResponse, admin::ResolveEffectError> {
        let (caller, actor) = self
            .authorize_admin::<admin::ResolveEffectError>(
                &context,
                admin::RESOLVE_EFFECT_OPERATION,
                &request.organization_id,
                ADMIN_RECOVER,
            )
            .await?;
        let request_id = parse_request_identity::<admin::ResolveEffectError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let effect_id = parse_effect_identity::<admin::ResolveEffectError>(&request.effect_id)?;
        let revision =
            parse_revision::<admin::ResolveEffectError>(&request.expected_effect_revision)?;
        if !valid_text(&request.evidence_reference, MAX_REFERENCE_BYTES, false)
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(
                admin::ResolveEffectError::InvalidRequest,
            ));
        }
        let succeeded = matches!(
            request.resolution,
            admin::ResolveEffectRequestResolution::Succeeded
        );
        let hash = hash_value(&(&actor, &request)).map_err(PluginError::runtime)?;
        let effect = storage::resolve_effect(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &actor,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            effect_id,
            revision,
            succeeded,
            &request.evidence_reference,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(admin_failure(failure)))?;
        project_effect(&effect)
    }

    async fn claim_due(
        &self,
        context: Ctx,
        request: worker::ClaimDueRequest,
    ) -> PluginResult<worker::ClaimDueResponse, worker::ClaimDueError> {
        let caller = self.worker_caller::<worker::ClaimDueError>(&context)?;
        if !valid_identifier(&request.worker_id, 160)
            || !(15..=900).contains(&request.lease_seconds)
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(worker::ClaimDueError::InvalidRequest));
        }
        let hash = hash_value(&request).map_err(PluginError::runtime)?;
        let job = storage::claim_due(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.worker_id,
            &request.idempotency_key,
            &hash,
            request.lease_seconds,
            self.config.max_notification_attempts,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(worker_failure(failure)))?;
        Ok(worker::ClaimDueResponse {
            job: job.as_ref().map(project_job).transpose()?,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn process(
        &self,
        context: Ctx,
        request: worker::ProcessRequest,
    ) -> PluginResult<worker::ProcessResponse, worker::ProcessError> {
        let caller = self.worker_caller::<worker::ProcessError>(&context)?;
        let job_id = storage::job_id(&request.job_id)
            .ok_or_else(|| PluginError::domain(worker::ProcessError::InvalidRequest))?;
        let lease_token = Uuid::parse_str(&request.lease_token)
            .map_err(|_| PluginError::domain(worker::ProcessError::InvalidRequest))?;
        let fence = parse_revision::<worker::ProcessError>(&request.fence)?;
        if !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(worker::ProcessError::InvalidRequest));
        }
        let hash = hash_value(&request).map_err(PluginError::runtime)?;
        let postgres = self.prepared().map_err(PluginError::runtime)?.postgres;
        match storage::begin_process(&postgres, &caller, &request.idempotency_key, &hash)
            .await
            .map_err(storage_runtime)?
            .map_err(|failure| PluginError::domain(worker_failure(failure)))?
        {
            storage::ProcessStart::Replay(result) => return project_process(&result),
            storage::ProcessStart::Execute => {}
        }
        let claimed = storage::load_claimed_work(&postgres, job_id, lease_token, fence)
            .await
            .map_err(storage_runtime)?
            .map_err(|failure| PluginError::domain(worker_failure(failure)))?;
        let result = match claimed {
            storage::ClaimedWork::Effect {
                job,
                effect,
                request: access_request,
            } => {
                let outcome = self
                    .execute_access_effect(&context, &effect.kind, &access_request)
                    .await;
                let request = storage::complete_effect(
                    &postgres,
                    &caller,
                    job.job_id,
                    job.lease_token,
                    job.fence,
                    &outcome,
                )
                .await
                .map_err(storage_runtime)?
                .map_err(|failure| PluginError::domain(worker_failure(failure)))?;
                storage::ProcessResult {
                    request_id: request.request_id,
                    request_status: request.status,
                    request_revision: request.revision,
                    job_status: match outcome {
                        storage::EffectOutcome::Succeeded { .. } => "succeeded".to_owned(),
                        storage::EffectOutcome::Failed { .. } => "failed".to_owned(),
                        storage::EffectOutcome::Unknown { .. } => "unknown".to_owned(),
                    },
                    automatic_retry_allowed: matches!(
                        outcome,
                        storage::EffectOutcome::Failed {
                            retry_allowed: true,
                            ..
                        }
                    ),
                }
            }
            storage::ClaimedWork::Notification {
                job,
                event,
                request: access_request,
            } => {
                let notification_result = self
                    .create_notification_intent(&context, &job, &event, &access_request)
                    .await;
                let (intent_id, error_code) = match notification_result {
                    Ok(intent_id) => (Some(intent_id), None),
                    Err(code) => (None, Some(code)),
                };
                let request = storage::complete_notification(
                    &postgres,
                    job.job_id,
                    job.lease_token,
                    job.fence,
                    intent_id.as_deref(),
                    error_code.as_deref(),
                    self.config.notification_retry_seconds,
                )
                .await
                .map_err(storage_runtime)?
                .map_err(|failure| PluginError::domain(worker_failure(failure)))?;
                storage::ProcessResult {
                    request_id: request.request_id,
                    request_status: request.status,
                    request_revision: request.revision,
                    job_status: if intent_id.is_some() {
                        "succeeded".to_owned()
                    } else {
                        "failed".to_owned()
                    },
                    automatic_retry_allowed: intent_id.is_none(),
                }
            }
        };
        storage::finish_process(&postgres, &caller, &request.idempotency_key, &hash, &result)
            .await
            .map_err(storage_runtime)?;
        project_process(&result)
    }

    async fn expire(
        &self,
        context: Ctx,
        request: worker::ExpireRequest,
    ) -> PluginResult<worker::ExpireResponse, worker::ExpireError> {
        let caller = self.worker_caller::<worker::ExpireError>(&context)?;
        let request_id = parse_request_identity::<worker::ExpireError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let revision = parse_revision::<worker::ExpireError>(&request.expected_revision)?;
        if !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(worker::ExpireError::InvalidRequest));
        }
        let hash = hash_value(&request).map_err(PluginError::runtime)?;
        let record = storage::expire_request(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            revision,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(worker_failure(failure)))?;
        project_process(&storage::ProcessResult {
            request_id: record.request_id,
            request_status: record.status,
            request_revision: record.revision,
            job_status: "expired".to_owned(),
            automatic_retry_allowed: false,
        })
    }

    async fn retry(
        &self,
        context: Ctx,
        request: worker::RetryRequest,
    ) -> PluginResult<worker::RetryResponse, worker::RetryError> {
        let caller = self.worker_caller::<worker::RetryError>(&context)?;
        let request_id = parse_request_identity::<worker::RetryError>(
            &request.organization_id,
            &request.request_id,
        )?;
        let effect_id = parse_effect_identity::<worker::RetryError>(&request.effect_id)?;
        let revision = parse_revision::<worker::RetryError>(&request.expected_effect_revision)?;
        if !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(worker::RetryError::InvalidRequest));
        }
        let hash = hash_value(&request).map_err(PluginError::runtime)?;
        let effect = storage::retry_effect(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            effect_id,
            revision,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(worker_failure(failure)))?;
        project_effect(&effect)
    }

    async fn execute_access_effect(
        &self,
        context: &Ctx,
        kind: &str,
        request: &storage::RequestRecord,
    ) -> storage::EffectOutcome {
        match kind {
            "create_role" => self.execute_create_role(context, request).await,
            "set_role_permissions" => self.execute_set_permissions(context, request).await,
            "assign_role" => self.execute_assign_role(context, request).await,
            _ => storage::EffectOutcome::Failed {
                error_code: "invalid_effect_kind".to_owned(),
                retry_allowed: false,
            },
        }
    }

    async fn execute_create_role(
        &self,
        context: &Ctx,
        request: &storage::RequestRecord,
    ) -> storage::EffectOutcome {
        let result = self
            .access_admin
            .create_role_with_context(
                context.clone(),
                access_admin::CreateRoleRequest {
                    name: request.role_name.clone(),
                    role_id: request.role_id.clone(),
                    scope: access_admin::CreateRoleRequestScope {
                        kind: request.scope_kind.clone(),
                        id: request.scope_id.clone(),
                    },
                },
            )
            .await;
        match result {
            Ok(response) => storage::EffectOutcome::Succeeded {
                policy_revision: response.policy_revision,
            },
            Err(
                access_admin::AccessControlAdminCreateRoleInvocationError::Runtime(_)
                | access_admin::AccessControlAdminCreateRoleInvocationError::Domain(
                    access_admin::CreateRoleError::Unknown(_),
                ),
            ) => storage::EffectOutcome::Unknown {
                error_code: "access_control_outcome_unknown".to_owned(),
            },
            Err(access_admin::AccessControlAdminCreateRoleInvocationError::Domain(
                access_admin::CreateRoleError::ScopeNotBootstrapped,
            )) => storage::EffectOutcome::Failed {
                error_code: "scope_not_bootstrapped".to_owned(),
                retry_allowed: true,
            },
            Err(access_admin::AccessControlAdminCreateRoleInvocationError::Domain(
                access_admin::CreateRoleError::Unauthenticated
                | access_admin::CreateRoleError::Forbidden,
            )) => storage::EffectOutcome::Failed {
                error_code: "access_control_authority_required".to_owned(),
                retry_allowed: true,
            },
            Err(access_admin::AccessControlAdminCreateRoleInvocationError::Domain(
                access_admin::CreateRoleError::RoleAlreadyExists,
            )) => storage::EffectOutcome::Failed {
                error_code: "target_role_conflict".to_owned(),
                retry_allowed: false,
            },
            Err(access_admin::AccessControlAdminCreateRoleInvocationError::Domain(_)) => {
                storage::EffectOutcome::Failed {
                    error_code: "access_control_rejected".to_owned(),
                    retry_allowed: false,
                }
            }
        }
    }

    async fn execute_set_permissions(
        &self,
        context: &Ctx,
        request: &storage::RequestRecord,
    ) -> storage::EffectOutcome {
        let result = self
            .access_admin
            .set_role_permissions_with_context(
                context.clone(),
                access_admin::SetRolePermissionsRequest {
                    permissions: request.permissions.clone(),
                    role_id: request.role_id.clone(),
                    scope: access_admin::SetRolePermissionsRequestScope {
                        kind: request.scope_kind.clone(),
                        id: request.scope_id.clone(),
                    },
                },
            )
            .await;
        match result {
            Ok(response) => storage::EffectOutcome::Succeeded {
                policy_revision: response.policy_revision,
            },
            Err(
                access_admin::AccessControlAdminSetRolePermissionsInvocationError::Runtime(_)
                | access_admin::AccessControlAdminSetRolePermissionsInvocationError::Domain(
                    access_admin::SetRolePermissionsError::Unknown(_),
                ),
            ) => storage::EffectOutcome::Unknown {
                error_code: "access_control_outcome_unknown".to_owned(),
            },
            Err(access_admin::AccessControlAdminSetRolePermissionsInvocationError::Domain(
                access_admin::SetRolePermissionsError::RoleNotFound
                | access_admin::SetRolePermissionsError::ScopeNotBootstrapped,
            )) => storage::EffectOutcome::Failed {
                error_code: "access_control_prerequisite_missing".to_owned(),
                retry_allowed: true,
            },
            Err(access_admin::AccessControlAdminSetRolePermissionsInvocationError::Domain(
                access_admin::SetRolePermissionsError::Unauthenticated
                | access_admin::SetRolePermissionsError::Forbidden,
            )) => storage::EffectOutcome::Failed {
                error_code: "access_control_authority_required".to_owned(),
                retry_allowed: true,
            },
            Err(access_admin::AccessControlAdminSetRolePermissionsInvocationError::Domain(_)) => {
                storage::EffectOutcome::Failed {
                    error_code: "access_control_rejected".to_owned(),
                    retry_allowed: false,
                }
            }
        }
    }

    async fn execute_assign_role(
        &self,
        context: &Ctx,
        request: &storage::RequestRecord,
    ) -> storage::EffectOutcome {
        let result = self
            .access_admin
            .assign_role_with_context(
                context.clone(),
                access_admin::AssignRoleRequest {
                    role_id: request.role_id.clone(),
                    subject: request.requester_subject.clone(),
                    scope: access_admin::AssignRoleRequestScope {
                        kind: request.scope_kind.clone(),
                        id: request.scope_id.clone(),
                    },
                },
            )
            .await;
        match result {
            Ok(response) => storage::EffectOutcome::Succeeded {
                policy_revision: response.policy_revision,
            },
            Err(
                access_admin::AccessControlAdminAssignRoleInvocationError::Runtime(_)
                | access_admin::AccessControlAdminAssignRoleInvocationError::Domain(
                    access_admin::AssignRoleError::Unknown(_),
                ),
            ) => storage::EffectOutcome::Unknown {
                error_code: "access_control_outcome_unknown".to_owned(),
            },
            Err(access_admin::AccessControlAdminAssignRoleInvocationError::Domain(
                access_admin::AssignRoleError::RoleNotFound
                | access_admin::AssignRoleError::ScopeNotBootstrapped,
            )) => storage::EffectOutcome::Failed {
                error_code: "access_control_prerequisite_missing".to_owned(),
                retry_allowed: true,
            },
            Err(access_admin::AccessControlAdminAssignRoleInvocationError::Domain(
                access_admin::AssignRoleError::Unauthenticated
                | access_admin::AssignRoleError::Forbidden,
            )) => storage::EffectOutcome::Failed {
                error_code: "access_control_authority_required".to_owned(),
                retry_allowed: true,
            },
            Err(access_admin::AccessControlAdminAssignRoleInvocationError::Domain(_)) => {
                storage::EffectOutcome::Failed {
                    error_code: "access_control_rejected".to_owned(),
                    retry_allowed: false,
                }
            }
        }
    }

    async fn create_notification_intent(
        &self,
        context: &Ctx,
        job: &storage::JobRecord,
        event: &str,
        request: &storage::RequestRecord,
    ) -> Result<String, String> {
        let event = match event {
            "submitted" => notification::CreateAccessRequestNotificationRequestEvent::Submitted,
            "approved" => notification::CreateAccessRequestNotificationRequestEvent::Approved,
            "denied" => notification::CreateAccessRequestNotificationRequestEvent::Denied,
            "expiring" => notification::CreateAccessRequestNotificationRequestEvent::Expiring,
            _ => return Err("invalid_notification_event".to_owned()),
        };
        let locale = match request.recipient_locale.as_str() {
            "en" => notification::CreateAccessRequestNotificationRequestRecipientLocale::En,
            "en-US" => notification::CreateAccessRequestNotificationRequestRecipientLocale::EnUS,
            _ => return Err("invalid_notification_locale".to_owned()),
        };
        let request_id = storage::wire_request_id(request.request_id);
        let event_key = job.event_or_effect.as_str();
        let result = self
            .notification
            .create_access_request_notification_with_context(
                context.clone(),
                notification::CreateAccessRequestNotificationRequest {
                    request_id: request_id.clone(),
                    organization_id: request.organization_id.clone(),
                    recipient: notification::CreateAccessRequestNotificationRequestRecipient {
                        address: request.recipient_address.clone(),
                        display_name: request.recipient_display_name.clone(),
                        locale,
                    },
                    event,
                    role: notification::CreateAccessRequestNotificationRequestRole {
                        role_id: request.role_id.clone(),
                        display_name: Some(request.role_name.clone()),
                    },
                    scope: notification::CreateAccessRequestNotificationRequestScope {
                        kind: request.scope_kind.clone(),
                        id: request.scope_id.clone(),
                        display_name: request.scope_name.clone(),
                    },
                    expires_at: Some(
                        request
                            .expires_at
                            .format(&Rfc3339)
                            .map_err(|_| "invalid_notification_expiry".to_owned())?,
                    ),
                    idempotency_key: format!("access-request:{request_id}:{event_key}"),
                    correlation_id: request_id,
                    causation_id: Some(storage::wire_job_id(job)),
                    requested_by: request
                        .decided_by
                        .clone()
                        .or_else(|| Some(request.requester_subject.clone())),
                },
            )
            .await;
        match result {
            Ok(response) => Ok(response.intent_id),
            Err(
                notification::TransactionalCreateAccessRequestNotificationInvocationError::Runtime(
                    _,
                ),
            ) => Err("notification_runtime_failure".to_owned()),
            Err(
                notification::TransactionalCreateAccessRequestNotificationInvocationError::Domain(
                    notification::CreateAccessRequestNotificationError::IdempotencyConflict,
                ),
            ) => Err("notification_idempotency_conflict".to_owned()),
            Err(
                notification::TransactionalCreateAccessRequestNotificationInvocationError::Domain(
                    _,
                ),
            ) => Err("notification_rejected".to_owned()),
        }
    }

    fn prepared(&self) -> Result<PreparedAccessRequest, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Access Request Plugin is not prepared".to_owned(),
            })
    }

    fn requester_actor<E: RoleError>(
        &self,
        context: &Ctx,
        operation: &str,
    ) -> PluginResult<(String, String), E> {
        let caller = allowed_caller(context, &self.config.requester_callers)
            .ok_or_else(|| PluginError::domain(E::forbidden()))?;
        let actor = self
            .authenticated_actor(context, requester::CAPABILITY_ID, operation)
            .map_err(|()| PluginError::domain(E::unauthenticated()))?;
        Ok((caller, actor))
    }

    async fn authorize_admin<E: RoleError>(
        &self,
        context: &Ctx,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> PluginResult<(String, String), E> {
        if !valid_identifier(organization_id, MAX_ID_BYTES) {
            return Err(PluginError::domain(E::invalid_request()));
        }
        let caller = allowed_caller(context, &self.config.admin_callers)
            .ok_or_else(|| PluginError::domain(E::forbidden()))?;
        let actor = self
            .authenticated_actor(context, admin::CAPABILITY_ID, operation)
            .map_err(|()| PluginError::domain(E::unauthenticated()))?;
        if !self
            .membership_state::<E>(context, organization_id, &actor)
            .await?
        {
            return Err(PluginError::domain(E::membership_required()));
        }
        let decision = self
            .access
            .check_permission_with_context(
                context.clone(),
                CheckPermissionRequest {
                    subject: actor.clone(),
                    scope: CheckPermissionRequestScope {
                        kind: "organization".to_owned(),
                        id: organization_id.to_owned(),
                    },
                    permission: permission.to_owned(),
                },
            )
            .await
            .map_err(|error| match error {
                AccessControlInvocationError::Runtime(error) => PluginError::runtime(error),
                AccessControlInvocationError::Domain(_) => PluginError::runtime(
                    dependency_failure("Access Control rejected an authorization query"),
                ),
            })?;
        if !decision.allowed {
            return Err(PluginError::domain(E::access_denied()));
        }
        Ok((caller, actor))
    }

    fn worker_caller<E: RoleError>(&self, context: &Ctx) -> PluginResult<String, E> {
        allowed_caller(context, &self.config.worker_callers)
            .ok_or_else(|| PluginError::domain(E::forbidden()))
    }

    fn authenticated_actor(
        &self,
        context: &Ctx,
        capability: &str,
        operation: &str,
    ) -> Result<String, ()> {
        let actor = self
            .config
            .verifier()
            .map_err(|_| ())?
            .project_context::<AccessRequestActor>(context, capability, operation, &UtcClock)
            .map_err(|_| ())?;
        valid_identifier(&actor.subject, MAX_ID_BYTES)
            .then_some(actor.subject)
            .ok_or(())
    }

    async fn require_active_organization<E: RoleError>(
        &self,
        context: &Ctx,
        organization_id: &str,
    ) -> PluginResult<(), E> {
        let organization = self
            .directory
            .get_organization_with_context(
                context.clone(),
                directory::GetOrganizationRequest {
                    organization_id: organization_id.to_owned(),
                },
            )
            .await
            .map_err(|error| match error {
                directory::OrganizationDirectoryInvocationError::Runtime(error) => {
                    PluginError::runtime(error)
                }
                directory::OrganizationDirectoryInvocationError::Domain(_) => {
                    PluginError::domain(E::organization_not_found())
                }
            })?;
        if !organization.active {
            return Err(PluginError::domain(E::organization_not_found()));
        }
        Ok(())
    }

    async fn membership_state<E: RoleError>(
        &self,
        context: &Ctx,
        organization_id: &str,
        subject: &str,
    ) -> PluginResult<bool, E> {
        self.membership
            .check_membership_with_context(
                context.clone(),
                CheckMembershipRequest {
                    organization_id: organization_id.to_owned(),
                    subject: subject.to_owned(),
                },
            )
            .await
            .map(|response| response.active)
            .map_err(|error| match error {
                OrganizationMembershipInvocationError::Runtime(error) => {
                    PluginError::runtime(error)
                }
                OrganizationMembershipInvocationError::Domain(
                    membership::CheckMembershipError::OrganizationNotFound,
                ) => PluginError::domain(E::organization_not_found()),
                OrganizationMembershipInvocationError::Domain(_) => PluginError::runtime(
                    dependency_failure("Organization Membership rejected a valid query"),
                ),
            })
    }

    async fn already_has_bundle(
        &self,
        context: &Ctx,
        actor: &str,
        scope_kind: &str,
        scope_id: &str,
        permissions: &[String],
    ) -> Result<bool, RuntimeFailure> {
        for permission in permissions {
            let response = self
                .access
                .check_permission_with_context(
                    context.clone(),
                    CheckPermissionRequest {
                        subject: actor.to_owned(),
                        scope: CheckPermissionRequestScope {
                            kind: scope_kind.to_owned(),
                            id: scope_id.to_owned(),
                        },
                        permission: permission.clone(),
                    },
                )
                .await
                .map_err(|error| match error {
                    AccessControlInvocationError::Runtime(error) => error,
                    AccessControlInvocationError::Domain(_) => {
                        dependency_failure("Access Control rejected a bundle preflight query")
                    }
                })?;
            if !response.allowed {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn target_policy_matches(&self, request: &storage::RequestRecord) -> bool {
        self.config
            .bundle(&request.bundle_id)
            .is_some_and(|bundle| {
                bundle.role_mode.as_str() == request.role_mode
                    && bundle.role_id == request.role_id
                    && bundle.role_name == request.role_name
                    && bundle.scope_kind == request.scope_kind
                    && bundle.permissions == request.permissions
                    && (request.requester_was_member || bundle.allow_non_members)
            })
    }
}

impl Lifecycle for PostgresAccessRequestPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared
            .borrow_mut()
            .replace(PreparedAccessRequest { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct AccessRequestActor {
    subject: String,
}

impl TypedActor for AccessRequestActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user" {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".to_owned(),
                actual: assertion.actor_kind().to_owned(),
            });
        }
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UtcClock;

impl AssertionClock for UtcClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("database URL secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

trait RoleError: Sized {
    fn unauthenticated() -> Self;
    fn forbidden() -> Self;
    fn invalid_request() -> Self;
    fn organization_not_found() -> Self;
    fn membership_required() -> Self;
    fn access_denied() -> Self;
}

macro_rules! impl_requester_role_error {
    ($($error:path),+ $(,)?) => {
        $(impl RoleError for $error {
            fn unauthenticated() -> Self { Self::Unauthenticated }
            fn forbidden() -> Self { Self::Forbidden }
            fn invalid_request() -> Self { Self::InvalidRequest }
            fn organization_not_found() -> Self { Self::OrganizationNotFound }
            fn membership_required() -> Self { Self::Forbidden }
            fn access_denied() -> Self { Self::Forbidden }
        })+
    };
}

impl_requester_role_error!(
    requester::CreateError,
    requester::GetError,
    requester::ListError,
    requester::CancelError,
);

macro_rules! impl_admin_role_error {
    ($($error:path),+ $(,)?) => {
        $(impl RoleError for $error {
            fn unauthenticated() -> Self { Self::Unauthenticated }
            fn forbidden() -> Self { Self::Forbidden }
            fn invalid_request() -> Self { Self::InvalidRequest }
            fn organization_not_found() -> Self { Self::OrganizationNotFound }
            fn membership_required() -> Self { Self::MembershipRequired }
            fn access_denied() -> Self { Self::AccessDenied }
        })+
    };
}

impl_admin_role_error!(
    admin::GetRequestError,
    admin::ListRequestsError,
    admin::ApproveError,
    admin::DenyError,
    admin::InspectEffectError,
    admin::ResolveEffectError,
);

macro_rules! impl_worker_role_error {
    ($($error:path),+ $(,)?) => {
        $(impl RoleError for $error {
            fn unauthenticated() -> Self { Self::Forbidden }
            fn forbidden() -> Self { Self::Forbidden }
            fn invalid_request() -> Self { Self::InvalidRequest }
            fn organization_not_found() -> Self { Self::InvalidRequest }
            fn membership_required() -> Self { Self::Forbidden }
            fn access_denied() -> Self { Self::Forbidden }
        })+
    };
}

impl_worker_role_error!(
    worker::ClaimDueError,
    worker::ProcessError,
    worker::ExpireError,
    worker::RetryError,
);

trait RequesterFailure: RoleError {
    fn from_storage(failure: storage::DomainFailure) -> Self;
}

macro_rules! impl_requester_failure {
    ($($error:path),+ $(,)?) => {
        $(impl RequesterFailure for $error {
            fn from_storage(failure: storage::DomainFailure) -> Self {
                match failure {
                    storage::DomainFailure::NotFound => Self::RequestNotFound,
                    storage::DomainFailure::RevisionConflict => Self::RevisionConflict,
                    storage::DomainFailure::IdempotencyConflict => Self::IdempotencyConflict,
                    storage::DomainFailure::InvalidTransition => Self::InvalidTransition,
                    storage::DomainFailure::ActiveRequestConflict => Self::ActiveRequestConflict,
                    storage::DomainFailure::RequestExpired => Self::RequestExpired,
                    _ => Self::InvalidTransition,
                }
            }
        })+
    };
}

impl_requester_failure!(
    requester::CreateError,
    requester::GetError,
    requester::ListError,
    requester::CancelError,
);

trait AdminFailure: RoleError {
    fn from_storage(failure: storage::DomainFailure) -> Self;
}

macro_rules! impl_admin_failure {
    ($($error:path),+ $(,)?) => {
        $(impl AdminFailure for $error {
            fn from_storage(failure: storage::DomainFailure) -> Self {
                match failure {
                    storage::DomainFailure::NotFound => Self::RequestNotFound,
                    storage::DomainFailure::EffectNotFound => Self::EffectNotFound,
                    storage::DomainFailure::RevisionConflict => Self::RevisionConflict,
                    storage::DomainFailure::IdempotencyConflict => Self::IdempotencyConflict,
                    storage::DomainFailure::InvalidTransition => Self::InvalidTransition,
                    storage::DomainFailure::RequestExpired => Self::RequestExpired,
                    storage::DomainFailure::OperationInProgress => Self::OperationInProgress,
                    storage::DomainFailure::EffectNotUncertain => Self::EffectNotUncertain,
                    _ => Self::InvalidTransition,
                }
            }
        })+
    };
}

impl_admin_failure!(
    admin::GetRequestError,
    admin::ListRequestsError,
    admin::ApproveError,
    admin::DenyError,
    admin::InspectEffectError,
    admin::ResolveEffectError,
);

trait WorkerFailure: RoleError {
    fn from_storage(failure: storage::DomainFailure) -> Self;
}

macro_rules! impl_worker_failure {
    ($($error:path),+ $(,)?) => {
        $(impl WorkerFailure for $error {
            fn from_storage(failure: storage::DomainFailure) -> Self {
                match failure {
                    storage::DomainFailure::NotFound => Self::RequestNotFound,
                    storage::DomainFailure::EffectNotFound => Self::EffectNotFound,
                    storage::DomainFailure::RevisionConflict => Self::RevisionConflict,
                    storage::DomainFailure::IdempotencyConflict => Self::IdempotencyConflict,
                    storage::DomainFailure::InvalidTransition => Self::InvalidTransition,
                    storage::DomainFailure::RequestNotExpired => Self::RequestNotExpired,
                    storage::DomainFailure::LeaseLost => Self::LeaseLost,
                    storage::DomainFailure::OperationInProgress => Self::OperationInProgress,
                    storage::DomainFailure::EffectUnknown => Self::EffectUnknown,
                    storage::DomainFailure::RetryNotAllowed => Self::RetryNotAllowed,
                    _ => Self::InvalidTransition,
                }
            }
        })+
    };
}

impl_worker_failure!(
    worker::ClaimDueError,
    worker::ProcessError,
    worker::ExpireError,
    worker::RetryError,
);

fn requester_failure<E: RequesterFailure>(failure: storage::DomainFailure) -> E {
    E::from_storage(failure)
}

fn admin_failure<E: AdminFailure>(failure: storage::DomainFailure) -> E {
    E::from_storage(failure)
}

fn worker_failure<E: WorkerFailure>(failure: storage::DomainFailure) -> E {
    E::from_storage(failure)
}

fn project_request<T: DeserializeOwned, E>(record: &storage::RequestRecord) -> PluginResult<T, E> {
    let value = json!({
        "request_id": storage::wire_request_id(record.request_id),
        "organization_id": record.organization_id,
        "requester_subject": record.requester_subject,
        "requester_was_member": record.requester_was_member,
        "bundle_id": record.bundle_id,
        "role": {"mode": record.role_mode, "role_id": record.role_id, "display_name": record.role_name},
        "scope": {"kind": record.scope_kind, "id": record.scope_id, "display_name": record.scope_name},
        "permissions": record.permissions,
        "reason": record.reason,
        "status": record.status,
        "effect_status": record.effect_status,
        "revision": record.revision.to_string(),
        "expires_at": format_timestamp(record.expires_at)?,
        "created_at": format_timestamp(record.created_at)?,
        "updated_at": format_timestamp(record.updated_at)?,
        "decided_by": record.decided_by,
        "decision_note": record.decision_note,
    });
    serde_json::from_value(value).map_err(serialization_runtime)
}

fn project_effect<T: DeserializeOwned, E>(record: &storage::EffectRecord) -> PluginResult<T, E> {
    let value = json!({
        "effect_id": storage::wire_effect_id(record.effect_id),
        "request_id": storage::wire_request_id(record.request_id),
        "sequence": record.sequence,
        "kind": record.kind,
        "status": record.status,
        "revision": record.revision.to_string(),
        "attempts": record.attempts,
        "automatic_retry_allowed": record.automatic_retry_allowed,
        "error_code": record.error_code,
        "policy_revision": record.policy_revision,
        "evidence_reference": record.evidence_reference,
        "lease_until": record.lease_until.map(format_timestamp).transpose()?,
        "created_at": format_timestamp(record.created_at)?,
        "updated_at": format_timestamp(record.updated_at)?,
    });
    serde_json::from_value(value).map_err(serialization_runtime)
}

fn project_job<E>(record: &storage::JobRecord) -> PluginResult<worker::ClaimDueResponseJob, E> {
    serde_json::from_value(json!({
        "job_id": storage::wire_job_id(record),
        "request_id": storage::wire_request_id(record.request_id),
        "organization_id": record.organization_id,
        "kind": record.kind,
        "fence": record.fence.to_string(),
        "lease_token": record.lease_token.to_string(),
        "lease_until": format_timestamp(record.lease_until)?,
    }))
    .map_err(serialization_runtime)
}

fn project_process<T: DeserializeOwned, E>(result: &storage::ProcessResult) -> PluginResult<T, E> {
    serde_json::from_value(json!({
        "request_id": storage::wire_request_id(result.request_id),
        "request_status": result.request_status,
        "request_revision": result.request_revision.to_string(),
        "job_status": result.job_status,
        "automatic_retry_allowed": result.automatic_retry_allowed,
    }))
    .map_err(serialization_runtime)
}

fn parse_request_identity<E: RoleError>(
    organization_id: &str,
    request_id: &str,
) -> PluginResult<Uuid, E> {
    if !valid_identifier(organization_id, MAX_ID_BYTES) {
        return Err(PluginError::domain(E::invalid_request()));
    }
    storage::request_id(request_id).ok_or_else(|| PluginError::domain(E::invalid_request()))
}

fn parse_effect_identity<E: RoleError>(effect_id: &str) -> PluginResult<Uuid, E> {
    storage::effect_id(effect_id).ok_or_else(|| PluginError::domain(E::invalid_request()))
}

fn parse_revision<E: RoleError>(value: &str) -> PluginResult<i64, E> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| PluginError::domain(E::invalid_request()))
}

fn parse_cursor<E: RoleError>(value: Option<&str>) -> PluginResult<Option<storage::Cursor>, E> {
    value
        .map(|value| {
            storage::decode_cursor(value).ok_or_else(|| PluginError::domain(E::invalid_request()))
        })
        .transpose()
}

fn enum_wire<T: Serialize, E>(value: &T) -> PluginResult<String, E> {
    serde_json::to_value(value)
        .map_err(serialization_runtime)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| PluginError::runtime(dependency_failure("generated enum was not a string")))
}

fn hash_value<T: Serialize>(value: &T) -> Result<Vec<u8>, RuntimeFailure> {
    serde_json::to_vec(value)
        .map(|value| Sha256::digest(value).to_vec())
        .map_err(|error| dependency_failure(format!("request hashing failed: {error}")))
}

fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn format_timestamp<E>(value: OffsetDateTime) -> PluginResult<String, E> {
    value.format(&Rfc3339).map_err(|error| {
        PluginError::runtime(dependency_failure(format!(
            "stored timestamp cannot be formatted: {error}"
        )))
    })
}

fn allowed_caller(context: &Ctx, allowed: &[String]) -> Option<String> {
    context.caller_instance().and_then(|caller| {
        allowed
            .iter()
            .any(|entry| entry == caller)
            .then(|| caller.to_owned())
    })
}

fn valid_callers(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_CALLERS
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
        && values.iter().all(|value| valid_identifier(value, 200))
}

fn validate_callers(values: &[String]) -> Result<(), ()> {
    valid_callers(values).then_some(()).ok_or(())
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty()) && value.len() <= max_bytes && !value.contains('\0')
}

fn valid_secret_reference(value: &str) -> bool {
    valid_identifier(value, 240)
}

fn valid_idempotency_key(value: &str) -> bool {
    valid_identifier(value, MAX_IDEMPOTENCY_BYTES)
}

fn valid_email(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 320
        && !value.contains(['\0', '\r', '\n', ' '])
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

#[allow(clippy::needless_pass_by_value)]
fn storage_runtime<E>(error: storage::StorageError) -> PluginError<E> {
    PluginError::runtime(dependency_failure(error.to_string()))
}

#[allow(clippy::needless_pass_by_value)]
fn serialization_runtime<E>(error: serde_json::Error) -> PluginError<E> {
    PluginError::runtime(dependency_failure(format!(
        "Access Request wire projection failed: {error}"
    )))
}

fn dependency_failure(detail: impl Into<String>) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.into(),
    }
}

const fn default_expiring_lead_seconds() -> i64 {
    DEFAULT_EXPIRING_LEAD_SECONDS
}

const fn default_max_notification_attempts() -> i32 {
    DEFAULT_MAX_NOTIFICATION_ATTEMPTS
}

const fn default_notification_retry_seconds() -> i64 {
    DEFAULT_NOTIFICATION_RETRY_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_auth_sdk::{ActorAssertionIssuer, Validity, audience};
    use lenso_kernel::{CancellationToken, InvocationContext};
    use lenso_native_adapter::NativePluginRegistry;
    use time::Duration as TimeDuration;

    fn config() -> AccessRequestConfig {
        let issuer = ActorAssertionIssuer::new("auth.users", b"access-request-test-key");
        AccessRequestConfig {
            schema: "access_request".to_owned(),
            database_url_secret: "access-request/database-url".to_owned(),
            auth_issuer: "auth.users".to_owned(),
            auth_assertion_public_key: issuer.public_key_base64(),
            requester_callers: vec!["access-request-api".to_owned()],
            admin_callers: vec!["access-request-admin".to_owned()],
            worker_callers: vec!["access-request-worker".to_owned()],
            requestable_bundles: vec![RequestableBundle {
                bundle_id: "project-reader".to_owned(),
                role_mode: BundleRoleMode::Existing,
                role_id: "project_reader".to_owned(),
                role_name: "Project reader".to_owned(),
                scope_kind: "project".to_owned(),
                permissions: vec!["project.read".to_owned()],
                allow_non_members: false,
            }],
            expiring_lead_seconds: DEFAULT_EXPIRING_LEAD_SECONDS,
            max_notification_attempts: DEFAULT_MAX_NOTIFICATION_ATTEMPTS,
            notification_retry_seconds: DEFAULT_NOTIFICATION_RETRY_SECONDS,
        }
    }

    fn context(caller: &str) -> InvocationContext {
        InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(caller)
    }

    #[test]
    fn descriptor_has_three_roles_and_exact_typed_dependencies() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let provided = descriptor["provided_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            provided,
            BTreeSet::from([
                requester::CAPABILITY_ID,
                admin::CAPABILITY_ID,
                worker::CAPABILITY_ID,
            ])
        );
        let required = descriptor["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            required,
            BTreeSet::from([
                secrets::CAPABILITY_ID,
                directory::CAPABILITY_ID,
                membership::CAPABILITY_ID,
                access::CAPABILITY_ID,
                access_admin::CAPABILITY_ID,
                notification::CAPABILITY_ID,
            ])
        );
        assert_eq!(access_admin::CAPABILITY_ID, "lenso.access-control-admin@1");
        assert_eq!(notification::DESCRIPTOR_VERSION, "1.1.0");
        assert_eq!(
            NativePluginRegistry::new()
                .with_linked_factories()
                .factories()
                .filter(|factory| factory.package_id() == PACKAGE_ID)
                .count(),
            1
        );
    }

    #[test]
    fn configuration_rejects_role_overlap_and_permission_expansion_ambiguity() {
        let mut invalid = config();
        invalid.admin_callers = invalid.requester_callers.clone();
        assert_eq!(
            invalid.validate(),
            Err(AccessRequestConfigError::OverlappingCallers)
        );
        let mut invalid = config();
        invalid.requestable_bundles[0].permissions =
            vec!["project.write".to_owned(), "project.read".to_owned()];
        assert_eq!(
            invalid.validate(),
            Err(AccessRequestConfigError::InvalidBundles)
        );
        let mut invalid = config();
        let mut overlapping = invalid.requestable_bundles[0].clone();
        overlapping.bundle_id = "project-reader-alias".to_owned();
        invalid.requestable_bundles.push(overlapping);
        assert_eq!(
            invalid.validate(),
            Err(AccessRequestConfigError::InvalidBundles)
        );
    }

    #[test]
    fn actor_assertions_are_bound_to_exact_role_and_operation() {
        let issuer = ActorAssertionIssuer::new("auth.users", b"access-request-test-key");
        let now = OffsetDateTime::now_utc();
        let assertion = issuer.issue(
            "usr_requester",
            "user",
            "strong",
            [audience(
                requester::CAPABILITY_ID,
                requester::CREATE_OPERATION,
            )],
            Validity::new(
                now - TimeDuration::seconds(1),
                now + TimeDuration::minutes(1),
            )
            .unwrap(),
            std::collections::BTreeMap::new(),
        );
        let plugin = PostgresAccessRequestPlugin {
            config: config(),
            secrets: Port::default(),
            directory: Port::default(),
            membership: Port::default(),
            access: Port::default(),
            access_admin: Port::default(),
            notification: Port::default(),
            prepared: Rc::new(RefCell::new(None)),
        };
        let context = assertion.attach(context("access-request-api")).unwrap();
        assert_eq!(
            plugin.authenticated_actor(
                &context,
                requester::CAPABILITY_ID,
                requester::CREATE_OPERATION,
            ),
            Ok("usr_requester".to_owned())
        );
        assert!(
            plugin
                .authenticated_actor(&context, admin::CAPABILITY_ID, admin::APPROVE_OPERATION)
                .is_err()
        );
    }

    #[test]
    fn sensitive_reason_note_recipient_and_lease_token_are_redacted() {
        let recipient = requester::CreateRequestRecipient {
            address: "sensitive@example.test".to_owned(),
            display_name: Some("Sensitive User".to_owned()),
            locale: requester::CreateRequestRecipientLocale::En,
        };
        let rendered = format!("{recipient:?}");
        assert!(!rendered.contains("sensitive@example.test"));
        assert!(!rendered.contains("Sensitive User"));
        let create: requester::CreateRequest = serde_json::from_value(json!({
            "bundle_id": "project-reader",
            "expires_at": "2030-01-01T00:00:00Z",
            "idempotency_key": "create-redaction",
            "organization_id": "org_1",
            "reason": "confidential customer assignment",
            "recipient": {
                "address": "sensitive@example.test",
                "display_name": "Sensitive User",
                "locale": "en"
            },
            "scope": {"kind": "project", "id": "project_1", "display_name": null}
        }))
        .unwrap();
        let rendered = format!("{create:?}");
        assert!(!rendered.contains("confidential customer assignment"));
        assert!(!rendered.contains("sensitive@example.test"));
        let approve: admin::ApproveRequest = serde_json::from_value(json!({
            "expected_revision": "1",
            "idempotency_key": "approve-redaction",
            "note": "confidential review note",
            "organization_id": "org_1",
            "request_id": "ar_00000000-0000-0000-0000-000000000001"
        }))
        .unwrap();
        assert!(!format!("{approve:?}").contains("confidential review note"));
        let job: worker::ClaimDueResponseJob = serde_json::from_value(json!({
            "job_id": "are_00000000-0000-0000-0000-000000000001",
            "request_id": "ar_00000000-0000-0000-0000-000000000002",
            "organization_id": "org_1",
            "kind": "access_effect",
            "fence": "1",
            "lease_token": "00000000-0000-0000-0000-000000000003",
            "lease_until": "2030-01-01T00:00:00Z"
        }))
        .unwrap();
        assert!(!format!("{job:?}").contains("00000000-0000-0000-0000-000000000003"));
    }
}
