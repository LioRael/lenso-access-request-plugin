use std::env;

use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, postgres::PgPoolOptions};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{AccessRequestOperator, schema, storage};

const DATABASE_ENV: &str = "LENSO_ACCESS_REQUEST_TEST_DATABASE_URL";

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn postgres_restart_concurrency_cas_expiry_and_effect_fencing() {
    let Some(base_url) = env::var(DATABASE_ENV).ok() else {
        eprintln!("skipping PostgreSQL acceptance; {DATABASE_ENV} is not set");
        return;
    };
    let (admin_url, prefix) = base_url
        .rsplit_once('/')
        .expect("test database URL must contain a database path");
    let database = format!("lenso_access_request_test_{}", Uuid::new_v4().simple());
    let target_url = format!("{admin_url}/{database}");
    let admin_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!("{admin_url}/{prefix}"))
        .await
        .unwrap();
    // `database` is generated from UUID hex and contains no user-controlled characters.
    sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{database}\"")))
        .execute(&admin_pool)
        .await
        .unwrap();

    let schema_name = "access_request_acceptance";
    AccessRequestOperator::setup(&target_url, schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &target_url,
        schema::schema_plan(schema_name.to_owned()).unwrap(),
    )
    .await
    .unwrap();

    let expiry = OffsetDateTime::now_utc() + Duration::days(7);
    let (left, right) = tokio::join!(
        create(
            &postgres,
            "idem-concurrent-a",
            b"hash-concurrent-a",
            b"same-fingerprint",
            "org_concurrent",
            "usr_requester",
            "project-reader",
            "project",
            "project_1",
            expiry,
        ),
        create(
            &postgres,
            "idem-concurrent-b",
            b"hash-concurrent-b",
            b"same-fingerprint",
            "org_concurrent",
            "usr_requester",
            "project-reader",
            "project",
            "project_1",
            expiry,
        )
    );
    let left = left.unwrap().unwrap();
    let right = right.unwrap().unwrap();
    assert_eq!(left.request.request_id, right.request.request_id);
    assert_eq!(usize::from(left.created) + usize::from(right.created), 1);
    assert_eq!(usize::from(left.merged) + usize::from(right.merged), 1);

    let replay = create(
        &postgres,
        "idem-concurrent-a",
        b"hash-concurrent-a",
        b"same-fingerprint",
        "org_concurrent",
        "usr_requester",
        "project-reader",
        "project",
        "project_1",
        expiry,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(replay, left);
    let conflict = create(
        &postgres,
        "idem-conflict",
        b"hash-conflict",
        b"different-fingerprint",
        "org_concurrent",
        "usr_requester",
        "project-reader",
        "project",
        "project_1",
        expiry,
    )
    .await
    .unwrap();
    assert!(matches!(
        conflict,
        Err(storage::DomainFailure::ActiveRequestConflict)
    ));

    postgres.pool().close().await;
    let postgres = OwnedPostgres::prepare(
        &target_url,
        schema::schema_plan(schema_name.to_owned()).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        storage::get_request(&postgres, "org_concurrent", left.request.request_id,)
            .await
            .unwrap()
            .is_some()
    );

    let stale_cancel = storage::cancel_request(
        &postgres,
        "api",
        "usr_requester",
        "cancel-stale",
        b"cancel-stale",
        "org_concurrent",
        left.request.request_id,
        99,
    )
    .await
    .unwrap();
    assert!(matches!(
        stale_cancel,
        Err(storage::DomainFailure::RevisionConflict)
    ));
    let cancelled = storage::cancel_request(
        &postgres,
        "api",
        "usr_requester",
        "cancel-ok",
        b"cancel-ok",
        "org_concurrent",
        left.request.request_id,
        1,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(cancelled.status, "cancelled");

    let approval = create(
        &postgres,
        "create-approval",
        b"create-approval",
        b"approval-fingerprint",
        "org_approval",
        "usr_target",
        "project-reader",
        "project",
        "project_2",
        expiry,
    )
    .await
    .unwrap()
    .unwrap()
    .request;
    let (decision_a, decision_b) = tokio::join!(
        storage::approve_request(
            &postgres,
            "admin-api",
            "usr_admin_a",
            "approve-a",
            b"approve-a",
            "org_approval",
            approval.request_id,
            1,
            None,
        ),
        storage::approve_request(
            &postgres,
            "admin-api",
            "usr_admin_b",
            "approve-b",
            b"approve-b",
            "org_approval",
            approval.request_id,
            1,
            None,
        )
    );
    let decision_a = decision_a.unwrap();
    let decision_b = decision_b.unwrap();
    assert_eq!(
        usize::from(decision_a.is_ok()) + usize::from(decision_b.is_ok()),
        1
    );

    let first_claim = storage::claim_due(
        &postgres,
        "worker-api",
        "worker-a",
        "claim-first",
        b"claim-first",
        15,
        10,
    )
    .await
    .unwrap()
    .unwrap()
    .expect("approved request should expose an effect");
    assert_eq!(first_claim.kind, "access_effect");
    let process_start = storage::begin_process(
        &postgres,
        "worker-api",
        "process-uncertain",
        b"process-uncertain",
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(process_start, storage::ProcessStart::Execute));
    let process_replay = storage::begin_process(
        &postgres,
        "worker-api",
        "process-uncertain",
        b"process-uncertain",
    )
    .await
    .unwrap();
    assert!(matches!(
        process_replay,
        Err(storage::DomainFailure::OperationInProgress)
    ));
    sqlx::query("UPDATE access_request_effects SET lease_until=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE effect_id=$1")
        .bind(first_claim.job_id)
        .execute(postgres.pool())
        .await
        .unwrap();
    let _ = storage::claim_due(
        &postgres,
        "worker-api",
        "worker-b",
        "claim-after-expiry",
        b"claim-after-expiry",
        15,
        10,
    )
    .await
    .unwrap()
    .unwrap();
    let uncertain = storage::inspect_effect(
        &postgres,
        "org_approval",
        approval.request_id,
        first_claim.job_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(uncertain.status, "unknown");
    assert!(!uncertain.automatic_retry_allowed);
    let stale_fence = storage::complete_effect(
        &postgres,
        "worker-api",
        first_claim.job_id,
        first_claim.lease_token,
        first_claim.fence,
        &storage::EffectOutcome::Succeeded {
            policy_revision: "2".to_owned(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        stale_fence,
        Err(storage::DomainFailure::LeaseLost)
    ));

    let retry_request = create(
        &postgres,
        "create-retry",
        b"create-retry",
        b"retry-fingerprint",
        "org_retry",
        "usr_retry",
        "project-reader",
        "project",
        "project_3",
        expiry,
    )
    .await
    .unwrap()
    .unwrap()
    .request;
    storage::approve_request(
        &postgres,
        "admin-api",
        "usr_admin",
        "approve-retry",
        b"approve-retry",
        "org_retry",
        retry_request.request_id,
        1,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let retry_claim = storage::claim_due(
        &postgres,
        "worker-api",
        "worker-c",
        "claim-retry",
        b"claim-retry",
        60,
        10,
    )
    .await
    .unwrap()
    .unwrap()
    .expect("retry scenario should expose an effect");
    storage::complete_effect(
        &postgres,
        "worker-api",
        retry_claim.job_id,
        retry_claim.lease_token,
        retry_claim.fence,
        &storage::EffectOutcome::Failed {
            error_code: "scope_not_bootstrapped".to_owned(),
            retry_allowed: true,
        },
    )
    .await
    .unwrap()
    .unwrap();
    let failed = storage::inspect_effect(
        &postgres,
        "org_retry",
        retry_request.request_id,
        retry_claim.job_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(failed.automatic_retry_allowed);
    let retried = storage::retry_effect(
        &postgres,
        "worker-api",
        "retry-known",
        b"retry-known",
        "org_retry",
        retry_request.request_id,
        retry_claim.job_id,
        failed.revision,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(retried.status, "pending");

    let retry_claim = storage::claim_due(
        &postgres,
        "worker-api",
        "worker-d",
        "claim-retried-effect",
        b"claim-retried-effect",
        60,
        10,
    )
    .await
    .unwrap()
    .unwrap()
    .expect("explicitly retried effect should become claimable");
    assert_eq!(retry_claim.job_id, retried.effect_id);
    let provisioning = storage::complete_effect(
        &postgres,
        "worker-api",
        retry_claim.job_id,
        retry_claim.lease_token,
        retry_claim.fence,
        &storage::EffectOutcome::Succeeded {
            policy_revision: "11".to_owned(),
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(provisioning.status, "provisioning");

    let binding_claim = storage::claim_due(
        &postgres,
        "worker-api",
        "worker-d",
        "claim-binding-effect",
        b"claim-binding-effect",
        60,
        10,
    )
    .await
    .unwrap()
    .unwrap()
    .expect("ordered binding effect should follow the role effect");
    assert_eq!(binding_claim.request_id, retry_request.request_id);
    let approved = storage::complete_effect(
        &postgres,
        "worker-api",
        binding_claim.job_id,
        binding_claim.lease_token,
        binding_claim.fence,
        &storage::EffectOutcome::Succeeded {
            policy_revision: "12".to_owned(),
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(approved.status, "approved");
    let approved_intents = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM access_request_notifications WHERE request_id=$1 AND event='approved'",
    )
    .bind(retry_request.request_id)
    .fetch_one(postgres.pool())
    .await
    .unwrap();
    assert_eq!(approved_intents, 1);

    let denied_request = create(
        &postgres,
        "create-denied",
        b"create-denied",
        b"denied-fingerprint",
        "org_denied",
        "usr_denied",
        "project-reader",
        "project",
        "project_denied",
        expiry,
    )
    .await
    .unwrap()
    .unwrap()
    .request;
    let denied = storage::deny_request(
        &postgres,
        "admin-api",
        "usr_admin",
        "deny-request",
        b"deny-request",
        "org_denied",
        denied_request.request_id,
        1,
        Some("not required"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(denied.status, "denied");
    let denied_intents = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM access_request_notifications WHERE request_id=$1 AND event='denied'",
    )
    .bind(denied_request.request_id)
    .fetch_one(postgres.pool())
    .await
    .unwrap();
    assert_eq!(denied_intents, 1);

    let expired = create(
        &postgres,
        "create-expired",
        b"create-expired",
        b"expired-fingerprint",
        "org_expired",
        "usr_expired",
        "project-reader",
        "project",
        "project_4",
        OffsetDateTime::now_utc() - Duration::minutes(1),
    )
    .await
    .unwrap()
    .unwrap()
    .request;
    let expired = storage::expire_request(
        &postgres,
        "worker-api",
        "expire-now",
        b"expire-now",
        "org_expired",
        expired.request_id,
        1,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(expired.status, "expired");

    postgres.pool().close().await;
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()")
        .bind(&database)
        .execute(&admin_pool)
        .await
        .unwrap();
    // `database` is generated from UUID hex and contains no user-controlled characters.
    sqlx::query(AssertSqlSafe(format!("DROP DATABASE \"{database}\"")))
        .execute(&admin_pool)
        .await
        .unwrap();
    admin_pool.close().await;
}

#[allow(clippy::too_many_arguments)]
async fn create(
    postgres: &OwnedPostgres,
    idempotency_key: &str,
    request_hash: &[u8],
    fingerprint: &[u8],
    organization_id: &str,
    requester: &str,
    bundle_id: &str,
    scope_kind: &str,
    scope_id: &str,
    expires_at: OffsetDateTime,
) -> Result<Result<storage::CreateResult, storage::DomainFailure>, storage::StorageError> {
    storage::create_request(
        postgres,
        &storage::CreateInput {
            caller: "requester-api",
            actor: requester,
            idempotency_key,
            request_hash,
            fingerprint,
            organization_id,
            requester_was_member: true,
            bundle_id,
            role_mode: "existing",
            role_id: "project_reader",
            role_name: "Project reader",
            scope_kind,
            scope_id,
            scope_name: Some("Project"),
            permissions: &["project.read".to_owned()],
            reason: "Need access for assigned work",
            recipient_address: "requester@example.test",
            recipient_display_name: Some("Requester"),
            recipient_locale: "en",
            expires_at,
            expiring_lead_seconds: 86_400,
        },
    )
    .await
}
