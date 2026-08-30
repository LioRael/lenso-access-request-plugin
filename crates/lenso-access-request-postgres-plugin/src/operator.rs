use lenso_postgres_kit::{PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome};
use thiserror::Error;

use crate::schema::schema_plan;

/// Explicit, operator-owned schema administration for Access Request storage.
#[derive(Clone, Copy, Debug, Default)]
pub struct AccessRequestOperator;

impl AccessRequestOperator {
    /// Creates the owned schema and installs all authored migrations.
    pub async fn setup(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, AccessRequestOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .setup()
            .await?)
    }

    /// Applies pending authored migrations. Plugin activation never performs this work.
    pub async fn upgrade(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, AccessRequestOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .upgrade()
            .await?)
    }
}

/// Operator failure.
#[derive(Debug, Error)]
pub enum AccessRequestOperatorError {
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
}
