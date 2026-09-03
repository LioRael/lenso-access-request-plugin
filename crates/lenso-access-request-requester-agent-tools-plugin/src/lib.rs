//! Agent-facing requester Tools over an explicitly bound Access Request capability.

use lenso::prelude::*;
use lenso_capability_access_request_requester::{
    self as requester, CancelRequest, CreateRequest, GetRequest, ListRequest,
};
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const CREATE_TOOL: &str = "access_request_create";
pub const GET_TOOL: &str = "access_request_get";
pub const LIST_TOOL: &str = "access_request_list";
pub const CANCEL_TOOL: &str = "access_request_cancel";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct AccessRequestRequesterAgentToolsPlugin {
    requester: Port<requester::RequesterClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl AccessRequestRequesterAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        macro_rules! invoke {
            ($future:expr, $tool:expr, $domain:path, $runtime:path) => {
                match $future.await {
                    Ok(response) => success($tool, &response),
                    Err($domain(error)) => Err(PluginError::domain(map_domain_error(&error))),
                    Err($runtime(error)) => Err(PluginError::runtime(error)),
                }
            };
        }

        match request.name.as_str() {
            GET_TOOL => {
                let arguments = decode::<GetRequest>(&request)?;
                invoke!(
                    self.requester.get_with_context(context, arguments),
                    GET_TOOL,
                    requester::RequesterGetInvocationError::Domain,
                    requester::RequesterGetInvocationError::Runtime
                )
            }
            LIST_TOOL => {
                let arguments = decode::<ListRequest>(&request)?;
                invoke!(
                    self.requester.list_with_context(context, arguments),
                    LIST_TOOL,
                    requester::RequesterListInvocationError::Domain,
                    requester::RequesterListInvocationError::Runtime
                )
            }
            CREATE_TOOL => {
                let arguments = decode::<CreateRequest>(&request)?;
                invoke!(
                    self.requester.create_with_context(context, arguments),
                    CREATE_TOOL,
                    requester::RequesterCreateInvocationError::Domain,
                    requester::RequesterCreateInvocationError::Runtime
                )
            }
            CANCEL_TOOL => {
                let arguments = decode::<CancelRequest>(&request)?;
                invoke!(
                    self.requester.cancel_with_context(context, arguments),
                    CANCEL_TOOL,
                    requester::RequesterCancelInvocationError::Domain,
                    requester::RequesterCancelInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET_TOOL,
            "Get one access request owned by the authenticated requester.",
            include_str!(
                "../../lenso-capability-access-request-requester/schemas/get-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_TOOL,
            "List access requests owned by the authenticated requester with bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-access-request-requester/schemas/list-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            CREATE_TOOL,
            "Request one configured access bundle. Reuse the same idempotency_key when retrying the same intent.",
            include_str!(
                "../../lenso-capability-access-request-requester/schemas/create-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            CANCEL_TOOL,
            "Cancel a pending owned request using its current expected_revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-access-request-requester/schemas/cancel-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value = serde_json::from_str(schema)
        .expect("Access Request requester Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Access Request requester Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!(
                "Access Request requester Tool could not serialize its typed response: {error}"
            ),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Access Request requester Tool metadata must be valid JSON"),
    })
}

trait DomainToolError {
    fn to_tool_error(&self) -> ExecuteError;
}

fn map_domain_error(error: &impl DomainToolError) -> ExecuteError {
    error.to_tool_error()
}

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Access Request rejected the requester operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Access Request requester Tool error metadata must be valid JSON"),
        },
    }
}

macro_rules! impl_requester_error {
    ($($error:ty),+ $(,)?) => {
        $(
            impl DomainToolError for $error {
                fn to_tool_error(&self) -> ExecuteError {
                    match self {
                        Self::InvalidRequest => ExecuteError::InvalidArguments,
                        Self::OrganizationNotFound | Self::RequestNotFound => ExecuteError::NotFound,
                        Self::Forbidden | Self::Unauthenticated => ExecuteError::PermissionDenied,
                        Self::AccessAlreadyGranted => rejected("access_already_granted"),
                        Self::ActiveRequestConflict => rejected("active_request_conflict"),
                        Self::BundleNotRequestable => rejected("bundle_not_requestable"),
                        Self::IdempotencyConflict => rejected("idempotency_conflict"),
                        Self::InvalidTransition => rejected("invalid_transition"),
                        Self::RequestExpired => rejected("request_expired"),
                        Self::RevisionConflict => rejected("revision_conflict"),
                        Self::ScopeNotRequestable => rejected("scope_not_requestable"),
                        Self::Unknown(_) => rejected("unknown_domain_error"),
                    }
                }
            }
        )+
    };
}

impl_requester_error!(
    requester::CreateError,
    requester::GetError,
    requester::ListError,
    requester::CancelError,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_requires_only_the_requester_capability() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.access-request.requester.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(
            required[0]["capability_id"],
            "lenso.access-request.requester@1"
        );
    }

    #[test]
    fn catalog_has_two_reads_and_two_mutations_without_worker_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 4);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            2
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            2
        );
        assert!(tools.iter().all(|tool| !tool.name.contains("worker")));
    }

    #[test]
    fn exact_request_decodes_and_domain_failures_stay_distinct() {
        let get = decode::<GetRequest>(&request(
            GET_TOOL,
            r#"{"organization_id":"org-1","request_id":"request-1"}"#,
        ))
        .unwrap();
        assert_eq!(get.request_id, "request-1");
        assert!(decode::<GetRequest>(&request(GET_TOOL, r#"{"request_id":42}"#)).is_err());

        assert_eq!(
            map_domain_error(&requester::GetError::Forbidden),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            map_domain_error(&requester::GetError::RequestNotFound),
            ExecuteError::NotFound
        );
        let ExecuteError::ExecutionFailed { payload } =
            map_domain_error(&requester::CancelError::RevisionConflict)
        else {
            panic!("revision conflict must remain an execution failure");
        };
        assert_eq!(payload.reason_code, "revision_conflict");
    }
}
