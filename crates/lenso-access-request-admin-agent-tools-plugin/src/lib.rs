//! Agent-facing reviewer Tools over an explicitly bound Access Request Admin capability.

use lenso::prelude::*;
use lenso_capability_access_request_admin::{
    self as admin, ApproveRequest, DenyRequest, GetRequestRequest, InspectEffectRequest,
    ListRequestsRequest,
};
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const GET_REQUEST_TOOL: &str = "access_request_admin_get_request";
pub const LIST_REQUESTS_TOOL: &str = "access_request_admin_list_requests";
pub const APPROVE_TOOL: &str = "access_request_admin_approve";
pub const DENY_TOOL: &str = "access_request_admin_deny";
pub const INSPECT_EFFECT_TOOL: &str = "access_request_admin_inspect_effect";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct AccessRequestAdminAgentToolsPlugin {
    admin: Port<admin::AdminClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl AccessRequestAdminAgentToolsPlugin {
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
            GET_REQUEST_TOOL => {
                let arguments = decode::<GetRequestRequest>(&request)?;
                invoke!(
                    self.admin.get_request_with_context(context, arguments),
                    GET_REQUEST_TOOL,
                    admin::AdminGetRequestInvocationError::Domain,
                    admin::AdminGetRequestInvocationError::Runtime
                )
            }
            LIST_REQUESTS_TOOL => {
                let arguments = decode::<ListRequestsRequest>(&request)?;
                invoke!(
                    self.admin.list_requests_with_context(context, arguments),
                    LIST_REQUESTS_TOOL,
                    admin::AdminListRequestsInvocationError::Domain,
                    admin::AdminListRequestsInvocationError::Runtime
                )
            }
            INSPECT_EFFECT_TOOL => {
                let arguments = decode::<InspectEffectRequest>(&request)?;
                invoke!(
                    self.admin.inspect_effect_with_context(context, arguments),
                    INSPECT_EFFECT_TOOL,
                    admin::AdminInspectEffectInvocationError::Domain,
                    admin::AdminInspectEffectInvocationError::Runtime
                )
            }
            APPROVE_TOOL => {
                let arguments = decode::<ApproveRequest>(&request)?;
                invoke!(
                    self.admin.approve_with_context(context, arguments),
                    APPROVE_TOOL,
                    admin::AdminApproveInvocationError::Domain,
                    admin::AdminApproveInvocationError::Runtime
                )
            }
            DENY_TOOL => {
                let arguments = decode::<DenyRequest>(&request)?;
                invoke!(
                    self.admin.deny_with_context(context, arguments),
                    DENY_TOOL,
                    admin::AdminDenyInvocationError::Domain,
                    admin::AdminDenyInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET_REQUEST_TOOL,
            "Get one organization access request for authorized review.",
            include_str!(
                "../../lenso-capability-access-request-admin/schemas/get-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_REQUESTS_TOOL,
            "List organization access requests for authorized review with bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-access-request-admin/schemas/list-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            INSPECT_EFFECT_TOOL,
            "Inspect the durable state and evidence for one Access Control effect without resolving uncertainty.",
            include_str!(
                "../../lenso-capability-access-request-admin/schemas/inspect-effect-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            APPROVE_TOOL,
            "Approve one pending request using its current expected_revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-access-request-admin/schemas/decision-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            DENY_TOOL,
            "Deny one pending request using its current expected_revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-access-request-admin/schemas/decision-request.schema.json"
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
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Access Request admin Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Access Request admin Tool schema must remain valid JSON"),
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
                "Access Request admin Tool could not serialize its typed response: {error}"
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
            .expect("Access Request admin Tool metadata must be valid JSON"),
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
            message: "Access Request rejected the administrator operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Access Request admin Tool error metadata must be valid JSON"),
        },
    }
}

macro_rules! impl_admin_error {
    ($($error:ty),+ $(,)?) => {
        $(
            impl DomainToolError for $error {
                fn to_tool_error(&self) -> ExecuteError {
                    match self {
                        Self::InvalidRequest => ExecuteError::InvalidArguments,
                        Self::EffectNotFound | Self::OrganizationNotFound | Self::RequestNotFound => ExecuteError::NotFound,
                        Self::AccessDenied
                        | Self::Forbidden
                        | Self::MembershipRequired
                        | Self::Unauthenticated => ExecuteError::PermissionDenied,
                        Self::EffectNotUncertain => rejected("effect_not_uncertain"),
                        Self::IdempotencyConflict => rejected("idempotency_conflict"),
                        Self::InvalidTransition => rejected("invalid_transition"),
                        Self::OperationInProgress => rejected("operation_in_progress"),
                        Self::RequestExpired => rejected("request_expired"),
                        Self::RevisionConflict => rejected("revision_conflict"),
                        Self::SelfApproval => rejected("self_approval"),
                        Self::TargetPolicyConflict => rejected("target_policy_conflict"),
                        Self::Unknown(_) => rejected("unknown_domain_error"),
                    }
                }
            }
        )+
    };
}

impl_admin_error!(
    admin::ApproveError,
    admin::DenyError,
    admin::GetRequestError,
    admin::InspectEffectError,
    admin::ListRequestsError,
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
    fn descriptor_requires_only_the_admin_capability() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.access-request.admin.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.access-request.admin@1");
    }

    #[test]
    fn catalog_has_three_reads_and_two_mutations_without_recovery_or_worker_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 5);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            3
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            2
        );
        assert!(tools.iter().all(|tool| {
            !tool.name.contains("resolve_effect") && !tool.name.contains("worker")
        }));
    }

    #[test]
    fn exact_request_decodes_and_domain_failures_stay_distinct() {
        let get = decode::<GetRequestRequest>(&request(
            GET_REQUEST_TOOL,
            r#"{"organization_id":"org-1","request_id":"request-1"}"#,
        ))
        .unwrap();
        assert_eq!(get.request_id, "request-1");
        assert!(
            decode::<GetRequestRequest>(&request(GET_REQUEST_TOOL, r#"{"request_id":42}"#))
                .is_err()
        );

        assert_eq!(
            map_domain_error(&admin::GetRequestError::AccessDenied),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            map_domain_error(&admin::InspectEffectError::EffectNotFound),
            ExecuteError::NotFound
        );
        let ExecuteError::ExecutionFailed { payload } =
            map_domain_error(&admin::ApproveError::SelfApproval)
        else {
            panic!("self approval must remain an execution failure");
        };
        assert_eq!(payload.reason_code, "self_approval");
    }
}
