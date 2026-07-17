//! Authenticated, stateless Streamable HTTP MCP boundary.
//!
//! MCP is intentionally a read-only Owner management surface in this first
//! slice. It exposes the existing non-secret Connector projection and never
//! accepts Agent prompts, route capsules, mailbox capabilities, or credentials.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use dtx_domain::{ChannelId, ConversationId, TenantId};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
};
use dtx_public_feed::{PublicFeedPayloadV1, SignedPublicFeedEventV1};
use dtx_storage::PgStore;
use dtx_wire::UtcMillis;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::Row;

use crate::{
    AgentProvisioningOwnerBackend, AgentProvisioningOwnerError, ConnectorProjectionQueryV1,
    DEFAULT_CONNECTOR_PROJECTION_LIMIT,
    owner_http::{CborOwnerReply, parse_device_session},
};

const MCP_PATH: &str = "/mcp";
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MCP_JSON_MEDIA_TYPE: &str = "application/json";
const MCP_SSE_MEDIA_TYPE: &str = "text/event-stream";
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const MAX_MCP_BODY_BYTES: usize = 64 * 1024;
const CONNECTORS_TOOL_NAME: &str = "dirextalk.list_connectors";
const REFERENCES_TOOL_NAME: &str = "dirextalk.query_references";
const CONNECTORS_RESOURCE_URI: &str = "dirextalk://connectors";
const MCP_REFERENCES_MEDIA_TYPE_V1: &str = "application/vnd.dirextalk.mcp-references.v1+json";
const MAX_REFERENCE_QUERY_BYTES: usize = 256;
const MAX_REFERENCES: u16 = 32;
const MAX_POST_SCAN: i32 = 256;
const MAX_REFERENCE_TITLE_CHARS: usize = 120;
const CHANNEL_ID_SCHEMA_PATTERN: &str = "^dtxc1[a-z2-7]{51}[aq]$";
const POST_ID_SCHEMA_PATTERN: &str = "^dtxc1[a-z2-7]{51}[aq]:[1-9][0-9]{0,15}$";
const REFERENCE_KIND_ROOM: u8 = 1;
const REFERENCE_KIND_CHANNEL: u8 = 2;
const REFERENCE_KIND_POST: u8 = 4;
const REFERENCE_KIND_ALL: u8 = REFERENCE_KIND_ROOM | REFERENCE_KIND_CHANNEL | REFERENCE_KIND_POST;

type McpBackendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CborOwnerReply, AgentProvisioningOwnerError>> + Send + 'a>>;

trait McpOwnerBackend: Send + Sync + 'static {
    fn connector_projection(
        &self,
        credential: DeviceSessionCredential,
        now: UtcMillis,
    ) -> McpBackendFuture<'_>;
    fn references(
        &self,
        credential: DeviceSessionCredential,
        query: String,
        kind_mask: u8,
        limit: u16,
        now: UtcMillis,
    ) -> McpBackendFuture<'_>;
}

struct AgentProvisioningMcpBackend {
    backend: Arc<dyn AgentProvisioningOwnerBackend>,
}

impl McpOwnerBackend for AgentProvisioningMcpBackend {
    fn connector_projection(
        &self,
        credential: DeviceSessionCredential,
        now: UtcMillis,
    ) -> McpBackendFuture<'_> {
        self.backend.list_connectors_v4(
            credential,
            ConnectorProjectionQueryV1 {
                after: None,
                limit: DEFAULT_CONNECTOR_PROJECTION_LIMIT,
            },
            now,
        )
    }

    fn references(
        &self,
        credential: DeviceSessionCredential,
        query: String,
        kind_mask: u8,
        limit: u16,
        now: UtcMillis,
    ) -> McpBackendFuture<'_> {
        self.backend
            .query_mcp_references(credential, query, kind_mask, limit, now)
    }
}

pub(crate) fn mcp_router(backend: Arc<dyn AgentProvisioningOwnerBackend>) -> Router {
    let backend: Arc<dyn McpOwnerBackend> = Arc::new(AgentProvisioningMcpBackend { backend });
    mcp_router_with_backend(backend)
}

fn mcp_router_with_backend(backend: Arc<dyn McpOwnerBackend>) -> Router {
    Router::new()
        .route(MCP_PATH, post(post_mcp))
        .layer(DefaultBodyLimit::max(MAX_MCP_BODY_BYTES))
        .with_state(backend)
}

async fn post_mcp(
    State(backend): State<Arc<dyn McpOwnerBackend>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let credential = match validate_http_boundary(&headers, &body) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    let request = match parse_request(&body) {
        Ok(request) => request,
        Err(error) => return json_rpc_error_response(StatusCode::BAD_REQUEST, None, error),
    };
    if request.method != "initialize" && !has_protocol_version(&headers) {
        return json_rpc_error_response(
            StatusCode::BAD_REQUEST,
            request.id,
            JsonRpcError::invalid_request("MCP protocol version is required"),
        );
    }

    let authenticated_at = match now() {
        Ok(now) => now,
        Err(error) => return backend_error_response(error),
    };
    let reference_query = parse_reference_query(&request).ok().flatten();
    let data = if let Some(reference_query) = reference_query {
        match backend
            .references(
                credential,
                reference_query.query,
                reference_query.kind_mask,
                reference_query.limit,
                authenticated_at,
            )
            .await
        {
            Ok(reply) => match parse_references(&reply) {
                Ok(references) => DispatchData::References(references),
                Err(error) => return backend_error_response(error),
            },
            Err(error) => return backend_error_response(error),
        }
    } else {
        match backend
            .connector_projection(credential, authenticated_at)
            .await
        {
            Ok(reply) => match parse_projection(&reply) {
                Ok(projection) => DispatchData::ConnectorProjection(projection),
                Err(error) => return backend_error_response(error),
            },
            Err(error) => return backend_error_response(error),
        }
    };
    dispatch(request, &data)
}

fn validate_http_boundary(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<DeviceSessionCredential, HttpBoundaryError> {
    if headers.contains_key(header::ORIGIN) {
        return Err(HttpBoundaryError::Protocol(
            StatusCode::FORBIDDEN,
            JsonRpcError::invalid_request("browser origins are not accepted"),
        ));
    }
    if body.is_empty() || body.len() > MAX_MCP_BODY_BYTES {
        return Err(HttpBoundaryError::Protocol(
            StatusCode::BAD_REQUEST,
            JsonRpcError::invalid_request("request body is outside the accepted bounds"),
        ));
    }
    if !has_exact_content_type(headers) || !accepts_streamable_http(headers) {
        return Err(HttpBoundaryError::Protocol(
            StatusCode::BAD_REQUEST,
            JsonRpcError::invalid_request("Streamable HTTP media types are required"),
        ));
    }
    parse_device_session(headers).map_err(HttpBoundaryError::Backend)
}

enum HttpBoundaryError {
    Protocol(StatusCode, JsonRpcError),
    Backend(AgentProvisioningOwnerError),
}

impl HttpBoundaryError {
    fn into_response(self) -> Response {
        match self {
            Self::Protocol(status, error) => json_rpc_error_response(status, None, error),
            Self::Backend(error) => backend_error_response(error),
        }
    }
}

fn has_exact_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    values.next().is_some_and(|value| {
        values.next().is_none() && value.as_bytes() == MCP_JSON_MEDIA_TYPE.as_bytes()
    })
}

fn accepts_streamable_http(headers: &HeaderMap) -> bool {
    let mut saw_json = false;
    let mut saw_sse = false;
    for value in headers.get_all(header::ACCEPT) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for item in value.split(',').map(str::trim) {
            let media_type = item.split(';').next().map(str::trim).unwrap_or_default();
            saw_json |= media_type == MCP_JSON_MEDIA_TYPE;
            saw_sse |= media_type == MCP_SSE_MEDIA_TYPE;
        }
    }
    saw_json && saw_sse
}

fn has_protocol_version(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(MCP_PROTOCOL_VERSION_HEADER).iter();
    values.next().is_some_and(|value| {
        values.next().is_none() && value.as_bytes() == MCP_PROTOCOL_VERSION.as_bytes()
    })
}

struct JsonRpcRequest {
    id: Option<Value>,
    method: String,
    params: Value,
}

fn parse_request(body: &[u8]) -> Result<JsonRpcRequest, JsonRpcError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| JsonRpcError::parse_error("request is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| JsonRpcError::invalid_request("request must be a JSON object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(JsonRpcError::invalid_request("jsonrpc must be 2.0"));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty() && method.len() <= 128)
        .ok_or_else(|| JsonRpcError::invalid_request("method is required"))?;
    let id = object.get("id").cloned();
    if id
        .as_ref()
        .is_some_and(|id| !id.is_string() && !id.is_i64() && !id.is_u64())
    {
        return Err(JsonRpcError::invalid_request(
            "id must be a string or integer",
        ));
    }
    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
    if !params.is_object() {
        return Err(JsonRpcError::invalid_params("params must be an object"));
    }
    Ok(JsonRpcRequest {
        id,
        method: method.to_owned(),
        params,
    })
}

fn parse_projection(reply: &CborOwnerReply) -> Result<Value, AgentProvisioningOwnerError> {
    if reply.status != StatusCode::OK
        || reply.content_type != crate::CONNECTOR_PROJECTION_MEDIA_TYPE_V4
    {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    serde_json::from_slice(&reply.exact_cbor)
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn parse_references(reply: &CborOwnerReply) -> Result<Value, AgentProvisioningOwnerError> {
    if reply.status != StatusCode::OK || reply.content_type != MCP_REFERENCES_MEDIA_TYPE_V1 {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    let references: Value = serde_json::from_slice(&reply.exact_cbor)
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if !references.is_array() {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    if !references_have_canonical_channel_ids(&references) {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    Ok(references)
}

fn references_have_canonical_channel_ids(references: &Value) -> bool {
    references
        .as_array()
        .is_some_and(|references| references.iter().all(reference_has_canonical_channel_ids))
}

fn reference_has_canonical_channel_ids(reference: &Value) -> bool {
    let target = &reference["target"];
    match reference["kind"].as_str() {
        Some("channel") => {
            is_canonical_channel_id(reference["stable_id"].as_str())
                && is_canonical_channel_id(target["channel_id"].as_str())
        }
        Some("post") => {
            reference["stable_id"]
                .as_str()
                .and_then(|stable_id| stable_id.rsplit_once(':'))
                .is_some_and(|(channel_id, _)| is_canonical_channel_id(Some(channel_id)))
                && is_canonical_channel_id(target["channel_id"].as_str())
        }
        _ => true,
    }
}

fn is_canonical_channel_id(channel_id: Option<&str>) -> bool {
    channel_id.is_some_and(|channel_id| channel_id.parse::<ChannelId>().is_ok())
}

enum DispatchData {
    ConnectorProjection(Value),
    References(Value),
}

fn dispatch(request: JsonRpcRequest, data: &DispatchData) -> Response {
    if request.method != "notifications/initialized" && request.id.is_none() {
        return json_rpc_error_response(
            StatusCode::BAD_REQUEST,
            None,
            JsonRpcError::invalid_request("MCP requests require an id"),
        );
    }
    match request.method.as_str() {
        "initialize" => initialize(request),
        "notifications/initialized" => {
            if request.id.is_some() || !empty_object(&request.params) {
                json_rpc_error_response(
                    StatusCode::BAD_REQUEST,
                    request.id,
                    JsonRpcError::invalid_request("invalid initialized notification"),
                )
            } else {
                empty_response(StatusCode::ACCEPTED)
            }
        }
        "ping" => success(request.id, &json!({})),
        "tools/list" => success(
            request.id,
            &json!({ "tools": [connectors_tool(), references_tool()] }),
        ),
        "tools/call" => call_tool(request, data),
        "resources/list" => success(
            request.id,
            &json!({
                "resources": [{
                    "uri": CONNECTORS_RESOURCE_URI,
                    "name": "Dirextalk Connector status",
                    "description": "Owner-scoped, non-secret Connector and Binding health projection.",
                    "mimeType": MCP_JSON_MEDIA_TYPE
                }]
            }),
        ),
        "resources/read" => read_resource(request, connector_projection(data)),
        _ => json_rpc_error_response(
            StatusCode::OK,
            request.id,
            JsonRpcError::method_not_found("method is not supported"),
        ),
    }
}

fn connector_projection(data: &DispatchData) -> &Value {
    match data {
        DispatchData::ConnectorProjection(projection) => projection,
        DispatchData::References(_) => {
            unreachable!("reference data is only selected for the reference tool")
        }
    }
}

fn initialize(request: JsonRpcRequest) -> Response {
    let Some(protocol_version) = request
        .params
        .get("protocolVersion")
        .and_then(Value::as_str)
    else {
        return json_rpc_error_response(
            StatusCode::OK,
            request.id,
            JsonRpcError::invalid_params("protocolVersion is required"),
        );
    };
    if protocol_version != MCP_PROTOCOL_VERSION {
        return json_rpc_error_response(
            StatusCode::OK,
            request.id,
            JsonRpcError::invalid_params("protocolVersion is not supported"),
        );
    }
    success(
        request.id,
        &json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "subscribe": false, "listChanged": false }
            },
            "serverInfo": {
                "name": "dirextalk-vnext-agent-control",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Read-only Owner management surface. Agent prompts and credentials are not accepted."
        }),
    )
}

fn connectors_tool() -> Value {
    json!({
        "name": CONNECTORS_TOOL_NAME,
        "title": "List Dirextalk Connectors",
        "description": "Returns the authenticated Owner's non-secret Connector and Binding health projection.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "required": ["schema_version", "tenant_id", "observed_at_ms", "items"],
            "properties": {
                "schema_version": { "type": "integer" },
                "tenant_id": { "type": "string" },
                "observed_at_ms": { "type": "integer" },
                "items": { "type": "array" },
                "next_cursor": { "type": ["string", "null"] }
            }
        }
    })
}

fn references_tool() -> Value {
    json!({
        "name": REFERENCES_TOOL_NAME,
        "title": "Query Dirextalk references",
        "description": "Queries private rooms visible to the authenticated identity and locally authoritative public Channels and posts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string", "maxLength": MAX_REFERENCE_QUERY_BYTES },
                "types": {
                    "type": "array",
                    "items": { "enum": ["room", "channel", "post"] },
                    "uniqueItems": true,
                    "maxItems": 3
                },
                "limit": { "type": "integer", "minimum": 1, "maximum": MAX_REFERENCES }
            },
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "required": ["references"],
            "properties": {
                "references": {
                    "type": "array",
                    "maxItems": MAX_REFERENCES,
                    "items": {
                        "oneOf": [
                            {
                                "type": "object",
                                "required": ["kind", "stable_id", "title", "target"],
                                "properties": {
                                    "kind": { "const": "room" },
                                    "stable_id": {
                                        "type": "string",
                                        "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                                    },
                                    "title": { "type": "string", "minLength": 1, "maxLength": MAX_REFERENCE_TITLE_CHARS },
                                    "target": {
                                        "type": "object",
                                        "required": ["kind", "conversation_id"],
                                        "properties": {
                                            "kind": { "const": "private_conversation" },
                                            "conversation_id": {
                                                "type": "string",
                                                "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                                            }
                                        },
                                        "additionalProperties": false
                                    }
                                },
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "required": ["kind", "stable_id", "title", "target"],
                                "properties": {
                                    "kind": { "const": "channel" },
                                    "stable_id": { "type": "string", "pattern": CHANNEL_ID_SCHEMA_PATTERN },
                                    "title": { "type": "string", "minLength": 1, "maxLength": MAX_REFERENCE_TITLE_CHARS },
                                    "target": {
                                        "type": "object",
                                        "required": ["kind", "channel_id"],
                                        "properties": {
                                            "kind": { "const": "public_channel" },
                                            "channel_id": { "type": "string", "pattern": CHANNEL_ID_SCHEMA_PATTERN }
                                        },
                                        "additionalProperties": false
                                    }
                                },
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "required": ["kind", "stable_id", "title", "target"],
                                "properties": {
                                    "kind": { "const": "post" },
                                    "stable_id": {
                                        "type": "string",
                                        "pattern": POST_ID_SCHEMA_PATTERN
                                    },
                                    "title": { "type": "string", "minLength": 1, "maxLength": MAX_REFERENCE_TITLE_CHARS },
                                    "target": {
                                        "type": "object",
                                        "required": ["kind", "channel_id", "sequence"],
                                        "properties": {
                                            "kind": { "const": "public_channel_post" },
                                            "channel_id": { "type": "string", "pattern": CHANNEL_ID_SCHEMA_PATTERN },
                                            "sequence": {
                                                "type": "integer",
                                                "minimum": 1,
                                                "maximum": 9007199254740991_u64
                                            }
                                        },
                                        "additionalProperties": false
                                    }
                                },
                                "additionalProperties": false
                            }
                        ]
                    }
                }
            },
            "additionalProperties": false
        }
    })
}

struct ReferenceQuery {
    query: String,
    kind_mask: u8,
    limit: u16,
}

fn parse_reference_query(request: &JsonRpcRequest) -> Result<Option<ReferenceQuery>, JsonRpcError> {
    if request.method != "tools/call"
        || request.params.get("name").and_then(Value::as_str) != Some(REFERENCES_TOOL_NAME)
    {
        return Ok(None);
    }
    let arguments = request
        .params
        .get("arguments")
        .and_then(Value::as_object)
        .ok_or_else(|| JsonRpcError::invalid_params("reference arguments are required"))?;
    if arguments
        .keys()
        .any(|key| !matches!(key.as_str(), "query" | "types" | "limit"))
    {
        return Err(JsonRpcError::invalid_params(
            "reference arguments contain an unknown field",
        ));
    }
    let query = arguments
        .get("query")
        .map(|value| {
            value
                .as_str()
                .filter(|query| query.len() <= MAX_REFERENCE_QUERY_BYTES)
                .map(str::to_owned)
                .ok_or_else(|| JsonRpcError::invalid_params("query is invalid"))
        })
        .transpose()?
        .unwrap_or_default();
    let mut kind_mask = 0_u8;
    if let Some(types) = arguments.get("types") {
        let types = types
            .as_array()
            .filter(|types| !types.is_empty() && types.len() <= 3)
            .ok_or_else(|| JsonRpcError::invalid_params("types are invalid"))?;
        for kind in types {
            let flag = match kind.as_str() {
                Some("room") => REFERENCE_KIND_ROOM,
                Some("channel") => REFERENCE_KIND_CHANNEL,
                Some("post") => REFERENCE_KIND_POST,
                _ => return Err(JsonRpcError::invalid_params("reference type is invalid")),
            };
            if kind_mask & flag != 0 {
                return Err(JsonRpcError::invalid_params(
                    "reference types must be unique",
                ));
            }
            kind_mask |= flag;
        }
    } else {
        kind_mask = REFERENCE_KIND_ALL;
    }
    let limit = arguments
        .get("limit")
        .map(|value| {
            value
                .as_u64()
                .and_then(|limit| u16::try_from(limit).ok())
                .filter(|limit| (1..=MAX_REFERENCES).contains(limit))
                .ok_or_else(|| JsonRpcError::invalid_params("limit is invalid"))
        })
        .transpose()?
        .unwrap_or(MAX_REFERENCES);
    Ok(Some(ReferenceQuery {
        query,
        kind_mask,
        limit,
    }))
}

fn call_tool(request: JsonRpcRequest, data: &DispatchData) -> Response {
    let name = request.params.get("name").and_then(Value::as_str);
    let arguments = request.params.get("arguments");
    if name == Some(REFERENCES_TOOL_NAME) {
        if parse_reference_query(&request).is_err() {
            return json_rpc_error_response(
                StatusCode::OK,
                request.id,
                JsonRpcError::invalid_params("reference arguments are invalid"),
            );
        }
        let DispatchData::References(references) = data else {
            return json_rpc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                request.id,
                JsonRpcError::internal_error("reference query result is unavailable"),
            );
        };
        let structured_content = json!({ "references": references });
        let Ok(text) = serde_json::to_string(&structured_content) else {
            return json_rpc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                request.id,
                JsonRpcError::internal_error("reference serialization failed"),
            );
        };
        return success(
            request.id,
            &json!({
                "content": [{ "type": "text", "text": text }],
                "structuredContent": structured_content,
                "isError": false
            }),
        );
    }
    if name != Some(CONNECTORS_TOOL_NAME)
        || arguments.is_some_and(|arguments| !empty_object(arguments))
    {
        return json_rpc_error_response(
            StatusCode::OK,
            request.id,
            JsonRpcError::invalid_params("unknown tool or invalid arguments"),
        );
    }
    let DispatchData::ConnectorProjection(projection) = data else {
        return json_rpc_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            request.id,
            JsonRpcError::internal_error("Connector projection is unavailable"),
        );
    };
    let Ok(text) = serde_json::to_string(projection) else {
        return json_rpc_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            request.id,
            JsonRpcError::internal_error("projection serialization failed"),
        );
    };
    success(
        request.id,
        &json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": projection,
            "isError": false
        }),
    )
}

fn read_resource(request: JsonRpcRequest, projection: &Value) -> Response {
    if request.params.get("uri").and_then(Value::as_str) != Some(CONNECTORS_RESOURCE_URI) {
        return json_rpc_error_response(
            StatusCode::OK,
            request.id,
            JsonRpcError::invalid_params("unknown resource"),
        );
    }
    let Ok(text) = serde_json::to_string(projection) else {
        return json_rpc_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            request.id,
            JsonRpcError::internal_error("projection serialization failed"),
        );
    };
    success(
        request.id,
        &json!({
            "contents": [{
                "uri": CONNECTORS_RESOURCE_URI,
                "mimeType": MCP_JSON_MEDIA_TYPE,
                "text": text
            }]
        }),
    )
}

fn empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn success(id: Option<Value>, result: &Value) -> Response {
    let Some(id) = id else {
        return empty_response(StatusCode::ACCEPTED);
    };
    json_response(
        StatusCode::OK,
        &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
    )
}

#[derive(Clone, Copy)]
struct JsonRpcError {
    code: i64,
    message: &'static str,
    data: &'static str,
}

impl JsonRpcError {
    const fn parse_error(data: &'static str) -> Self {
        Self {
            code: -32700,
            message: "Parse error",
            data,
        }
    }

    const fn invalid_request(data: &'static str) -> Self {
        Self {
            code: -32600,
            message: "Invalid Request",
            data,
        }
    }

    const fn method_not_found(data: &'static str) -> Self {
        Self {
            code: -32601,
            message: "Method not found",
            data,
        }
    }

    const fn invalid_params(data: &'static str) -> Self {
        Self {
            code: -32602,
            message: "Invalid params",
            data,
        }
    }

    const fn internal_error(data: &'static str) -> Self {
        Self {
            code: -32603,
            message: "Internal error",
            data,
        }
    }
}

fn json_rpc_error_response(status: StatusCode, id: Option<Value>, error: JsonRpcError) -> Response {
    json_response(
        status,
        &json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": {
                "code": error.code,
                "message": error.message,
                "data": error.data
            }
        }),
    )
}

fn backend_error_response(error: AgentProvisioningOwnerError) -> Response {
    let (status, error) = match error {
        AgentProvisioningOwnerError::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            JsonRpcError::invalid_request("device authentication failed"),
        ),
        AgentProvisioningOwnerError::AccessDenied => (
            StatusCode::FORBIDDEN,
            JsonRpcError::invalid_request("access denied"),
        ),
        AgentProvisioningOwnerError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            JsonRpcError::invalid_request("request rejected"),
        ),
        AgentProvisioningOwnerError::NotFound => (
            StatusCode::NOT_FOUND,
            JsonRpcError::invalid_request("resource unavailable"),
        ),
        AgentProvisioningOwnerError::Conflict => (
            StatusCode::CONFLICT,
            JsonRpcError::invalid_request("request conflicts with current state"),
        ),
        AgentProvisioningOwnerError::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            JsonRpcError::internal_error("service unavailable"),
        ),
    };
    let mut response = json_rpc_error_response(status, None, error);
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("DTX-Device-Session"),
        );
    }
    response
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    let body = serde_json::to_vec(value).expect("fixed JSON-RPC envelope serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(MCP_JSON_MEDIA_TYPE),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn empty_response(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn now() -> Result<UtcMillis, AgentProvisioningOwnerError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?
        .as_millis();
    UtcMillis::new(
        i64::try_from(millis).map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
    )
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

#[derive(Serialize)]
struct ReferenceV1 {
    kind: &'static str,
    stable_id: String,
    title: String,
    target: ReferenceTargetV1,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReferenceTargetV1 {
    PrivateConversation { conversation_id: String },
    PublicChannel { channel_id: String },
    PublicChannelPost { channel_id: String, sequence: u64 },
}

impl ReferenceV1 {
    fn room(conversation_id: ConversationId) -> Self {
        let stable_id = conversation_id.to_string();
        let short = stable_id.get(..8).unwrap_or(&stable_id);
        Self {
            kind: "room",
            title: format!("私密会话 {short}"),
            target: ReferenceTargetV1::PrivateConversation {
                conversation_id: stable_id.clone(),
            },
            stable_id,
        }
    }

    fn channel(channel_id: ChannelId) -> Self {
        let stable_id = channel_id.to_string();
        Self {
            kind: "channel",
            title: short_public_title("公开频道", &stable_id),
            target: ReferenceTargetV1::PublicChannel {
                channel_id: stable_id.clone(),
            },
            stable_id,
        }
    }

    fn post(channel_id: ChannelId, sequence: u64, body: &str) -> Self {
        let channel_id = channel_id.to_string();
        let stable_id = format!("{channel_id}:{sequence}");
        let title = reference_title(body, &format!("频道帖子 {sequence}"));
        Self {
            kind: "post",
            stable_id,
            title,
            target: ReferenceTargetV1::PublicChannelPost {
                channel_id,
                sequence,
            },
        }
    }

    fn kind_rank(&self) -> u8 {
        match self.kind {
            "room" => 1,
            "channel" => 2,
            "post" => 3,
            _ => unreachable!(),
        }
    }
}

fn short_public_title(prefix: &str, stable_id: &str) -> String {
    let short: String = stable_id.chars().take(13).collect();
    format!("{prefix} {short}…")
}

fn reference_title(value: &str, fallback: &str) -> String {
    let normalized = value
        .chars()
        .map(|character| {
            if character.is_control() || character.is_whitespace() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    let title: String = normalized.chars().take(MAX_REFERENCE_TITLE_CHARS).collect();
    if title.is_empty() {
        fallback.to_owned()
    } else {
        title
    }
}

pub(crate) async fn query_postgres_references(
    store: &PgStore,
    tenant_id: TenantId,
    credential: DeviceSessionCredential,
    query: String,
    kind_mask: u8,
    limit: u16,
    now: UtcMillis,
) -> Result<CborOwnerReply, AgentProvisioningOwnerError> {
    if query.len() > MAX_REFERENCE_QUERY_BYTES
        || kind_mask == 0
        || kind_mask & !REFERENCE_KIND_ALL != 0
        || limit == 0
        || limit > MAX_REFERENCES
    {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let authenticated = DeviceSessionRepository::authenticate_in_transaction(
        session.connection(),
        &credential,
        now,
    )
    .await
    .map_err(map_reference_identity_error)?;
    let identity_id = authenticated.identity_id().to_string();
    let mut references = Vec::new();

    if kind_mask & REFERENCE_KIND_ROOM != 0 {
        let rows = sqlx::query(
            "SELECT scope_id
               FROM groups.mcp_visible_private_conversations($1, $2, $3, $4)",
        )
        .bind(*tenant_id.as_uuid())
        .bind(&identity_id)
        .bind(&query)
        .bind(i32::from(limit))
        .fetch_all(session.connection())
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
        for row in rows {
            let conversation_id = row
                .try_get::<String, _>("scope_id")
                .ok()
                .and_then(|value| value.parse::<ConversationId>().ok())
                .ok_or(AgentProvisioningOwnerError::TemporarilyUnavailable)?;
            references.push(ReferenceV1::room(conversation_id));
        }
    }

    if kind_mask & (REFERENCE_KIND_CHANNEL | REFERENCE_KIND_POST) != 0 {
        let rows = sqlx::query(
            "SELECT reference_kind, subject_id, sequence, exact_cbor
               FROM directory.mcp_public_reference_facts($1, $2, $3, $4)",
        )
        .bind(*tenant_id.as_uuid())
        .bind(i32::from(
            kind_mask & (REFERENCE_KIND_CHANNEL | REFERENCE_KIND_POST),
        ))
        .bind(MAX_POST_SCAN)
        .bind(now.get())
        .fetch_all(session.connection())
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
        let normalized_query = query.to_lowercase();
        for row in rows {
            let reference_kind = row
                .try_get::<i16, _>("reference_kind")
                .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
            let subject = row
                .try_get::<String, _>("subject_id")
                .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
            let channel_id = subject
                .parse::<ChannelId>()
                .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
            match reference_kind {
                2 if kind_mask & REFERENCE_KIND_CHANNEL != 0 => {
                    if normalized_query.is_empty()
                        || subject.to_lowercase().contains(&normalized_query)
                    {
                        references.push(ReferenceV1::channel(channel_id));
                    }
                }
                3 if kind_mask & REFERENCE_KIND_POST != 0 => {
                    let sequence = row
                        .try_get::<i64, _>("sequence")
                        .ok()
                        .and_then(|value| u64::try_from(value).ok())
                        .filter(|value| (1..=9_007_199_254_740_991).contains(value))
                        .ok_or(AgentProvisioningOwnerError::TemporarilyUnavailable)?;
                    let exact = row
                        .try_get::<Vec<u8>, _>("exact_cbor")
                        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
                    let event = SignedPublicFeedEventV1::decode_and_verify(&exact)
                        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
                    if event.subject_id().to_string() != subject
                        || event.sequence().get() != sequence
                    {
                        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
                    }
                    let PublicFeedPayloadV1::Post { body, .. } = event.payload() else {
                        continue;
                    };
                    if normalized_query.is_empty()
                        || body.to_lowercase().contains(&normalized_query)
                    {
                        references.push(ReferenceV1::post(channel_id, sequence, body));
                    }
                }
                2 | 3 => {}
                _ => return Err(AgentProvisioningOwnerError::TemporarilyUnavailable),
            }
        }
    }

    references.sort_by(|left, right| {
        left.kind_rank()
            .cmp(&right.kind_rank())
            .then_with(|| left.stable_id.cmp(&right.stable_id))
    });
    references.dedup_by(|left, right| left.kind == right.kind && left.stable_id == right.stable_id);
    references.truncate(usize::from(limit));
    session
        .commit()
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let exact_cbor = serde_json::to_vec(&references)
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    Ok(CborOwnerReply {
        status: StatusCode::OK,
        content_type: MCP_REFERENCES_MEDIA_TYPE_V1,
        exact_cbor,
    })
}

fn map_reference_identity_error(error: IdentityPersistenceError) -> AgentProvisioningOwnerError {
    match error {
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::IdentityInactive => {
            AgentProvisioningOwnerError::AuthenticationRejected
        }
        _ => AgentProvisioningOwnerError::TemporarilyUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use axum::{
        body::{Body, to_bytes},
        http::{HeaderValue, Request, header},
        response::Response,
    };
    use dtx_domain::ChannelId;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::{
        AgentProvisioningOwnerError, CborOwnerReply, MCP_JSON_MEDIA_TYPE, MCP_PROTOCOL_VERSION,
        MCP_PROTOCOL_VERSION_HEADER, MCP_SSE_MEDIA_TYPE, McpBackendFuture, McpOwnerBackend,
        ReferenceV1, StatusCode, UtcMillis, mcp_router_with_backend,
    };

    const AUTHORIZATION: &str = concat!(
        "DTX-Device-Session 019f75cc-f2db-7a50-8747-9f4a292f361c.",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
    );

    struct FakeBackend {
        result: Result<Value, AgentProvisioningOwnerError>,
    }

    impl McpOwnerBackend for FakeBackend {
        fn connector_projection(
            &self,
            _credential: dtx_identity_persistence::DeviceSessionCredential,
            _now: UtcMillis,
        ) -> McpBackendFuture<'_> {
            let result = self.result.clone().map(|value| CborOwnerReply {
                status: StatusCode::OK,
                content_type: crate::CONNECTOR_PROJECTION_MEDIA_TYPE_V4,
                exact_cbor: serde_json::to_vec(&value).expect("projection serializes"),
            });
            Box::pin(async move { result })
        }

        fn references(
            &self,
            _credential: dtx_identity_persistence::DeviceSessionCredential,
            _query: String,
            _kind_mask: u8,
            _limit: u16,
            _now: UtcMillis,
        ) -> McpBackendFuture<'_> {
            let result = self.result.clone().map(|value| CborOwnerReply {
                status: StatusCode::OK,
                content_type: super::MCP_REFERENCES_MEDIA_TYPE_V1,
                exact_cbor: serde_json::to_vec(&value).expect("references serialize"),
            });
            Box::pin(async move { result })
        }
    }

    fn projection() -> Value {
        json!({
            "schema_version": 4,
            "tenant_id": "019f75cc-f2db-7a50-8747-9f4a292f361d",
            "observed_at_ms": 1,
            "items": [],
            "next_cursor": null
        })
    }

    fn request(body: Value) -> Request<Body> {
        Request::post("/mcp")
            .header(header::AUTHORIZATION, AUTHORIZATION)
            .header(header::CONTENT_TYPE, MCP_JSON_MEDIA_TYPE)
            .header(
                header::ACCEPT,
                format!("{MCP_JSON_MEDIA_TYPE}, {MCP_SSE_MEDIA_TYPE}"),
            )
            .header(MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION)
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    async fn response_json(response: Response) -> Value {
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body");
        serde_json::from_slice(&body).expect("JSON response")
    }

    #[tokio::test]
    async fn initialize_and_connector_tool_are_callable() {
        let router = mcp_router_with_backend(Arc::new(FakeBackend {
            result: Ok(projection()),
        }));
        let initialize = router
            .clone()
            .oneshot(request(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1" }
                }
            })))
            .await
            .expect("initialize response");
        assert_eq!(initialize.status(), StatusCode::OK);
        assert_eq!(
            response_json(initialize).await["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );

        let call = router
            .oneshot(request(json!({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "dirextalk.list_connectors",
                    "arguments": {}
                }
            })))
            .await
            .expect("tool response");
        assert_eq!(call.status(), StatusCode::OK);
        let body = response_json(call).await;
        assert_eq!(body["result"]["structuredContent"]["schema_version"], 4);
        assert_eq!(body["result"]["isError"], false);
    }

    #[tokio::test]
    async fn reference_tool_preserves_zero_one_and_many_stable_references() {
        let cases = [
            json!([]),
            json!([{
                "kind": "room",
                "stable_id": "019f75cc-f2db-7a50-8747-9f4a292f361c",
                "title": "私密会话 019f75cc",
                "target": {
                    "kind": "private_conversation",
                    "conversation_id": "019f75cc-f2db-7a50-8747-9f4a292f361c"
                }
            }]),
            json!([
                {
                    "kind": "channel",
                    "stable_id": format!("dtxc1{}", "a".repeat(52)),
                    "title": "公开频道",
                    "target": {
                        "kind": "public_channel",
                        "channel_id": format!("dtxc1{}", "a".repeat(52))
                    }
                },
                {
                    "kind": "post",
                    "stable_id": format!("dtxc1{}q:7", "b".repeat(51)),
                    "title": "首个帖子",
                    "target": {
                        "kind": "public_channel_post",
                        "channel_id": format!("dtxc1{}q", "b".repeat(51)),
                        "sequence": 7
                    }
                }
            ]),
        ];
        for expected in cases {
            let router = mcp_router_with_backend(Arc::new(FakeBackend {
                result: Ok(expected.clone()),
            }));
            let response = router
                .oneshot(request(json!({
                    "jsonrpc": "2.0",
                    "id": "references",
                    "method": "tools/call",
                    "params": {
                        "name": "dirextalk.query_references",
                        "arguments": { "query": "", "limit": 32 }
                    }
                })))
                .await
                .expect("reference response");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response_json(response).await["result"]["structuredContent"]["references"],
                expected
            );
        }
    }

    #[test]
    fn reference_tool_schema_requires_canonical_channel_ids() {
        let schema = super::references_tool();
        let variants = &schema["outputSchema"]["properties"]["references"]["items"]["oneOf"];
        let channel = &variants[1];
        let post = &variants[2];

        assert_eq!(
            channel["properties"]["stable_id"]["pattern"],
            "^dtxc1[a-z2-7]{51}[aq]$"
        );
        assert_eq!(
            channel["properties"]["target"]["properties"]["channel_id"]["pattern"],
            "^dtxc1[a-z2-7]{51}[aq]$"
        );
        assert_eq!(
            post["properties"]["stable_id"]["pattern"],
            "^dtxc1[a-z2-7]{51}[aq]:[1-9][0-9]{0,15}$"
        );
        assert_eq!(
            post["properties"]["target"]["properties"]["channel_id"]["pattern"],
            "^dtxc1[a-z2-7]{51}[aq]$"
        );
    }

    #[tokio::test]
    async fn reference_tool_rejects_noncanonical_channel_ids_from_backend() {
        let canonical = format!("dtxc1{}", "a".repeat(52));
        let noncanonical = format!("dtxc1{}t", "a".repeat(51));
        let cases = [
            json!([{
                "kind": "channel",
                "stable_id": noncanonical.clone(),
                "title": "公开频道",
                "target": {
                    "kind": "public_channel",
                    "channel_id": canonical.clone()
                }
            }]),
            json!([{
                "kind": "channel",
                "stable_id": canonical.clone(),
                "title": "公开频道",
                "target": {
                    "kind": "public_channel",
                    "channel_id": noncanonical.clone()
                }
            }]),
            json!([{
                "kind": "post",
                "stable_id": format!("{noncanonical}:7"),
                "title": "频道帖子",
                "target": {
                    "kind": "public_channel_post",
                    "channel_id": canonical.clone(),
                    "sequence": 7
                }
            }]),
            json!([{
                "kind": "post",
                "stable_id": format!("{canonical}:7"),
                "title": "频道帖子",
                "target": {
                    "kind": "public_channel_post",
                    "channel_id": noncanonical,
                    "sequence": 7
                }
            }]),
        ];

        for references in cases {
            let router = mcp_router_with_backend(Arc::new(FakeBackend {
                result: Ok(references),
            }));
            let response = router
                .oneshot(request(json!({
                    "jsonrpc": "2.0",
                    "id": "references",
                    "method": "tools/call",
                    "params": {
                        "name": "dirextalk.query_references",
                        "arguments": { "query": "", "limit": 32 }
                    }
                })))
                .await
                .expect("reference response");

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[test]
    fn generated_channel_and_post_references_have_exact_stable_schema() {
        let channel_id =
            ChannelId::from_str(&format!("dtxc1c{}", "a".repeat(51))).expect("valid channel ID");
        let channel_id_text = channel_id.to_string();
        assert_eq!(
            serde_json::to_value(ReferenceV1::channel(channel_id)).expect("channel serializes"),
            json!({
                "kind": "channel",
                "stable_id": channel_id_text,
                "title": format!("公开频道 {}…", &channel_id_text[..13]),
                "target": {
                    "kind": "public_channel",
                    "channel_id": channel_id_text
                }
            })
        );

        let title_source = format!("\n 公开\t帖子\u{0} {} ", "内".repeat(140));
        let post = serde_json::to_value(ReferenceV1::post(
            channel_id,
            9_007_199_254_740_991,
            &title_source,
        ))
        .expect("post serializes");
        assert_eq!(post["kind"], "post");
        assert_eq!(
            post["stable_id"],
            format!("{channel_id_text}:9007199254740991")
        );
        assert_eq!(
            post["target"],
            json!({
                "kind": "public_channel_post",
                "channel_id": channel_id_text,
                "sequence": 9_007_199_254_740_991_u64
            })
        );
        let title = post["title"].as_str().expect("title is text");
        assert!(!title.chars().any(char::is_control));
        assert!(!title.contains("  "));
        assert_eq!(title.chars().count(), 120);
    }

    #[tokio::test]
    async fn authentication_and_owner_authorization_fail_closed() {
        let router = mcp_router_with_backend(Arc::new(FakeBackend {
            result: Ok(projection()),
        }));
        let mut missing_auth = request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }));
        missing_auth.headers_mut().remove(header::AUTHORIZATION);
        let response = router
            .oneshot(missing_auth)
            .await
            .expect("authentication response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));

        let router = mcp_router_with_backend(Arc::new(FakeBackend {
            result: Err(AgentProvisioningOwnerError::AccessDenied),
        }));
        let response = router
            .oneshot(request(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": { "uri": "dirextalk://connectors" }
            })))
            .await
            .expect("authorization response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn streamable_http_headers_and_browser_origin_are_rejected_strictly() {
        let router = mcp_router_with_backend(Arc::new(FakeBackend {
            result: Ok(projection()),
        }));
        let mut missing_sse = request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }));
        missing_sse.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static(MCP_JSON_MEDIA_TYPE),
        );
        let response = router
            .clone()
            .oneshot(missing_sse)
            .await
            .expect("media response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut initialized = request(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
        initialized
            .headers_mut()
            .remove(MCP_PROTOCOL_VERSION_HEADER);
        let response = router
            .clone()
            .oneshot(initialized)
            .await
            .expect("protocol version response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut browser = request(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }));
        browser.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("https://attacker.invalid"),
        );
        let response = router.oneshot(browser).await.expect("origin response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
