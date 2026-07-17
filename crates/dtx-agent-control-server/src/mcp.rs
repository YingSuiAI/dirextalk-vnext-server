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
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_wire::UtcMillis;
use serde_json::{Value, json};

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
const CONNECTORS_RESOURCE_URI: &str = "dirextalk://connectors";

type McpBackendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CborOwnerReply, AgentProvisioningOwnerError>> + Send + 'a>>;

trait McpOwnerBackend: Send + Sync + 'static {
    fn connector_projection(
        &self,
        credential: DeviceSessionCredential,
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
    let projection = match backend
        .connector_projection(credential, authenticated_at)
        .await
    {
        Ok(reply) => match parse_projection(&reply) {
            Ok(projection) => projection,
            Err(error) => return backend_error_response(error),
        },
        Err(error) => return backend_error_response(error),
    };
    dispatch(request, &projection)
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

fn dispatch(request: JsonRpcRequest, projection: &Value) -> Response {
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
        "tools/list" => success(request.id, &json!({ "tools": [connectors_tool()] })),
        "tools/call" => call_tool(request, projection),
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
        "resources/read" => read_resource(request, projection),
        _ => json_rpc_error_response(
            StatusCode::OK,
            request.id,
            JsonRpcError::method_not_found("method is not supported"),
        ),
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

fn call_tool(request: JsonRpcRequest, projection: &Value) -> Response {
    let name = request.params.get("name").and_then(Value::as_str);
    let arguments = request.params.get("arguments");
    if name != Some(CONNECTORS_TOOL_NAME)
        || arguments.is_some_and(|arguments| !empty_object(arguments))
    {
        return json_rpc_error_response(
            StatusCode::OK,
            request.id,
            JsonRpcError::invalid_params("unknown tool or invalid arguments"),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::{Body, to_bytes},
        http::{HeaderValue, Request, header},
        response::Response,
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::{
        AgentProvisioningOwnerError, CborOwnerReply, MCP_JSON_MEDIA_TYPE, MCP_PROTOCOL_VERSION,
        MCP_PROTOCOL_VERSION_HEADER, MCP_SSE_MEDIA_TYPE, McpBackendFuture, McpOwnerBackend,
        StatusCode, UtcMillis, mcp_router_with_backend,
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
