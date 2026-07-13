use std::{collections::BTreeSet, error::Error, fmt, str::FromStr};

use dtx_agent_control::MAX_CAPABILITY_NAME_BYTES;
use dtx_agent_control_proto::gateway_v1;
use dtx_agent_router::{DispatchMode, MAX_REQUIRED_CAPABILITIES, RunRoutingState};
use dtx_domain::{
    ConnectorId, ConversationId, EventId, InstallationId, RequestId, Revision, TenantId,
};
use sha2::{Digest as _, Sha256};

use crate::{CreateAgentRunRequest, CreatedAgentRun};

/// Validated internal request that retains its correlation ID for the response.
#[derive(Clone, Debug)]
pub struct ParsedAgentRunIngress {
    pub request_id: RequestId,
    pub request: CreateAgentRunRequest,
}

/// Parses a bounded Gateway request and binds it to the authenticated tenant.
///
/// # Errors
///
/// Rejects malformed lifecycle IDs, digests, dispatch modes, revisions, or
/// capability sets before any database operation begins.
pub fn parse_agent_run_ingress(
    value: gateway_v1::CreateAgentRunRequest,
    tenant_id: TenantId,
) -> Result<ParsedAgentRunIngress, GatewayWireError> {
    let request_id = parse_id(&value.request_id, "request_id")?;
    let idempotency_digest = exact_digest(value.idempotency_digest, "idempotency_digest")?;
    let request_digest = exact_digest(value.request_digest, "request_digest")?;
    let installation_id = parse_id(&value.installation_id, "installation_id")?;
    let conversation_id = parse_id(&value.conversation_id, "conversation_id")?;
    let request_event_id = parse_id(&value.request_event_id, "request_event_id")?;
    let preferred_connector_id = value
        .preferred_connector_id
        .as_deref()
        .map(|identifier| parse_id(identifier, "preferred_connector_id"))
        .transpose()?;
    let required_capabilities = normalize_capabilities(value.required_capabilities)?;
    let dispatch_mode = match gateway_v1::DispatchMode::try_from(value.dispatch_mode) {
        Ok(gateway_v1::DispatchMode::Single) => DispatchMode::Single,
        Ok(gateway_v1::DispatchMode::Failover) => DispatchMode::Failover,
        Ok(gateway_v1::DispatchMode::Unspecified) | Err(_) => {
            return Err(GatewayWireError::new(
                GatewayWireErrorKind::UnsupportedValue,
                "dispatch_mode",
            ));
        }
    };
    Revision::new(value.grant_version)
        .map_err(|_| GatewayWireError::new(GatewayWireErrorKind::InvalidValue, "grant_version"))?;
    if request_digest
        != build_agent_run_request_digest(
            tenant_id,
            request_id,
            idempotency_digest,
            installation_id,
            conversation_id,
            request_event_id,
            preferred_connector_id,
            &required_capabilities,
            dispatch_mode,
            value.grant_version,
        )
    {
        return Err(GatewayWireError::new(
            GatewayWireErrorKind::InvalidValue,
            "request_digest",
        ));
    }
    let request = CreateAgentRunRequest::new(
        tenant_id,
        request_id,
        idempotency_digest,
        request_digest,
        installation_id,
        conversation_id,
        request_event_id,
        preferred_connector_id,
        required_capabilities,
        dispatch_mode,
        value.grant_version,
        None,
    )
    .map_err(|_| GatewayWireError::new(GatewayWireErrorKind::InvalidValue, "request"))?;
    Ok(ParsedAgentRunIngress {
        request_id,
        request,
    })
}

#[allow(clippy::too_many_arguments)] // Mirrors the frozen request transcript field-for-field.
fn build_agent_run_request_digest(
    tenant_id: TenantId,
    request_id: RequestId,
    idempotency_digest: [u8; 32],
    installation_id: InstallationId,
    conversation_id: ConversationId,
    request_event_id: EventId,
    preferred_connector_id: Option<ConnectorId>,
    required_capabilities: &[String],
    dispatch_mode: DispatchMode,
    grant_version: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, b"dirextalk.agent-gateway-run-request.v1");
    update_length_prefixed(&mut hasher, tenant_id.as_uuid().as_bytes());
    update_length_prefixed(&mut hasher, request_id.as_uuid().as_bytes());
    update_length_prefixed(&mut hasher, &idempotency_digest);
    update_length_prefixed(&mut hasher, installation_id.as_uuid().as_bytes());
    update_length_prefixed(&mut hasher, conversation_id.as_uuid().as_bytes());
    update_length_prefixed(&mut hasher, request_event_id.as_uuid().as_bytes());
    match preferred_connector_id {
        Some(connector_id) => {
            update_length_prefixed(&mut hasher, &[1]);
            update_length_prefixed(&mut hasher, connector_id.as_uuid().as_bytes());
        }
        None => update_length_prefixed(&mut hasher, &[0]),
    }
    update_length_prefixed(
        &mut hasher,
        &u64::try_from(required_capabilities.len())
            .expect("bounded capability count fits u64")
            .to_be_bytes(),
    );
    for capability in required_capabilities {
        update_length_prefixed(&mut hasher, capability.as_bytes());
    }
    let dispatch_mode = match dispatch_mode {
        DispatchMode::Single => 1_u64,
        DispatchMode::Failover => 2_u64,
    };
    update_length_prefixed(&mut hasher, &dispatch_mode.to_be_bytes());
    update_length_prefixed(&mut hasher, &grant_version.to_be_bytes());
    hasher.finalize().into()
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("bounded Gateway transcript part fits u64");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

/// Encodes the stable current Router state without exposing route candidates.
#[must_use]
pub fn build_agent_run_ingress_response(
    request_id: RequestId,
    completion: &CreatedAgentRun,
) -> gateway_v1::CreateAgentRunResponse {
    let routing_state = match completion.state() {
        RunRoutingState::Queued => gateway_v1::RunRoutingState::Queued,
        RunRoutingState::Offered => gateway_v1::RunRoutingState::Offered,
        RunRoutingState::Leased => gateway_v1::RunRoutingState::Leased,
        RunRoutingState::ReconcileRequired => gateway_v1::RunRoutingState::ReconcileRequired,
        RunRoutingState::Expired => gateway_v1::RunRoutingState::Expired,
    };
    gateway_v1::CreateAgentRunResponse {
        request_id: request_id.to_string(),
        run_id: completion.run_id().to_string(),
        inserted: completion.inserted(),
        routing_state: routing_state.into(),
    }
}

fn exact_digest(value: Vec<u8>, field: &'static str) -> Result<[u8; 32], GatewayWireError> {
    value
        .try_into()
        .map_err(|_| GatewayWireError::new(GatewayWireErrorKind::InvalidLength, field))
}

fn parse_id<T>(value: &str, field: &'static str) -> Result<T, GatewayWireError>
where
    T: FromStr,
{
    value
        .parse()
        .map_err(|_| GatewayWireError::new(GatewayWireErrorKind::InvalidIdentifier, field))
}

fn normalize_capabilities(mut values: Vec<String>) -> Result<Vec<String>, GatewayWireError> {
    if values.len() > MAX_REQUIRED_CAPABILITIES
        || values.iter().any(|value| !valid_stable_name(value))
    {
        return Err(GatewayWireError::new(
            GatewayWireErrorKind::InvalidValue,
            "required_capabilities",
        ));
    }
    values.sort_unstable();
    let mut unique = BTreeSet::new();
    if values.iter().all(|value| unique.insert(value.as_str())) {
        Ok(values)
    } else {
        Err(GatewayWireError::new(
            GatewayWireErrorKind::InvalidValue,
            "required_capabilities",
        ))
    }
}

fn valid_stable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CAPABILITY_NAME_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
}

/// Sanitized category for a rejected internal Gateway field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayWireErrorKind {
    InvalidIdentifier,
    InvalidLength,
    InvalidValue,
    UnsupportedValue,
}

/// Bounded wire failure that never retains or displays untrusted field contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayWireError {
    kind: GatewayWireErrorKind,
    field: &'static str,
}

impl GatewayWireError {
    const fn new(kind: GatewayWireErrorKind, field: &'static str) -> Self {
        Self { kind, field }
    }

    #[must_use]
    pub const fn kind(self) -> GatewayWireErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for GatewayWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "agent-gateway wire field {} is invalid ({:?})",
            self.field, self.kind
        )
    }
}

impl Error for GatewayWireError {}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn valid_request(tenant_id: TenantId) -> gateway_v1::CreateAgentRunRequest {
        let request_id = RequestId::new();
        let installation_id = InstallationId::new();
        let conversation_id = ConversationId::new();
        let request_event_id = EventId::new();
        let preferred_connector_id = ConnectorId::new();
        let idempotency_digest = [1; 32];
        let required_capabilities = vec!["chat.streaming".to_owned(), "tool.read".to_owned()];
        let request_digest = build_agent_run_request_digest(
            tenant_id,
            request_id,
            idempotency_digest,
            installation_id,
            conversation_id,
            request_event_id,
            Some(preferred_connector_id),
            &required_capabilities,
            DispatchMode::Single,
            4,
        );
        gateway_v1::CreateAgentRunRequest {
            request_id: request_id.to_string(),
            idempotency_digest: idempotency_digest.to_vec(),
            request_digest: request_digest.to_vec(),
            installation_id: installation_id.to_string(),
            conversation_id: conversation_id.to_string(),
            request_event_id: request_event_id.to_string(),
            preferred_connector_id: Some(preferred_connector_id.to_string()),
            required_capabilities,
            dispatch_mode: gateway_v1::DispatchMode::Single.into(),
            grant_version: 4,
        }
    }

    #[test]
    fn parses_an_exact_request_and_binds_authenticated_tenant() {
        let tenant_id = TenantId::try_from(Uuid::now_v7()).expect("test tenant is UUIDv7");
        let parsed = parse_agent_run_ingress(valid_request(tenant_id), tenant_id)
            .expect("valid Gateway request parses");
        assert_eq!(parsed.request.tenant_id(), tenant_id);
        assert_eq!(parsed.request.request_id(), parsed.request_id);
    }

    #[test]
    fn rejects_unknown_dispatch_duplicate_capabilities_and_wrong_digest_size() {
        let tenant_id = TenantId::try_from(Uuid::now_v7()).expect("test tenant is UUIDv7");
        let mut request = valid_request(tenant_id);
        request.dispatch_mode = 99;
        assert_eq!(
            parse_agent_run_ingress(request, tenant_id)
                .expect_err("unknown dispatch is rejected")
                .field(),
            "dispatch_mode"
        );

        let mut request = valid_request(tenant_id);
        request.required_capabilities = vec!["chat".to_owned(), "chat".to_owned()];
        assert_eq!(
            parse_agent_run_ingress(request, tenant_id)
                .expect_err("duplicate capabilities are rejected")
                .field(),
            "required_capabilities"
        );

        let mut request = valid_request(tenant_id);
        request.request_digest.pop();
        assert_eq!(
            parse_agent_run_ingress(request, tenant_id)
                .expect_err("wrong digest size is rejected")
                .kind(),
            GatewayWireErrorKind::InvalidLength
        );

        let mut request = valid_request(tenant_id);
        request.request_digest[0] ^= 1;
        assert_eq!(
            parse_agent_run_ingress(request, tenant_id)
                .expect_err("a request digest mismatch is rejected")
                .field(),
            "request_digest"
        );
    }

    #[test]
    fn request_digest_matches_the_cross_language_conformance_vector() {
        let tenant_id = "01890f00-0000-7000-8000-000000000301"
            .parse()
            .expect("fixture tenant is UUIDv7");
        let request_id = "01890f00-0000-7000-8000-000000000310"
            .parse()
            .expect("fixture request is UUIDv7");
        let installation_id = "01890f00-0000-7000-8000-000000000311"
            .parse()
            .expect("fixture installation is UUIDv7");
        let conversation_id = "01890f00-0000-7000-8000-000000000312"
            .parse()
            .expect("fixture conversation is UUIDv7");
        let request_event_id = "01890f00-0000-7000-8000-000000000313"
            .parse()
            .expect("fixture event is UUIDv7");
        let preferred_connector_id = "01890f00-0000-7000-8000-000000000314"
            .parse()
            .expect("fixture Connector is UUIDv7");
        let idempotency_digest = [
            0x64, 0xc1, 0xaf, 0x57, 0xad, 0x01, 0xed, 0x35, 0xdd, 0xc0, 0x24, 0x95, 0x8d, 0x56,
            0xc8, 0xae, 0xc1, 0x24, 0x05, 0xd9, 0x75, 0x42, 0x9f, 0x3b, 0xed, 0xb7, 0xa7, 0x2a,
            0xf8, 0x72, 0x00, 0xd3,
        ];
        let digest = build_agent_run_request_digest(
            tenant_id,
            request_id,
            idempotency_digest,
            installation_id,
            conversation_id,
            request_event_id,
            Some(preferred_connector_id),
            &["chat.streaming".to_owned(), "tool.read".to_owned()],
            DispatchMode::Single,
            4,
        );
        assert_eq!(
            digest,
            [
                0xa4, 0x9f, 0xbe, 0xb7, 0x0e, 0xf8, 0xa0, 0xe7, 0xe1, 0xcd, 0xf1, 0x96, 0x1f, 0x58,
                0x73, 0xf4, 0x50, 0xa2, 0x21, 0x12, 0x30, 0x6c, 0x52, 0xd5, 0x99, 0x2b, 0xe9, 0xcb,
                0xfb, 0x6a, 0xcf, 0x80,
            ]
        );
    }
}
