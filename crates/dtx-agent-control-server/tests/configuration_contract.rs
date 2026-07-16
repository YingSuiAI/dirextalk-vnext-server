use dtx_agent_control::ConfigEntry;
use dtx_agent_control_server::{
    ApplyConnectorConfigurationRequest, ConnectorCommandFence, ConnectorControlApplicationError,
};
use dtx_connect_registry::{AdapterKind, ConnectorDesiredState};
use dtx_domain::{ConnectorId, RequestId, Revision, TenantId};

fn entry(key: &str, value: &str) -> ConfigEntry {
    ConfigEntry::new(key.to_owned(), value.to_owned()).expect("registered fixture entry")
}

fn fence() -> ConnectorCommandFence {
    ConnectorCommandFence {
        tenant_id: TenantId::new(),
        connector_id: ConnectorId::new(),
        generation: 1,
        spec_revision: Revision::INITIAL,
    }
}

#[test]
fn owner_configuration_is_canonical_and_adapter_scoped() {
    let request = ApplyConnectorConfigurationRequest::new(
        fence(),
        RequestId::new(),
        ConnectorDesiredState::Running,
        AdapterKind::Codex,
        vec![
            entry("profile", "safe"),
            entry("model", "agent-v1"),
            entry("adapter", "codex-app-server"),
        ],
        vec![
            entry("offline-policy", "queue"),
            entry("max-concurrent-runs", "2"),
        ],
    )
    .expect("Codex schema is registered");

    assert_eq!(request.adapter_kind(), AdapterKind::Codex);
    assert_eq!(request.adapter_config()[0].key(), "adapter");
    assert_eq!(request.runtime_config()[0].key(), "max-concurrent-runs");
    assert_eq!(request.fence().generation, 1);
    assert_eq!(request.desired_state(), ConnectorDesiredState::Running);

    assert_eq!(
        ApplyConnectorConfigurationRequest::new(
            fence(),
            RequestId::new(),
            ConnectorDesiredState::Running,
            AdapterKind::Codex,
            vec![entry("endpoint", "local")],
            Vec::new(),
        ),
        Err(ConnectorControlApplicationError::InvalidRequest),
        "an ACP-only key must not cross the Codex adapter boundary",
    );
    assert_eq!(
        ApplyConnectorConfigurationRequest::new(
            fence(),
            RequestId::new(),
            ConnectorDesiredState::Running,
            AdapterKind::OpenClawAcp,
            vec![entry("model", "agent-v1")],
            Vec::new(),
        ),
        Err(ConnectorControlApplicationError::InvalidRequest),
        "an unregistered OpenClaw adapter key must fail closed",
    );
    assert!(
        ConfigEntry::new("adapter".to_owned(), "unregistered-runtime".to_owned()).is_err(),
        "a known adapter kind must not select an arbitrary runtime implementation",
    );
    assert_eq!(
        ApplyConnectorConfigurationRequest::new(
            fence(),
            RequestId::new(),
            ConnectorDesiredState::Running,
            AdapterKind::CustomAcp,
            vec![entry("adapter", "vendor-v1"), entry("endpoint", "local")],
            vec![entry("policy-id", "policy-v1")],
        )
        .map(|request| request.adapter_kind()),
        Ok(AdapterKind::CustomAcp),
    );
    assert_eq!(
        ApplyConnectorConfigurationRequest::new(
            fence(),
            RequestId::new(),
            ConnectorDesiredState::Running,
            AdapterKind::HermesAcp,
            vec![entry("adapter", "hermes-acp"), entry("profile", "safe")],
            vec![entry("policy-id", "policy-v1")],
        )
        .map(|request| request.adapter_kind()),
        Ok(AdapterKind::HermesAcp),
    );
}

#[test]
fn owner_configuration_rejects_wrong_scope_duplicates_and_secret_material() {
    assert_eq!(
        ApplyConnectorConfigurationRequest::new(
            fence(),
            RequestId::new(),
            ConnectorDesiredState::Running,
            AdapterKind::Codex,
            Vec::new(),
            vec![entry("model", "agent-v1")],
        ),
        Err(ConnectorControlApplicationError::InvalidRequest),
    );
    assert_eq!(
        ApplyConnectorConfigurationRequest::new(
            fence(),
            RequestId::new(),
            ConnectorDesiredState::Running,
            AdapterKind::Codex,
            vec![entry("profile", "safe"), entry("profile", "default")],
            Vec::new(),
        ),
        Err(ConnectorControlApplicationError::InvalidRequest),
    );
    assert!(ConfigEntry::new("api-key".to_owned(), "public".to_owned()).is_err());
    assert!(ConfigEntry::new("profile".to_owned(), "secret://codex/token".to_owned()).is_err());
    assert!(ConfigEntry::new("profile".to_owned(), "my-opaque-token-123".to_owned()).is_err());
}

#[test]
fn configuration_debug_never_discloses_values() {
    let canary = "safe";
    let request = ApplyConnectorConfigurationRequest::new(
        fence(),
        RequestId::new(),
        ConnectorDesiredState::Running,
        AdapterKind::Codex,
        vec![entry("profile", canary)],
        Vec::new(),
    )
    .unwrap();

    let debug = format!("{request:?}");
    assert!(!debug.contains(canary));
    assert!(debug.contains("[REDACTED]"));
}
