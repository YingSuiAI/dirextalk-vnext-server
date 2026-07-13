use std::str::FromStr;

use dtx_agent_registry::{
    AgentDevice, AgentDeviceCommand, AgentDeviceError, AgentDeviceState, AgentInstallation,
    DescriptorDigest, DeviceCredentialFingerprint, ExecutionMode,
};
use dtx_domain::{AgentDeviceId, AgentId, IdentityId, InstallationId, Revision, TenantId};

const UUID_A: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";
const UUID_B: &str = "0190f2a5-7b1c-7abc-8def-0123456789ac";
const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn installation(tenant: &str, installation_id: &str) -> AgentInstallation {
    AgentInstallation::new(
        TenantId::from_str(tenant).unwrap(),
        InstallationId::from_str(installation_id).unwrap(),
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        ExecutionMode::ConnectorManaged,
        Revision::new(1).unwrap(),
        DescriptorDigest::from_bytes([1; 32]),
    )
}

#[test]
fn device_lifecycle_is_bound_to_its_exact_tenant_and_installation() {
    let owner = installation(UUID_A, UUID_A);
    let other_tenant = installation(UUID_B, UUID_A);
    let other_installation = installation(UUID_A, UUID_B);
    let fingerprint = DeviceCredentialFingerprint::from_bytes([0xa5; 32]);
    let mut device = AgentDevice::enroll(
        &owner,
        AgentDeviceId::from_str(UUID_A).unwrap(),
        fingerprint,
    )
    .unwrap();

    assert_eq!(device.state(), AgentDeviceState::Provisioning);
    assert_eq!(
        device.apply(
            &other_tenant,
            Revision::new(1).unwrap(),
            AgentDeviceCommand::Activate,
        ),
        Err(AgentDeviceError::ScopeMismatch)
    );
    assert_eq!(
        device.apply(
            &other_installation,
            Revision::new(1).unwrap(),
            AgentDeviceCommand::Activate,
        ),
        Err(AgentDeviceError::ScopeMismatch)
    );

    device
        .apply(
            &owner,
            Revision::new(1).unwrap(),
            AgentDeviceCommand::Activate,
        )
        .unwrap();
    assert_eq!(device.state(), AgentDeviceState::Active);
    device
        .apply(
            &owner,
            Revision::new(2).unwrap(),
            AgentDeviceCommand::Revoke,
        )
        .unwrap();
    let terminal = device.clone();
    assert_eq!(
        device.apply(
            &owner,
            Revision::new(3).unwrap(),
            AgentDeviceCommand::Activate,
        ),
        Err(AgentDeviceError::Revoked)
    );
    assert_eq!(device, terminal);
}

#[test]
fn device_state_retains_only_a_redacted_credential_fingerprint() {
    let owner = installation(UUID_A, UUID_A);
    let fingerprint = DeviceCredentialFingerprint::from_bytes([0xa5; 32]);
    let device = AgentDevice::enroll(
        &owner,
        AgentDeviceId::from_str(UUID_A).unwrap(),
        fingerprint,
    )
    .unwrap();

    assert!(device.credential_matches(fingerprint));
    let debug = format!("{device:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("165"));
    assert!(!debug.contains("a5a5"));
}
