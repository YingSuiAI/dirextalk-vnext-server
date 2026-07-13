use std::str::FromStr;

use dtx_agent_registry::{
    AgentConversationPermission, AgentConversationPermissions, AgentDefinitionRegistry,
    AgentDefinitionRegistrySnapshot, AgentDefinitionSnapshotError, AgentDevice,
    AgentDeviceSnapshotError, AgentDeviceState, AgentInstallation, AgentInstallationSnapshotError,
    ConversationGrantCommand, ConversationGrantUpdate, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode, InstallationCommand, InstallationDesiredState,
    PermissionExpansionConfirmation, PrivacyPolicyDigest, TriggerPolicy, VerifiedAgentDefinition,
};
use dtx_domain::{
    AgentDeviceId, AgentId, ConversationId, DeviceId, GrantId, IdentityId, InstallationId,
    Revision, TenantId,
};

const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn installation() -> AgentInstallation {
    AgentInstallation::new(
        TenantId::new(),
        InstallationId::new(),
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        ExecutionMode::ConnectorManaged,
        Revision::INITIAL,
        DescriptorDigest::from_bytes([1; 32]),
    )
}

#[test]
fn definition_and_installation_snapshots_round_trip_and_reject_malformed_state() {
    let mut registry = AgentDefinitionRegistry::new();
    let definition = VerifiedAgentDefinition::new(
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        Revision::INITIAL,
        DescriptorDigest::from_bytes([2; 32]),
        2_000,
    );
    registry.admit(definition.clone(), 1_000).unwrap();
    registry
        .admit(
            VerifiedAgentDefinition::new(
                AgentId::from_str(AGENT_ID).unwrap(),
                IdentityId::from_str(OWNER_ID).unwrap(),
                Revision::new(2).unwrap(),
                DescriptorDigest::from_bytes([3; 32]),
                3_000,
            ),
            1_000,
        )
        .unwrap();
    assert_eq!(
        AgentDefinitionRegistry::try_from_snapshot(registry.snapshot()).unwrap(),
        registry
    );
    assert_eq!(
        AgentDefinitionRegistry::try_from_snapshot(AgentDefinitionRegistrySnapshot {
            definitions: vec![definition.clone(), definition],
        }),
        Err(AgentDefinitionSnapshotError::DuplicateVersion)
    );

    let mut installation = installation();
    installation
        .apply(installation.revision(), InstallationCommand::Disable)
        .unwrap();
    assert_eq!(
        AgentInstallation::try_from_snapshot(installation.snapshot()).unwrap(),
        installation
    );
    let mut malformed = installation.snapshot();
    malformed.revision = Revision::INITIAL;
    malformed.desired_state = InstallationDesiredState::Disabled;
    assert_eq!(
        AgentInstallation::try_from_snapshot(malformed),
        Err(AgentInstallationSnapshotError::UnreachableInitialState)
    );
}

#[test]
fn device_snapshot_rejects_every_unreachable_revision_state_pair() {
    let installation = installation();
    let mut device = AgentDevice::enroll(
        &installation,
        AgentDeviceId::new(),
        DeviceCredentialFingerprint::from_bytes([3; 32]),
    )
    .unwrap();
    device
        .apply(
            &installation,
            Revision::INITIAL,
            dtx_agent_registry::AgentDeviceCommand::Activate,
        )
        .unwrap();
    assert_eq!(
        AgentDevice::try_from_snapshot(device.snapshot()).unwrap(),
        device
    );

    for (state, revision) in [
        (AgentDeviceState::Provisioning, Revision::new(2).unwrap()),
        (AgentDeviceState::Active, Revision::INITIAL),
        (AgentDeviceState::Active, Revision::new(3).unwrap()),
        (AgentDeviceState::Revoked, Revision::new(4).unwrap()),
    ] {
        let mut malformed = device.snapshot();
        malformed.state = state;
        malformed.revision = revision;
        assert_eq!(
            AgentDevice::try_from_snapshot(malformed),
            Err(AgentDeviceSnapshotError::UnreachableInitialState)
        );
    }
}

#[test]
fn grant_snapshot_preserves_retired_ids_and_rejects_missing_id_history() {
    let installation = installation();
    let grant_id = GrantId::new();
    let mut grant = dtx_agent_registry::ConversationGrant::issue(
        &installation,
        grant_id,
        ConversationId::new(),
        AgentConversationPermissions::none().with(AgentConversationPermission::SendMessages),
        TriggerPolicy::MentionOnly,
        PrivacyPolicyDigest::from_bytes([4; 32]),
        DeviceId::new(),
        1_000,
        Some(2_000),
        None,
    )
    .unwrap();
    grant
        .apply(
            &installation,
            grant.grant_version(),
            ConversationGrantCommand::Revoke {
                revoked_at_ms: 1_500,
            },
        )
        .unwrap();
    let replacement_id = GrantId::new();
    grant
        .apply(
            &installation,
            grant.grant_version(),
            ConversationGrantCommand::Regrant {
                grant_id: replacement_id,
                update: ConversationGrantUpdate::new(
                    AgentConversationPermissions::none()
                        .with(AgentConversationPermission::SendMessages),
                    TriggerPolicy::ManualOnly,
                    PrivacyPolicyDigest::from_bytes([5; 32]),
                    DeviceId::new(),
                    1_600,
                    Some(2_500),
                ),
                permission_expansion: PermissionExpansionConfirmation::confirmed(),
                all_messages: None,
            },
        )
        .unwrap();
    assert!(grant.snapshot().used_grant_ids.contains(&grant_id));
    assert!(grant.snapshot().used_grant_ids.contains(&replacement_id));
    assert_eq!(
        dtx_agent_registry::ConversationGrant::try_from_snapshot(grant.snapshot()).unwrap(),
        grant
    );
    let mut malformed = grant.snapshot();
    malformed.used_grant_ids.clear();
    assert!(
        dtx_agent_registry::ConversationGrant::try_from_snapshot(malformed).is_err(),
        "current lifecycle ID must remain fenced after rehydration"
    );
    let mut impossible_history = grant.snapshot();
    impossible_history.grant_version = Revision::new(2).unwrap();
    assert!(
        dtx_agent_registry::ConversationGrant::try_from_snapshot(impossible_history).is_err(),
        "regrant requires both revoke and replacement version advances"
    );
}
