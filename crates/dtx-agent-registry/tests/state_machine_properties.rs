use std::str::FromStr;

use dtx_agent_registry::{
    AgentConversationPermission, AgentConversationPermissions, AgentDevice, AgentDeviceCommand,
    AgentDeviceState, AgentInstallation, AllMessagesConfirmation, ConversationGrant,
    ConversationGrantCommand, ConversationGrantUpdate, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode, InstallationCommand, InstallationDesiredState,
    PermissionExpansionConfirmation, PrivacyPolicyDigest, TriggerPolicy,
};
use dtx_domain::{
    AgentDeviceId, AgentId, ConversationId, DeviceId, GrantId, IdentityId, InstallationId,
    Revision, TenantId,
};
use proptest::prelude::*;

const UUID_A: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";
const UUID_B: &str = "0190f2a5-7b1c-7abc-8def-0123456789ac";
const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn installation() -> AgentInstallation {
    AgentInstallation::new(
        TenantId::from_str(UUID_A).unwrap(),
        InstallationId::from_str(UUID_A).unwrap(),
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        ExecutionMode::ConnectorManaged,
        Revision::new(1).unwrap(),
        DescriptorDigest::from_bytes([1; 32]),
    )
}

fn installation_command(value: u8) -> InstallationCommand {
    match value % 8 {
        0 => InstallationCommand::MarkReady,
        1 => InstallationCommand::MarkDegraded,
        2 => InstallationCommand::RequireUpgrade,
        3 => InstallationCommand::Disable,
        4 => InstallationCommand::Enable,
        5 => InstallationCommand::UpgradeDescriptor {
            version: Revision::new(u64::from(value / 7) + 1).unwrap(),
            hash: DescriptorDigest::from_bytes([value; 32]),
        },
        6 => InstallationCommand::AdvancePolicy {
            revision: Revision::new(u64::from(value / 8) + 1).unwrap(),
        },
        _ => InstallationCommand::Revoke,
    }
}

fn base_permissions() -> AgentConversationPermissions {
    AgentConversationPermissions::none().with(AgentConversationPermission::SendMessages)
}

fn grant() -> ConversationGrant {
    ConversationGrant::issue(
        &installation(),
        GrantId::from_str(UUID_A).unwrap(),
        ConversationId::from_str(UUID_A).unwrap(),
        base_permissions(),
        TriggerPolicy::MentionOnly,
        PrivacyPolicyDigest::from_bytes([1; 32]),
        DeviceId::from_str(UUID_A).unwrap(),
        1_000,
        None,
        None,
    )
    .unwrap()
}

fn grant_update(value: u8, index: usize) -> ConversationGrantUpdate {
    let mut permissions = base_permissions();
    if value & 1 != 0 {
        permissions = permissions.with(AgentConversationPermission::InvokeTools);
    }
    ConversationGrantUpdate::new(
        permissions,
        if value & 2 != 0 {
            TriggerPolicy::AllMessages
        } else {
            TriggerPolicy::MentionOnly
        },
        PrivacyPolicyDigest::from_bytes([value; 32]),
        DeviceId::from_str(UUID_A).unwrap(),
        3_000 + i64::try_from(index).unwrap(),
        None,
    )
}

proptest! {
    #[test]
    fn installation_random_commands_are_atomic_and_revoked_is_absorbing(
        commands in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut state = installation();
        for value in commands {
            let before = state.clone();
            let expected = state.revision();
            let result = state.apply(expected, installation_command(value));
            if result.is_ok() {
                prop_assert_eq!(state.revision(), before.revision().checked_next().unwrap());
            } else {
                prop_assert_eq!(&state, &before);
            }
            if before.desired_state() == InstallationDesiredState::Revoked {
                prop_assert!(result.is_err());
                prop_assert_eq!(&state, &before);
            }
        }
    }

    #[test]
    fn device_random_commands_never_leave_revoked_and_failed_commands_are_atomic(
        commands in prop::collection::vec(any::<bool>(), 0..128),
    ) {
        let owner = installation();
        let mut state = AgentDevice::enroll(
            &owner,
            AgentDeviceId::from_str(UUID_A).unwrap(),
            DeviceCredentialFingerprint::from_bytes([7; 32]),
        ).unwrap();
        for activate in commands {
            let before = state.clone();
            let result = state.apply(
                &owner,
                state.revision(),
                if activate { AgentDeviceCommand::Activate } else { AgentDeviceCommand::Revoke },
            );
            if result.is_ok() {
                prop_assert_eq!(state.revision(), before.revision().checked_next().unwrap());
            } else {
                prop_assert_eq!(&state, &before);
            }
            if before.state() == AgentDeviceState::Revoked {
                prop_assert!(result.is_err());
                prop_assert_eq!(&state, &before);
            }
        }
    }

    #[test]
    fn grant_random_commands_are_atomic_monotonic_and_version_fenced(
        commands in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let owner = installation();
        let mut state = grant();
        for (index, value) in commands.into_iter().enumerate() {
            let before = state.clone();
            let captured_version = state.grant_version();
            let update = grant_update(value, index);
            let all_messages = (value & 4 != 0).then(AllMessagesConfirmation::confirmed);
            let command = match value % 3 {
                0 => ConversationGrantCommand::Update {
                    update,
                    permission_expansion: (value & 8 != 0)
                        .then(PermissionExpansionConfirmation::confirmed),
                    all_messages,
                },
                1 => ConversationGrantCommand::Revoke {
                    revoked_at_ms: 2_000 + i64::try_from(index).unwrap(),
                },
                _ => ConversationGrantCommand::Regrant {
                    grant_id: if state.grant_id() == GrantId::from_str(UUID_A).unwrap() {
                        GrantId::from_str(UUID_B).unwrap()
                    } else {
                        GrantId::from_str(UUID_A).unwrap()
                    },
                    update,
                    permission_expansion: PermissionExpansionConfirmation::confirmed(),
                    all_messages,
                },
            };
            let result = state.apply(&owner, captured_version, command);
            if result.is_ok() {
                prop_assert_eq!(state.grant_version(), captured_version.checked_next().unwrap());
                prop_assert!(!state.authorizes_version_for(&owner, 1_500, captured_version));
            } else {
                prop_assert_eq!(&state, &before);
            }
        }
    }
}
