use std::str::FromStr;

use dtx_agent_registry::{
    AgentInstallation, DescriptorDigest, ExecutionMode, InstallationCommand,
    InstallationDesiredState, InstallationError, InstallationObservedState,
};
use dtx_domain::{AgentId, IdentityId, InstallationId, Revision, TenantId};

const UUID_V7: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";
const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
const OTHER_ID: &str = "dtxi1cteymucsdoxo3y2ssyv3lbxqcmuivts5g4bpgocvobmv3i5xbjna";

fn installation() -> AgentInstallation {
    AgentInstallation::new(
        TenantId::from_str(UUID_V7).unwrap(),
        InstallationId::from_str(UUID_V7).unwrap(),
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        ExecutionMode::ConnectorManaged,
        Revision::new(1).unwrap(),
        DescriptorDigest::from_bytes([1; 32]),
    )
}

#[test]
fn desired_and_observed_transitions_are_separate_and_revocation_is_terminal() {
    let mut installation = installation();
    installation
        .apply(
            Revision::INITIAL,
            InstallationCommand::BindAgentIdentity {
                identity_id: IdentityId::from_str(OWNER_ID).unwrap(),
            },
        )
        .unwrap();
    assert_eq!(
        installation.desired_state(),
        InstallationDesiredState::Enabled
    );
    assert_eq!(
        installation.observed_state(),
        InstallationObservedState::Installing
    );
    assert_eq!(installation.revision(), Revision::new(2).unwrap());

    installation
        .apply(Revision::new(2).unwrap(), InstallationCommand::MarkReady)
        .unwrap();
    installation
        .apply(Revision::new(3).unwrap(), InstallationCommand::Disable)
        .unwrap();
    assert_eq!(
        installation.desired_state(),
        InstallationDesiredState::Disabled
    );
    assert_eq!(
        installation.apply(Revision::new(4).unwrap(), InstallationCommand::MarkReady),
        Err(InstallationError::InvalidTransition)
    );

    installation
        .apply(Revision::new(4).unwrap(), InstallationCommand::Enable)
        .unwrap();
    assert_eq!(
        installation.observed_state(),
        InstallationObservedState::Installing
    );
    installation
        .apply(
            Revision::new(5).unwrap(),
            InstallationCommand::RequireUpgrade,
        )
        .unwrap();
    installation
        .apply(
            Revision::new(6).unwrap(),
            InstallationCommand::UpgradeDescriptor {
                version: Revision::new(2).unwrap(),
                hash: DescriptorDigest::from_bytes([2; 32]),
            },
        )
        .unwrap();

    assert_eq!(installation.descriptor_version(), Revision::new(2).unwrap());
    assert_eq!(
        installation.observed_state(),
        InstallationObservedState::Installing
    );
    assert_eq!(
        installation.apply(Revision::new(6).unwrap(), InstallationCommand::MarkReady),
        Err(InstallationError::RevisionConflict {
            actual: Revision::new(7).unwrap(),
            expected: Revision::new(6).unwrap(),
        })
    );

    installation
        .apply(Revision::new(7).unwrap(), InstallationCommand::Revoke)
        .unwrap();
    let terminal = installation.clone();
    assert_eq!(
        installation.desired_state(),
        InstallationDesiredState::Revoked
    );
    assert_eq!(
        installation.apply(Revision::new(8).unwrap(), InstallationCommand::Enable),
        Err(InstallationError::Revoked)
    );
    assert_eq!(installation, terminal);
}

#[test]
fn descriptor_upgrade_never_downgrades_or_equivocates() {
    let mut installation = installation();
    assert_eq!(
        installation.apply(
            Revision::new(1).unwrap(),
            InstallationCommand::UpgradeDescriptor {
                version: Revision::new(1).unwrap(),
                hash: DescriptorDigest::from_bytes([2; 32]),
            },
        ),
        Err(InstallationError::DescriptorVersionConflict)
    );
    assert_eq!(
        installation.apply(
            Revision::new(1).unwrap(),
            InstallationCommand::UpgradeDescriptor {
                version: Revision::new(1).unwrap(),
                hash: DescriptorDigest::from_bytes([1; 32]),
            },
        ),
        Err(InstallationError::NoChange)
    );
}

#[test]
fn policy_revision_advances_monotonically_and_is_independent_of_descriptor_version() {
    let mut installation = installation();
    assert_eq!(installation.policy_revision(), Revision::INITIAL);

    installation
        .apply(
            Revision::INITIAL,
            InstallationCommand::AdvancePolicy {
                revision: Revision::new(3).unwrap(),
            },
        )
        .unwrap();

    assert_eq!(installation.policy_revision(), Revision::new(3).unwrap());
    assert_eq!(installation.descriptor_version(), Revision::INITIAL);
    let unchanged = installation.clone();
    assert_eq!(
        installation.apply(
            installation.revision(),
            InstallationCommand::AdvancePolicy {
                revision: Revision::new(2).unwrap(),
            },
        ),
        Err(InstallationError::PolicyRevisionRegressed)
    );
    assert_eq!(installation, unchanged);
}

#[test]
fn agent_identity_is_bind_once_and_required_before_ready() {
    let mut installation = installation();
    let agent_identity = IdentityId::from_str(OWNER_ID).unwrap();

    assert_eq!(
        installation.apply(Revision::INITIAL, InstallationCommand::MarkReady),
        Err(InstallationError::AgentIdentityRequired)
    );
    installation
        .apply(
            Revision::INITIAL,
            InstallationCommand::BindAgentIdentity {
                identity_id: agent_identity,
            },
        )
        .unwrap();
    assert_eq!(installation.agent_identity_id(), Some(agent_identity));
    assert_eq!(
        installation
            .apply(
                Revision::new(2).unwrap(),
                InstallationCommand::ConfirmAgentIdentity {
                    identity_id: agent_identity,
                },
            )
            .unwrap(),
        Revision::new(3).unwrap()
    );
    assert_eq!(
        installation.apply(
            Revision::new(3).unwrap(),
            InstallationCommand::ConfirmAgentIdentity {
                identity_id: IdentityId::from_str(OTHER_ID).unwrap(),
            },
        ),
        Err(InstallationError::AgentIdentityAlreadyBound)
    );
    assert_eq!(
        installation.apply(
            Revision::new(3).unwrap(),
            InstallationCommand::BindAgentIdentity {
                identity_id: agent_identity,
            },
        ),
        Err(InstallationError::AgentIdentityAlreadyBound)
    );
    installation
        .apply(Revision::new(3).unwrap(), InstallationCommand::MarkReady)
        .unwrap();
}
