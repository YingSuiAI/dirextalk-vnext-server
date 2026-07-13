use std::str::FromStr;

use dtx_agent_registry::{
    AgentConversationPermission, AgentConversationPermissions, AgentInstallation,
    AllMessagesConfirmation, ConversationGrant, ConversationGrantCommand, ConversationGrantError,
    ConversationGrantUpdate, DescriptorDigest, ExecutionMode, PermissionExpansionConfirmation,
    PrivacyPolicyDigest, TriggerPolicy,
};
use dtx_domain::{
    AgentId, CloudConnectionId, ConversationId, DeviceId, GrantId, IdentityId, InstallationId,
    Revision, TenantId,
};

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

fn base_permissions() -> AgentConversationPermissions {
    AgentConversationPermissions::none().with(AgentConversationPermission::SendMessages)
}

fn update(
    permissions: AgentConversationPermissions,
    trigger_policy: TriggerPolicy,
    expires_at_ms: Option<i64>,
) -> ConversationGrantUpdate {
    ConversationGrantUpdate::new(
        permissions,
        trigger_policy,
        PrivacyPolicyDigest::from_bytes([2; 32]),
        DeviceId::from_str(UUID_A).unwrap(),
        1_100,
        expires_at_ms,
    )
}

#[test]
fn permissions_are_typed_and_expansion_requires_explicit_confirmation() {
    let owner = installation(UUID_A, UUID_A);
    let mut grant = ConversationGrant::issue(
        &owner,
        GrantId::from_str(UUID_A).unwrap(),
        ConversationId::from_str(UUID_A).unwrap(),
        base_permissions(),
        TriggerPolicy::MentionOnly,
        PrivacyPolicyDigest::from_bytes([1; 32]),
        DeviceId::from_str(UUID_A).unwrap(),
        1_000,
        Some(1_500),
        None,
    )
    .unwrap();

    let expanded = base_permissions()
        .with(AgentConversationPermission::InvokeTools)
        .with_cloud_connection(CloudConnectionId::from_str(UUID_A).unwrap());
    let proposed = update(expanded.clone(), TriggerPolicy::MentionOnly, Some(1_500));
    assert_eq!(
        grant.apply(
            &owner,
            Revision::new(1).unwrap(),
            ConversationGrantCommand::Update {
                update: proposed.clone(),
                permission_expansion: None,
                all_messages: None,
            },
        ),
        Err(ConversationGrantError::PermissionExpansionConfirmationRequired)
    );
    assert_eq!(grant.grant_version(), Revision::new(1).unwrap());

    grant
        .apply(
            &owner,
            Revision::new(1).unwrap(),
            ConversationGrantCommand::Update {
                update: proposed,
                permission_expansion: Some(PermissionExpansionConfirmation::confirmed()),
                all_messages: None,
            },
        )
        .unwrap();
    assert_eq!(grant.permissions(), &expanded);
    assert_eq!(grant.grant_version(), Revision::new(2).unwrap());
}

#[test]
fn expiry_revoke_and_regrant_are_version_fenced_and_tenant_bound() {
    let owner = installation(UUID_A, UUID_A);
    let other_tenant = installation(UUID_B, UUID_A);
    let mut grant = ConversationGrant::issue(
        &owner,
        GrantId::from_str(UUID_A).unwrap(),
        ConversationId::from_str(UUID_A).unwrap(),
        base_permissions(),
        TriggerPolicy::MentionOnly,
        PrivacyPolicyDigest::from_bytes([1; 32]),
        DeviceId::from_str(UUID_A).unwrap(),
        1_000,
        Some(1_500),
        None,
    )
    .unwrap();

    assert!(!grant.is_active_for(&owner, 999));
    assert!(grant.is_active_for(&owner, 1_499));
    assert!(grant.authorizes_version_for(&owner, 1_499, Revision::new(1).unwrap()));
    assert!(!grant.authorizes_version_for(&owner, 1_499, Revision::new(2).unwrap()));
    assert!(!grant.is_active_for(&owner, 1_500));
    assert!(!grant.is_active_for(&other_tenant, 1_100));
    assert_eq!(
        grant.apply(
            &other_tenant,
            Revision::new(1).unwrap(),
            ConversationGrantCommand::Revoke {
                revoked_at_ms: 1_200
            },
        ),
        Err(ConversationGrantError::ScopeMismatch)
    );

    grant
        .apply(
            &owner,
            Revision::new(1).unwrap(),
            ConversationGrantCommand::Revoke {
                revoked_at_ms: 1_200,
            },
        )
        .unwrap();
    assert!(!grant.is_active_for(&owner, 1_201));

    let regrant = ConversationGrantUpdate::new(
        base_permissions(),
        TriggerPolicy::MentionOnly,
        PrivacyPolicyDigest::from_bytes([2; 32]),
        DeviceId::from_str(UUID_A).unwrap(),
        1_201,
        Some(2_000),
    );
    grant
        .apply(
            &owner,
            Revision::new(2).unwrap(),
            ConversationGrantCommand::Regrant {
                grant_id: GrantId::from_str(UUID_B).unwrap(),
                update: regrant,
                permission_expansion: PermissionExpansionConfirmation::confirmed(),
                all_messages: None,
            },
        )
        .unwrap();
    assert_eq!(grant.grant_id(), GrantId::from_str(UUID_B).unwrap());
    assert_eq!(grant.grant_version(), Revision::new(3).unwrap());
    assert!(grant.is_active_for(&owner, 1_500));
}

#[test]
fn all_messages_trigger_requires_its_own_high_risk_confirmation() {
    let owner = installation(UUID_A, UUID_A);
    let mut grant = ConversationGrant::issue(
        &owner,
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
    .unwrap();
    let proposed = update(base_permissions(), TriggerPolicy::AllMessages, None);

    assert_eq!(
        grant.apply(
            &owner,
            Revision::new(1).unwrap(),
            ConversationGrantCommand::Update {
                update: proposed.clone(),
                permission_expansion: None,
                all_messages: None,
            },
        ),
        Err(ConversationGrantError::AllMessagesConfirmationRequired)
    );
    grant
        .apply(
            &owner,
            Revision::new(1).unwrap(),
            ConversationGrantCommand::Update {
                update: proposed,
                permission_expansion: None,
                all_messages: Some(AllMessagesConfirmation::confirmed()),
            },
        )
        .unwrap();
    assert_eq!(grant.trigger_policy(), TriggerPolicy::AllMessages);

    grant
        .apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Update {
                update: ConversationGrantUpdate::new(
                    base_permissions(),
                    TriggerPolicy::AllMessages,
                    PrivacyPolicyDigest::from_bytes([3; 32]),
                    DeviceId::from_str(UUID_A).unwrap(),
                    1_200,
                    None,
                ),
                permission_expansion: None,
                all_messages: None,
            },
        )
        .expect("retaining an already confirmed trigger does not require another marker");
}

#[test]
fn grant_approval_time_is_monotonic_and_regrant_must_follow_revocation() {
    let owner = installation(UUID_A, UUID_A);
    let mut grant = ConversationGrant::issue(
        &owner,
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
    .unwrap();
    let before_update = grant.clone();
    assert_eq!(
        grant.apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Update {
                update: ConversationGrantUpdate::new(
                    base_permissions(),
                    TriggerPolicy::MentionOnly,
                    PrivacyPolicyDigest::from_bytes([2; 32]),
                    DeviceId::from_str(UUID_A).unwrap(),
                    999,
                    None,
                ),
                permission_expansion: None,
                all_messages: None,
            },
        ),
        Err(ConversationGrantError::InvalidApprovalTime)
    );
    assert_eq!(grant, before_update);

    grant
        .apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Revoke {
                revoked_at_ms: 1_100,
            },
        )
        .unwrap();
    let revoked = grant.clone();
    assert_eq!(
        grant.apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Regrant {
                grant_id: GrantId::from_str(UUID_B).unwrap(),
                update: ConversationGrantUpdate::new(
                    base_permissions(),
                    TriggerPolicy::MentionOnly,
                    PrivacyPolicyDigest::from_bytes([2; 32]),
                    DeviceId::from_str(UUID_A).unwrap(),
                    1_099,
                    None,
                ),
                permission_expansion: PermissionExpansionConfirmation::confirmed(),
                all_messages: None,
            },
        ),
        Err(ConversationGrantError::InvalidApprovalTime)
    );
    assert_eq!(grant, revoked);
}

#[test]
fn regrant_never_reuses_any_prior_grant_lifecycle_id() {
    let owner = installation(UUID_A, UUID_A);
    let first_id = GrantId::from_str(UUID_A).unwrap();
    let second_id = GrantId::from_str(UUID_B).unwrap();
    let mut grant = ConversationGrant::issue(
        &owner,
        first_id,
        ConversationId::from_str(UUID_A).unwrap(),
        base_permissions(),
        TriggerPolicy::MentionOnly,
        PrivacyPolicyDigest::from_bytes([1; 32]),
        DeviceId::from_str(UUID_A).unwrap(),
        1_000,
        None,
        None,
    )
    .unwrap();
    grant
        .apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Revoke {
                revoked_at_ms: 1_001,
            },
        )
        .unwrap();
    grant
        .apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Regrant {
                grant_id: second_id,
                update: ConversationGrantUpdate::new(
                    base_permissions(),
                    TriggerPolicy::MentionOnly,
                    PrivacyPolicyDigest::from_bytes([2; 32]),
                    DeviceId::from_str(UUID_A).unwrap(),
                    1_002,
                    None,
                ),
                permission_expansion: PermissionExpansionConfirmation::confirmed(),
                all_messages: None,
            },
        )
        .unwrap();
    grant
        .apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Revoke {
                revoked_at_ms: 1_003,
            },
        )
        .unwrap();

    let before = grant.clone();
    assert_eq!(
        grant.apply(
            &owner,
            grant.grant_version(),
            ConversationGrantCommand::Regrant {
                grant_id: first_id,
                update: ConversationGrantUpdate::new(
                    base_permissions(),
                    TriggerPolicy::MentionOnly,
                    PrivacyPolicyDigest::from_bytes([3; 32]),
                    DeviceId::from_str(UUID_A).unwrap(),
                    1_004,
                    None,
                ),
                permission_expansion: PermissionExpansionConfirmation::confirmed(),
                all_messages: None,
            },
        ),
        Err(ConversationGrantError::GrantIdReused)
    );
    assert_eq!(grant, before);
}
