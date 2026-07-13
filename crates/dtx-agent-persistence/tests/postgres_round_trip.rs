#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr};

use dtx_agent_host::{AgentHost, ReportedHealth};
use dtx_agent_persistence::{
    AgentDefinitionRepository, AgentDeviceRepository, AgentHostRepository,
    AgentInstallationRepository, AgentPersistenceError, BindingSetRepository, ConnectorRepository,
    ConversationGrantRepository, CurrentWrite, DefinitionInsert,
};
use dtx_agent_registry::{
    AgentConversationPermission, AgentConversationPermissions, AgentDevice, AgentDeviceCommand,
    AgentInstallation, ConversationGrant, ConversationGrantCommand, ConversationGrantUpdate,
    DescriptorDigest, DeviceCredentialFingerprint, ExecutionMode, InstallationCommand,
    PermissionExpansionConfirmation, PrivacyPolicyDigest, TriggerPolicy, VerifiedAgentDefinition,
};
use dtx_connect_registry::{
    AdapterConformance, AdapterKind, BindingSet, BindingSpec, Connector, ConnectorFence,
    ConnectorObservedState, ConnectorSnapshot, LeaseStatus, RoutingPolicy, TenantRef,
};
use dtx_domain::{
    AgentDeviceId, AgentId, BindingId, BootId, CloudConnectionId, ConnectorId, ConversationId,
    DeviceId, Ed25519PublicKey, GrantId, HostCredentialId, HostId, IdentityId, InstallationId,
    LeaseId, Revision, TenantId,
};
use dtx_storage::PgStore;
use sqlx::PgConnection;
use support::PostgresHarness;
use uuid::Uuid;

const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

struct PersistedFixture {
    tenant_id: TenantId,
    definition: VerifiedAgentDefinition,
    installation: AgentInstallation,
    stale_installation: AgentInstallation,
    device: AgentDevice,
    host: AgentHost,
    connector: Connector,
    first_lease_fence: ConnectorFence,
    binding_set: BindingSet,
    stale_binding_set: BindingSet,
    grant: ConversationGrant,
    stale_grant: ConversationGrant,
}

struct BindingRaceFixture {
    base: BindingSet,
    left_installation: AgentInstallation,
    left_device: AgentDevice,
    right_installation: AgentInstallation,
    right_device: AgentDevice,
    connector: Connector,
}

#[tokio::test]
async fn agent_control_aggregates_round_trip_and_preserve_database_fences()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(4).await?;
    let tenant_id = TenantId::new();
    let foreign_tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    provision_tenant(&store, foreign_tenant_id).await?;

    let fixture = persist_complete_fixture(&store, tenant_id).await?;
    assert_definition_history_fences(&store, &fixture.definition).await?;
    assert_stale_cas_is_rejected(&store, &fixture).await?;
    assert_cross_tenant_rows_are_hidden(&store, foreign_tenant_id, &fixture).await?;
    assert_only_one_concurrent_replacement_lease_wins(&store, &fixture).await?;
    assert_only_one_concurrent_single_session_binding_wins(&store, &fixture).await?;
    Ok(())
}

async fn provision_tenant(store: &PgStore, tenant_id: TenantId) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query(
        "INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence)
         VALUES ($1, 0)",
    )
    .bind(Uuid::from(tenant_id))
    .execute(session.connection())
    .await?;
    session.commit().await?;
    Ok(())
}

async fn persist_complete_fixture(
    store: &PgStore,
    tenant_id: TenantId,
) -> Result<PersistedFixture, Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let connection = session.connection();
    let (definition, installation, stale_installation) =
        persist_definition_and_installation(connection, tenant_id).await?;
    let device = persist_device(connection, &installation).await?;
    let host = persist_host(connection, tenant_id).await?;
    let (connector, first_lease_fence) = persist_connector(connection, &host).await?;
    let (binding_set, stale_binding_set) =
        persist_binding_set(connection, &installation, &device, &connector).await?;
    let (grant, stale_grant) = persist_grant(connection, &installation).await?;
    session.commit().await?;
    Ok(PersistedFixture {
        tenant_id,
        definition,
        installation,
        stale_installation,
        device,
        host,
        connector,
        first_lease_fence,
        binding_set,
        stale_binding_set,
        grant,
        stale_grant,
    })
}

async fn persist_definition_and_installation(
    connection: &mut PgConnection,
    tenant_id: TenantId,
) -> Result<
    (
        VerifiedAgentDefinition,
        AgentInstallation,
        AgentInstallation,
    ),
    Box<dyn Error>,
> {
    let agent_id = AgentId::from_str(AGENT_ID)?;
    let owner_id = IdentityId::from_str(OWNER_ID)?;
    let definition = VerifiedAgentDefinition::new(
        agent_id,
        owner_id,
        Revision::INITIAL,
        DescriptorDigest::from_bytes([11; 32]),
        20_000,
    );
    let definitions = AgentDefinitionRepository::new();
    assert_eq!(
        definitions.insert(connection, &definition, 1_000).await?,
        DefinitionInsert::Inserted
    );
    assert_eq!(
        definitions.insert(connection, &definition, 1_001).await?,
        DefinitionInsert::Existing
    );
    let conflicting = VerifiedAgentDefinition::new(
        agent_id,
        owner_id,
        Revision::INITIAL,
        DescriptorDigest::from_bytes([12; 32]),
        20_000,
    );
    assert!(matches!(
        definitions.insert(connection, &conflicting, 1_002).await,
        Err(AgentPersistenceError::ImmutableConflict(_))
    ));

    let mut installation = AgentInstallation::new(
        tenant_id,
        InstallationId::new(),
        agent_id,
        owner_id,
        ExecutionMode::ConnectorManaged,
        definition.version(),
        definition.descriptor_hash(),
    );
    let stale_installation = installation.clone();
    let installations = AgentInstallationRepository::new();
    assert_eq!(
        installations.save(connection, &installation, 1_010).await?,
        CurrentWrite::Inserted
    );
    assert_eq!(
        installations.save(connection, &installation, 1_011).await?,
        CurrentWrite::Existing
    );
    installation.apply(installation.revision(), InstallationCommand::MarkReady)?;
    assert_eq!(
        installations.save(connection, &installation, 1_012).await?,
        CurrentWrite::Advanced
    );
    let loaded = installations
        .load(connection, tenant_id, installation.installation_id())
        .await?
        .expect("saved Installation must reload");
    assert_eq!(loaded.snapshot(), installation.snapshot());
    Ok((definition, installation, stale_installation))
}

async fn persist_device(
    connection: &mut PgConnection,
    installation: &AgentInstallation,
) -> Result<AgentDevice, Box<dyn Error>> {
    let mut device = AgentDevice::enroll(
        installation,
        AgentDeviceId::new(),
        DeviceCredentialFingerprint::from_bytes([21; 32]),
    )?;
    let devices = AgentDeviceRepository::new();
    assert_eq!(
        devices.save(connection, &device, 1_020).await?,
        CurrentWrite::Inserted
    );
    device.apply(
        installation,
        device.revision(),
        AgentDeviceCommand::Activate,
    )?;
    assert_eq!(
        devices.save(connection, &device, 1_021).await?,
        CurrentWrite::Advanced
    );
    assert_eq!(
        devices.save(connection, &device, 1_022).await?,
        CurrentWrite::Existing
    );
    assert_eq!(
        devices
            .load(
                connection,
                installation.tenant_id(),
                device.agent_device_id()
            )
            .await?
            .expect("saved Device must reload")
            .snapshot(),
        device.snapshot()
    );
    Ok(device)
}

async fn persist_host(
    connection: &mut PgConnection,
    tenant_id: TenantId,
) -> Result<AgentHost, Box<dyn Error>> {
    let mut host = AgentHost::register(tenant_id, HostId::new(), IdentityId::from_str(OWNER_ID)?);
    let hosts = AgentHostRepository::new();
    assert_eq!(
        hosts.save(connection, &host, 1_030).await?,
        CurrentWrite::Inserted
    );
    let first_credential = HostCredentialId::new();
    host.enroll(host.revision(), first_credential)?;
    assert_eq!(
        hosts.save(connection, &host, 1_031).await?,
        CurrentWrite::Advanced
    );
    let current_credential = HostCredentialId::new();
    host.rotate_credential(host.revision(), current_credential)?;
    assert_eq!(
        hosts.save(connection, &host, 1_032).await?,
        CurrentWrite::Advanced
    );
    host.record_heartbeat(
        host.revision(),
        current_credential,
        host.desired_revision(),
        ReportedHealth::Healthy,
        1_040,
        100,
    )?;
    assert_eq!(
        hosts.save(connection, &host, 1_041).await?,
        CurrentWrite::Advanced
    );
    assert_eq!(
        hosts.save(connection, &host, 1_042).await?,
        CurrentWrite::Existing
    );
    assert_eq!(
        hosts
            .load(connection, tenant_id, host.host_id())
            .await?
            .expect("saved Host must reload")
            .snapshot(),
        host.snapshot()
    );
    Ok(host)
}

async fn persist_connector(
    connection: &mut PgConnection,
    host: &AgentHost,
) -> Result<(Connector, ConnectorFence), Box<dyn Error>> {
    let mut connector = Connector::register(host, ConnectorId::new(), AdapterKind::Codex, 4)?;
    let connectors = ConnectorRepository::new();
    assert_eq!(
        connectors.save(connection, &connector, None, 1_050).await?,
        CurrentWrite::Inserted
    );
    let initial = connector.snapshot();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, 1_060)?;
    let first_fence = connector.issue_lease(LeaseId::new(), boot_id, 1_060, 1_160)?;
    let active_without_heartbeat = connector.snapshot();
    assert_eq!(
        connectors
            .save(connection, &connector, Some(&initial), 1_071)
            .await?,
        CurrentWrite::Advanced
    );
    connector.record_heartbeat(&first_fence, 7, 1_070, ConnectorObservedState::Ready, 3, 1)?;
    let second_fence = connector.issue_lease(LeaseId::new(), boot_id, 1_080, 1_180)?;
    connector.record_heartbeat(&second_fence, 1, 1_090, ConnectorObservedState::Busy, 0, 1)?;
    assert_eq!(
        connectors
            .save(
                connection,
                &connector,
                Some(&active_without_heartbeat),
                1_091,
            )
            .await?,
        CurrentWrite::Advanced
    );
    assert_eq!(
        connectors.save(connection, &connector, None, 1_092).await?,
        CurrentWrite::Existing
    );
    let mut loaded = connectors
        .load(connection, host.tenant_id(), connector.connector_id())
        .await?
        .expect("saved Connector must reload");
    assert_eq!(loaded.snapshot(), connector.snapshot());
    let before_stale_heartbeat = loaded.snapshot();
    assert!(
        loaded
            .record_heartbeat(&first_fence, 8, 1_100, ConnectorObservedState::Ready, 2, 1,)
            .is_err(),
        "a replacement lease must fence the prior stream"
    );
    assert_eq!(loaded.snapshot(), before_stale_heartbeat);
    Ok((connector, first_fence))
}

async fn persist_binding_set(
    connection: &mut PgConnection,
    installation: &AgentInstallation,
    device: &AgentDevice,
    connector: &Connector,
) -> Result<(BindingSet, BindingSet), Box<dyn Error>> {
    let tenant_id = installation.tenant_id();
    let mut set = BindingSet::new(tenant_id);
    set.register_connector_conformance(
        connector,
        AdapterConformance::trusted_multi_session(AdapterKind::Codex, Revision::INITIAL),
    )?;
    let spec = BindingSpec::for_entities(
        TenantRef::new(tenant_id, BindingId::new()),
        installation,
        device,
        connector,
        1,
        2,
    )?;
    let binding_ref = spec.binding_ref();
    set.create_binding(spec, RoutingPolicy::OrderedFailover)?;
    let bindings = BindingSetRepository::new();
    bindings.save(connection, &set, 1_100).await?;
    let stale = set.clone();
    set.enable(binding_ref, Revision::INITIAL, installation, device)?;
    bindings.save(connection, &set, 1_101).await?;
    bindings.save(connection, &set, 1_102).await?;
    assert_eq!(
        bindings.load(connection, tenant_id).await?.snapshot(),
        set.snapshot()
    );
    Ok((set, stale))
}

async fn persist_grant(
    connection: &mut PgConnection,
    installation: &AgentInstallation,
) -> Result<(ConversationGrant, ConversationGrant), Box<dyn Error>> {
    let permissions = AgentConversationPermissions::none()
        .with(AgentConversationPermission::SendMessages)
        .with(AgentConversationPermission::StartServerJobs)
        .with_cloud_connection(CloudConnectionId::new());
    let mut grant = ConversationGrant::issue(
        installation,
        GrantId::new(),
        ConversationId::new(),
        permissions.clone(),
        TriggerPolicy::MentionOnly,
        PrivacyPolicyDigest::from_bytes([31; 32]),
        DeviceId::new(),
        1_100,
        Some(5_000),
        None,
    )?;
    let grants = ConversationGrantRepository::new();
    assert_eq!(
        grants.save(connection, &grant, 1_110).await?,
        CurrentWrite::Inserted
    );
    let stale = grant.clone();
    grant.apply(
        installation,
        grant.grant_version(),
        ConversationGrantCommand::Revoke {
            revoked_at_ms: 1_120,
        },
    )?;
    assert_eq!(
        grants.save(connection, &grant, 1_121).await?,
        CurrentWrite::Advanced
    );
    grant.apply(
        installation,
        grant.grant_version(),
        ConversationGrantCommand::Regrant {
            grant_id: GrantId::new(),
            update: ConversationGrantUpdate::new(
                permissions,
                TriggerPolicy::ManualOnly,
                PrivacyPolicyDigest::from_bytes([32; 32]),
                DeviceId::new(),
                1_130,
                Some(6_000),
            ),
            permission_expansion: PermissionExpansionConfirmation::confirmed(),
            all_messages: None,
        },
    )?;
    assert_eq!(
        grants.save(connection, &grant, 1_131).await?,
        CurrentWrite::Advanced
    );
    assert_eq!(
        grants.save(connection, &grant, 1_132).await?,
        CurrentWrite::Existing
    );
    assert_eq!(
        grants
            .load(
                connection,
                installation.tenant_id(),
                grant.conversation_id(),
                installation.installation_id(),
            )
            .await?
            .expect("saved Grant must reload")
            .snapshot(),
        grant.snapshot()
    );
    Ok((grant, stale))
}

async fn assert_definition_history_fences(
    store: &PgStore,
    definition: &VerifiedAgentDefinition,
) -> Result<(), Box<dyn Error>> {
    let higher = VerifiedAgentDefinition::new(
        definition.agent_id(),
        definition.publisher_id(),
        Revision::new(3)?,
        DescriptorDigest::from_bytes([41; 32]),
        30_000,
    );
    let mut session = store.begin_tenant(TenantId::new()).await?;
    let definitions = AgentDefinitionRepository::new();
    assert_eq!(
        definitions
            .insert(session.connection(), &higher, 3_000)
            .await?,
        DefinitionInsert::Inserted
    );
    let registry = definitions.load_registry(session.connection()).await?;
    assert_eq!(registry.version_count(definition.agent_id()), 2);
    assert_eq!(registry.head(definition.agent_id()), Some(&higher));
    session.commit().await?;

    let rollback = VerifiedAgentDefinition::new(
        definition.agent_id(),
        definition.publisher_id(),
        Revision::new(2)?,
        DescriptorDigest::from_bytes([42; 32]),
        30_000,
    );
    let mut session = store.begin_tenant(TenantId::new()).await?;
    assert!(
        AgentDefinitionRepository::new()
            .insert(session.connection(), &rollback, 3_001)
            .await
            .is_err(),
        "an unadmitted version below the persisted head must be rejected"
    );
    session.rollback().await?;

    let other_publisher = IdentityId::derive(&alternate_public_key());
    let publisher_change = VerifiedAgentDefinition::new(
        definition.agent_id(),
        other_publisher,
        Revision::new(4)?,
        DescriptorDigest::from_bytes([43; 32]),
        30_000,
    );
    let mut session = store.begin_tenant(TenantId::new()).await?;
    assert!(
        AgentDefinitionRepository::new()
            .insert(session.connection(), &publisher_change, 3_002)
            .await
            .is_err(),
        "an Agent ID cannot switch publishers at a later version"
    );
    session.rollback().await?;

    let mut session = store.begin_tenant(TenantId::new()).await?;
    assert_eq!(
        AgentDefinitionRepository::new()
            .insert(session.connection(), definition, 30_003)
            .await?,
        DefinitionInsert::Existing,
        "an exact old-version retry remains idempotent after the head advances"
    );
    session.rollback().await?;
    Ok(())
}

fn alternate_public_key() -> Ed25519PublicKey {
    Ed25519PublicKey::try_from([
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ])
    .expect("RFC 8032 public key is canonical and non-weak")
}

async fn assert_stale_cas_is_rejected(
    store: &PgStore,
    fixture: &PersistedFixture,
) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(fixture.tenant_id).await?;
    let connection = session.connection();
    assert!(matches!(
        AgentInstallationRepository::new()
            .save(connection, &fixture.stale_installation, 2_000)
            .await,
        Err(AgentPersistenceError::RevisionConflict { current: Some(2) })
    ));
    assert!(matches!(
        BindingSetRepository::new()
            .save(connection, &fixture.stale_binding_set, 2_001)
            .await,
        Err(AgentPersistenceError::RevisionConflict { current: Some(2) })
    ));
    assert!(matches!(
        ConversationGrantRepository::new()
            .save(connection, &fixture.stale_grant, 2_002)
            .await,
        Err(AgentPersistenceError::RevisionConflict { current: Some(3) })
    ));
    session.rollback().await?;
    Ok(())
}

async fn assert_cross_tenant_rows_are_hidden(
    store: &PgStore,
    foreign_tenant_id: TenantId,
    fixture: &PersistedFixture,
) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(foreign_tenant_id).await?;
    let connection = session.connection();
    assert!(
        AgentDefinitionRepository::new()
            .load(
                connection,
                fixture.definition.agent_id(),
                fixture.definition.version(),
            )
            .await?
            .is_some(),
        "public Agent definitions are intentionally global"
    );
    assert!(
        AgentInstallationRepository::new()
            .load(
                connection,
                fixture.tenant_id,
                fixture.installation.installation_id(),
            )
            .await?
            .is_none()
    );
    assert!(
        AgentDeviceRepository::new()
            .load(
                connection,
                fixture.tenant_id,
                fixture.device.agent_device_id(),
            )
            .await?
            .is_none()
    );
    assert!(
        AgentHostRepository::new()
            .load(connection, fixture.tenant_id, fixture.host.host_id())
            .await?
            .is_none()
    );
    assert!(
        ConnectorRepository::new()
            .load(
                connection,
                fixture.tenant_id,
                fixture.connector.connector_id(),
            )
            .await?
            .is_none()
    );
    assert!(
        BindingSetRepository::new()
            .load(connection, fixture.tenant_id)
            .await?
            .snapshot()
            .bindings
            .is_empty()
    );
    assert!(
        ConversationGrantRepository::new()
            .load(
                connection,
                fixture.tenant_id,
                fixture.grant.conversation_id(),
                fixture.installation.installation_id(),
            )
            .await?
            .is_none()
    );
    session.rollback().await?;
    Ok(())
}

async fn assert_only_one_concurrent_replacement_lease_wins(
    store: &PgStore,
    fixture: &PersistedFixture,
) -> Result<(), Box<dyn Error>> {
    let expected = fixture.connector.snapshot();
    let boot_id = expected
        .current_boot_id
        .expect("Connector has an active Boot");
    let mut left = fixture.connector.clone();
    left.issue_lease(LeaseId::new(), boot_id, 1_140, 1_240)?;
    let mut right = fixture.connector.clone();
    right.issue_lease(LeaseId::new(), boot_id, 1_140, 1_240)?;
    let (left_result, right_result) = tokio::join!(
        save_connector_transaction(
            store.clone(),
            fixture.tenant_id,
            left,
            expected.clone(),
            2_100,
        ),
        save_connector_transaction(store.clone(), fixture.tenant_id, right, expected, 2_100,)
    );
    let successes = [&left_result, &right_result]
        .into_iter()
        .filter(|result| matches!(result, Ok(CurrentWrite::Advanced)))
        .count();
    assert_eq!(successes, 1, "exactly one Connector CAS must win");
    assert_eq!(
        u8::from(left_result.is_err()) + u8::from(right_result.is_err()),
        1
    );

    let mut session = store.begin_tenant(fixture.tenant_id).await?;
    let mut reloaded = ConnectorRepository::new()
        .load(
            session.connection(),
            fixture.tenant_id,
            fixture.connector.connector_id(),
        )
        .await?
        .expect("raced Connector must reload");
    let snapshot = reloaded.snapshot();
    assert_eq!(
        snapshot
            .leases
            .iter()
            .filter(|lease| lease.status == LeaseStatus::Active)
            .count(),
        1
    );
    assert_eq!(snapshot.leases.len(), 3);
    let before_stale = reloaded.snapshot();
    assert!(
        reloaded
            .record_heartbeat(
                &fixture.first_lease_fence,
                8,
                1_150,
                ConnectorObservedState::Ready,
                1,
                1,
            )
            .is_err()
    );
    assert_eq!(reloaded.snapshot(), before_stale);
    session.rollback().await?;
    Ok(())
}

async fn assert_only_one_concurrent_single_session_binding_wins(
    store: &PgStore,
    fixture: &PersistedFixture,
) -> Result<(), Box<dyn Error>> {
    let race = persist_binding_race_base(store, fixture).await?;
    let left = enabled_exclusive_proposal(
        &race.base,
        &race.left_installation,
        &race.left_device,
        &race.connector,
    )?;
    let right = enabled_exclusive_proposal(
        &race.base,
        &race.right_installation,
        &race.right_device,
        &race.connector,
    )?;
    let (left_result, right_result) = tokio::join!(
        save_binding_transaction(store.clone(), fixture.tenant_id, left.clone(), 4_100),
        save_binding_transaction(store.clone(), fixture.tenant_id, right.clone(), 4_100),
    );
    assert_eq!(
        u8::from(left_result.is_ok()) + u8::from(right_result.is_ok()),
        1,
        "the tenant-wide BindingSet lock must serialize conflicting complete sets"
    );

    let mut session = store.begin_tenant(fixture.tenant_id).await?;
    let persisted = BindingSetRepository::new()
        .load(session.connection(), fixture.tenant_id)
        .await?;
    let persisted = persisted.snapshot();
    assert!(
        persisted == left.snapshot() || persisted == right.snapshot(),
        "the committed BindingSet must equal one complete proposal"
    );
    session.rollback().await?;
    Ok(())
}

async fn persist_binding_race_base(
    store: &PgStore,
    fixture: &PersistedFixture,
) -> Result<BindingRaceFixture, Box<dyn Error>> {
    let mut session = store.begin_tenant(fixture.tenant_id).await?;
    let connection = session.connection();
    let (left_installation, left_device) =
        persist_binding_race_entity(connection, fixture, 3_100, 51).await?;
    let (right_installation, right_device) =
        persist_binding_race_entity(connection, fixture, 3_200, 52).await?;
    let connector = Connector::register(
        &fixture.host,
        ConnectorId::new(),
        AdapterKind::OpenClawAcp,
        2,
    )?;
    assert_eq!(
        ConnectorRepository::new()
            .save(connection, &connector, None, 3_300)
            .await?,
        CurrentWrite::Inserted
    );
    let mut base = fixture.binding_set.clone();
    base.register_connector_conformance(
        &connector,
        AdapterConformance::trusted_single_session(AdapterKind::OpenClawAcp, Revision::INITIAL),
    )?;
    BindingSetRepository::new()
        .save(connection, &base, 3_301)
        .await?;
    session.commit().await?;
    Ok(BindingRaceFixture {
        base,
        left_installation,
        left_device,
        right_installation,
        right_device,
        connector,
    })
}

async fn persist_binding_race_entity(
    connection: &mut PgConnection,
    fixture: &PersistedFixture,
    stored_at_ms: i64,
    fingerprint_byte: u8,
) -> Result<(AgentInstallation, AgentDevice), Box<dyn Error>> {
    let installation = AgentInstallation::new(
        fixture.tenant_id,
        InstallationId::new(),
        fixture.definition.agent_id(),
        fixture.definition.publisher_id(),
        ExecutionMode::ConnectorManaged,
        fixture.definition.version(),
        fixture.definition.descriptor_hash(),
    );
    assert_eq!(
        AgentInstallationRepository::new()
            .save(connection, &installation, stored_at_ms)
            .await?,
        CurrentWrite::Inserted
    );
    let mut device = AgentDevice::enroll(
        &installation,
        AgentDeviceId::new(),
        DeviceCredentialFingerprint::from_bytes([fingerprint_byte; 32]),
    )?;
    assert_eq!(
        AgentDeviceRepository::new()
            .save(connection, &device, stored_at_ms + 1)
            .await?,
        CurrentWrite::Inserted
    );
    device.apply(
        &installation,
        device.revision(),
        AgentDeviceCommand::Activate,
    )?;
    assert_eq!(
        AgentDeviceRepository::new()
            .save(connection, &device, stored_at_ms + 2)
            .await?,
        CurrentWrite::Advanced
    );
    Ok((installation, device))
}

fn enabled_exclusive_proposal(
    base: &BindingSet,
    installation: &AgentInstallation,
    device: &AgentDevice,
    connector: &Connector,
) -> Result<BindingSet, Box<dyn Error>> {
    let mut proposal = base.clone();
    let specification = BindingSpec::for_entities(
        TenantRef::new(base.tenant_id(), BindingId::new()),
        installation,
        device,
        connector,
        0,
        1,
    )?;
    let binding_ref = specification.binding_ref();
    proposal.create_binding(specification, RoutingPolicy::Exclusive)?;
    proposal.enable(binding_ref, Revision::INITIAL, installation, device)?;
    Ok(proposal)
}

async fn save_binding_transaction(
    store: PgStore,
    tenant_id: TenantId,
    set: BindingSet,
    stored_at_ms: i64,
) -> Result<(), String> {
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|error| error.to_string())?;
    match BindingSetRepository::new()
        .save(session.connection(), &set, stored_at_ms)
        .await
    {
        Ok(()) => session.commit().await.map_err(|error| error.to_string()),
        Err(error) => {
            session
                .rollback()
                .await
                .map_err(|rollback| rollback.to_string())?;
            Err(error.to_string())
        }
    }
}

async fn save_connector_transaction(
    store: PgStore,
    tenant_id: TenantId,
    connector: Connector,
    expected: ConnectorSnapshot,
    stored_at_ms: i64,
) -> Result<CurrentWrite, String> {
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|error| error.to_string())?;
    match ConnectorRepository::new()
        .save(
            session.connection(),
            &connector,
            Some(&expected),
            stored_at_ms,
        )
        .await
    {
        Ok(write) => {
            session.commit().await.map_err(|error| error.to_string())?;
            Ok(write)
        }
        Err(error) => {
            session
                .rollback()
                .await
                .map_err(|rollback| rollback.to_string())?;
            Err(error.to_string())
        }
    }
}
