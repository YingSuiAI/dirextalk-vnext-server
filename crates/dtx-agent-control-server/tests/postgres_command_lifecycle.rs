#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr, sync::Arc, time::Duration};

use dtx_agent_control::{
    CloseStreamCommand, CommandLog, CommandLogState, ConfigEntry, ConnectorCredential,
    ConnectorCredentialAuthorizationState, ConnectorCredentialStatus, CredentialRotationTranscript,
    DurableServerCommand, EnrollmentRequest, EnrollmentToken, EnrollmentTranscript, RuntimeClaims,
    ServerCommandPayload, Sha256Digest,
};
use dtx_agent_control_proto::v1;
use dtx_agent_control_server::{
    ApplyConnectorConfigurationRequest, CloseConnectorStreamRequest, ConnectorCertificateAuthority,
    ConnectorCommandFence, ConnectorControlApplication, ConnectorControlApplicationError,
    ConnectorControlPolicy, ConnectorCredentialAuthorizationIndex,
    CreateConnectorEnrollmentRequest, ParsedCapacity, ParsedCommandAcknowledgement,
    ParsedEnrollment, ParsedHello, ParsedLeaseFence, ParsedProtocolRange,
    PostgresConnectorControlApplication, ProtobufDurableCommandDecoder,
    RotateConnectorCredentialRequest, build_lease_fence, parse_credential_rotation_proof,
};
use dtx_agent_host::AgentHost;
use dtx_agent_persistence::{
    AgentHostRepository, CommandLogRepository, ConnectorCredentialAuthorizationRepository,
    ConnectorRepository,
};
use dtx_connect_registry::{
    AdapterKind, Connector, ConnectorDesiredState, ConnectorFence, LeaseStatus,
};
use dtx_domain::{
    BootId, Clock, ConnectorId, Ed25519PublicKey, HostCredentialId, HostId, IdGenerator,
    IdentityId, RequestId, Revision, TenantId, UuidV7Generator,
};
use dtx_security::{
    AuthenticatedConnectorPeer, CertificateFingerprint, ConnectorAuthorizationError,
    ConnectorCredentialAuthorizer, ConnectorMtlsClientVerifier, ConnectorWorkloadIdentity,
    SecretBytes,
};
use dtx_storage::PgStore;
use dtx_testkit::FixedClock;
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, UnixTime},
};
use support::PostgresHarness;
use time::OffsetDateTime;
use uuid::Uuid;

const NOW_MILLIS: i64 = 1_800_000_000_000;
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_command_lifecycle_is_exact_restart_safe_and_ack_gated()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(8).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    let (host, connector) = provision_host_and_connector(&store, tenant_id).await?;
    let revoked_connector = provision_connector(&store, &host).await?;
    let rotation_connector = provision_connector(&store, &host).await?;

    let (issuer, ca_certificate_der) = certificate_issuer(NOW_MILLIS)?;
    let authorization_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let app = application(store.clone(), issuer.clone(), authorization_index.clone());
    let opened = enroll_and_open(
        &app,
        authorization_index.clone(),
        &ca_certificate_der,
        &host,
        &connector,
        0x31,
        0x32,
    )
    .await?;

    let initial_fence = owner_fence(&connector);
    let mismatched_adapter = ApplyConnectorConfigurationRequest::new(
        initial_fence,
        RequestId::new(),
        ConnectorDesiredState::Draining,
        AdapterKind::OpenClawAcp,
        vec![ConfigEntry::new("endpoint".to_owned(), "local".to_owned())?],
        Vec::new(),
    )?;
    assert_eq!(
        app.enqueue_apply_configuration(mismatched_adapter).await,
        Err(ConnectorControlApplicationError::InvalidRequest),
        "the claimed adapter schema must match the durable Connector kind",
    );

    let drain_request = ApplyConnectorConfigurationRequest::new(
        initial_fence,
        RequestId::new(),
        ConnectorDesiredState::Draining,
        AdapterKind::Codex,
        vec![ConfigEntry::new(
            "endpoint-profile".to_owned(),
            "private".to_owned(),
        )?],
        vec![ConfigEntry::new(
            "max-concurrent-runs".to_owned(),
            "2".to_owned(),
        )?],
    )?;
    let drain_command = app
        .enqueue_apply_configuration(drain_request.clone())
        .await?;
    assert_eq!(drain_command.sequence(), 1);
    assert_eq!(drain_command.generation(), initial_fence.generation);
    assert_eq!(drain_command.spec_revision(), initial_fence.spec_revision);
    let drain_applied_revision = initial_fence.spec_revision.checked_next()?;
    assert!(matches!(
        drain_command.payload(),
        ServerCommandPayload::ApplyConfig(configuration)
            if configuration.config_revision() == drain_applied_revision
                && configuration.desired_state() == ConnectorDesiredState::Draining
    ));

    let exact_retry = app
        .enqueue_apply_configuration(drain_request.clone())
        .await?;
    assert_eq!(exact_retry, drain_command);
    assert_eq!(
        exact_retry.exact_bytes().as_slice(),
        drain_command.exact_bytes().as_slice(),
    );

    let changed_retry = ApplyConnectorConfigurationRequest::new(
        drain_request.fence(),
        drain_request.operation_id(),
        drain_request.desired_state(),
        drain_request.adapter_kind(),
        vec![ConfigEntry::new(
            "endpoint-profile".to_owned(),
            "public".to_owned(),
        )?],
        drain_request.runtime_config().to_vec(),
    )?;
    assert_eq!(
        app.enqueue_apply_configuration(changed_retry).await,
        Err(ConnectorControlApplicationError::Conflict),
    );

    let polled = app.poll_commands(opened.peer, opened.fence, 0).await?;
    assert_exact_commands(&polled, std::slice::from_ref(&drain_command));

    drop(app);
    drop(authorization_index);
    let replay_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let replayed_app = application(store.clone(), issuer.clone(), replay_index.clone());
    replayed_app
        .hydrate_connector_authorization(tenant_id, connector.connector_id())
        .await?;
    let replay_peer =
        authenticate_credential(replay_index, &ca_certificate_der, &opened.credential)?;
    let recovered = replayed_app
        .open_control(
            replay_peer,
            parsed_hello(
                &host,
                &connector,
                BootId::new(),
                drain_applied_revision,
                drain_command.sequence(),
            )?,
        )
        .await?;
    assert_eq!(recovered.acknowledged_command_sequence, 0);
    assert_exact_commands(
        &recovered.replay_commands,
        std::slice::from_ref(&drain_command),
    );
    let recovered_fence = recovered.lease.fence();
    assert_eq!(
        acknowledge(&replayed_app, replay_peer, recovered_fence, &drain_command,).await,
        Ok(()),
        "ApplyConfig ACK must atomically persist its cursor and target spec fence",
    );
    assert_command_head(
        &store,
        tenant_id,
        connector.connector_id(),
        1,
        CommandLogState::Active,
    )
    .await?;

    drop(replayed_app);
    let restarted_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let restarted = application(store.clone(), issuer.clone(), restarted_index.clone());
    restarted
        .hydrate_connector_authorization(tenant_id, connector.connector_id())
        .await?;
    let restarted_peer = authenticate_credential(
        restarted_index.clone(),
        &ca_certificate_der,
        &opened.credential,
    )?;
    assert!(
        restarted
            .poll_commands(restarted_peer, recovered_fence, 1)
            .await?
            .is_empty(),
        "an acknowledged command must not replay after application restart",
    );

    let stop_request = ApplyConnectorConfigurationRequest::new(
        ConnectorCommandFence {
            tenant_id,
            connector_id: connector.connector_id(),
            generation: drain_command.generation(),
            spec_revision: drain_applied_revision,
        },
        RequestId::new(),
        ConnectorDesiredState::Stopped,
        AdapterKind::Codex,
        Vec::new(),
        Vec::new(),
    )?;
    let stop_command = restarted.enqueue_apply_configuration(stop_request).await?;
    assert_eq!(stop_command.sequence(), 2);
    assert_eq!(stop_command.spec_revision(), drain_applied_revision);
    let stopped_revision = drain_applied_revision.checked_next()?;
    assert!(matches!(
        stop_command.payload(),
        ServerCommandPayload::ApplyConfig(configuration)
            if configuration.config_revision() == stopped_revision
                && configuration.desired_state() == ConnectorDesiredState::Stopped
    ));
    assert_exact_commands(
        &restarted
            .poll_commands(restarted_peer, recovered_fence, 1)
            .await?,
        std::slice::from_ref(&stop_command),
    );
    assert_eq!(
        acknowledge(&restarted, restarted_peer, recovered_fence, &stop_command,).await,
        Ok(()),
        "Stopped ACK must atomically persist its cursor and terminalize the lease",
    );

    let (stopped, stopped_log) =
        load_connector_and_log(&store, tenant_id, connector.connector_id()).await?;
    assert_eq!(stopped.desired_state(), ConnectorDesiredState::Stopped);
    assert_eq!(stopped.snapshot().current_boot_id, None);
    assert_eq!(stopped_log.acknowledged_sequence(), 2);
    assert_eq!(stopped_log.state(), CommandLogState::Active);
    assert_eq!(
        stopped
            .leases()
            .iter()
            .find(|lease| lease.fence() == recovered_fence)
            .map(dtx_connect_registry::ConnectorLease::status),
        Some(LeaseStatus::Revoked),
    );
    assert_eq!(
        restarted
            .poll_commands(restarted_peer, recovered_fence, 2)
            .await,
        Err(ConnectorControlApplicationError::StaleFence),
        "terminal stop must invalidate the pre-ACK lease",
    );

    let revoked_opened = enroll_and_open(
        &restarted,
        restarted_index.clone(),
        &ca_certificate_der,
        &host,
        &revoked_connector,
        0x41,
        0x42,
    )
    .await?;
    assert_eq!(
        restarted
            .enqueue_close_stream(CloseConnectorStreamRequest {
                fence: owner_fence(&revoked_connector),
                operation_id: drain_request.operation_id(),
                command: CloseStreamCommand::reconnect(),
            })
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "tenant-global command operation IDs cannot be reused by another Connector",
    );
    let revoke_request = CloseConnectorStreamRequest {
        fence: owner_fence(&revoked_connector),
        operation_id: RequestId::new(),
        command: CloseStreamCommand::revoked(),
    };
    let revoke_command = restarted
        .enqueue_close_stream(revoke_request.clone())
        .await?;
    let revoke_retry = restarted
        .enqueue_close_stream(revoke_request.clone())
        .await?;
    assert_eq!(revoke_retry, revoke_command);
    assert_eq!(
        revoke_retry.exact_bytes().as_slice(),
        revoke_command.exact_bytes().as_slice(),
    );
    assert_eq!(
        restarted
            .enqueue_close_stream(CloseConnectorStreamRequest {
                command: CloseStreamCommand::protocol_upgrade(),
                ..revoke_request
            })
            .await,
        Err(ConnectorControlApplicationError::Conflict),
    );

    let (revoked, revoked_log) =
        load_connector_and_log(&store, tenant_id, revoked_connector.connector_id()).await?;
    assert_eq!(revoked.desired_state(), ConnectorDesiredState::Revoked);
    assert_eq!(revoked.snapshot().current_boot_id, None);
    assert_eq!(revoked_log.acknowledged_sequence(), 0);
    assert_eq!(revoked_log.state(), CommandLogState::Revoked);
    assert_eq!(
        revoked_log.commands(),
        std::slice::from_ref(&revoke_command)
    );
    assert_eq!(
        revoked
            .leases()
            .iter()
            .find(|lease| lease.fence() == revoked_opened.fence)
            .map(dtx_connect_registry::ConnectorLease::status),
        Some(LeaseStatus::Revoked),
    );

    let mut session = store.begin_tenant(tenant_id).await?;
    let authorization = ConnectorCredentialAuthorizationRepository::new()
        .load(
            session.connection(),
            tenant_id,
            revoked_connector.connector_id(),
        )
        .await?
        .expect("revoked authorization head remains durable");
    session.rollback().await?;
    assert_eq!(
        authorization.state(),
        ConnectorCredentialAuthorizationState::Revoked,
    );
    assert_eq!(
        authorization.status(revoked_opened.credential.credential_id()),
        Some(ConnectorCredentialStatus::Revoked),
    );
    assert_eq!(
        restarted_index.authorize(
            ConnectorWorkloadIdentity::new(tenant_id, revoked_connector.connector_id()),
            CertificateFingerprint::from_bytes(
                revoked_opened
                    .credential
                    .certificate_fingerprint()
                    .as_bytes(),
            ),
            u64::try_from(NOW_MILLIS / 1_000)?,
        ),
        Err(ConnectorAuthorizationError::Revoked),
        "the committed revoke must be visible to live TLS admission immediately",
    );

    let rotation_opened = enroll_and_open(
        &restarted,
        restarted_index.clone(),
        &ca_certificate_der,
        &host,
        &rotation_connector,
        0x51,
        0x52,
    )
    .await?;
    let rotation_request = RotateConnectorCredentialRequest {
        fence: owner_fence(&rotation_connector),
        operation_id: RequestId::new(),
        deadline_millis: NOW_MILLIS + 60_000,
    };
    let rotation_command = restarted
        .enqueue_credential_rotation(rotation_request)
        .await?;
    let ServerCommandPayload::RotateCredential(rotation) = rotation_command.payload() else {
        panic!("expected a durable credential-rotation challenge");
    };
    assert_eq!(
        acknowledge(
            &restarted,
            rotation_opened.peer,
            rotation_opened.fence,
            &rotation_command,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "a normal command ACK must not bypass the credential-rotation proof",
    );
    assert_command_head(
        &store,
        tenant_id,
        rotation_connector.connector_id(),
        0,
        CommandLogState::Active,
    )
    .await?;
    assert_exact_commands(
        &restarted
            .poll_commands(rotation_opened.peer, rotation_opened.fence, 0)
            .await?,
        std::slice::from_ref(&rotation_command),
    );
    let successor_control = SigningKey::from_bytes(&[0x53; 32]);
    let successor_public_key =
        Ed25519PublicKey::try_from(successor_control.verifying_key().to_bytes())?;
    let rotation_transcript = CredentialRotationTranscript::new(
        tenant_id,
        rotation_connector.connector_id(),
        rotation_request.operation_id,
        rotation_opened.credential.credential_id(),
        rotation_opened.credential.generation(),
        rotation_command.sequence(),
        rotation_command.payload_digest(),
        rotation.successor_revision(),
        rotation.nonce(),
        successor_public_key,
    )?;
    let signing_bytes = rotation_transcript.signing_bytes();
    let current_refresh = SigningKey::from_bytes(&[0x52; 32]);
    let rotation_proof = parse_credential_rotation_proof(v1::CredentialRotationProof {
        fence: Some(build_lease_fence(rotation_opened.fence)),
        request_id: rotation_request.operation_id.to_string(),
        command_sequence: rotation_command.sequence(),
        command_payload_digest: rotation_command.payload_digest().as_bytes().to_vec(),
        encoded_command_digest: rotation_command
            .encoded_command_digest()
            .as_bytes()
            .to_vec(),
        successor_revision: rotation.successor_revision().get(),
        new_control_public_key: successor_public_key.as_bytes().to_vec(),
        current_refresh_signature: current_refresh.sign(&signing_bytes).to_bytes().to_vec(),
        new_control_signature: successor_control.sign(&signing_bytes).to_bytes().to_vec(),
    })?;
    let rotation_completion = restarted
        .rotate_credential(rotation_opened.peer, rotation_proof.clone())
        .await?;
    assert_eq!(
        rotation_completion.request.transcript(),
        &rotation_transcript
    );
    assert_eq!(
        rotation_completion.credential.generation(),
        rotation_connector.generation().get() + 1,
    );
    assert_eq!(
        rotation_completion.credential.revision(),
        rotation.successor_revision(),
    );
    assert_command_head(
        &store,
        tenant_id,
        rotation_connector.connector_id(),
        rotation_command.sequence(),
        CommandLogState::Active,
    )
    .await?;

    drop(restarted);
    drop(restarted_index);
    let rotation_replay_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let rotation_replayed = application(store.clone(), issuer, rotation_replay_index.clone());
    rotation_replayed
        .hydrate_connector_authorization(tenant_id, rotation_connector.connector_id())
        .await?;
    let replay_current_peer = authenticate_credential(
        rotation_replay_index.clone(),
        &ca_certificate_der,
        &rotation_opened.credential,
    )?;
    let successor_peer = authenticate_credential(
        rotation_replay_index,
        &ca_certificate_der,
        &rotation_completion.credential,
    )?;
    let replayed_completion = rotation_replayed
        .rotate_credential(replay_current_peer, rotation_proof)
        .await?;
    assert_eq!(replayed_completion, rotation_completion);
    assert_command_head(
        &store,
        tenant_id,
        rotation_connector.connector_id(),
        rotation_command.sequence(),
        CommandLogState::Active,
    )
    .await?;
    assert_eq!(
        rotation_replayed
            .poll_commands(
                successor_peer,
                rotation_opened.fence,
                rotation_command.sequence(),
            )
            .await,
        Err(ConnectorControlApplicationError::AuthenticationFailed),
        "the pending successor must not authorize an ordinary frame before promotion",
    );

    let successor_generation = rotation_connector.generation().get() + 1;
    let successor_revision = rotation_connector.spec_revision().checked_next()?;
    let promoted = rotation_replayed
        .open_control(
            successor_peer,
            parsed_hello_at_generation(
                &host,
                &rotation_connector,
                BootId::new(),
                successor_generation,
                successor_revision,
                rotation_command.sequence(),
            )?,
        )
        .await?;
    assert_eq!(
        promoted.acknowledged_command_sequence,
        rotation_command.sequence(),
    );
    assert!(promoted.replay_commands.is_empty());
    assert_eq!(
        promoted.lease.fence().generation().get(),
        successor_generation
    );

    let (promoted_connector, promoted_log) =
        load_connector_and_log(&store, tenant_id, rotation_connector.connector_id()).await?;
    assert_eq!(promoted_connector.generation().get(), successor_generation);
    assert_eq!(promoted_connector.spec_revision(), successor_revision);
    assert_eq!(promoted_log.generation(), successor_generation);
    assert_eq!(promoted_log.spec_revision(), successor_revision);
    assert_eq!(
        promoted_log.acknowledged_sequence(),
        rotation_command.sequence(),
    );
    assert_eq!(
        promoted_connector
            .leases()
            .iter()
            .find(|lease| lease.fence() == rotation_opened.fence)
            .map(dtx_connect_registry::ConnectorLease::status),
        Some(LeaseStatus::Superseded),
    );

    let mut session = store.begin_tenant(tenant_id).await?;
    let promoted_authorization = ConnectorCredentialAuthorizationRepository::new()
        .load(
            session.connection(),
            tenant_id,
            rotation_connector.connector_id(),
        )
        .await?
        .expect("promoted authorization remains durable");
    session.rollback().await?;
    assert_eq!(
        promoted_authorization.status(rotation_opened.credential.credential_id()),
        Some(ConnectorCredentialStatus::Retired),
    );
    assert_eq!(
        promoted_authorization.status(rotation_completion.credential.credential_id()),
        Some(ConnectorCredentialStatus::Current),
    );
    assert!(promoted_authorization.pending().is_none());

    let promoted_fence = promoted.lease.fence();
    assert_eq!(
        rotation_replayed
            .open_control(
                replay_current_peer,
                parsed_hello_at_generation(
                    &host,
                    &rotation_connector,
                    BootId::new(),
                    successor_generation,
                    successor_revision,
                    rotation_command.sequence(),
                )?,
            )
            .await,
        Err(ConnectorControlApplicationError::AuthenticationFailed),
        "the retired current credential must fail after successor promotion",
    );
    assert_eq!(
        rotation_replayed
            .poll_commands(
                successor_peer,
                rotation_opened.fence,
                rotation_command.sequence(),
            )
            .await,
        Err(ConnectorControlApplicationError::StaleFence),
        "the pre-promotion lease fence must fail after generation advance",
    );
    assert!(
        rotation_replayed
            .poll_commands(successor_peer, promoted_fence, rotation_command.sequence())
            .await?
            .is_empty(),
        "the promoted successor must authorize ordinary frames at the new fence",
    );
    Ok(())
}

struct OpenedConnector {
    credential: ConnectorCredential,
    peer: AuthenticatedConnectorPeer,
    fence: ConnectorFence,
}

async fn enroll_and_open(
    app: &PostgresConnectorControlApplication,
    authorization_index: Arc<ConnectorCredentialAuthorizationIndex>,
    ca_certificate_der: &[u8],
    host: &AgentHost,
    connector: &Connector,
    control_seed: u8,
    refresh_seed: u8,
) -> Result<OpenedConnector, Box<dyn Error>> {
    let token = [control_seed.wrapping_add(0x30); 32];
    let created = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            host.tenant_id(),
            connector.connector_id(),
            RequestId::new(),
            EnrollmentToken::from_bytes(token),
            None,
        )?)
        .await?;
    let request = signed_enrollment_request(&created, &token, control_seed, refresh_seed)?;
    let completion = app
        .enroll(ParsedEnrollment {
            token: EnrollmentToken::from_bytes(token),
            request,
        })
        .await?;
    let peer = authenticate_credential(
        authorization_index,
        ca_certificate_der,
        &completion.credential,
    )?;
    let opened = app
        .open_control(
            peer,
            parsed_hello(host, connector, BootId::new(), connector.spec_revision(), 0)?,
        )
        .await?;
    assert!(opened.replay_commands.is_empty());
    Ok(OpenedConnector {
        credential: completion.credential,
        peer,
        fence: opened.lease.fence(),
    })
}

fn parsed_hello(
    host: &AgentHost,
    connector: &Connector,
    boot_id: BootId,
    spec_revision: Revision,
    last_applied_command_sequence: u64,
) -> Result<ParsedHello, Box<dyn Error>> {
    parsed_hello_at_generation(
        host,
        connector,
        boot_id,
        connector.generation().get(),
        spec_revision,
        last_applied_command_sequence,
    )
}

fn parsed_hello_at_generation(
    host: &AgentHost,
    connector: &Connector,
    boot_id: BootId,
    connector_generation: u64,
    spec_revision: Revision,
    last_applied_command_sequence: u64,
) -> Result<ParsedHello, Box<dyn Error>> {
    Ok(ParsedHello {
        tenant_id: host.tenant_id(),
        connector_id: connector.connector_id(),
        host_id: host.host_id(),
        boot_id,
        connector_generation,
        spec_revision,
        protocol: ParsedProtocolRange {
            minimum_major: 1,
            minimum_minor: 0,
            maximum_major: 1,
            maximum_minor: 0,
        },
        runtime_claims: RuntimeClaims::new(
            connector.adapter_kind(),
            "1.0.0".to_owned(),
            Sha256Digest::from_bytes([0x61; 32]),
            0,
            Vec::new(),
            None,
            vec!["agent.run".to_owned()],
        )?,
        capacity: ParsedCapacity {
            maximum_concurrent_runs: connector.max_concurrency(),
            available_concurrent_runs: connector.max_concurrency(),
            maximum_queue_depth: 32,
        },
        last_applied_command_sequence,
        required_server_capabilities: Vec::new(),
    })
}

async fn acknowledge(
    app: &PostgresConnectorControlApplication,
    peer: AuthenticatedConnectorPeer,
    fence: ConnectorFence,
    command: &DurableServerCommand,
) -> Result<(), ConnectorControlApplicationError> {
    app.acknowledge_command(
        peer,
        ParsedCommandAcknowledgement {
            fence: parsed_fence(fence),
            command_sequence: command.sequence(),
            payload_digest: command.payload_digest(),
            encoded_command_digest: command.encoded_command_digest(),
        },
    )
    .await
}

fn assert_exact_commands(actual: &[DurableServerCommand], expected: &[DurableServerCommand]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual, expected);
        assert_eq!(
            actual.exact_bytes().as_slice(),
            expected.exact_bytes().as_slice(),
        );
    }
}

fn parsed_fence(fence: ConnectorFence) -> ParsedLeaseFence {
    ParsedLeaseFence {
        tenant_id: fence.tenant_id(),
        connector_id: fence.connector_id(),
        boot_id: fence.boot_id(),
        connector_generation: fence.generation().get(),
        lease_id: fence.lease_id(),
        lease_epoch: fence.lease_epoch().get(),
    }
}

fn owner_fence(connector: &Connector) -> ConnectorCommandFence {
    ConnectorCommandFence {
        tenant_id: connector.tenant_id(),
        connector_id: connector.connector_id(),
        generation: connector.generation().get(),
        spec_revision: connector.spec_revision(),
    }
}

async fn assert_command_head(
    store: &PgStore,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    acknowledged_sequence: u64,
    state: CommandLogState,
) -> Result<(), Box<dyn Error>> {
    let (_, log) = load_connector_and_log(store, tenant_id, connector_id).await?;
    assert_eq!(log.acknowledged_sequence(), acknowledged_sequence);
    assert_eq!(log.state(), state);
    Ok(())
}

async fn load_connector_and_log(
    store: &PgStore,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<(Connector, CommandLog), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let connector = ConnectorRepository::new()
        .load(session.connection(), tenant_id, connector_id)
        .await?
        .expect("Connector remains durable");
    let log = CommandLogRepository::new()
        .load(
            session.connection(),
            tenant_id,
            connector_id,
            &ProtobufDurableCommandDecoder,
        )
        .await?
        .expect("command log remains durable");
    session.rollback().await?;
    Ok((connector, log))
}

fn application(
    store: PgStore,
    issuer: Arc<ConnectorCertificateAuthority>,
    authorization_index: Arc<ConnectorCredentialAuthorizationIndex>,
) -> PostgresConnectorControlApplication {
    PostgresConnectorControlApplication::with_ports(
        store,
        Arc::new(FixedClock::new(NOW_MILLIS)) as Arc<dyn Clock>,
        Arc::new(UuidV7Generator) as Arc<dyn IdGenerator>,
        issuer,
        authorization_index,
        Arc::new(ProtobufDurableCommandDecoder),
        ConnectorControlPolicy::default(),
    )
}

async fn provision_tenant(store: &PgStore, tenant_id: TenantId) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query("INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence) VALUES ($1, 0)")
        .bind(Uuid::from(tenant_id))
        .execute(session.connection())
        .await?;
    session.commit().await?;
    Ok(())
}

async fn provision_host_and_connector(
    store: &PgStore,
    tenant_id: TenantId,
) -> Result<(AgentHost, Connector), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let mut host = AgentHost::register(tenant_id, HostId::new(), IdentityId::from_str(OWNER_ID)?);
    AgentHostRepository::new()
        .save(session.connection(), &host, NOW_MILLIS - 2_000)
        .await?;
    host.enroll(host.revision(), HostCredentialId::new())?;
    AgentHostRepository::new()
        .save(session.connection(), &host, NOW_MILLIS - 1_999)
        .await?;
    let connector = Connector::register(&host, ConnectorId::new(), AdapterKind::Codex, 4)?;
    ConnectorRepository::new()
        .save(session.connection(), &connector, None, NOW_MILLIS - 1_998)
        .await?;
    session.commit().await?;
    Ok((host, connector))
}

async fn provision_connector(
    store: &PgStore,
    host: &AgentHost,
) -> Result<Connector, Box<dyn Error>> {
    let connector = Connector::register(host, ConnectorId::new(), AdapterKind::OpenClawAcp, 3)?;
    let mut session = store.begin_tenant(host.tenant_id()).await?;
    ConnectorRepository::new()
        .save(session.connection(), &connector, None, NOW_MILLIS - 1_997)
        .await?;
    session.commit().await?;
    Ok(connector)
}

fn signed_enrollment_request(
    enrollment: &dtx_agent_control_server::CreatedConnectorEnrollment,
    token: &[u8; 32],
    control_seed: u8,
    refresh_seed: u8,
) -> Result<EnrollmentRequest, Box<dyn Error>> {
    let control = SigningKey::from_bytes(&[control_seed; 32]);
    let refresh = SigningKey::from_bytes(&[refresh_seed; 32]);
    let transcript = EnrollmentTranscript::new(
        enrollment.tenant_id(),
        enrollment.host_id(),
        enrollment.connector_id(),
        enrollment.generation(),
        enrollment.spec_revision(),
        enrollment.request_id(),
        EnrollmentToken::from_bytes(*token).digest(),
        Ed25519PublicKey::try_from(control.verifying_key().to_bytes())?,
        Ed25519PublicKey::try_from(refresh.verifying_key().to_bytes())?,
    )?;
    let signing_bytes = transcript.signing_bytes();
    Ok(EnrollmentRequest::new(
        transcript,
        control.sign(&signing_bytes).to_bytes(),
        refresh.sign(&signing_bytes).to_bytes(),
    ))
}

fn certificate_issuer(
    now_millis: i64,
) -> Result<(Arc<ConnectorCertificateAuthority>, Vec<u8>), Box<dyn Error>> {
    let mut params = CertificateParams::default();
    params.not_before = offset_time(now_millis - 60_000)?;
    params.not_after = offset_time(now_millis + 172_800_000)?;
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    let certificate = params.self_signed(&key)?.der().to_vec();
    let secret = SecretBytes::new(key.serialize_der())?;
    let issuer =
        ConnectorCertificateAuthority::from_ed25519_pkcs8(certificate.clone(), secret, Vec::new())?;
    Ok((Arc::new(issuer), certificate))
}

fn authenticate_credential(
    index: Arc<ConnectorCredentialAuthorizationIndex>,
    ca_certificate_der: &[u8],
    credential: &ConnectorCredential,
) -> Result<AuthenticatedConnectorPeer, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_certificate_der.to_vec()))?;
    let verifier = ConnectorMtlsClientVerifier::new(Arc::new(roots), index)?;
    let chain = credential.certificate_chain();
    let leaf = CertificateDer::from(chain[0].clone());
    let intermediates = chain[1..]
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let now = UnixTime::since_unix_epoch(Duration::from_millis(u64::try_from(NOW_MILLIS)?));
    Ok(verifier.authenticate_peer_certificate(&leaf, &intermediates, now)?)
}

fn offset_time(millis: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
}
