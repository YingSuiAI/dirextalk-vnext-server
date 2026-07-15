#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr, sync::Arc, time::Duration};

use dtx_agent_control::{
    EnrollmentRequest, EnrollmentToken, EnrollmentTranscript, RuntimeClaims, Sha256Digest,
};
use dtx_agent_control_server::{
    ConnectorCertificateAuthority, ConnectorCommandFence, ConnectorControlApplication,
    ConnectorControlApplicationError, ConnectorControlPolicy,
    ConnectorCredentialAuthorizationIndex, CreateConnectorEnrollmentRequest, ParsedCapacity,
    ParsedEnrollment, ParsedHeartbeat, ParsedHello, ParsedLeaseFence, ParsedProtocolRange,
    PostgresConnectorControlApplication, ProtobufDurableCommandDecoder,
    RotateConnectorCredentialRequest,
};
use dtx_agent_host::AgentHost;
use dtx_agent_persistence::{
    AgentHostRepository, CommandLogRepository, ConnectorCredentialAuthorizationRepository,
    ConnectorRepository, EnrollmentIntentRepository,
};
use dtx_connect_registry::{AdapterKind, Connector, ConnectorObservedState};
use dtx_domain::{
    BootId, Clock, ConnectorId, Ed25519PublicKey, HostCredentialId, HostId, IdGenerator,
    IdentityId, Revision, TenantId, UuidV7Generator,
};
use dtx_security::{
    CertificateFingerprint, ConnectorAuthorizationError, ConnectorCredentialAdmission,
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
use sqlx::{PgPool, Row};
use support::PostgresHarness;
use time::OffsetDateTime;
use uuid::Uuid;

const NOW_MILLIS: i64 = 1_800_000_000_000;
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_application_enrollment_is_atomic_idempotent_and_restart_safe()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(8).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    let (host, connector) = provision_host_and_connector(&store, tenant_id).await?;
    let raced_connector = provision_connector(&store, &host).await?;
    let enrollment_first_connector = provision_connector(&store, &host).await?;
    let command_first_connector = provision_connector(&store, &host).await?;
    let command_blocked_enrollment_connector = provision_connector(&store, &host).await?;
    let concurrent_enrollment_connector = provision_connector(&store, &host).await?;
    let concurrent_command_connector = provision_connector(&store, &host).await?;

    let (issuer, ca_certificate_der) = certificate_issuer(NOW_MILLIS)?;
    let authorization_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let app = Arc::new(application(
        store.clone(),
        issuer.clone(),
        authorization_index.clone(),
    ));

    let operation_id = dtx_domain::RequestId::new();
    let token_bytes = [0x21; 32];
    let created = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            operation_id,
            EnrollmentToken::from_bytes(token_bytes),
            None,
        )?)
        .await?;
    let response_loss_retry = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            operation_id,
            EnrollmentToken::from_bytes(token_bytes),
            None,
        )?)
        .await?;
    assert_eq!(response_loss_retry, created);
    assert_eq!(created.tenant_id(), tenant_id);
    assert_eq!(created.host_id(), host.host_id());
    assert_eq!(created.connector_id(), connector.connector_id());
    assert_eq!(created.generation(), 1);
    assert_eq!(created.spec_revision(), Revision::INITIAL);
    assert!(format!("{created:?}").contains(&created.intent_id().to_string()));
    assert_eq!(
        app.create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            operation_id,
            EnrollmentToken::from_bytes([0x22; 32]),
            None,
        )?)
        .await,
        Err(ConnectorControlApplicationError::Conflict),
    );
    assert_eq!(
        app.create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            raced_connector.connector_id(),
            operation_id,
            EnrollmentToken::from_bytes(token_bytes),
            None,
        )?)
        .await,
        Err(ConnectorControlApplicationError::Conflict),
    );
    assert_eq!(
        app.create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            operation_id,
            EnrollmentToken::from_bytes(token_bytes),
            Some(300_001),
        )?)
        .await,
        Err(ConnectorControlApplicationError::Conflict),
    );
    let debug_request = CreateConnectorEnrollmentRequest::new(
        tenant_id,
        connector.connector_id(),
        dtx_domain::RequestId::new(),
        EnrollmentToken::from_bytes([0x23; 32]),
        None,
    )?;
    assert!(format!("{debug_request:?}").contains("[REDACTED]"));
    let stored_token_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT token_digest
           FROM agent.connector_enrollment_intents
          WHERE tenant_id=$1 AND enrollment_intent_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(created.intent_id()))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        stored_token_digest.as_slice(),
        EnrollmentToken::from_bytes(token_bytes).digest().as_bytes()
    );
    assert_ne!(stored_token_digest.as_slice(), token_bytes.as_slice());

    let request = signed_enrollment_request(&created, &token_bytes, 0x31, 0x32)?;
    let completion = app
        .enroll(parsed_enrollment(token_bytes, request.clone()))
        .await?;
    assert_eq!(completion.request, request);
    assert_eq!(completion.credential.tenant_id(), tenant_id);
    assert_eq!(
        completion.credential.connector_id(),
        connector.connector_id()
    );
    assert_eq!(completion.credential.generation(), 1);
    assert_eq!(completion.credential.revision(), Revision::INITIAL);
    assert_eq!(
        completion.credential.control_key(),
        request.transcript().control_key()
    );
    assert_eq!(
        completion.credential.refresh_key(),
        request.transcript().refresh_key()
    );

    assert_enrolled_state(
        &store,
        tenant_id,
        connector.connector_id(),
        created.intent_id(),
        &completion.credential,
    )
    .await?;

    let exact_retry = app
        .enroll(parsed_enrollment(token_bytes, request.clone()))
        .await?;
    assert_eq!(exact_retry, completion);
    assert_eq!(
        app.enqueue_credential_rotation(RotateConnectorCredentialRequest {
            fence: ConnectorCommandFence {
                tenant_id,
                connector_id: connector.connector_id(),
                generation: connector.generation().get(),
                spec_revision: connector.spec_revision(),
            },
            operation_id,
            deadline_millis: NOW_MILLIS + 60_000,
        })
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "an enrollment operation ID cannot become an unfulfillable rotation command",
    );
    let commands_after_origin_conflict: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM agent.connector_control_commands
          WHERE tenant_id=$1 AND connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector.connector_id()))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(commands_after_origin_conflict, 0);

    let changed_request = signed_enrollment_request(&created, &token_bytes, 0x41, 0x42)?;
    assert_eq!(
        app.enroll(parsed_enrollment(token_bytes, changed_request))
            .await,
        Err(ConnectorControlApplicationError::Conflict),
    );
    assert_connector_control_row_counts(
        harness.admin_pool(),
        tenant_id,
        connector.connector_id(),
        1,
    )
    .await?;

    let raced_token = [0x24; 32];
    let raced_intent = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            raced_connector.connector_id(),
            dtx_domain::RequestId::new(),
            EnrollmentToken::from_bytes(raced_token),
            None,
        )?)
        .await?;
    let left_request = signed_enrollment_request(&raced_intent, &raced_token, 0x51, 0x52)?;
    let right_request = signed_enrollment_request(&raced_intent, &raced_token, 0x53, 0x54)?;
    let (left, right) = tokio::join!(
        app.enroll(parsed_enrollment(raced_token, left_request)),
        app.enroll(parsed_enrollment(raced_token, right_request)),
    );
    let winners = [&left, &right]
        .into_iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(
        winners, 1,
        "exactly one concurrent token consumer must commit"
    );
    let loser = if left.is_err() { left } else { right };
    assert!(matches!(
        loser,
        Err(ConnectorControlApplicationError::AuthenticationFailed
            | ConnectorControlApplicationError::Conflict
            | ConnectorControlApplicationError::StaleFence)
    ));
    assert_connector_control_row_counts(
        harness.admin_pool(),
        tenant_id,
        raced_connector.connector_id(),
        1,
    )
    .await?;

    enroll_connector_for_owner_command(
        app.as_ref(),
        tenant_id,
        &command_first_connector,
        [0x71; 32],
        0x72,
        0x73,
    )
    .await?;
    enroll_connector_for_owner_command(
        app.as_ref(),
        tenant_id,
        &concurrent_command_connector,
        [0x74; 32],
        0x75,
        0x76,
    )
    .await?;

    let enrollment_first_operation = dtx_domain::RequestId::new();
    app.create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
        tenant_id,
        enrollment_first_connector.connector_id(),
        enrollment_first_operation,
        EnrollmentToken::from_bytes([0x77; 32]),
        None,
    )?)
    .await?;
    assert_eq!(
        app.enqueue_credential_rotation(RotateConnectorCredentialRequest {
            fence: connector_command_fence(tenant_id, &command_first_connector),
            operation_id: enrollment_first_operation,
            deadline_millis: NOW_MILLIS + 60_000,
        })
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "an unconsumed enrollment operation must block a command for another Connector",
    );
    let enrollment_first_commands: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM agent.connector_control_commands
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(enrollment_first_operation))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(enrollment_first_commands, 0);

    let command_first_operation = dtx_domain::RequestId::new();
    app.enqueue_credential_rotation(RotateConnectorCredentialRequest {
        fence: connector_command_fence(tenant_id, &command_first_connector),
        operation_id: command_first_operation,
        deadline_millis: NOW_MILLIS + 60_000,
    })
    .await?;
    assert_eq!(
        app.create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            command_blocked_enrollment_connector.connector_id(),
            command_first_operation,
            EnrollmentToken::from_bytes([0x78; 32]),
            None,
        )?)
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "a command operation must block an enrollment for another Connector",
    );
    let command_first_facts = sqlx::query(
        "SELECT
            (SELECT count(*) FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND operation_id=$2) AS commands,
            (SELECT count(*) FROM agent.connector_enrollment_intents
              WHERE tenant_id=$1 AND request_id=$2) AS enrollment_intents",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command_first_operation))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(command_first_facts.try_get::<i64, _>("commands")?, 1);
    assert_eq!(
        command_first_facts.try_get::<i64, _>("enrollment_intents")?,
        0,
    );

    let concurrent_operation = dtx_domain::RequestId::new();
    let concurrent_enrollment =
        app.create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            concurrent_enrollment_connector.connector_id(),
            concurrent_operation,
            EnrollmentToken::from_bytes([0x79; 32]),
            None,
        )?);
    let concurrent_command = app.enqueue_credential_rotation(RotateConnectorCredentialRequest {
        fence: connector_command_fence(tenant_id, &concurrent_command_connector),
        operation_id: concurrent_operation,
        deadline_millis: NOW_MILLIS + 60_000,
    });
    let (concurrent_enrollment, concurrent_command) =
        tokio::join!(concurrent_enrollment, concurrent_command);
    assert_eq!(
        usize::from(concurrent_enrollment.is_ok()) + usize::from(concurrent_command.is_ok()),
        1,
        "only one operation kind may commit for a tenant-global operation ID",
    );
    if let Err(error) = concurrent_enrollment {
        assert_eq!(error, ConnectorControlApplicationError::Conflict);
    }
    if let Err(error) = concurrent_command {
        assert_eq!(error, ConnectorControlApplicationError::Conflict);
    }
    let concurrent_facts = sqlx::query(
        "SELECT
            (SELECT count(*) FROM agent.connector_control_operations
              WHERE tenant_id=$1 AND operation_id=$2) AS operations,
            (SELECT count(*) FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND operation_id=$2) AS commands,
            (SELECT count(*) FROM agent.connector_enrollment_intents
              WHERE tenant_id=$1 AND request_id=$2) AS enrollment_intents",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(concurrent_operation))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(concurrent_facts.try_get::<i64, _>("operations")?, 1);
    assert_eq!(
        concurrent_facts.try_get::<i64, _>("commands")?
            + concurrent_facts.try_get::<i64, _>("enrollment_intents")?,
        1,
    );

    drop(app);
    drop(authorization_index);
    let restarted_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let restarted = application(store.clone(), issuer.clone(), restarted_index.clone());
    restarted
        .hydrate_connector_authorization(tenant_id, connector.connector_id())
        .await?;
    assert_eq!(
        restarted_index.authorize(
            ConnectorWorkloadIdentity::new(tenant_id, connector.connector_id()),
            CertificateFingerprint::from_bytes(
                completion.credential.certificate_fingerprint().as_bytes(),
            ),
            u64::try_from(NOW_MILLIS / 1_000)?,
        ),
        Ok(ConnectorCredentialAdmission::Current),
    );
    restarted_index.hydrate(Vec::new())?;
    assert_eq!(
        restarted_index.authorize(
            ConnectorWorkloadIdentity::new(tenant_id, connector.connector_id()),
            CertificateFingerprint::from_bytes(
                completion.credential.certificate_fingerprint().as_bytes(),
            ),
            u64::try_from(NOW_MILLIS / 1_000)?,
        ),
        Err(ConnectorAuthorizationError::UnknownCredential),
        "an empty process-local index cannot become an application authorization source",
    );

    let peer = authenticate_credential(
        restarted_index.clone(),
        &ca_certificate_der,
        &completion.credential,
    )?;
    assert_eq!(
        peer.credential_admission(),
        ConnectorCredentialAdmission::Unresolved,
    );
    let boot_id = BootId::new();
    let opened = restarted
        .open_control(
            peer,
            ParsedHello {
                tenant_id,
                connector_id: connector.connector_id(),
                host_id: host.host_id(),
                boot_id,
                connector_generation: 1,
                spec_revision: Revision::INITIAL,
                protocol: ParsedProtocolRange {
                    minimum_major: 1,
                    minimum_minor: 0,
                    maximum_major: 1,
                    maximum_minor: 2,
                },
                runtime_claims: RuntimeClaims::new(
                    AdapterKind::Codex,
                    "1.0.0".to_owned(),
                    Sha256Digest::from_bytes([0x61; 32]),
                    0,
                    Vec::new(),
                    None,
                    vec!["agent.run".to_owned()],
                )?,
                capacity: ParsedCapacity {
                    maximum_concurrent_runs: 4,
                    available_concurrent_runs: 4,
                    maximum_queue_depth: 32,
                },
                last_applied_command_sequence: 0,
                required_server_capabilities: Vec::new(),
            },
        )
        .await?;
    assert_eq!(opened.acknowledged_command_sequence, 0);
    assert_eq!(
        opened.protocol_minor, 2,
        "the production default negotiates the Agent Control 1.2 execution-report contract"
    );
    assert!(opened.replay_commands.is_empty());
    assert_eq!(opened.lease.fence().tenant_id(), tenant_id);
    assert_eq!(
        opened.lease.fence().connector_id(),
        connector.connector_id()
    );
    assert_eq!(opened.lease.fence().boot_id(), boot_id);

    let fence = opened.lease.fence();
    let heartbeat = ParsedHeartbeat {
        fence: ParsedLeaseFence {
            tenant_id,
            connector_id: connector.connector_id(),
            boot_id,
            connector_generation: fence.generation().get(),
            lease_id: fence.lease_id(),
            lease_epoch: fence.lease_epoch().get(),
        },
        heartbeat_sequence: 1,
        applied_config_revision: Revision::INITIAL,
        applied_command_sequence: 0,
        runtime_claims: RuntimeClaims::new(
            AdapterKind::Codex,
            "1.0.0".to_owned(),
            Sha256Digest::from_bytes([0x61; 32]),
            0,
            Vec::new(),
            None,
            vec!["agent.run".to_owned()],
        )?,
        capacity: ParsedCapacity {
            maximum_concurrent_runs: 4,
            available_concurrent_runs: 4,
            maximum_queue_depth: 32,
        },
    };
    let first_heartbeat = restarted
        .heartbeat(
            authenticate_credential(
                restarted_index.clone(),
                &ca_certificate_der,
                &completion.credential,
            )?,
            heartbeat.clone(),
        )
        .await?;
    assert_eq!(first_heartbeat.observed_at_millis, NOW_MILLIS);

    let later = application_at(
        store.clone(),
        issuer,
        restarted_index.clone(),
        NOW_MILLIS + 1_000,
    );
    let replayed_heartbeat = later
        .heartbeat(
            authenticate_credential(
                restarted_index.clone(),
                &ca_certificate_der,
                &completion.credential,
            )?,
            heartbeat.clone(),
        )
        .await?;
    assert_eq!(replayed_heartbeat, first_heartbeat);

    let mut changed_heartbeat = heartbeat;
    changed_heartbeat.capacity.available_concurrent_runs = 3;
    assert_eq!(
        later
            .heartbeat(
                authenticate_credential(
                    restarted_index,
                    &ca_certificate_der,
                    &completion.credential,
                )?,
                changed_heartbeat,
            )
            .await,
        Err(ConnectorControlApplicationError::StaleFence),
    );

    let mut session = store.begin_tenant(tenant_id).await?;
    let restored_connector = ConnectorRepository::new()
        .load(session.connection(), tenant_id, connector.connector_id())
        .await?
        .expect("opened Connector remains durable");
    let restored_snapshot = restored_connector.snapshot();
    assert_eq!(restored_snapshot.current_boot_id, Some(boot_id));
    let restored_lease = restored_snapshot
        .leases
        .last()
        .expect("active lease remains");
    assert_eq!(restored_lease.tenant_id, fence.tenant_id());
    assert_eq!(restored_lease.connector_id, fence.connector_id());
    assert_eq!(restored_lease.boot_id, fence.boot_id());
    assert_eq!(restored_lease.lease_id, fence.lease_id());
    assert_eq!(restored_lease.lease_epoch, fence.lease_epoch().get());
    let persisted_heartbeat = restored_lease
        .last_heartbeat
        .expect("accepted heartbeat is durable");
    assert_eq!(persisted_heartbeat.sequence, 1);
    assert_eq!(persisted_heartbeat.state, ConnectorObservedState::Ready);
    assert_eq!(persisted_heartbeat.capacity_available, 4);
    assert_eq!(restored_lease.last_heartbeat_at_millis, Some(NOW_MILLIS));
    session.rollback().await?;
    Ok(())
}

fn application(
    store: PgStore,
    issuer: Arc<ConnectorCertificateAuthority>,
    authorization_index: Arc<ConnectorCredentialAuthorizationIndex>,
) -> PostgresConnectorControlApplication {
    application_at(store, issuer, authorization_index, NOW_MILLIS)
}

fn application_at(
    store: PgStore,
    issuer: Arc<ConnectorCertificateAuthority>,
    authorization_index: Arc<ConnectorCredentialAuthorizationIndex>,
    now_millis: i64,
) -> PostgresConnectorControlApplication {
    PostgresConnectorControlApplication::with_ports(
        store,
        Arc::new(FixedClock::new(now_millis)) as Arc<dyn Clock>,
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
    let connector = Connector::register(host, ConnectorId::new(), AdapterKind::Codex, 4)?;
    let mut session = store.begin_tenant(host.tenant_id()).await?;
    ConnectorRepository::new()
        .save(session.connection(), &connector, None, NOW_MILLIS - 1_997)
        .await?;
    session.commit().await?;
    Ok(connector)
}

async fn enroll_connector_for_owner_command(
    app: &PostgresConnectorControlApplication,
    tenant_id: TenantId,
    connector: &Connector,
    token: [u8; 32],
    control_seed: u8,
    refresh_seed: u8,
) -> Result<(), Box<dyn Error>> {
    let enrollment = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            dtx_domain::RequestId::new(),
            EnrollmentToken::from_bytes(token),
            None,
        )?)
        .await?;
    let request = signed_enrollment_request(&enrollment, &token, control_seed, refresh_seed)?;
    app.enroll(parsed_enrollment(token, request)).await?;
    Ok(())
}

fn connector_command_fence(tenant_id: TenantId, connector: &Connector) -> ConnectorCommandFence {
    ConnectorCommandFence {
        tenant_id,
        connector_id: connector.connector_id(),
        generation: connector.generation().get(),
        spec_revision: connector.spec_revision(),
    }
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

fn parsed_enrollment(token: [u8; 32], request: EnrollmentRequest) -> ParsedEnrollment {
    ParsedEnrollment {
        token: EnrollmentToken::from_bytes(token),
        request,
    }
}

async fn assert_enrolled_state(
    store: &PgStore,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    intent_id: dtx_domain::EnrollmentIntentId,
    credential: &dtx_agent_control::ConnectorCredential,
) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let intent = EnrollmentIntentRepository::new()
        .load(session.connection(), tenant_id, intent_id)
        .await?
        .expect("consumed intent remains durable");
    let authorization = ConnectorCredentialAuthorizationRepository::new()
        .load(session.connection(), tenant_id, connector_id)
        .await?
        .expect("credential authorization remains durable");
    let command_log = CommandLogRepository::new()
        .load(
            session.connection(),
            tenant_id,
            connector_id,
            &ProtobufDurableCommandDecoder,
        )
        .await?
        .expect("empty command log is created atomically with enrollment");
    session.rollback().await?;

    match intent.snapshot().state {
        dtx_agent_control::EnrollmentIntentSnapshotState::Consumed {
            consumed_at_millis,
            result_digest,
            result,
            ..
        } => {
            assert_eq!(consumed_at_millis, NOW_MILLIS);
            assert_eq!(result_digest, credential.result_digest());
            assert_eq!(*result, *credential);
        }
        state => panic!("enrollment intent is not consumed: {state:?}"),
    }
    assert_eq!(authorization.current(), Some(credential));
    let command_snapshot = command_log.snapshot();
    assert_eq!(command_snapshot.generation, credential.generation());
    assert_eq!(command_snapshot.spec_revision, credential.revision());
    assert_eq!(command_snapshot.acknowledged_sequence, 0);
    assert!(command_snapshot.commands.is_empty());
    Ok(())
}

async fn assert_connector_control_row_counts(
    pool: &PgPool,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    expected_credentials: i64,
) -> Result<(), Box<dyn Error>> {
    let row = sqlx::query(
        "SELECT
            (SELECT count(*) FROM agent.connector_control_credentials
              WHERE tenant_id=$1 AND connector_id=$2) AS credentials,
            (SELECT count(*) FROM agent.connector_control_credential_revisions
              WHERE tenant_id=$1 AND connector_id=$2) AS authorization_revisions,
            (SELECT count(*) FROM agent.connector_control_stream_heads
              WHERE tenant_id=$1 AND connector_id=$2) AS stream_heads,
            (SELECT count(*) FROM agent.connector_control_commands
              WHERE tenant_id=$1 AND connector_id=$2) AS commands",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_one(pool)
    .await?;
    assert_eq!(row.try_get::<i64, _>("credentials")?, expected_credentials);
    assert_eq!(
        row.try_get::<i64, _>("authorization_revisions")?,
        expected_credentials,
    );
    assert_eq!(row.try_get::<i64, _>("stream_heads")?, 1);
    assert_eq!(row.try_get::<i64, _>("commands")?, 0);
    Ok(())
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
    credential: &dtx_agent_control::ConnectorCredential,
) -> Result<dtx_security::AuthenticatedConnectorPeer, Box<dyn Error>> {
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
