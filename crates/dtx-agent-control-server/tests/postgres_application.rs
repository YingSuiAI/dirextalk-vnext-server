#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr, sync::Arc, time::Duration};

use dtx_agent_control::{
    ConnectorCredential, ConnectorCredentialStatus, CredentialReissueRequest,
    CredentialReissueToken, EnrollmentRequest, EnrollmentToken, EnrollmentTranscript,
    RuntimeClaims, Sha256Digest,
};
use dtx_agent_control_server::{
    ConnectorCertificateAuthority, ConnectorCommandFence, ConnectorControlApplication,
    ConnectorControlApplicationError, ConnectorControlPolicy,
    ConnectorCredentialAuthorizationIndex, CreateConnectorEnrollmentRequest, ParsedCapacity,
    ParsedCredentialReissue, ParsedEnrollment, ParsedHeartbeat, ParsedHello, ParsedLeaseFence,
    ParsedProtocolRange, PostgresConnectorControlApplication,
    PrepareConnectorCredentialReissueRequest, ProtobufDurableCommandDecoder,
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
    IdentityId, RequestId, Revision, TenantId, UuidV7Generator,
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real-PostgreSQL recovery workflow keeps its concurrency, RLS, promotion, abort, and downgrade assertions on the same durable fixtures"
)]
async fn postgres_credential_reissue_is_fenced_idempotent_and_downgrade_safe()
-> Result<(), Box<dyn Error>> {
    const REISSUE_NOW_MILLIS: i64 =
        NOW_MILLIS + dtx_agent_control::MAX_CONNECTOR_CREDENTIAL_VALIDITY_MILLIS + 1_000;
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    let other_tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    provision_tenant(&store, other_tenant_id).await?;
    let (host, primary_connector) = provision_host_and_connector(&store, tenant_id).await?;
    let concurrent_connector = provision_connector(&store, &host).await?;
    let aborted_connector = provision_connector(&store, &host).await?;

    let (issuer, ca_certificate_der) = certificate_issuer(NOW_MILLIS)?;
    let authorization_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let enrollment_app = application(store.clone(), issuer.clone(), authorization_index.clone());
    let primary = enroll_connector(
        &enrollment_app,
        tenant_id,
        &primary_connector,
        [0x81; 32],
        0x31,
        0x32,
    )
    .await?;
    let concurrent = enroll_connector(
        &enrollment_app,
        tenant_id,
        &concurrent_connector,
        [0x82; 32],
        0x41,
        0x42,
    )
    .await?;
    let aborted = enroll_connector(
        &enrollment_app,
        tenant_id,
        &aborted_connector,
        [0x83; 32],
        0x51,
        0x52,
    )
    .await?;
    let recovery_app = Arc::new(application_at(
        store.clone(),
        issuer.clone(),
        authorization_index.clone(),
        REISSUE_NOW_MILLIS,
    ));

    let primary_operation = RequestId::new();
    let primary_token = [0x91; 32];
    let primary_prepare = reissue_prepare_request(
        tenant_id,
        &host,
        &primary_connector,
        primary_operation,
        &primary.credential,
        primary_token,
        0xa1,
    );
    let primary_created = recovery_app
        .prepare_connector_credential_reissue(primary_prepare)
        .await
        .expect("primary reissue preparation must commit");
    assert!(!primary_created.replayed);
    let primary_replayed = recovery_app
        .prepare_connector_credential_reissue(reissue_prepare_request(
            tenant_id,
            &host,
            &primary_connector,
            primary_operation,
            &primary.credential,
            primary_token,
            0xa1,
        ))
        .await
        .expect("exact primary preparation must replay");
    assert_eq!(primary_replayed.intent_id, primary_created.intent_id);
    assert_eq!(
        primary_replayed.expires_at_millis,
        primary_created.expires_at_millis
    );
    assert!(primary_replayed.replayed);
    assert_eq!(
        recovery_app
            .prepare_connector_credential_reissue(reissue_prepare_request(
                tenant_id,
                &host,
                &concurrent_connector,
                primary_operation,
                &concurrent.credential,
                primary_token,
                0xa1,
            ))
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "an operation cannot replay against a different Connector",
    );
    let mut changed_ttl = reissue_prepare_request(
        tenant_id,
        &host,
        &primary_connector,
        primary_operation,
        &primary.credential,
        primary_token,
        0xa1,
    );
    changed_ttl.ttl_millis /= 2;
    assert_eq!(
        recovery_app
            .prepare_connector_credential_reissue(changed_ttl)
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "an operation cannot replay with a changed TTL",
    );
    assert_eq!(
        recovery_app
            .prepare_connector_credential_reissue(reissue_prepare_request(
                tenant_id,
                &host,
                &primary_connector,
                primary_operation,
                &primary.credential,
                primary_token,
                0xa2,
            ))
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "changed prepare replay must not inherit the durable token",
    );

    let mut active_mutation = store.begin_tenant(tenant_id).await?;
    let active_mutation_error = sqlx::query(
        "UPDATE agent.connector_credential_reissue_intents
            SET plan_digest=$3
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(primary_operation))
    .bind(vec![0xff_u8; 32])
    .execute(active_mutation.connection())
    .await
    .expect_err("runtime SQL cannot rewrite an active intent fence");
    assert_eq!(
        active_mutation_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514")),
    );
    active_mutation.rollback().await?;

    assert_eq!(
        recovery_app
            .prepare_connector_credential_reissue(reissue_prepare_request(
                other_tenant_id,
                &host,
                &primary_connector,
                primary_operation,
                &primary.credential,
                primary_token,
                0xa1,
            ))
            .await,
        Err(ConnectorControlApplicationError::NotFound),
        "cross-tenant preparation must not observe another tenant's operation",
    );
    let mut other_tenant_session = store.begin_tenant(other_tenant_id).await?;
    let visible_reissue_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.connector_credential_reissue_intents
          WHERE operation_id=$1",
    )
    .bind(Uuid::from(primary_operation))
    .fetch_one(other_tenant_session.connection())
    .await?;
    assert_eq!(visible_reissue_rows, 0, "forced RLS must hide the row");
    other_tenant_session.rollback().await?;

    let concurrent_operation = RequestId::new();
    let concurrent_token = [0x92; 32];
    let concurrent_created = recovery_app
        .prepare_connector_credential_reissue(reissue_prepare_request(
            tenant_id,
            &host,
            &concurrent_connector,
            concurrent_operation,
            &concurrent.credential,
            concurrent_token,
            0xb1,
        ))
        .await
        .expect("concurrent-consumption fixture must prepare");
    let concurrent_request = signed_reissue_request(
        concurrent_operation,
        concurrent_created.intent_id,
        &host,
        &concurrent_connector,
        &concurrent.credential,
        concurrent_token,
        0x41,
        0x61,
    )?;
    let (left, right) = tokio::join!(
        recovery_app
            .reissue_credential(parsed_reissue(concurrent_token, concurrent_request.clone(),)),
        recovery_app
            .reissue_credential(parsed_reissue(concurrent_token, concurrent_request.clone(),)),
    );
    let left = left.expect("left exact consumer must commit or replay");
    let right = right.expect("right exact consumer must commit or replay");
    assert_eq!(
        left, right,
        "concurrent exact consumers must receive one result"
    );
    assert_eq!(
        recovery_app
            .reissue_credential(parsed_reissue(
                concurrent_token,
                signed_reissue_request(
                    concurrent_operation,
                    concurrent_created.intent_id,
                    &host,
                    &concurrent_connector,
                    &concurrent.credential,
                    concurrent_token,
                    0x41,
                    0x62,
                )?,
            ))
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "a changed consumed replay is an idempotency conflict",
    );
    let after_ttl_app = application_at(
        store.clone(),
        issuer.clone(),
        authorization_index.clone(),
        primary_created.expires_at_millis + 1,
    );
    let after_ttl_replay = after_ttl_app
        .reissue_credential(parsed_reissue(concurrent_token, concurrent_request.clone()))
        .await
        .expect("consumed exact request must replay after TTL");
    assert_eq!(after_ttl_replay, left);
    assert_eq!(
        recovery_app
            .abort_connector_credential_reissue(tenant_id, concurrent_operation)
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "consumption closes the abort boundary",
    );

    let mut before_promotion = store.begin_tenant(tenant_id).await?;
    let before_authorization = ConnectorCredentialAuthorizationRepository::new()
        .load(
            before_promotion.connection(),
            tenant_id,
            concurrent_connector.connector_id(),
        )
        .await?
        .expect("reissue authorization exists");
    let before_command = CommandLogRepository::new()
        .load(
            before_promotion.connection(),
            tenant_id,
            concurrent_connector.connector_id(),
            &ProtobufDurableCommandDecoder,
        )
        .await?
        .expect("command cursor exists");
    assert_eq!(before_authorization.current(), Some(&concurrent.credential));
    assert_eq!(before_authorization.pending(), Some(&left.credential));
    assert!(
        !ConnectorCredentialAuthorizationRepository::new()
            .authorize_current(
                before_promotion.connection(),
                tenant_id,
                concurrent_connector.connector_id(),
                concurrent_connector.generation().get(),
                left.credential.certificate_fingerprint(),
                REISSUE_NOW_MILLIS,
            )
            .await?,
        "a pending reissue credential is not current before Hello",
    );
    let before_command = before_command.snapshot();
    before_promotion.rollback().await?;

    assert!(
        authenticate_credential_at(
            authorization_index.clone(),
            &ca_certificate_der,
            &concurrent.credential,
            REISSUE_NOW_MILLIS,
        )
        .is_err(),
        "the expired predecessor cannot authenticate",
    );
    let pending_peer = authenticate_credential_at(
        authorization_index.clone(),
        &ca_certificate_der,
        &left.credential,
        REISSUE_NOW_MILLIS,
    )?;
    assert_eq!(
        authorization_index.authorize(
            ConnectorWorkloadIdentity::new(tenant_id, concurrent_connector.connector_id()),
            CertificateFingerprint::from_bytes(
                left.credential.certificate_fingerprint().as_bytes(),
            ),
            u64::try_from(REISSUE_NOW_MILLIS / 1_000)?,
        ),
        Ok(ConnectorCredentialAdmission::PendingSuccessor),
    );
    assert_eq!(
        pending_peer.credential_admission(),
        ConnectorCredentialAdmission::Unresolved,
        "transport metadata remains advisory; PostgreSQL decides the first Hello",
    );
    let boot_id = BootId::new();
    let opened = recovery_app
        .open_control(
            pending_peer,
            hello_for(
                tenant_id,
                host.host_id(),
                &concurrent_connector,
                boot_id,
                before_command.acknowledged_sequence,
            )?,
        )
        .await
        .expect("pending reissue credential must promote on its first Hello");
    assert_eq!(
        opened.acknowledged_command_sequence,
        before_command.acknowledged_sequence
    );

    let mut after_promotion = store.begin_tenant(tenant_id).await?;
    let after_authorization = ConnectorCredentialAuthorizationRepository::new()
        .load(
            after_promotion.connection(),
            tenant_id,
            concurrent_connector.connector_id(),
        )
        .await?
        .expect("promoted authorization exists");
    let authorization_snapshot = after_authorization.snapshot();
    assert_eq!(after_authorization.current(), Some(&left.credential));
    assert!(after_authorization.pending().is_none());
    assert_eq!(
        authorization_snapshot
            .history
            .iter()
            .find(|entry| entry.credential.credential_id() == concurrent.credential.credential_id())
            .map(|entry| entry.status),
        Some(ConnectorCredentialStatus::Retired),
    );
    let after_command = CommandLogRepository::new()
        .load(
            after_promotion.connection(),
            tenant_id,
            concurrent_connector.connector_id(),
            &ProtobufDurableCommandDecoder,
        )
        .await?
        .expect("command cursor remains");
    let after_command = after_command.snapshot();
    assert_eq!(after_command.generation, before_command.generation);
    assert_eq!(after_command.spec_revision, before_command.spec_revision);
    assert_eq!(
        after_command.acknowledged_sequence,
        before_command.acknowledged_sequence
    );
    let promoted_connector = ConnectorRepository::new()
        .load(
            after_promotion.connection(),
            tenant_id,
            concurrent_connector.connector_id(),
        )
        .await?
        .expect("Connector remains");
    assert_eq!(
        promoted_connector.generation().get(),
        concurrent_connector.generation().get()
    );
    assert_eq!(
        promoted_connector.spec_revision(),
        concurrent_connector.spec_revision()
    );
    let persisted_result: Vec<u8> = sqlx::query_scalar(
        "SELECT result_digest FROM agent.connector_credential_reissue_intents
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(concurrent_operation))
    .fetch_one(after_promotion.connection())
    .await?;
    assert_eq!(
        persisted_result,
        left.credential
            .reissue_result_digest(&concurrent_request)
            .as_bytes()
    );
    after_promotion.rollback().await?;

    let mut consumed_mutation = store.begin_tenant(tenant_id).await?;
    let consumed_mutation_error = sqlx::query(
        "UPDATE agent.connector_credential_reissue_intents
            SET result_digest=$3
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(concurrent_operation))
    .bind(vec![0xee_u8; 32])
    .execute(consumed_mutation.connection())
    .await
    .expect_err("runtime SQL cannot rewrite a consumed receipt");
    assert_eq!(
        consumed_mutation_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514")),
    );
    consumed_mutation.rollback().await?;

    let promoted_replay = after_ttl_app
        .reissue_credential(parsed_reissue(concurrent_token, concurrent_request.clone()))
        .await
        .expect("exact consumed request must replay after promotion");
    assert_eq!(promoted_replay, left);
    assert_eq!(
        recovery_app
            .abort_connector_credential_reissue(tenant_id, concurrent_operation)
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "promotion remains outside the abort boundary",
    );

    let second_reissue_now = left.credential.not_after_millis() + 1;
    let second_recovery_app = application_at(
        store.clone(),
        issuer,
        authorization_index.clone(),
        second_reissue_now,
    );
    let second_operation = RequestId::new();
    let second_token = [0x94; 32];
    let second_created = second_recovery_app
        .prepare_connector_credential_reissue(reissue_prepare_request(
            tenant_id,
            &host,
            &concurrent_connector,
            second_operation,
            &left.credential,
            second_token,
            0xd1,
        ))
        .await
        .expect("the promoted credential can later enter a new recovery");
    let second_request = signed_reissue_request(
        second_operation,
        second_created.intent_id,
        &host,
        &concurrent_connector,
        &left.credential,
        second_token,
        0x61,
        0x63,
    )?;
    let second = second_recovery_app
        .reissue_credential(parsed_reissue(second_token, second_request))
        .await
        .expect("the later recovery must commit");
    let second_peer = authenticate_credential_at(
        authorization_index.clone(),
        &ca_certificate_der,
        &second.credential,
        second_reissue_now,
    )?;
    second_recovery_app
        .open_control(
            second_peer,
            hello_for(
                tenant_id,
                host.host_id(),
                &concurrent_connector,
                BootId::new(),
                after_command.acknowledged_sequence,
            )?,
        )
        .await
        .expect("the later recovery must promote its pending credential");
    let retired_result_replay = second_recovery_app
        .reissue_credential(parsed_reissue(concurrent_token, concurrent_request.clone()))
        .await
        .expect("an exact consumed result must replay after its credential is retired");
    assert_eq!(retired_result_replay, left);
    let mut after_second_promotion = store.begin_tenant(tenant_id).await?;
    let second_authorization = ConnectorCredentialAuthorizationRepository::new()
        .load(
            after_second_promotion.connection(),
            tenant_id,
            concurrent_connector.connector_id(),
        )
        .await?
        .expect("the later promotion remains auditable");
    assert_eq!(second_authorization.current(), Some(&second.credential));
    assert_eq!(
        second_authorization
            .snapshot()
            .history
            .iter()
            .find(|entry| entry.credential.credential_id() == left.credential.credential_id())
            .map(|entry| entry.status),
        Some(ConnectorCredentialStatus::Retired),
    );
    after_second_promotion.rollback().await?;

    let aborted_operation = RequestId::new();
    let aborted_token = [0x93; 32];
    let aborted_created = recovery_app
        .prepare_connector_credential_reissue(reissue_prepare_request(
            tenant_id,
            &host,
            &aborted_connector,
            aborted_operation,
            &aborted.credential,
            aborted_token,
            0xc1,
        ))
        .await
        .expect("abort fixture must prepare");
    recovery_app
        .abort_connector_credential_reissue(tenant_id, aborted_operation)
        .await
        .expect("active reissue must abort");
    let mut aborted_mutation = store.begin_tenant(tenant_id).await?;
    let aborted_mutation_error = sqlx::query(
        "UPDATE agent.connector_credential_reissue_intents
            SET transitioned_at_ms=transitioned_at_ms+1
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(aborted_operation))
    .execute(aborted_mutation.connection())
    .await
    .expect_err("runtime SQL cannot rewrite an aborted receipt");
    assert_eq!(
        aborted_mutation_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514")),
    );
    aborted_mutation.rollback().await?;
    assert_eq!(
        recovery_app
            .abort_connector_credential_reissue(tenant_id, aborted_operation)
            .await,
        Err(ConnectorControlApplicationError::Conflict),
    );
    assert_eq!(
        recovery_app
            .prepare_connector_credential_reissue(reissue_prepare_request(
                tenant_id,
                &host,
                &aborted_connector,
                aborted_operation,
                &aborted.credential,
                aborted_token,
                0xc1,
            ))
            .await,
        Err(ConnectorControlApplicationError::Conflict),
        "an aborted operation must never replay as active",
    );
    assert_eq!(
        recovery_app
            .reissue_credential(parsed_reissue(
                aborted_token,
                signed_reissue_request(
                    aborted_operation,
                    aborted_created.intent_id,
                    &host,
                    &aborted_connector,
                    &aborted.credential,
                    aborted_token,
                    0x51,
                    0x71,
                )?,
            ))
            .await,
        Err(ConnectorControlApplicationError::AuthenticationFailed),
        "an aborted handoff cannot be consumed",
    );

    let downgrade = sqlx::raw_sql(include_str!(
        "../../../migrations/202607190044_connector_credential_reissue_v1.down.sql"
    ))
    .execute(harness.admin_pool())
    .await
    .expect_err("same-generation reissue history makes a V43 downgrade lossy");
    assert_eq!(
        downgrade
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("55000")),
    );
    let post_refusal = sqlx::query(
        "SELECT
            to_regclass('agent.connector_credential_reissue_intents') IS NOT NULL AS intents_exist,
            (SELECT status FROM agent.connector_credential_reissue_intents
              WHERE tenant_id=$1 AND operation_id=$2) AS intent_status,
            (SELECT cause_kind FROM agent.connector_control_credential_revisions
              WHERE tenant_id=$1 AND connector_id=$3
              ORDER BY authorization_revision DESC LIMIT 1) AS head_cause,
            (SELECT count(*) FROM agent.connector_control_credentials
              WHERE tenant_id=$1 AND connector_id=$3 AND origin_kind='reissue') AS reissue_credentials",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(concurrent_operation))
    .bind(Uuid::from(concurrent_connector.connector_id()))
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(post_refusal.try_get::<bool, _>("intents_exist")?);
    assert_eq!(
        post_refusal.try_get::<String, _>("intent_status")?,
        "consumed"
    );
    assert_eq!(
        post_refusal.try_get::<String, _>("head_cause")?,
        "reissue_promoted"
    );
    assert_eq!(post_refusal.try_get::<i64, _>("reissue_credentials")?, 2);
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
    enroll_connector(app, tenant_id, connector, token, control_seed, refresh_seed).await?;
    Ok(())
}

async fn enroll_connector(
    app: &PostgresConnectorControlApplication,
    tenant_id: TenantId,
    connector: &Connector,
    token: [u8; 32],
    control_seed: u8,
    refresh_seed: u8,
) -> Result<dtx_agent_control_server::EnrollmentCompletion, Box<dyn Error>> {
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
    Ok(app.enroll(parsed_enrollment(token, request)).await?)
}

fn reissue_prepare_request(
    tenant_id: TenantId,
    host: &AgentHost,
    connector: &Connector,
    operation_id: RequestId,
    current: &ConnectorCredential,
    token: [u8; 32],
    plan_digest_byte: u8,
) -> PrepareConnectorCredentialReissueRequest {
    PrepareConnectorCredentialReissueRequest {
        tenant_id,
        host_id: host.host_id(),
        connector_id: connector.connector_id(),
        operation_id,
        expected_credential_id: current.credential_id(),
        expected_leaf_fingerprint: current.certificate_fingerprint(),
        expected_generation: connector.generation().get(),
        expected_spec_revision: connector.spec_revision(),
        plan_digest: Sha256Digest::from_bytes([plan_digest_byte; 32]),
        token_digest: CredentialReissueToken::from_bytes(token).digest(),
        ttl_millis: 60_000,
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_reissue_request(
    operation_id: RequestId,
    intent_id: dtx_domain::EnrollmentIntentId,
    host: &AgentHost,
    connector: &Connector,
    current: &ConnectorCredential,
    token: [u8; 32],
    current_control_seed: u8,
    new_control_seed: u8,
) -> Result<CredentialReissueRequest, Box<dyn Error>> {
    let current_control = SigningKey::from_bytes(&[current_control_seed; 32]);
    let new_control = SigningKey::from_bytes(&[new_control_seed; 32]);
    assert_eq!(
        current.control_key().as_bytes(),
        &current_control.verifying_key().to_bytes(),
        "the fixture must sign with the enrolled current control key",
    );
    let unsigned = CredentialReissueRequest::new(
        operation_id,
        intent_id,
        CredentialReissueToken::from_bytes(token).digest(),
        current.tenant_id(),
        host.host_id(),
        connector.connector_id(),
        current.credential_id(),
        current.certificate_fingerprint(),
        connector.generation().get(),
        connector.spec_revision(),
        Ed25519PublicKey::try_from(new_control.verifying_key().to_bytes())?,
        [0; 64],
        [0; 64],
    );
    let signing_bytes = unsigned.signing_bytes();
    Ok(CredentialReissueRequest::new(
        operation_id,
        intent_id,
        unsigned.token_digest(),
        unsigned.tenant_id(),
        unsigned.host_id(),
        unsigned.connector_id(),
        unsigned.current_credential_id(),
        unsigned.current_fingerprint(),
        unsigned.generation(),
        unsigned.spec_revision(),
        unsigned.new_control_key(),
        current_control.sign(&signing_bytes).to_bytes(),
        new_control.sign(&signing_bytes).to_bytes(),
    ))
}

fn parsed_reissue(token: [u8; 32], request: CredentialReissueRequest) -> ParsedCredentialReissue {
    ParsedCredentialReissue {
        token: CredentialReissueToken::from_bytes(token),
        request,
    }
}

fn hello_for(
    tenant_id: TenantId,
    host_id: HostId,
    connector: &Connector,
    boot_id: BootId,
    last_applied_command_sequence: u64,
) -> Result<ParsedHello, Box<dyn Error>> {
    Ok(ParsedHello {
        tenant_id,
        connector_id: connector.connector_id(),
        host_id,
        boot_id,
        connector_generation: connector.generation().get(),
        spec_revision: connector.spec_revision(),
        protocol: ParsedProtocolRange {
            minimum_major: 1,
            minimum_minor: 0,
            maximum_major: 1,
            maximum_minor: 2,
        },
        runtime_claims: RuntimeClaims::new(
            AdapterKind::Codex,
            "1.0.0".to_owned(),
            Sha256Digest::from_bytes([0x73; 32]),
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
    authenticate_credential_at(index, ca_certificate_der, credential, NOW_MILLIS)
}

fn authenticate_credential_at(
    index: Arc<ConnectorCredentialAuthorizationIndex>,
    ca_certificate_der: &[u8],
    credential: &dtx_agent_control::ConnectorCredential,
    now_millis: i64,
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
    let now = UnixTime::since_unix_epoch(Duration::from_millis(u64::try_from(now_millis)?));
    Ok(verifier.authenticate_peer_certificate(&leaf, &intermediates, now)?)
}

fn offset_time(millis: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
}
