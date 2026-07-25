use std::{
    error::Error,
    str::FromStr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::support::PostgresHarness;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_agent_control::{
    EnrollmentRequest, EnrollmentToken, EnrollmentTranscript, RuntimeClaims, ServerCommandPayload,
    Sha256Digest as ControlDigest,
};
use dtx_agent_control_server::{
    AgentProvisioningInstalledReceiptFacts, ConnectorCertificateAuthority,
    ConnectorControlApplication, ConnectorControlApplicationError, ConnectorControlPolicy,
    ConnectorCredentialAuthorizationIndex, CreateConnectorEnrollmentRequest,
    MAX_CONNECTOR_PROJECTION_BINDINGS, ParsedAgentProvisioningInstalled,
    ParsedAgentRouteBootstrapInstalled, ParsedAgentRouteBootstrapRejected,
    ParsedAgentRouteRecipientReady, ParsedCapacity, ParsedCommandAcknowledgement, ParsedEnrollment,
    ParsedHello, ParsedLeaseFence, ParsedProtocolRange, ParsedProvisioningRecipientAnnouncement,
    PostgresAgentProvisioningOwnerBackend, PostgresConnectorControlApplication,
    ProtobufDurableCommandDecoder, agent_provisioning_installed_receipt_digest,
    agent_provisioning_owner_router,
};
use dtx_agent_host::AgentHost;
use dtx_agent_persistence::{
    AgentDefinitionRepository, AgentDeviceRepository, AgentHostRepository,
    AgentInstallationRepository, BindingSetRepository, ConnectorRepository,
    ConversationGrantRepository, CurrentWrite, DefinitionInsert,
};
use dtx_agent_registry::{
    AgentConversationPermission, AgentDevice, AgentDeviceCommand, AgentDeviceState,
    AgentInstallation, ConversationGrantCommand, ConversationGrantUpdate, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode, InstallationCommand, InstallationDesiredState,
    PermissionExpansionConfirmation, VerifiedAgentDefinition,
};
use dtx_connect_registry::{
    AdapterConformance, AdapterKind, BindingSpec, BindingState, Connector, RoutingPolicy, TenantRef,
};
use dtx_domain::{
    AgentDeviceId, AgentId, AgentRouteBootstrapId, AgentRouteDeliveryId, AgentRouteRecipientId,
    BindingId, BootId, Clock, ConnectorId, ConversationId, DeviceId, DeviceSessionId,
    Ed25519PublicKey, EventId, HostCredentialId, HostId, IdGenerator, IdentityId, InstallationId,
    ProvisioningDeliveryId, ProvisioningRecipientKeyId, RequestId, Revision, RouteHealthKeyId,
    SystemClock, TenantId, UuidV7Generator,
};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCredential, IdentityAppendCommand,
    IdentityAppendOutcome, IdentityLogHead, IdentityLogRepository, IdentityPgStore,
};
use dtx_security::{ConnectorMtlsClientVerifier, SecretBytes};
use dtx_storage::PgStore;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, UnixTime},
};
use sha2::{Digest, Sha256};
use sqlx::Executor;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;
static TEST_NOW: OnceLock<i64> = OnceLock::new();
static BINDING_FIXTURE_CLOCK_OFFSET: AtomicI64 = AtomicI64::new(0);
const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const PRIVATE_CONVERSATION_TOOLS_PROFILE_V1: &[u8] = b"dirextalk/private-conversation-agent-profile/v1\nmention-only\nfuture-messages\nsend-messages\nexclude-history\nexclude-attachments\ninclude-tools\nexclude-cloud\nexclude-egress";
pub(crate) fn init_test_clock() {
    TEST_NOW.get_or_init(|| {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_millis(),
        )
        .expect("current time fits i64")
    });
}
pub(crate) async fn owner_post(
    router: axum::Router,
    uri: &str,
    authorization: &str,
    idempotency: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let response = router
        .oneshot(
            Request::post(uri)
                .header(header::AUTHORIZATION, authorization)
                .header("idempotency-key", idempotency)
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        to_bytes(response.into_body(), 1_000_000).await?.to_vec(),
    ))
}

pub(crate) async fn owner_lifecycle_post(
    router: axum::Router,
    uri: &str,
    authorization: &str,
    operation_id: RequestId,
    if_match: &str,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let response = router
        .oneshot(
            Request::post(uri)
                .header(header::AUTHORIZATION, authorization)
                .header("idempotency-key", operation_id.to_string())
                .header(header::IF_MATCH, if_match)
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        to_bytes(response.into_body(), 1_000_000).await?.to_vec(),
    ))
}

pub(crate) async fn owner_conversation_grant_mutation(
    router: axum::Router,
    method: Method,
    uri: &str,
    authorization: &str,
    operation_id: RequestId,
    if_match: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let response = router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, authorization)
                .header("idempotency-key", operation_id.to_string())
                .header(header::IF_MATCH, if_match)
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.dirextalk.conversation-agent-grant.v1+cbor",
                )
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        to_bytes(response.into_body(), 1_000_000).await?.to_vec(),
    ))
}

pub(crate) async fn owner_connector_binding_state_mutation(
    router: axum::Router,
    uri: &str,
    authorization: &str,
    operation_id: RequestId,
    if_match: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, Option<String>, Option<String>, Vec<u8>), Box<dyn Error>> {
    let response = router
        .oneshot(
            Request::post(uri)
                .header(header::AUTHORIZATION, authorization)
                .header("idempotency-key", operation_id.to_string())
                .header(header::IF_MATCH, if_match)
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.dirextalk.connector-binding-state-command.v1+cbor",
                )
                .header(
                    header::ACCEPT,
                    "application/vnd.dirextalk.connector-binding-state-receipt.v1+cbor",
                )
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    Ok((
        status,
        content_type,
        cache_control,
        to_bytes(response.into_body(), 1_000_000).await?.to_vec(),
    ))
}

pub(crate) async fn owner_agent_route_run(
    router: axum::Router,
    uri: &str,
    authorization: &str,
    operation_id: RequestId,
    if_match: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let response = router
        .oneshot(
            Request::post(uri)
                .header(header::AUTHORIZATION, authorization)
                .header("idempotency-key", operation_id.to_string())
                .header(header::IF_MATCH, if_match)
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.dirextalk.agent-route-run.v1+cbor",
                )
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        to_bytes(response.into_body(), 1_000_000).await?.to_vec(),
    ))
}

pub(crate) async fn owner_agent_route_bootstrap_delivery(
    router: axum::Router,
    uri: &str,
    authorization: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let response = router
        .oneshot(
            Request::put(uri)
                .header(header::AUTHORIZATION, authorization)
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor",
                )
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        to_bytes(response.into_body(), 1_000_000).await?.to_vec(),
    ))
}

pub(crate) async fn owner_get(
    router: axum::Router,
    uri: &str,
    authorization: &str,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let (status, _, body) = owner_get_with_accept(router, uri, authorization, None).await?;
    Ok((status, body))
}

pub(crate) async fn owner_get_with_accept(
    router: axum::Router,
    uri: &str,
    authorization: &str,
    accept: Option<&str>,
) -> Result<(StatusCode, Option<String>, Vec<u8>), Box<dyn Error>> {
    let mut request = Request::get(uri).header(header::AUTHORIZATION, authorization);
    if let Some(accept) = accept {
        request = request.header(header::ACCEPT, accept);
    }
    let response = router.oneshot(request.body(Body::empty())?).await?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = to_bytes(response.into_body(), 1_000_000).await?.to_vec();
    Ok((status, content_type, body))
}

pub(crate) async fn provision_tenant(
    store: &PgStore,
    tenant_id: TenantId,
) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query("INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence) VALUES ($1,0)")
        .bind(Uuid::from(tenant_id))
        .execute(session.connection())
        .await?;
    session.commit().await?;
    Ok(())
}

pub(crate) async fn grant_agent_route_run_runtime_access(
    harness: &PostgresHarness,
) -> Result<(), Box<dyn Error>> {
    sqlx::raw_sql(
        "GRANT SELECT, INSERT, UPDATE ON agent.agent_runs TO dtx_runtime_test;
         GRANT SELECT, INSERT ON agent.agent_run_candidates TO dtx_runtime_test;
         GRANT SELECT, INSERT, UPDATE ON agent.connector_run_capacity_heads TO dtx_runtime_test;
         GRANT SELECT, INSERT, UPDATE ON agent.binding_run_capacity_heads TO dtx_runtime_test;
         GRANT SELECT, INSERT, UPDATE ON agent.agent_run_offers TO dtx_runtime_test;
         GRANT SELECT, INSERT, UPDATE ON agent.agent_run_leases TO dtx_runtime_test;
         GRANT EXECUTE ON FUNCTION agent.router_stable_names(text[]) TO dtx_runtime_test;
         GRANT SELECT, INSERT, UPDATE ON agent.agent_route_run_operations TO dtx_runtime_test;
         GRANT SELECT, INSERT, UPDATE ON agent.agent_route_bootstraps,
             agent.agent_route_bootstrap_outbox, agent.agent_route_binding_heads
             TO dtx_runtime_test;",
    )
    .execute(harness.admin_pool())
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn install_agent_route_binding_head(
    store: &PgStore,
    tenant_id: TenantId,
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    connector: &Connector,
    route_id: ConversationId,
    route_fence: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    let bootstrap_id = AgentRouteBootstrapId::new();
    let delivery_id = AgentRouteDeliveryId::new();
    let recipient_id = AgentRouteRecipientId::new();
    let expires_at = now() + 300_000;
    let installed_at = now();
    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query(
        "INSERT INTO agent.agent_route_bootstraps (
             tenant_id, bootstrap_id, owner_identity_id, owner_device_id, installation_id,
             binding_id, agent_control_device_id, connector_id, route_fence, owner_signed_intent,
             request_digest, begin_receipt_bytes, begin_receipt_digest, recipient_id,
             recipient_capsule_digest, opaque_recipient_capsule, route_id, delivery_id,
             bootstrap_capsule_digest, opaque_sealed_bootstrap, delivery_request_digest,
             delivery_receipt_bytes, delivery_receipt_digest, state, expires_at_ms,
             created_at_ms, updated_at_ms
         ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
             $19,$20,$21,$22,$23,'installed',$24,$25,$26
         )",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .bind(owner_identity_id.to_string())
    .bind(Uuid::from(owner_device_id))
    .bind(Uuid::from(installation_id))
    .bind(Uuid::from(binding_id))
    .bind(Uuid::from(agent_control_device_id))
    .bind(Uuid::from(connector.connector_id()))
    .bind(route_fence.as_slice())
    .bind([0x01_u8].as_slice())
    .bind([0x02_u8; 32].as_slice())
    .bind([0x03_u8].as_slice())
    .bind([0x04_u8; 32].as_slice())
    .bind(Uuid::from(recipient_id))
    .bind([0x05_u8; 32].as_slice())
    .bind([0x06_u8].as_slice())
    .bind(Uuid::from(route_id))
    .bind(Uuid::from(delivery_id))
    .bind([0x07_u8; 32].as_slice())
    .bind([0x08_u8].as_slice())
    .bind([0x09_u8; 32].as_slice())
    .bind([0x0A_u8].as_slice())
    .bind([0x0B_u8; 32].as_slice())
    .bind(expires_at)
    .bind(installed_at - 1)
    .bind(installed_at)
    .execute(session.connection())
    .await?;
    sqlx::query(
        "INSERT INTO agent.agent_route_binding_heads (
             tenant_id, owner_identity_id, owner_device_id, installation_id, binding_id,
             agent_control_device_id, bootstrap_id, delivery_id, route_id, route_fence,
             capsule_digest, expires_at_ms, installed_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(owner_identity_id.to_string())
    .bind(Uuid::from(owner_device_id))
    .bind(Uuid::from(installation_id))
    .bind(Uuid::from(binding_id))
    .bind(Uuid::from(agent_control_device_id))
    .bind(Uuid::from(bootstrap_id))
    .bind(Uuid::from(delivery_id))
    .bind(Uuid::from(route_id))
    .bind(route_fence.as_slice())
    .bind([0x07_u8; 32].as_slice())
    .bind(expires_at)
    .bind(installed_at)
    .execute(session.connection())
    .await?;
    session.commit().await?;
    Ok(())
}

pub(crate) async fn provision_private_conversation_owner(
    harness: &PostgresHarness,
    tenant_id: TenantId,
    conversation_id: ConversationId,
    owner_identity_id: IdentityId,
) -> Result<(), Box<dyn Error>> {
    sqlx::query(
        "INSERT INTO groups.policy_heads (
             tenant_id, scope_kind, scope_id, owner_identity_id, policy_revision,
             created_at_ms, updated_at_ms
         ) VALUES ($1, 'private_conversation', $2, $3, 1, $4, $4)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(conversation_id.to_string())
    .bind(owner_identity_id.to_string())
    .bind(now() - 1_000)
    .execute(harness.admin_pool())
    .await?;
    Ok(())
}

pub(crate) async fn provision_identity(
    harness: &PostgresHarness,
    root: &SigningKey,
    device: &SigningKey,
    device_id: DeviceId,
    encryption_seed: u8,
) -> Result<(IdentityId, IdentityLogHead, DeviceCertificateV1), Box<dyn Error>> {
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 2).await?;
    let repository = IdentityLogRepository::new();
    let genesis = genesis(root, &key(encryption_seed.wrapping_add(40)));
    let identity_id = genesis.identity_id();
    let genesis_receipt = committed(
        repository
            .append(
                &store,
                &identity_command(encryption_seed, None, &genesis)?,
                UtcMillis::new(now() - 20_000)?,
            )
            .await?,
    )?;
    let certificate = device_certificate(root, identity_id, device, device_id, encryption_seed);
    let event = signed_event(
        root,
        identity_id,
        2,
        Some(genesis_receipt.hash()),
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: certificate.clone(),
        },
    );
    let device_receipt = committed(
        repository
            .append(
                &store,
                &identity_command(
                    encryption_seed.wrapping_add(1),
                    Some(genesis_receipt),
                    &event,
                )?,
                UtcMillis::new(now() - 19_000)?,
            )
            .await?,
    )?;
    Ok((identity_id, device_receipt, certificate))
}

pub(crate) async fn provision_owner_session(
    harness: &PostgresHarness,
    identity_id: IdentityId,
    device_id: DeviceId,
    head: IdentityLogHead,
    secret: [u8; 32],
) -> Result<(DeviceSessionCredential, String), Box<dyn Error>> {
    let session_id = DeviceSessionId::new();
    let challenge_id = Uuid::now_v7();
    let mut tx = harness.admin_pool().begin().await?;
    tx.execute("SET CONSTRAINTS ALL DEFERRED").await?;
    sqlx::query(
        "INSERT INTO identity.device_session_challenges (
            challenge_id, identity_id, device_id, nonce_hash, audience, state,
            created_at_ms, expires_at_ms, session_expires_at_ms
         ) VALUES ($1,$2,$3,$4,'owner-http-test','open',$5,$6,$7)",
    )
    .bind(challenge_id)
    .bind(identity_id.to_string())
    .bind(Uuid::from(device_id))
    .bind([0x33_u8; 32].as_slice())
    .bind(now() - 10_000)
    .bind(now() + 300_000)
    .bind(now() + 600_000)
    .execute(&mut *tx)
    .await?;
    let secret_hash = Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &secret);
    sqlx::query(
        "INSERT INTO identity.device_sessions (
            session_id, identity_id, device_id, challenge_id, session_secret_hash,
            issued_head_sequence, issued_head_hash, issued_at_ms, expires_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(Uuid::from(session_id))
    .bind(identity_id.to_string())
    .bind(Uuid::from(device_id))
    .bind(challenge_id)
    .bind(secret_hash.as_bytes().as_slice())
    .bind(i64::try_from(head.sequence().get())?)
    .bind(head.hash().as_bytes().as_slice())
    .bind(now() - 9_000)
    .bind(now() + 600_000)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE identity.device_session_challenges
            SET state='consumed', consumed_at_ms=$2, session_id=$3
          WHERE challenge_id=$1 AND state='open'",
    )
    .bind(challenge_id)
    .bind(now() - 9_000)
    .bind(Uuid::from(session_id))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let authorization = format!(
        "DTX-Device-Session {session_id}.{}",
        Base64UrlUnpadded::encode_string(&secret)
    );
    Ok((
        DeviceSessionCredential::new(session_id, secret)?,
        authorization,
    ))
}

pub(crate) async fn provision_host_and_connector(
    store: &PgStore,
    tenant_id: TenantId,
    owner_id: IdentityId,
) -> Result<(AgentHost, Connector), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let mut host = AgentHost::register(tenant_id, HostId::new(), owner_id);
    AgentHostRepository::new()
        .save(session.connection(), &host, now() - 8_000)
        .await?;
    host.enroll(host.revision(), HostCredentialId::new())?;
    AgentHostRepository::new()
        .save(session.connection(), &host, now() - 7_999)
        .await?;
    let connector = Connector::register(&host, ConnectorId::new(), AdapterKind::Codex, 4)?;
    ConnectorRepository::new()
        .save(session.connection(), &connector, None, now() - 7_998)
        .await?;
    session.commit().await?;
    Ok((host, connector))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn provision_installation_binding(
    store: &PgStore,
    tenant_id: TenantId,
    owner_id: IdentityId,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
    identity_device_id: DeviceId,
    fingerprint: DeviceCredentialFingerprint,
    binding_id: BindingId,
    connector: &Connector,
) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let definition = VerifiedAgentDefinition::new(
        AgentId::from_str(AGENT_ID)?,
        owner_id,
        Revision::INITIAL,
        DescriptorDigest::from_bytes([0x44; 32]),
        now() + 600_000,
    );
    assert!(matches!(
        AgentDefinitionRepository::new()
            .insert(session.connection(), &definition, now() - 7_000)
            .await?,
        DefinitionInsert::Inserted | DefinitionInsert::Existing
    ));
    let installation = AgentInstallation::new(
        tenant_id,
        installation_id,
        definition.agent_id(),
        owner_id,
        ExecutionMode::ConnectorManaged,
        definition.version(),
        definition.descriptor_hash(),
    );
    assert_eq!(
        AgentInstallationRepository::new()
            .save(session.connection(), &installation, now() - 6_000)
            .await?,
        CurrentWrite::Inserted
    );
    let mut device = AgentDevice::enroll(
        &installation,
        agent_device_id,
        identity_device_id,
        fingerprint,
    )?;
    assert_eq!(
        AgentDeviceRepository::new()
            .save(session.connection(), &device, now() - 5_000)
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
            .save(session.connection(), &device, now() - 4_999)
            .await?,
        CurrentWrite::Advanced
    );
    let binding_repository = BindingSetRepository::new();
    let mut bindings = binding_repository
        .load(session.connection(), tenant_id)
        .await?;
    bindings.register_connector_conformance(
        connector,
        AdapterConformance::trusted_multi_session(AdapterKind::Codex, Revision::INITIAL),
    )?;
    let spec = BindingSpec::for_entities(
        TenantRef::new(tenant_id, binding_id),
        &installation,
        &device,
        connector,
        0,
        1,
    )?;
    let binding_ref = spec.binding_ref();
    bindings.create_binding(spec, RoutingPolicy::Exclusive)?;
    let binding_stored_at = next_binding_fixture_timestamp();
    binding_repository
        .save(session.connection(), &bindings, binding_stored_at)
        .await?;
    bindings.enable(binding_ref, Revision::INITIAL, &installation, &device)?;
    binding_repository
        .save(session.connection(), &bindings, binding_stored_at + 1)
        .await?;
    session.commit().await?;
    Ok(())
}

pub(crate) async fn set_binding_state(
    store: &PgStore,
    tenant_id: TenantId,
    binding_id: BindingId,
    revoke: bool,
) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let repository = BindingSetRepository::new();
    let mut bindings = repository.load(session.connection(), tenant_id).await?;
    let binding_ref = TenantRef::new(tenant_id, binding_id);
    let disabled_revision =
        bindings.disable(binding_ref, bindings.binding(binding_ref)?.revision())?;
    let stored_at = next_binding_fixture_timestamp();
    repository
        .save(session.connection(), &bindings, stored_at)
        .await?;
    if revoke {
        bindings.revoke(binding_ref, disabled_revision)?;
        repository
            .save(session.connection(), &bindings, stored_at + 1)
            .await?;
    }
    session.commit().await?;
    Ok(())
}

pub(crate) async fn revoke_agent_device(
    store: &PgStore,
    tenant_id: TenantId,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let installation = AgentInstallationRepository::new()
        .load(session.connection(), tenant_id, installation_id)
        .await?
        .expect("Agent Installation fixture must exist");
    let mut device = AgentDeviceRepository::new()
        .load(session.connection(), tenant_id, agent_device_id)
        .await?
        .expect("Agent Device fixture must exist");
    device.apply(&installation, device.revision(), AgentDeviceCommand::Revoke)?;
    AgentDeviceRepository::new()
        .save(session.connection(), &device, current_store_timestamp()?)
        .await?;
    session.commit().await?;
    Ok(())
}

pub(crate) fn current_store_timestamp() -> Result<i64, Box<dyn Error>> {
    Ok(i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )? + 1)
}

pub(crate) fn fingerprint_for_binding(
    certificate: &DeviceCertificateV1,
    marker: u8,
) -> Result<DeviceCredentialFingerprint, Box<dyn Error>> {
    let mut material = certificate.to_deterministic_cbor()?;
    material.push(marker);
    Ok(DeviceCredentialFingerprint::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-device-credential-fingerprint.v1\0",
            &material,
        )
        .as_bytes(),
    ))
}

pub(crate) fn next_binding_fixture_timestamp() -> i64 {
    let wall_clock = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )
    .expect("current time fits i64");
    let previous = BINDING_FIXTURE_CLOCK_OFFSET
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
            Some(previous.saturating_add(2).max(wall_clock))
        })
        .expect("binding fixture clock update cannot fail");
    previous.saturating_add(2).max(wall_clock)
}

pub(crate) fn application(
    store: PgStore,
    issuer: Arc<ConnectorCertificateAuthority>,
    index: Arc<ConnectorCredentialAuthorizationIndex>,
) -> PostgresConnectorControlApplication {
    PostgresConnectorControlApplication::with_ports(
        store,
        Arc::new(SystemClock) as Arc<dyn Clock>,
        Arc::new(UuidV7Generator) as Arc<dyn IdGenerator>,
        issuer,
        index,
        Arc::new(ProtobufDurableCommandDecoder),
        ConnectorControlPolicy::default(),
    )
}

pub(crate) fn claims() -> Result<RuntimeClaims, Box<dyn Error>> {
    Ok(RuntimeClaims::new(
        AdapterKind::Codex,
        "1.0.0".into(),
        ControlDigest::from_bytes([0x61; 32]),
        0,
        Vec::new(),
        None,
        vec!["agent.run".into(), "opaque-agent-provisioning".into()],
    )?)
}

pub(crate) const fn capacity() -> ParsedCapacity {
    ParsedCapacity {
        maximum_concurrent_runs: 4,
        available_concurrent_runs: 4,
        maximum_queue_depth: 32,
    }
}

pub(crate) fn parsed_fence(fence: dtx_connect_registry::ConnectorFence) -> ParsedLeaseFence {
    ParsedLeaseFence {
        tenant_id: fence.tenant_id(),
        connector_id: fence.connector_id(),
        boot_id: fence.boot_id(),
        connector_generation: fence.generation().get(),
        lease_id: fence.lease_id(),
        lease_epoch: fence.lease_epoch().get(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn conversation_grant_body(
    action: u64,
    operation_id: RequestId,
    tenant_id: TenantId,
    conversation_id: ConversationId,
    installation_id: InstallationId,
    expected_grant_version: Option<Revision>,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    owner_key: &SigningKey,
    grant_expires_at: Option<i64>,
    privacy_policy_hash: Option<[u8; 32]>,
    proof_expires_at: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let grant_expires_at = match grant_expires_at {
        Some(expires_at) => UtcMillis::new(expires_at)?.to_canonical_value(),
        None => CanonicalValue::Null,
    };
    let privacy_policy_hash = match privacy_policy_hash {
        Some(digest) => bytes(&digest),
        None => CanonicalValue::Null,
    };
    let binding = CanonicalValue::Map(vec![
        (u(1), u(1)),
        (u(2), u(action)),
        (u(3), text(tenant_id)),
        (u(4), text(conversation_id)),
        (u(5), text(installation_id)),
        (u(6), text(operation_id)),
        (
            u(7),
            u(expected_grant_version.map_or(0, |version| version.get())),
        ),
        (u(8), text(owner_id)),
        (u(9), text(owner_device_id)),
        (
            u(10),
            UtcMillis::new(proof_expires_at)?.to_canonical_value(),
        ),
        (u(11), grant_expires_at),
        (u(12), privacy_policy_hash),
    ]);
    signed_owner_body(
        binding,
        b"dirextalk.conversation-agent-grant-binding.v1\0",
        b"dirextalk.conversation-agent-grant-signature.v1\0",
        owner_key,
        None,
    )
}

pub(crate) fn private_conversation_tools_profile_v1_digest() -> [u8; 32] {
    *Sha256Digest::hash_domain(&[], PRIVATE_CONVERSATION_TOOLS_PROFILE_V1).as_bytes()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn connector_binding_state_body(
    action: u64,
    operation_id: RequestId,
    tenant_id: TenantId,
    binding_id: BindingId,
    expected_binding_revision: Revision,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    owner_key: &SigningKey,
    proof_expires_at: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let binding = CanonicalValue::Map(vec![
        (u(1), u(1)),
        (u(2), u(action)),
        (u(3), text(tenant_id)),
        (u(4), text(binding_id)),
        (u(5), u(expected_binding_revision.get())),
        (u(6), text(operation_id)),
        (u(7), text(owner_id)),
        (u(8), text(owner_device_id)),
        (u(9), UtcMillis::new(proof_expires_at)?.to_canonical_value()),
    ]);
    signed_owner_body(
        binding,
        b"dirextalk.connector-binding-state-command-binding.v1\0",
        b"dirextalk.connector-binding-state-command-signature.v1\0",
        owner_key,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn agent_route_run_body(
    tenant_id: TenantId,
    source_conversation_id: ConversationId,
    route_id: ConversationId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    route_fence: [u8; 32],
    request_event_id: EventId,
    operation_id: RequestId,
    grant_version: Revision,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    owner_key: &SigningKey,
    proof_expires_at: i64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let binding = CanonicalValue::Map(vec![
        (u(1), u(1)),
        (u(2), text(tenant_id)),
        (u(3), text(source_conversation_id)),
        (u(4), text(route_id)),
        (u(5), text(installation_id)),
        (u(6), text(request_event_id)),
        (u(7), text(operation_id)),
        (u(8), u(grant_version.get())),
        (u(9), text(owner_id)),
        (u(10), text(owner_device_id)),
        (
            u(11),
            UtcMillis::new(proof_expires_at)?.to_canonical_value(),
        ),
        (u(12), text(binding_id)),
        (u(13), text(agent_control_device_id)),
        (u(14), bytes(&route_fence)),
    ]);
    signed_owner_body(
        binding,
        b"dirextalk.agent-route-run-binding.v1\0",
        b"dirextalk.agent-route-run-signature.v1\0",
        owner_key,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn agent_route_bootstrap_begin_body(
    bootstrap_id: AgentRouteBootstrapId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    expires_at: i64,
    owner_signed_intent: Vec<u8>,
    owner_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let binding = CanonicalValue::Map(vec![
        (u(1), u(1)),
        (u(2), text(bootstrap_id)),
        (u(3), text(tenant_id)),
        (u(4), text(installation_id)),
        (u(5), text(binding_id)),
        (u(6), text(agent_control_device_id)),
        (u(7), text(owner_id)),
        (u(8), text(owner_device_id)),
        (u(9), UtcMillis::new(expires_at)?.to_canonical_value()),
        (u(10), CanonicalValue::Bytes(owner_signed_intent)),
    ]);
    signed_owner_body(
        binding,
        b"dirextalk.agent-route-bootstrap-begin-binding.v1\0",
        b"dirextalk.agent-route-bootstrap-begin-signature.v1\0",
        owner_key,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn agent_route_bootstrap_delivery_body(
    bootstrap_id: AgentRouteBootstrapId,
    delivery_id: AgentRouteDeliveryId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    recipient_id: AgentRouteRecipientId,
    route_id: ConversationId,
    capsule_digest: Sha256Digest,
    opaque_sealed_bootstrap: Vec<u8>,
    expires_at: i64,
    owner_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    agent_route_bootstrap_delivery_body_with_pin(
        bootstrap_id,
        delivery_id,
        tenant_id,
        installation_id,
        binding_id,
        agent_control_device_id,
        owner_id,
        owner_device_id,
        recipient_id,
        route_id,
        capsule_digest,
        opaque_sealed_bootstrap,
        expires_at,
        owner_key,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn agent_route_bootstrap_delivery_body_v2(
    bootstrap_id: AgentRouteBootstrapId,
    delivery_id: AgentRouteDeliveryId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    recipient_id: AgentRouteRecipientId,
    route_id: ConversationId,
    capsule_digest: Sha256Digest,
    opaque_sealed_bootstrap: Vec<u8>,
    expires_at: i64,
    owner_key: &SigningKey,
    server_receipt_key_id: RouteHealthKeyId,
    server_receipt_public_key_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    agent_route_bootstrap_delivery_body_with_pin(
        bootstrap_id,
        delivery_id,
        tenant_id,
        installation_id,
        binding_id,
        agent_control_device_id,
        owner_id,
        owner_device_id,
        recipient_id,
        route_id,
        capsule_digest,
        opaque_sealed_bootstrap,
        expires_at,
        owner_key,
        Some(server_receipt_key_id),
        Some(server_receipt_public_key_digest),
    )
}

#[allow(clippy::too_many_arguments)]
fn agent_route_bootstrap_delivery_body_with_pin(
    bootstrap_id: AgentRouteBootstrapId,
    delivery_id: AgentRouteDeliveryId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    recipient_id: AgentRouteRecipientId,
    route_id: ConversationId,
    capsule_digest: Sha256Digest,
    opaque_sealed_bootstrap: Vec<u8>,
    expires_at: i64,
    owner_key: &SigningKey,
    server_receipt_key_id: Option<RouteHealthKeyId>,
    server_receipt_public_key_digest: Option<Sha256Digest>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let binding = CanonicalValue::Map(vec![
        (u(1), u(1)),
        (u(2), text(bootstrap_id)),
        (u(3), text(delivery_id)),
        (u(4), text(tenant_id)),
        (u(5), text(installation_id)),
        (u(6), text(binding_id)),
        (u(7), text(agent_control_device_id)),
        (u(8), text(owner_id)),
        (u(9), text(owner_device_id)),
        (u(10), text(recipient_id)),
        (u(11), text(route_id)),
        (u(12), bytes(capsule_digest.as_bytes())),
        (u(13), CanonicalValue::Bytes(opaque_sealed_bootstrap)),
        (u(14), UtcMillis::new(expires_at)?.to_canonical_value()),
        (u(15), optional_text(server_receipt_key_id)),
        (
            u(16),
            server_receipt_public_key_digest
                .map(|digest| bytes(digest.as_bytes()))
                .unwrap_or(CanonicalValue::Null),
        ),
    ]);
    let binding = if server_receipt_key_id.is_some() && server_receipt_public_key_digest.is_some() {
        binding
    } else {
        let CanonicalValue::Map(mut fields) = binding else {
            unreachable!()
        };
        fields.truncate(14);
        CanonicalValue::Map(fields)
    };
    let (binding_domain, signature_domain) =
        if server_receipt_key_id.is_some() && server_receipt_public_key_digest.is_some() {
            (
                b"dirextalk.agent-route-bootstrap-delivery-binding.v2\0".as_slice(),
                b"dirextalk.agent-route-bootstrap-delivery-signature.v2\0".as_slice(),
            )
        } else {
            (
                b"dirextalk.agent-route-bootstrap-delivery-binding.v1\0".as_slice(),
                b"dirextalk.agent-route-bootstrap-delivery-signature.v1\0".as_slice(),
            )
        };
    signed_owner_body(binding, binding_domain, signature_domain, owner_key, None)
}

fn optional_text(value: Option<RouteHealthKeyId>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, |value| {
        CanonicalValue::Text(value.to_string())
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn approval_body(
    approval_id: dtx_domain::ApprovalId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_device_id: AgentDeviceId,
    agent_identity_id: IdentityId,
    identity_device_id: DeviceId,
    head: IdentityLogHead,
    fingerprint: DeviceCredentialFingerprint,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    owner_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let binding = CanonicalValue::Map(vec![
        (u(1), u(1)),
        (u(2), text(approval_id)),
        (u(3), text(tenant_id)),
        (u(4), text(installation_id)),
        (u(5), text(binding_id)),
        (u(6), text(agent_device_id)),
        (u(7), text(agent_identity_id)),
        (u(8), text(identity_device_id)),
        (u(9), u(head.sequence().get())),
        (u(10), bytes(head.hash().as_bytes())),
        (u(11), bytes(&fingerprint.as_bytes())),
        (u(12), u(1)),
        (u(13), text(owner_id)),
        (u(14), text(owner_device_id)),
        (u(15), UtcMillis::new(now() + 300_000)?.to_canonical_value()),
    ]);
    signed_owner_body(
        binding,
        b"dirextalk.agent-identity-approval-binding.v1\0",
        b"dirextalk.agent-identity-approval-signature.v1\0",
        owner_key,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn delivery_body(
    delivery_id: ProvisioningDeliveryId,
    approval_id: dtx_domain::ApprovalId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_device_id: AgentDeviceId,
    agent_identity_id: IdentityId,
    identity_device_id: DeviceId,
    recipient_key_id: ProvisioningRecipientKeyId,
    descriptor_digest: ControlDigest,
    capsule_digest: Sha256Digest,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    owner_key: &SigningKey,
    capsule: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let binding = CanonicalValue::Map(vec![
        (u(1), u(1)),
        (u(2), text(delivery_id)),
        (u(3), text(approval_id)),
        (u(4), text(tenant_id)),
        (u(5), text(installation_id)),
        (u(6), text(binding_id)),
        (u(7), text(agent_device_id)),
        (u(8), text(agent_identity_id)),
        (u(9), text(identity_device_id)),
        (u(10), u(2)),
        (u(11), text(recipient_key_id)),
        (u(12), bytes(&descriptor_digest.as_bytes())),
        (u(13), bytes(capsule_digest.as_bytes())),
        (u(14), text(owner_id)),
        (u(15), text(owner_device_id)),
        (u(16), UtcMillis::new(now())?.to_canonical_value()),
        (u(17), UtcMillis::new(now() + 300_000)?.to_canonical_value()),
    ]);
    signed_owner_body(
        binding,
        b"dirextalk.agent-provisioning-delivery-binding.v1\0",
        b"dirextalk.agent-provisioning-delivery-signature.v1\0",
        owner_key,
        Some(capsule),
    )
}

pub(crate) fn revocation_body(
    revocation_id: RequestId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    revision: Revision,
    owner_id: IdentityId,
    owner_device_id: DeviceId,
    owner_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut fields = vec![
        (u(1), u(1)),
        (u(2), text(revocation_id)),
        (u(3), text(tenant_id)),
        (u(4), text(installation_id)),
        (u(5), u(revision.get())),
        (u(6), text(owner_id)),
        (u(7), text(owner_device_id)),
        (u(8), u(1)),
        (u(9), UtcMillis::new(now() + 300_000)?.to_canonical_value()),
    ];
    let binding = CanonicalValue::Map(fields.clone());
    let binding_bytes = encode_deterministic_cbor(&binding)?;
    let digest = Sha256Digest::hash_domain(
        b"dirextalk.agent-provisioning-revocation-binding.v1\0",
        &binding_bytes,
    );
    let mut signature_input = b"dirextalk.agent-provisioning-revocation-signature.v1\0".to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    fields.push((u(10), bytes(digest.as_bytes())));
    fields.push((u(11), bytes(&owner_key.sign(&signature_input).to_bytes())));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

pub(crate) fn signed_owner_body(
    binding: CanonicalValue,
    binding_domain: &[u8],
    signature_domain: &[u8],
    key: &SigningKey,
    capsule: Option<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let binding_bytes = encode_deterministic_cbor(&binding)?;
    let digest = Sha256Digest::hash_domain(binding_domain, &binding_bytes);
    let mut input = signature_domain.to_vec();
    input.extend_from_slice(digest.as_bytes());
    let signature = key.sign(&input).to_bytes();
    let fields = if let Some(capsule) = capsule {
        vec![
            (u(1), binding),
            (u(2), CanonicalValue::Bytes(capsule)),
            (u(3), bytes(digest.as_bytes())),
            (u(4), bytes(&signature)),
        ]
    } else {
        vec![
            (u(1), binding),
            (u(2), bytes(digest.as_bytes())),
            (u(3), bytes(&signature)),
        ]
    };
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

pub(crate) const fn u(value: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(value)
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn text(value: impl ToString) -> CanonicalValue {
    CanonicalValue::Text(value.to_string())
}

pub(crate) fn bytes(value: &[u8]) -> CanonicalValue {
    CanonicalValue::Bytes(value.to_vec())
}

pub(crate) fn recipient_descriptor_digest(
    announcement: &ParsedProvisioningRecipientAnnouncement,
) -> ControlDigest {
    let revision = announcement.provisioning_revision.to_be_bytes();
    let created = u64::try_from(announcement.created_at_millis)
        .unwrap()
        .to_be_bytes();
    let expires = u64::try_from(announcement.expires_at_millis)
        .unwrap()
        .to_be_bytes();
    let generation = announcement
        .connector_fence
        .connector_generation
        .to_be_bytes();
    provisioning_commit(
        b"dirextalk.agent-provisioning-recipient.v1",
        &[
            Uuid::from(announcement.connector_fence.tenant_id).as_bytes(),
            Uuid::from(announcement.connector_fence.connector_id).as_bytes(),
            Uuid::from(announcement.binding_id).as_bytes(),
            Uuid::from(announcement.installation_id).as_bytes(),
            Uuid::from(announcement.agent_device_id).as_bytes(),
            &revision,
            Uuid::from(announcement.recipient_key_id).as_bytes(),
            &announcement.recipient_public_key,
            &created,
            &expires,
            Uuid::from(announcement.credential_id).as_bytes(),
            &generation,
        ],
    )
}

pub(crate) fn recipient_signature_input(digest: ControlDigest) -> Vec<u8> {
    let mut output = Vec::new();
    push_lp(
        &mut output,
        b"dirextalk.agent-provisioning-recipient-signature.v1",
    );
    push_lp(&mut output, &digest.as_bytes());
    output
}

pub(crate) fn provisioning_commit(domain: &[u8], parts: &[&[u8]]) -> ControlDigest {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    ControlDigest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn route_bootstrap_recipient_ready_result_digest(
    bootstrap_id: AgentRouteBootstrapId,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    recipient_id: AgentRouteRecipientId,
    command_sequence: u64,
    recipient_capsule_digest: ControlDigest,
    expires_at_millis: i64,
) -> ControlDigest {
    provisioning_commit(
        b"dirextalk.agent-route-recipient-ready.v1",
        &[
            Uuid::from(bootstrap_id).as_bytes(),
            Uuid::from(tenant_id).as_bytes(),
            Uuid::from(installation_id).as_bytes(),
            Uuid::from(binding_id).as_bytes(),
            Uuid::from(agent_control_device_id).as_bytes(),
            Uuid::from(recipient_id).as_bytes(),
            &command_sequence.to_be_bytes(),
            &recipient_capsule_digest.as_bytes(),
            &u64::try_from(expires_at_millis)
                .expect("positive RouteBootstrap expiry")
                .to_be_bytes(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn route_bootstrap_installed_result_digest(
    bootstrap_id: AgentRouteBootstrapId,
    delivery_id: AgentRouteDeliveryId,
    route_id: ConversationId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    recipient_id: AgentRouteRecipientId,
    command_sequence: u64,
    capsule_digest: ControlDigest,
    route_fence: [u8; 32],
    installed_at_millis: i64,
) -> ControlDigest {
    provisioning_commit(
        b"dirextalk.agent-route-bootstrap-installed.v1",
        &[
            Uuid::from(bootstrap_id).as_bytes(),
            Uuid::from(delivery_id).as_bytes(),
            Uuid::from(route_id).as_bytes(),
            Uuid::from(installation_id).as_bytes(),
            Uuid::from(binding_id).as_bytes(),
            Uuid::from(agent_control_device_id).as_bytes(),
            Uuid::from(recipient_id).as_bytes(),
            &command_sequence.to_be_bytes(),
            &capsule_digest.as_bytes(),
            &route_fence,
            &u64::try_from(installed_at_millis)
                .expect("positive RouteBootstrap installed timestamp")
                .to_be_bytes(),
        ],
    )
}

pub(crate) fn route_bootstrap_rejected_result_digest(
    bootstrap_id: AgentRouteBootstrapId,
    delivery_id: AgentRouteDeliveryId,
    route_id: ConversationId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    recipient_id: AgentRouteRecipientId,
    command_sequence: u64,
    capsule_digest: ControlDigest,
    code: &str,
    at: i64,
) -> ControlDigest {
    provisioning_commit(
        b"dirextalk.agent-route-bootstrap-rejected.v1",
        &[
            Uuid::from(bootstrap_id).as_bytes(),
            Uuid::from(delivery_id).as_bytes(),
            Uuid::from(route_id).as_bytes(),
            Uuid::from(installation_id).as_bytes(),
            Uuid::from(binding_id).as_bytes(),
            Uuid::from(agent_control_device_id).as_bytes(),
            Uuid::from(recipient_id).as_bytes(),
            &command_sequence.to_be_bytes(),
            &capsule_digest.as_bytes(),
            code.as_bytes(),
            &u64::try_from(at).expect("positive timestamp").to_be_bytes(),
        ],
    )
}

pub(crate) fn push_lp(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn public_key(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}

pub(crate) fn wire_signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

pub(crate) fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
    let root_key = public_key(root);
    let recovery_key = public_key(recovery);
    let identity_id = IdentityId::derive(root_key.as_domain_key());
    signed_event_at(
        root,
        identity_id,
        1,
        None,
        now() - 22_000,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: wire_signature(
                recovery,
                &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key).unwrap(),
            ),
        },
    )
}

pub(crate) fn device_certificate(
    root: &SigningKey,
    identity_id: IdentityId,
    device: &SigningKey,
    device_id: DeviceId,
    encryption_seed: u8,
) -> DeviceCertificateV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        public_key(device),
        DeviceEncryptionPublicKey::try_from([encryption_seed; 32]).unwrap(),
        public_key(root),
        UtcMillis::new(now() - 21_000).unwrap(),
    )
    .unwrap();
    DeviceCertificateV1::signed(
        unsigned.clone(),
        wire_signature(
            root,
            &device_certificate_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}

pub(crate) fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    signed_event_at(
        signer,
        identity_id,
        sequence,
        previous,
        now() - 20_000,
        payload,
    )
}

pub(crate) fn signed_event_at(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        SafeUint::new(sequence).unwrap(),
        previous,
        UtcMillis::new(occurred_at).unwrap(),
        payload,
        public_key(signer),
    )
    .unwrap();
    IdentityLogEventV1::signed(
        unsigned.clone(),
        wire_signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}

pub(crate) fn identity_command(
    seed: u8,
    expected_head: Option<IdentityLogHead>,
    event: &IdentityLogEventV1,
) -> Result<IdentityAppendCommand, Box<dyn Error>> {
    Ok(IdentityAppendCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        expected_head,
        event.to_deterministic_cbor()?,
    )?)
}

pub(crate) fn committed(outcome: IdentityAppendOutcome) -> Result<IdentityLogHead, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt.head()),
        _ => Err("expected new identity append".into()),
    }
}

pub(crate) fn signed_enrollment_request(
    enrollment: &dtx_agent_control_server::CreatedConnectorEnrollment,
    token: &[u8; 32],
    control_seed: u8,
    refresh_seed: u8,
) -> Result<EnrollmentRequest, Box<dyn Error>> {
    let control = key(control_seed);
    let refresh = key(refresh_seed);
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

pub(crate) fn certificate_issuer(
    now_millis: i64,
) -> Result<(Arc<ConnectorCertificateAuthority>, Vec<u8>), Box<dyn Error>> {
    let mut params = CertificateParams::default();
    params.not_before = offset_time(now_millis - 60_000)?;
    params.not_after = offset_time(now_millis + 172_800_000)?;
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
    let certificate = params.self_signed(&key_pair)?.der().to_vec();
    let issuer = ConnectorCertificateAuthority::from_ed25519_pkcs8(
        certificate.clone(),
        SecretBytes::new(key_pair.serialize_der())?,
        Vec::new(),
    )?;
    Ok((Arc::new(issuer), certificate))
}

pub(crate) fn authenticate(
    index: Arc<ConnectorCredentialAuthorizationIndex>,
    ca_der: &[u8],
    credential: &dtx_agent_control::ConnectorCredential,
) -> Result<dtx_security::AuthenticatedConnectorPeer, Box<dyn Error>> {
    authenticate_at(index, ca_der, credential, now())
}

pub(crate) fn authenticate_at(
    index: Arc<ConnectorCredentialAuthorizationIndex>,
    ca_der: &[u8],
    credential: &dtx_agent_control::ConnectorCredential,
    auth_time_ms: i64,
) -> Result<dtx_security::AuthenticatedConnectorPeer, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec()))?;
    let verifier = ConnectorMtlsClientVerifier::new(Arc::new(roots), index)?;
    let chain = credential.certificate_chain();
    Ok(verifier.authenticate_peer_certificate(
        &CertificateDer::from(chain[0].clone()),
        &chain[1..]
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect::<Vec<_>>(),
        UnixTime::since_unix_epoch(Duration::from_millis(u64::try_from(auth_time_ms)?)),
    )?)
}

pub(crate) fn offset_time(millis: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
}

pub(crate) fn now() -> i64 {
    *TEST_NOW.get().expect("test clock initialized")
}
