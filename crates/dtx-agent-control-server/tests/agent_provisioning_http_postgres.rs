#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    str::FromStr,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
    ConnectorControlApplication, ConnectorControlPolicy, ConnectorCredentialAuthorizationIndex,
    CreateConnectorEnrollmentRequest, ParsedAgentProvisioningInstalled, ParsedCapacity,
    ParsedEnrollment, ParsedHello, ParsedLeaseFence, ParsedProtocolRange,
    ParsedProvisioningRecipientAnnouncement, PostgresAgentProvisioningOwnerBackend,
    PostgresConnectorControlApplication, ProtobufDurableCommandDecoder,
    agent_provisioning_installed_receipt_digest, agent_provisioning_owner_router,
};
use dtx_agent_host::AgentHost;
use dtx_agent_persistence::{
    AgentDefinitionRepository, AgentDeviceRepository, AgentHostRepository,
    AgentInstallationRepository, BindingSetRepository, ConnectorRepository,
    ConversationGrantRepository, CurrentWrite, DefinitionInsert,
};
use dtx_agent_registry::{
    AgentDevice, AgentDeviceCommand, AgentDeviceState, AgentInstallation, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode, InstallationDesiredState, VerifiedAgentDefinition,
};
use dtx_connect_registry::{
    AdapterConformance, AdapterKind, BindingSet, BindingSpec, Connector, RoutingPolicy, TenantRef,
};
use dtx_domain::{
    AgentDeviceId, AgentId, BindingId, BootId, Clock, ConnectorId, ConversationId, DeviceId,
    DeviceSessionId, Ed25519PublicKey, HostCredentialId, HostId, IdGenerator, IdentityId,
    InstallationId, ProvisioningDeliveryId, ProvisioningRecipientKeyId, RequestId, Revision,
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
    UtcMillis, encode_deterministic_cbor,
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
use support::PostgresHarness;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

static TEST_NOW: OnceLock<i64> = OnceLock::new();
const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn production_owner_http_and_control_survive_loss_and_revoke_fail_closed()
-> Result<(), Box<dyn Error>> {
    TEST_NOW.get_or_init(|| {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_millis(),
        )
        .expect("current time fits i64")
    });
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;

    let owner_root = key(10);
    let owner_device_key = key(11);
    let owner_device_id = DeviceId::new();
    let (owner_id, owner_head, _) = provision_identity(
        &harness,
        &owner_root,
        &owner_device_key,
        owner_device_id,
        12,
    )
    .await?;
    let agent_root = key(20);
    let agent_device_key = key(21);
    let identity_device_id = DeviceId::new();
    let (agent_identity_id, agent_head, agent_certificate) = provision_identity(
        &harness,
        &agent_root,
        &agent_device_key,
        identity_device_id,
        22,
    )
    .await?;
    let (owner_credential, authorization) =
        provision_owner_session(&harness, owner_id, owner_device_id, owner_head, [0x71; 32])
            .await?;

    let (host, connector) = provision_host_and_connector(&store, tenant_id, owner_id).await?;
    let installation_id = InstallationId::new();
    let agent_device_id = AgentDeviceId::new();
    let binding_id = BindingId::new();
    let fingerprint = DeviceCredentialFingerprint::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-device-credential-fingerprint.v1\0",
            &agent_certificate.to_deterministic_cbor()?,
        )
        .as_bytes(),
    );
    provision_installation_binding(
        &store,
        tenant_id,
        owner_id,
        installation_id,
        agent_device_id,
        identity_device_id,
        fingerprint,
        binding_id,
        &connector,
    )
    .await?;

    let (issuer, ca_der) = certificate_issuer(now())?;
    let index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let app = Arc::new(application(store.clone(), issuer, index.clone()));
    let enrollment = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            RequestId::new(),
            EnrollmentToken::from_bytes([0x31; 32]),
            None,
        )?)
        .await?;
    let enrollment_request = signed_enrollment_request(&enrollment, &[0x31; 32], 41, 42)?;
    let completion = app
        .enroll(ParsedEnrollment {
            token: EnrollmentToken::from_bytes([0x31; 32]),
            request: enrollment_request,
        })
        .await?;
    app.hydrate_connector_authorization(tenant_id, connector.connector_id())
        .await?;
    let boot_id = BootId::new();
    let opened = app
        .open_control(
            authenticate(index.clone(), &ca_der, &completion.credential)?,
            ParsedHello {
                tenant_id,
                connector_id: connector.connector_id(),
                host_id: host.host_id(),
                boot_id,
                connector_generation: completion.credential.generation(),
                spec_revision: completion.credential.revision(),
                protocol: ParsedProtocolRange {
                    minimum_major: 1,
                    minimum_minor: 3,
                    maximum_major: 1,
                    maximum_minor: 3,
                },
                runtime_claims: claims()?,
                capacity: capacity(),
                last_applied_command_sequence: 0,
                required_server_capabilities: vec!["opaque-agent-provisioning".into()],
            },
        )
        .await?;
    let fence = opened.lease.fence();

    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app.clone()),
    ));
    let approval_id = dtx_domain::ApprovalId::new();
    let approval_body = approval_body(
        approval_id,
        tenant_id,
        installation_id,
        binding_id,
        agent_device_id,
        agent_identity_id,
        identity_device_id,
        agent_head,
        fingerprint,
        owner_id,
        owner_device_id,
        &owner_device_key,
    )?;
    let approval_uri = format!("/v1/agent-installations/{installation_id}/identity-approvals");
    let first = owner_post(
        router.clone(),
        &approval_uri,
        &authorization,
        "approval_response_loss_1",
        "application/vnd.dirextalk.agent-identity-approval.v1+cbor",
        approval_body.clone(),
    )
    .await?;
    assert_eq!(first.0, StatusCode::CREATED);
    let approval_get = owner_get(
        router.clone(),
        &format!("{approval_uri}/{approval_id}"),
        &authorization,
    )
    .await?;
    assert_eq!(approval_get.0, StatusCode::OK);
    let approval_replay = owner_post(
        router.clone(),
        &approval_uri,
        &authorization,
        "approval_response_loss_1",
        "application/vnd.dirextalk.agent-identity-approval.v1+cbor",
        approval_body,
    )
    .await?;
    assert_eq!(approval_replay, approval_get);

    let recipient_key_id = ProvisioningRecipientKeyId::new();
    let recipient_public_key = [0x61; 32];
    let created = now();
    let expires = now() + 300_000;
    let mut announcement = ParsedProvisioningRecipientAnnouncement {
        connector_fence: parsed_fence(fence),
        binding_id,
        installation_id,
        agent_device_id,
        provisioning_revision: 2,
        recipient_key_id: recipient_key_id.to_string().parse()?,
        recipient_public_key,
        credential_id: completion.credential.credential_id(),
        created_at_millis: created,
        expires_at_millis: expires,
        descriptor_digest: ControlDigest::from_bytes([1; 32]),
        recipient_signature: [0; 64],
    };
    announcement.descriptor_digest = recipient_descriptor_digest(&announcement);
    announcement.recipient_signature = key(41)
        .sign(&recipient_signature_input(announcement.descriptor_digest))
        .to_bytes();
    app.announce_provisioning_recipient(
        authenticate(index.clone(), &ca_der, &completion.credential)?,
        announcement.clone(),
    )
    .await?;
    let target = owner_get(
        router.clone(),
        &format!(
            "/v1/agent-installations/{installation_id}/provisioning-target?approval_id={approval_id}&binding_id={binding_id}"
        ),
        &authorization,
    )
    .await?;
    assert_eq!(target.0, StatusCode::OK);
    assert!(
        target
            .1
            .windows(32)
            .any(|bytes| bytes == recipient_public_key)
    );

    let delivery_id = ProvisioningDeliveryId::new();
    let capsule = vec![0x99; 4096];
    let capsule_digest =
        Sha256Digest::hash_domain(b"dirextalk.agent-provisioning-capsule.v1\0", &capsule);
    let delivery_body = delivery_body(
        delivery_id,
        approval_id,
        tenant_id,
        installation_id,
        binding_id,
        agent_device_id,
        agent_identity_id,
        identity_device_id,
        recipient_key_id,
        announcement.descriptor_digest,
        capsule_digest,
        owner_id,
        owner_device_id,
        &owner_device_key,
        capsule.clone(),
    )?;
    let delivery_uri = format!("/v1/agent-installations/{installation_id}/provisioning-deliveries");
    let first_delivery = owner_post(
        router.clone(),
        &delivery_uri,
        &authorization,
        "delivery_response_loss_1",
        "application/vnd.dirextalk.agent-provisioning-delivery.v1+cbor",
        delivery_body.clone(),
    )
    .await?;
    assert_eq!(first_delivery.0, StatusCode::ACCEPTED);
    let replayed_delivery = owner_post(
        router.clone(),
        &delivery_uri,
        &authorization,
        "delivery_response_loss_1",
        "application/vnd.dirextalk.agent-provisioning-delivery.v1+cbor",
        delivery_body,
    )
    .await?;
    assert_eq!(replayed_delivery.0, StatusCode::OK);
    assert_eq!(first_delivery.1, replayed_delivery.1);

    let commands = app
        .poll_commands(
            authenticate(index.clone(), &ca_der, &completion.credential)?,
            fence,
            0,
        )
        .await
        .map_err(|error| format!("poll durable delivery: {error:?}"))?;
    let delivery_command = commands
        .iter()
        .find(|command| {
            matches!(
                command.payload(),
                ServerCommandPayload::DeliverAgentProvisioning(_)
            )
        })
        .expect("durable opaque delivery command");
    let ServerCommandPayload::DeliverAgentProvisioning(payload) = delivery_command.payload() else {
        unreachable!()
    };
    assert_eq!(payload.sealed_capsule(), capsule.as_slice());
    let receipt_digest =
        agent_provisioning_installed_receipt_digest(AgentProvisioningInstalledReceiptFacts {
            tenant_id,
            installation_id,
            binding_id,
            agent_device_id,
            delivery_id,
            recipient_key_id,
            bundle_revision: Revision::new(2)?,
            capsule_digest,
        })?;
    let installed_at = now();
    let result_digest = provisioning_commit(
        b"dirextalk.agent-provisioning-installed.v1",
        &[
            Uuid::from(delivery_id).as_bytes(),
            Uuid::from(recipient_key_id).as_bytes(),
            capsule_digest.as_bytes(),
            receipt_digest.as_bytes(),
            &u64::try_from(installed_at)?.to_be_bytes(),
        ],
    );
    let installed = ParsedAgentProvisioningInstalled {
        connector_fence: parsed_fence(fence),
        delivery_id: delivery_id.to_string().parse()?,
        command_sequence: delivery_command.sequence(),
        command_payload_digest: delivery_command.payload_digest(),
        encoded_command_digest: delivery_command.encoded_command_digest(),
        recipient_key_id: recipient_key_id.to_string().parse()?,
        capsule_digest: ControlDigest::from_bytes(*capsule_digest.as_bytes()),
        installation_receipt_digest: ControlDigest::from_bytes(*receipt_digest.as_bytes()),
        installed_at_millis: installed_at,
        result_digest,
    };
    app.complete_agent_provisioning(
        authenticate(index.clone(), &ca_der, &completion.credential)?,
        installed.clone(),
    )
    .await
    .map_err(|error| format!("first installed ACK: {error:?}"))?;
    app.complete_agent_provisioning(
        authenticate(index.clone(), &ca_der, &completion.credential)?,
        installed,
    )
    .await
    .map_err(|error| format!("replayed installed ACK: {error:?}"))?;
    let terminal = owner_get(
        router.clone(),
        &format!("{delivery_uri}/{delivery_id}"),
        &authorization,
    )
    .await?;
    assert_eq!(terminal.0, StatusCode::OK);
    assert!(
        terminal
            .1
            .windows(32)
            .any(|bytes| bytes == result_digest.as_bytes())
    );

    let revoke_body = revocation_body(
        RequestId::new(),
        tenant_id,
        installation_id,
        Revision::new(2)?,
        owner_id,
        owner_device_id,
        &owner_device_key,
    )?;
    let revoked = owner_post(
        router.clone(),
        &format!("/v1/agent-installations/{installation_id}/revocations"),
        &authorization,
        "revoke_installation_1",
        "application/vnd.dirextalk.agent-provisioning-revocation.v1+cbor",
        revoke_body,
    )
    .await?;
    assert_eq!(revoked.0, StatusCode::OK);

    let revoke_commands = app
        .poll_commands(
            authenticate(index.clone(), &ca_der, &completion.credential)?,
            fence,
            delivery_command.sequence(),
        )
        .await?;
    let revoke_command = revoke_commands
        .iter()
        .find_map(|command| match command.payload() {
            ServerCommandPayload::RevokeAgentProvisioning(payload) => Some(payload),
            _ => None,
        })
        .expect("revoke emits durable exact-binding cleanup");
    assert_eq!(revoke_command.binding_id(), binding_id);
    assert_eq!(revoke_command.installation_id(), installation_id);

    let mut session = store.begin_tenant(tenant_id).await?;
    let installation = AgentInstallationRepository::new()
        .load(session.connection(), tenant_id, installation_id)
        .await?
        .expect("installation remains");
    let device = AgentDeviceRepository::new()
        .load(session.connection(), tenant_id, agent_device_id)
        .await?
        .expect("device remains");
    let bindings = BindingSetRepository::new()
        .load(session.connection(), tenant_id)
        .await?;
    assert!(
        bindings
            .configured_route_order(TenantRef::new(tenant_id, installation_id))?
            .is_empty()
    );
    assert!(
        bindings
            .eligible_route_order(&installation, &[&device])
            .is_err()
    );
    assert_eq!(
        installation.desired_state(),
        InstallationDesiredState::Revoked
    );
    assert_eq!(device.state(), AgentDeviceState::Revoked);
    let stored_capsule: Vec<u8> = sqlx::query_scalar(
        "SELECT sealed_capsule FROM agent.agent_provisioning_deliveries WHERE tenant_id=$1 AND delivery_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(delivery_id))
    .fetch_one(session.connection())
    .await?;
    assert_eq!(stored_capsule, capsule);
    session.rollback().await?;
    let lifecycle_fence = format!(
        "\"g{}-r{}\"",
        fence.generation().get(),
        completion.credential.revision().get()
    );
    let drain_operation = RequestId::new();
    let drain_uri = format!("/v1/connectors/{}/drain", connector.connector_id());
    let first_drain = owner_lifecycle_post(
        router.clone(),
        &drain_uri,
        &authorization,
        drain_operation,
        &lifecycle_fence,
    )
    .await?;
    assert_eq!(first_drain.0, StatusCode::CREATED);
    let drain_receipt: serde_json::Value = serde_json::from_slice(&first_drain.1)?;
    assert_eq!(drain_receipt["action"], "drain");
    assert_eq!(
        drain_receipt["connector_id"],
        connector.connector_id().to_string()
    );
    assert_eq!(drain_receipt["operation_id"], drain_operation.to_string());
    let replayed_drain = owner_lifecycle_post(
        router.clone(),
        &drain_uri,
        &authorization,
        drain_operation,
        &lifecycle_fence,
    )
    .await?;
    assert_eq!(replayed_drain.0, StatusCode::OK);
    assert_eq!(replayed_drain.1, first_drain.1);
    let conflicting_retry = owner_lifecycle_post(
        router.clone(),
        &format!("/v1/connectors/{}/restart", connector.connector_id()),
        &authorization,
        drain_operation,
        &lifecycle_fence,
    )
    .await?;
    assert_eq!(conflicting_retry.0, StatusCode::CONFLICT);
    let stale_fence = owner_lifecycle_post(
        router.clone(),
        &drain_uri,
        &authorization,
        RequestId::new(),
        &format!("\"g{}-r2\"", fence.generation().get()),
    )
    .await?;
    assert_eq!(stale_fence.0, StatusCode::CONFLICT);
    let (_, foreign_authorization) = provision_owner_session(
        &harness,
        agent_identity_id,
        identity_device_id,
        agent_head,
        [0x72; 32],
    )
    .await?;
    let denied = owner_lifecycle_post(
        router.clone(),
        &drain_uri,
        &foreign_authorization,
        RequestId::new(),
        &lifecycle_fence,
    )
    .await?;
    assert_eq!(denied.0, StatusCode::FORBIDDEN);
    let lifecycle_commands = app
        .poll_commands(
            authenticate(index.clone(), &ca_der, &completion.credential)?,
            fence,
            delivery_command.sequence(),
        )
        .await?;
    assert!(lifecycle_commands.iter().any(|command| {
        matches!(
            command.payload(),
            ServerCommandPayload::CloseStream(close)
                if close.reason() == dtx_agent_control::CloseStreamReason::Drained
        )
    }));
    drop(owner_credential);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn private_conversation_owner_grant_http_is_exact_and_revoke_fences_persisted_grant()
-> Result<(), Box<dyn Error>> {
    TEST_NOW.get_or_init(|| {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_millis(),
        )
        .expect("current time fits i64")
    });
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;

    let owner_root = key(80);
    let owner_device_key = key(81);
    let owner_device_id = DeviceId::new();
    let (owner_id, owner_head, _) = provision_identity(
        &harness,
        &owner_root,
        &owner_device_key,
        owner_device_id,
        82,
    )
    .await?;
    let (owner_credential, owner_authorization) =
        provision_owner_session(&harness, owner_id, owner_device_id, owner_head, [0x83; 32])
            .await?;

    let non_owner_root = key(84);
    let non_owner_device_key = key(85);
    let non_owner_device_id = DeviceId::new();
    let (non_owner_id, non_owner_head, non_owner_certificate) = provision_identity(
        &harness,
        &non_owner_root,
        &non_owner_device_key,
        non_owner_device_id,
        86,
    )
    .await?;
    let (non_owner_credential, non_owner_authorization) = provision_owner_session(
        &harness,
        non_owner_id,
        non_owner_device_id,
        non_owner_head,
        [0x87; 32],
    )
    .await?;

    let (_, connector) = provision_host_and_connector(&store, tenant_id, owner_id).await?;
    let installation_id = InstallationId::new();
    let agent_device_id = AgentDeviceId::new();
    let binding_id = BindingId::new();
    let fingerprint = DeviceCredentialFingerprint::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-device-credential-fingerprint.v1\0",
            &non_owner_certificate.to_deterministic_cbor()?,
        )
        .as_bytes(),
    );
    provision_installation_binding(
        &store,
        tenant_id,
        owner_id,
        installation_id,
        agent_device_id,
        non_owner_device_id,
        fingerprint,
        binding_id,
        &connector,
    )
    .await?;
    let conversation_id = ConversationId::new();
    provision_private_conversation_owner(&harness, tenant_id, conversation_id, owner_id).await?;

    let (issuer, _) = certificate_issuer(now())?;
    let app = Arc::new(application(
        store.clone(),
        issuer,
        Arc::new(ConnectorCredentialAuthorizationIndex::new()),
    ));
    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app),
    ));
    let uri = format!("/v1/conversations/{conversation_id}/agent-grants/{installation_id}");
    let grant_operation = RequestId::new();
    let expiring_proof_at = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )? + 3_000;
    let first_grant_body = conversation_grant_body(
        1,
        grant_operation,
        tenant_id,
        conversation_id,
        installation_id,
        None,
        owner_id,
        owner_device_id,
        &owner_device_key,
        Some(now() + 600_000),
        Some([0x91; 32]),
        expiring_proof_at,
    )?;
    let first = owner_conversation_grant_mutation(
        router.clone(),
        Method::PUT,
        &uri,
        &owner_authorization,
        grant_operation,
        "\"g0\"",
        first_grant_body.clone(),
    )
    .await?;
    assert_eq!(first.0, StatusCode::CREATED);

    // The original signed proof is now stale, but a response-loss replay must
    // still return the committed receipt rather than treating the operation as
    // a new, expired approval.
    tokio::time::sleep(Duration::from_millis(3_100)).await;
    let replay = owner_conversation_grant_mutation(
        router.clone(),
        Method::PUT,
        &uri,
        &owner_authorization,
        grant_operation,
        "\"g0\"",
        first_grant_body,
    )
    .await?;
    assert_eq!(replay.0, StatusCode::OK);
    assert_eq!(replay.1, first.1);

    let changed_same_operation_body = conversation_grant_body(
        1,
        grant_operation,
        tenant_id,
        conversation_id,
        installation_id,
        None,
        owner_id,
        owner_device_id,
        &owner_device_key,
        Some(now() + 600_000),
        Some([0x92; 32]),
        now() + 300_000,
    )?;
    let conflicting_retry = owner_conversation_grant_mutation(
        router.clone(),
        Method::PUT,
        &uri,
        &owner_authorization,
        grant_operation,
        "\"g0\"",
        changed_same_operation_body,
    )
    .await?;
    assert_eq!(conflicting_retry.0, StatusCode::CONFLICT);

    let non_owner_operation = RequestId::new();
    let non_owner_attempt = owner_conversation_grant_mutation(
        router.clone(),
        Method::PUT,
        &uri,
        &non_owner_authorization,
        non_owner_operation,
        "\"g1\"",
        conversation_grant_body(
            1,
            non_owner_operation,
            tenant_id,
            conversation_id,
            installation_id,
            Some(Revision::INITIAL),
            non_owner_id,
            non_owner_device_id,
            &non_owner_device_key,
            Some(now() + 600_000),
            Some([0x93; 32]),
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(non_owner_attempt.0, StatusCode::FORBIDDEN);

    let revoke_operation = RequestId::new();
    let revoked = owner_conversation_grant_mutation(
        router.clone(),
        Method::DELETE,
        &uri,
        &owner_authorization,
        revoke_operation,
        "\"g1\"",
        conversation_grant_body(
            2,
            revoke_operation,
            tenant_id,
            conversation_id,
            installation_id,
            Some(Revision::INITIAL),
            owner_id,
            owner_device_id,
            &owner_device_key,
            None,
            None,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(revoked.0, StatusCode::OK);

    let mut session = store.begin_tenant(tenant_id).await?;
    let installation = AgentInstallationRepository::new()
        .load(session.connection(), tenant_id, installation_id)
        .await?
        .expect("target installation persists");
    let grant = ConversationGrantRepository::new()
        .load_for_share(
            session.connection(),
            tenant_id,
            conversation_id,
            installation_id,
        )
        .await?
        .expect("grant persists after owner revoke");
    assert_eq!(grant.grant_version(), Revision::new(2)?);
    assert!(grant.snapshot().revoked_at_ms.is_some());
    assert!(!grant.authorizes_version_for(&installation, now(), Revision::INITIAL));
    session.rollback().await?;

    drop(non_owner_credential);
    drop(owner_credential);
    Ok(())
}

async fn owner_post(
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

async fn owner_lifecycle_post(
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

async fn owner_conversation_grant_mutation(
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

async fn owner_get(
    router: axum::Router,
    uri: &str,
    authorization: &str,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let response = router
        .oneshot(
            Request::get(uri)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        to_bytes(response.into_body(), 1_000_000).await?.to_vec(),
    ))
}

async fn provision_tenant(store: &PgStore, tenant_id: TenantId) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query("INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence) VALUES ($1,0)")
        .bind(Uuid::from(tenant_id))
        .execute(session.connection())
        .await?;
    session.commit().await?;
    Ok(())
}

async fn provision_private_conversation_owner(
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

async fn provision_identity(
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

async fn provision_owner_session(
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

async fn provision_host_and_connector(
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
async fn provision_installation_binding(
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
    assert_eq!(
        AgentDefinitionRepository::new()
            .insert(session.connection(), &definition, now() - 7_000)
            .await?,
        DefinitionInsert::Inserted
    );
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
    let mut bindings = BindingSet::new(tenant_id);
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
    BindingSetRepository::new()
        .save(session.connection(), &bindings, now() - 4_000)
        .await?;
    bindings.enable(binding_ref, Revision::INITIAL, &installation, &device)?;
    BindingSetRepository::new()
        .save(session.connection(), &bindings, now() - 3_999)
        .await?;
    session.commit().await?;
    Ok(())
}

fn application(
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

fn claims() -> Result<RuntimeClaims, Box<dyn Error>> {
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

const fn capacity() -> ParsedCapacity {
    ParsedCapacity {
        maximum_concurrent_runs: 4,
        available_concurrent_runs: 4,
        maximum_queue_depth: 32,
    }
}

fn parsed_fence(fence: dtx_connect_registry::ConnectorFence) -> ParsedLeaseFence {
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
fn conversation_grant_body(
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

#[allow(clippy::too_many_arguments)]
fn approval_body(
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
fn delivery_body(
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

fn revocation_body(
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

fn signed_owner_body(
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

const fn u(value: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(value)
}

#[allow(clippy::needless_pass_by_value)]
fn text(value: impl ToString) -> CanonicalValue {
    CanonicalValue::Text(value.to_string())
}

fn bytes(value: &[u8]) -> CanonicalValue {
    CanonicalValue::Bytes(value.to_vec())
}

fn recipient_descriptor_digest(
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

fn recipient_signature_input(digest: ControlDigest) -> Vec<u8> {
    let mut output = Vec::new();
    push_lp(
        &mut output,
        b"dirextalk.agent-provisioning-recipient-signature.v1",
    );
    push_lp(&mut output, &digest.as_bytes());
    output
}

fn provisioning_commit(domain: &[u8], parts: &[&[u8]]) -> ControlDigest {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    ControlDigest::from_bytes(hasher.finalize().into())
}

fn push_lp(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}

fn wire_signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
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

fn device_certificate(
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

fn signed_event(
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

fn signed_event_at(
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

fn identity_command(
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

fn committed(outcome: IdentityAppendOutcome) -> Result<IdentityLogHead, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt.head()),
        _ => Err("expected new identity append".into()),
    }
}

fn signed_enrollment_request(
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

fn certificate_issuer(
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

fn authenticate(
    index: Arc<ConnectorCredentialAuthorizationIndex>,
    ca_der: &[u8],
    credential: &dtx_agent_control::ConnectorCredential,
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
        UnixTime::since_unix_epoch(Duration::from_millis(u64::try_from(now())?)),
    )?)
}

fn offset_time(millis: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
}

fn now() -> i64 {
    *TEST_NOW.get().expect("test clock initialized")
}
