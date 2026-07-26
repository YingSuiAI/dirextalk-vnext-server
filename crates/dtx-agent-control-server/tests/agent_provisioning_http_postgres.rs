#[path = "support/mod.rs"]
mod support;

use support::agent_provisioning::*;

use std::{
    error::Error,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_agent_control::{
    CredentialRotationTranscript, EnrollmentRequest, EnrollmentToken, EnrollmentTranscript,
    RuntimeClaims, ServerCommandPayload, Sha256Digest as ControlDigest,
};
use dtx_agent_control_proto::v1;
use dtx_agent_control_server::{
    AgentProvisioningInstalledReceiptFacts, ConnectorCertificateAuthority, ConnectorCommandFence,
    ConnectorControlApplication, ConnectorControlApplicationError, ConnectorControlPolicy,
    ConnectorCredentialAuthorizationIndex, CreateConnectorEnrollmentRequest,
    MAX_CONNECTOR_PROJECTION_BINDINGS, ParsedAgentProvisioningInstalled,
    ParsedAgentRouteBootstrapInstalled, ParsedAgentRouteBootstrapRejected,
    ParsedAgentRouteRecipientReady, ParsedCapacity, ParsedCommandAcknowledgement, ParsedEnrollment,
    ParsedHello, ParsedLeaseFence, ParsedProtocolRange, ParsedProvisioningRecipientAnnouncement,
    PostgresAgentProvisioningOwnerBackend, PostgresConnectorControlApplication,
    ProtobufDurableCommandDecoder, RotateConnectorCredentialRequest,
    agent_provisioning_installed_receipt_digest, agent_provisioning_owner_router,
    build_lease_fence, parse_credential_rotation_proof,
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
use support::PostgresHarness;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn production_owner_http_and_control_survive_loss_and_revoke_fail_closed()
-> Result<(), Box<dyn Error>> {
    init_test_clock();
    let harness = PostgresHarness::start().await?;
    grant_agent_route_run_runtime_access(&harness).await?;
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
    provision_private_conversation_owner(&harness, tenant_id, ConversationId::new(), owner_id)
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
                    minimum_minor: 6,
                    maximum_major: 1,
                    maximum_minor: 6,
                },
                runtime_claims: claims()?,
                capacity: capacity(),
                last_applied_command_sequence: 0,
                required_server_capabilities: vec![
                    "agent-route-health.v1".into(),
                    "opaque-agent-provisioning".into(),
                ],
            },
        )
        .await?;
    let fence = opened.lease.fence();

    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app.clone()),
    ));
    let v1_connectors =
        owner_get_with_accept(router.clone(), "/v1/connectors", &authorization, None).await?;
    assert_eq!(v1_connectors.0, StatusCode::OK);
    assert_eq!(
        v1_connectors.1.as_deref(),
        Some("application/vnd.dirextalk.connector-projection-page.v1+json")
    );
    let v1_connectors_json: serde_json::Value = serde_json::from_slice(&v1_connectors.2)?;
    assert_eq!(v1_connectors_json["schema_version"], 1);
    assert!(v1_connectors_json.get("tenant_id").is_none());

    let v2_connectors = owner_get_with_accept(
        router.clone(),
        "/v1/connectors",
        &authorization,
        Some("application/vnd.dirextalk.connector-projection-page.v2+json"),
    )
    .await?;
    assert_eq!(v2_connectors.0, StatusCode::OK);
    assert_eq!(
        v2_connectors.1.as_deref(),
        Some("application/vnd.dirextalk.connector-projection-page.v2+json")
    );
    let v2_connectors_json: serde_json::Value = serde_json::from_slice(&v2_connectors.2)?;
    assert_eq!(v2_connectors_json["schema_version"], 2);
    assert_eq!(v2_connectors_json["tenant_id"], tenant_id.to_string());
    assert_eq!(v2_connectors_json["items"], v1_connectors_json["items"]);
    assert_eq!(
        v2_connectors_json["next_cursor"],
        v1_connectors_json["next_cursor"]
    );

    let unauthenticated_v2 = owner_get_with_accept(
        router.clone(),
        "/v1/connectors",
        "",
        Some("application/vnd.dirextalk.connector-projection-page.v2+json"),
    )
    .await?;
    assert_eq!(unauthenticated_v2.0, StatusCode::UNAUTHORIZED);
    let unauthenticated_v2_json: serde_json::Value = serde_json::from_slice(&unauthenticated_v2.2)?;
    assert!(unauthenticated_v2_json.get("tenant_id").is_none());

    let unsupported_accept = owner_get_with_accept(
        router.clone(),
        "/v1/connectors",
        &authorization,
        Some("application/json"),
    )
    .await?;
    assert_eq!(unsupported_accept.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unsupported_accept.1.as_deref(), Some("application/json"));
    let unsupported_accept_json: serde_json::Value = serde_json::from_slice(&unsupported_accept.2)?;
    assert_eq!(unsupported_accept_json["error"]["code"], "request_invalid");
    assert!(unsupported_accept_json.get("tenant_id").is_none());

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
async fn owner_connector_projection_v3_shows_owner_visible_binding_state_and_remains_bounded()
-> Result<(), Box<dyn Error>> {
    init_test_clock();
    let harness = PostgresHarness::start().await?;
    grant_agent_route_run_runtime_access(&harness).await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;

    let owner_device_id = DeviceId::new();
    let (owner_id, owner_head, _) =
        provision_identity(&harness, &key(31), &key(32), owner_device_id, 33).await?;
    let (_owner_credential, authorization) =
        provision_owner_session(&harness, owner_id, owner_device_id, owner_head, [0x34; 32])
            .await?;
    let identity_device_id = DeviceId::new();
    let (_, _, agent_certificate) =
        provision_identity(&harness, &key(35), &key(36), identity_device_id, 37).await?;
    let (host, connector) = provision_host_and_connector(&store, tenant_id, owner_id).await?;
    let hermes_connector_id =
        ConnectorId::try_from(Uuid::parse_str("01890f47-5fd4-7cc2-8f8f-5f9476f4f001")?)?;
    let hermes_connector =
        Connector::register(&host, hermes_connector_id, AdapterKind::HermesAcp, 1)?;
    let mut session = store.begin_tenant(tenant_id).await?;
    ConnectorRepository::new()
        .save(session.connection(), &hermes_connector, None, now() - 7_997)
        .await?;
    session.commit().await?;

    let enabled_binding_id = BindingId::new();
    provision_installation_binding(
        &store,
        tenant_id,
        owner_id,
        InstallationId::new(),
        AgentDeviceId::new(),
        identity_device_id,
        fingerprint_for_binding(&agent_certificate, 1)?,
        enabled_binding_id,
        &connector,
    )
    .await?;
    let disabled_binding_id = BindingId::new();
    provision_installation_binding(
        &store,
        tenant_id,
        owner_id,
        InstallationId::new(),
        AgentDeviceId::new(),
        DeviceId::new(),
        fingerprint_for_binding(&agent_certificate, 2)?,
        disabled_binding_id,
        &connector,
    )
    .await?;
    set_binding_state(&store, tenant_id, disabled_binding_id, false).await?;
    let revoked_binding_id = BindingId::new();
    provision_installation_binding(
        &store,
        tenant_id,
        owner_id,
        InstallationId::new(),
        AgentDeviceId::new(),
        DeviceId::new(),
        fingerprint_for_binding(&agent_certificate, 3)?,
        revoked_binding_id,
        &connector,
    )
    .await?;
    set_binding_state(&store, tenant_id, revoked_binding_id, true).await?;

    let (issuer, _) = certificate_issuer(now())?;
    let app = Arc::new(application(
        store.clone(),
        issuer,
        Arc::new(ConnectorCredentialAuthorizationIndex::new()),
    ));
    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app),
    ));

    let v1 = owner_get_with_accept(
        router.clone(),
        &format!("/v1/connectors?after={hermes_connector_id}&limit=1"),
        &authorization,
        None,
    )
    .await?;
    assert_eq!(v1.0, StatusCode::OK);
    let v1_json: serde_json::Value = serde_json::from_slice(&v1.2)?;
    assert_eq!(v1_json["schema_version"], 1);
    assert_eq!(
        v1_json["items"][0]["connector_id"],
        connector.connector_id().to_string()
    );
    assert_eq!(v1_json["next_cursor"], serde_json::Value::Null);

    let v2 = owner_get_with_accept(
        router.clone(),
        "/v1/connectors?limit=1",
        &authorization,
        Some("application/vnd.dirextalk.connector-projection-page.v2+json"),
    )
    .await?;
    assert_eq!(v2.0, StatusCode::OK);
    let v2_json: serde_json::Value = serde_json::from_slice(&v2.2)?;
    assert_eq!(v2_json["schema_version"], 2);
    assert_eq!(
        v2_json["items"][0]["connector_id"],
        connector.connector_id().to_string()
    );
    assert_eq!(v2_json["next_cursor"], serde_json::Value::Null);
    assert!(
        v2_json["items"]
            .as_array()
            .expect("V2 items")
            .iter()
            .all(|item| item["adapter_kind"] != "hermes_acp")
    );
    let v2_bindings = v2_json["items"][0]["bindings"]
        .as_array()
        .expect("V2 binding list");
    assert_eq!(v2_bindings.len(), 1, "V2 remains enabled-only");
    assert_eq!(v2_bindings[0]["binding_id"], enabled_binding_id.to_string());
    assert!(v2_bindings[0].get("binding_state").is_none());

    let v3_media_type = "application/vnd.dirextalk.connector-projection-page.v3+json";
    let v3 = owner_get_with_accept(
        router.clone(),
        "/v1/connectors?limit=1",
        &authorization,
        Some(v3_media_type),
    )
    .await?;
    assert_eq!(v3.0, StatusCode::OK);
    assert_eq!(v3.1.as_deref(), Some(v3_media_type));
    let v3_json: serde_json::Value = serde_json::from_slice(&v3.2)?;
    assert_eq!(v3_json["schema_version"], 3);
    assert_eq!(v3_json["tenant_id"], tenant_id.to_string());
    assert_eq!(
        v3_json["items"][0]["connector_id"],
        connector.connector_id().to_string(),
        "legacy filtering must happen before ORDER/LIMIT so Hermes cannot starve V3 pages",
    );
    assert_eq!(v3_json["next_cursor"], serde_json::Value::Null);
    let v3_bindings = v3_json["items"][0]["bindings"]
        .as_array()
        .expect("V3 binding list");
    assert_eq!(v3_bindings.len(), 2);
    assert!(v3_bindings.iter().any(|binding| {
        binding["binding_id"] == enabled_binding_id.to_string()
            && binding["binding_state"] == "enabled"
    }));
    assert!(v3_bindings.iter().any(|binding| {
        binding["binding_id"] == disabled_binding_id.to_string()
            && binding["binding_state"] == "disabled"
    }));
    assert!(
        v3_bindings
            .iter()
            .all(|binding| binding["binding_id"] != revoked_binding_id.to_string())
    );
    assert!(v3_bindings.iter().all(|binding| {
        binding.get("agent_device_id").is_none()
            && binding.get("route_id").is_none()
            && binding.get("credential").is_none()
            && binding.get("secret").is_none()
            && binding.get("endpoint").is_none()
            && binding.get("session").is_none()
    }));
    assert!(
        !v3_json["items"][0]["bindings_truncated"]
            .as_bool()
            .expect("V3 truncation flag")
    );

    let v4_media_type = "application/vnd.dirextalk.connector-projection-page.v4+json";
    let v4 = owner_get_with_accept(
        router.clone(),
        "/v1/connectors",
        &authorization,
        Some(v4_media_type),
    )
    .await?;
    assert_eq!(v4.0, StatusCode::OK);
    assert_eq!(v4.1.as_deref(), Some(v4_media_type));
    let v4_json: serde_json::Value = serde_json::from_slice(&v4.2)?;
    assert_eq!(v4_json["schema_version"], 4);
    assert_eq!(v4_json["tenant_id"], tenant_id.to_string());
    assert!(
        v4_json["items"]
            .as_array()
            .expect("V4 items")
            .iter()
            .any(
                |item| item["connector_id"] == hermes_connector_id.to_string()
                    && item["adapter_kind"] == "hermes_acp"
            )
    );

    let foreign_device_id = DeviceId::new();
    let (foreign_owner, foreign_head, _) =
        provision_identity(&harness, &key(38), &key(39), foreign_device_id, 40).await?;
    let (_foreign_credential, foreign_authorization) = provision_owner_session(
        &harness,
        foreign_owner,
        foreign_device_id,
        foreign_head,
        [0x41; 32],
    )
    .await?;
    let non_owner = owner_get_with_accept(
        router.clone(),
        "/v1/connectors",
        &foreign_authorization,
        Some(v3_media_type),
    )
    .await?;
    assert_eq!(non_owner.0, StatusCode::OK);
    let non_owner_json: serde_json::Value = serde_json::from_slice(&non_owner.2)?;
    assert_eq!(non_owner_json["items"], serde_json::json!([]));
    let unknown_accept = owner_get_with_accept(
        router.clone(),
        "/v1/connectors",
        &authorization,
        Some("application/vnd.dirextalk.connector-projection-page.v99+json"),
    )
    .await?;
    assert_eq!(unknown_accept.0, StatusCode::UNPROCESSABLE_ENTITY);

    for marker in 4..=(MAX_CONNECTOR_PROJECTION_BINDINGS + 2) {
        let binding_id = BindingId::new();
        provision_installation_binding(
            &store,
            tenant_id,
            owner_id,
            InstallationId::new(),
            AgentDeviceId::new(),
            DeviceId::new(),
            fingerprint_for_binding(
                &agent_certificate,
                u8::try_from(marker).expect("projection fixture marker fits u8"),
            )?,
            binding_id,
            &connector,
        )
        .await?;
        set_binding_state(&store, tenant_id, binding_id, false).await?;
    }
    let bounded_v3 = owner_get_with_accept(
        router.clone(),
        "/v1/connectors",
        &authorization,
        Some(v3_media_type),
    )
    .await?;
    assert_eq!(bounded_v3.0, StatusCode::OK);
    let bounded_v3_json: serde_json::Value = serde_json::from_slice(&bounded_v3.2)?;
    assert_eq!(
        bounded_v3_json["items"][0]["bindings"]
            .as_array()
            .expect("bounded V3 bindings")
            .len(),
        MAX_CONNECTOR_PROJECTION_BINDINGS
    );
    assert!(
        bounded_v3_json["items"][0]["bindings_truncated"]
            .as_bool()
            .expect("bounded V3 truncation flag")
    );
    let bounded_v2 = owner_get_with_accept(
        router,
        "/v1/connectors",
        &authorization,
        Some("application/vnd.dirextalk.connector-projection-page.v2+json"),
    )
    .await?;
    assert_eq!(bounded_v2.0, StatusCode::OK);
    let bounded_v2_json: serde_json::Value = serde_json::from_slice(&bounded_v2.2)?;
    assert_eq!(
        bounded_v2_json["items"][0]["bindings"]
            .as_array()
            .expect("bounded V2 bindings")
            .len(),
        1,
        "V2 must remain enabled-only after V3 adds disabled bindings"
    );
    assert!(
        !bounded_v2_json["items"][0]["bindings_truncated"]
            .as_bool()
            .expect("bounded V2 truncation flag")
    );
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn owner_connector_binding_state_http_is_exact_authorized_and_fenced()
-> Result<(), Box<dyn Error>> {
    init_test_clock();
    let harness = PostgresHarness::start().await?;
    grant_agent_route_run_runtime_access(&harness).await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;

    let owner_root = key(65);
    let owner_device_key = key(66);
    let owner_device_id = DeviceId::new();
    let (owner_id, owner_head, _) = provision_identity(
        &harness,
        &owner_root,
        &owner_device_key,
        owner_device_id,
        67,
    )
    .await?;
    let (owner_credential, owner_authorization) =
        provision_owner_session(&harness, owner_id, owner_device_id, owner_head, [0x68; 32])
            .await?;

    let foreign_root = key(69);
    let foreign_device_key = key(70);
    let foreign_device_id = DeviceId::new();
    let (foreign_id, foreign_head, foreign_certificate) = provision_identity(
        &harness,
        &foreign_root,
        &foreign_device_key,
        foreign_device_id,
        71,
    )
    .await?;
    let (foreign_credential, foreign_authorization) = provision_owner_session(
        &harness,
        foreign_id,
        foreign_device_id,
        foreign_head,
        [0x72; 32],
    )
    .await?;

    let (_, connector) = provision_host_and_connector(&store, tenant_id, owner_id).await?;
    let installation_id = InstallationId::new();
    let agent_device_id = AgentDeviceId::new();
    let binding_id = BindingId::new();
    let fingerprint = fingerprint_for_binding(&foreign_certificate, 73)?;
    provision_installation_binding(
        &store,
        tenant_id,
        owner_id,
        installation_id,
        agent_device_id,
        foreign_device_id,
        fingerprint,
        binding_id,
        &connector,
    )
    .await?;

    let (issuer, _) = certificate_issuer(now())?;
    let app = Arc::new(application(
        store.clone(),
        issuer,
        Arc::new(ConnectorCredentialAuthorizationIndex::new()),
    ));
    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app),
    ));
    let disable_uri = format!("/v1/connector-bindings/{binding_id}/disable");
    let enable_uri = format!("/v1/connector-bindings/{binding_id}/enable");

    let disable_operation = RequestId::new();
    let disable_body = connector_binding_state_body(
        2,
        disable_operation,
        tenant_id,
        binding_id,
        Revision::new(2)?,
        owner_id,
        owner_device_id,
        &owner_device_key,
        now() + 300_000,
    )?;
    // The signed command is not a bearer for a different URL, operation, or
    // revision fence.  Every mismatch is rejected before the durable Owner
    // backend can append an operation or transition the Binding.
    let wrong_path = owner_connector_binding_state_mutation(
        router.clone(),
        &format!("/v1/connector-bindings/{}/disable", BindingId::new()),
        &owner_authorization,
        disable_operation,
        "\"b2\"",
        disable_body.clone(),
    )
    .await?;
    assert_eq!(wrong_path.0, StatusCode::UNPROCESSABLE_ENTITY);
    let wrong_operation = owner_connector_binding_state_mutation(
        router.clone(),
        &disable_uri,
        &owner_authorization,
        RequestId::new(),
        "\"b2\"",
        disable_body.clone(),
    )
    .await?;
    assert_eq!(wrong_operation.0, StatusCode::UNPROCESSABLE_ENTITY);
    let wrong_fence = owner_connector_binding_state_mutation(
        router.clone(),
        &disable_uri,
        &owner_authorization,
        disable_operation,
        "\"b3\"",
        disable_body.clone(),
    )
    .await?;
    assert_eq!(wrong_fence.0, StatusCode::UNPROCESSABLE_ENTITY);
    let mut rejected_session = store.begin_tenant(tenant_id).await?;
    let initial_bindings = BindingSetRepository::new()
        .load(rejected_session.connection(), tenant_id)
        .await?;
    let initial_binding = initial_bindings.binding(TenantRef::new(tenant_id, binding_id))?;
    assert_eq!(initial_binding.state(), BindingState::Enabled);
    assert_eq!(initial_binding.revision(), Revision::new(2)?);
    let rejected_operation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.connector_binding_state_owner_operations
          WHERE tenant_id=$1",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_one(rejected_session.connection())
    .await?;
    assert_eq!(rejected_operation_count, 0);
    rejected_session.rollback().await?;

    let disabled = owner_connector_binding_state_mutation(
        router.clone(),
        &disable_uri,
        &owner_authorization,
        disable_operation,
        "\"b2\"",
        disable_body.clone(),
    )
    .await?;
    assert_eq!(disabled.0, StatusCode::CREATED);
    assert_eq!(
        disabled.1.as_deref(),
        Some("application/vnd.dirextalk.connector-binding-state-receipt.v1+cbor")
    );
    assert_eq!(disabled.2.as_deref(), Some("no-store"));
    let CanonicalValue::Map(disabled_receipt) = decode_deterministic_cbor(&disabled.3)? else {
        panic!("Binding-state receipt must be a canonical map");
    };
    assert_eq!(disabled_receipt.len(), 10);
    for (index, (key, _)) in disabled_receipt.iter().enumerate() {
        assert_eq!(*key, u(u64::try_from(index + 1)?));
    }
    assert_eq!(disabled_receipt[0].1, u(1));
    assert_eq!(disabled_receipt[1].1, u(2));
    assert_eq!(disabled_receipt[2].1, text(tenant_id));
    assert_eq!(disabled_receipt[3].1, text(binding_id));
    assert_eq!(disabled_receipt[4].1, u(2));
    assert_eq!(disabled_receipt[5].1, u(3));
    assert_eq!(disabled_receipt[6].1, text(owner_device_id));
    assert_eq!(disabled_receipt[8].1, text(disable_operation));
    assert_eq!(
        disabled_receipt[9].1,
        CanonicalValue::Bytes(
            Sha256Digest::hash_domain(
                b"dirextalk.connector-binding-state-command-request.v1\0",
                &disable_body,
            )
            .as_bytes()
            .to_vec(),
        )
    );

    let replay = owner_connector_binding_state_mutation(
        router.clone(),
        &disable_uri,
        &owner_authorization,
        disable_operation,
        "\"b2\"",
        disable_body,
    )
    .await?;
    assert_eq!(replay.0, StatusCode::OK);
    assert_eq!(replay.3, disabled.3);

    // A new same-target operation is a domain-level no-op: it still receives
    // a durable receipt, but the Binding revision remains at the supplied
    // expected fence instead of incrementing again.
    let same_target_operation = RequestId::new();
    let same_target = owner_connector_binding_state_mutation(
        router.clone(),
        &disable_uri,
        &owner_authorization,
        same_target_operation,
        "\"b3\"",
        connector_binding_state_body(
            2,
            same_target_operation,
            tenant_id,
            binding_id,
            Revision::new(3)?,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(same_target.0, StatusCode::CREATED);
    let CanonicalValue::Map(same_target_receipt) = decode_deterministic_cbor(&same_target.3)?
    else {
        panic!("same-target Binding-state receipt must be a canonical map");
    };
    assert_eq!(same_target_receipt[4].1, u(2));
    assert_eq!(same_target_receipt[5].1, u(3));

    let stale_operation = RequestId::new();
    let stale = owner_connector_binding_state_mutation(
        router.clone(),
        &enable_uri,
        &owner_authorization,
        stale_operation,
        "\"b2\"",
        connector_binding_state_body(
            1,
            stale_operation,
            tenant_id,
            binding_id,
            Revision::new(2)?,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(stale.0, StatusCode::CONFLICT);

    let reused_operation = owner_connector_binding_state_mutation(
        router.clone(),
        &enable_uri,
        &owner_authorization,
        disable_operation,
        "\"b3\"",
        connector_binding_state_body(
            1,
            disable_operation,
            tenant_id,
            binding_id,
            Revision::new(3)?,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(reused_operation.0, StatusCode::CONFLICT);

    let foreign_operation = RequestId::new();
    let foreign = owner_connector_binding_state_mutation(
        router.clone(),
        &enable_uri,
        &foreign_authorization,
        foreign_operation,
        "\"b3\"",
        connector_binding_state_body(
            1,
            foreign_operation,
            tenant_id,
            binding_id,
            Revision::new(3)?,
            foreign_id,
            foreign_device_id,
            &foreign_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(foreign.0, StatusCode::FORBIDDEN);

    let enable_operation = RequestId::new();
    let enabled = owner_connector_binding_state_mutation(
        router.clone(),
        &enable_uri,
        &owner_authorization,
        enable_operation,
        "\"b3\"",
        connector_binding_state_body(
            1,
            enable_operation,
            tenant_id,
            binding_id,
            Revision::new(3)?,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(enabled.0, StatusCode::CREATED);
    let CanonicalValue::Map(enabled_receipt) = decode_deterministic_cbor(&enabled.3)? else {
        panic!("Binding-state receipt must be a canonical map");
    };
    assert_eq!(enabled_receipt[1].1, u(1));
    assert_eq!(enabled_receipt[4].1, u(1));
    assert_eq!(enabled_receipt[5].1, u(4));

    let mut session = store.begin_tenant(tenant_id).await?;
    let binding_ref = TenantRef::new(tenant_id, binding_id);
    let bindings = BindingSetRepository::new()
        .load(session.connection(), tenant_id)
        .await?;
    assert_eq!(
        bindings.binding(binding_ref)?.state(),
        BindingState::Enabled
    );
    assert_eq!(bindings.binding(binding_ref)?.revision(), Revision::new(4)?);
    let operation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.connector_binding_state_owner_operations
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(disable_operation))
    .fetch_one(session.connection())
    .await?;
    assert_eq!(operation_count, 1);
    session.rollback().await?;

    set_binding_state(&store, tenant_id, binding_id, true).await?;
    let revoked_enable_operation = RequestId::new();
    let revoked_enable = owner_connector_binding_state_mutation(
        router,
        &enable_uri,
        &owner_authorization,
        revoked_enable_operation,
        "\"b6\"",
        connector_binding_state_body(
            1,
            revoked_enable_operation,
            tenant_id,
            binding_id,
            Revision::new(6)?,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(revoked_enable.0, StatusCode::CONFLICT);

    drop(foreign_credential);
    drop(owner_credential);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn private_conversation_owner_grant_http_is_exact_and_revoke_fences_persisted_grant()
-> Result<(), Box<dyn Error>> {
    init_test_clock();
    let harness = PostgresHarness::start().await?;
    grant_agent_route_run_runtime_access(&harness).await?;
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
    let inactive_installation_id = InstallationId::new();
    let inactive_agent_device_id = AgentDeviceId::new();
    let inactive_binding_id = BindingId::new();
    provision_installation_binding(
        &store,
        tenant_id,
        owner_id,
        inactive_installation_id,
        inactive_agent_device_id,
        DeviceId::new(),
        fingerprint_for_binding(&non_owner_certificate, 94)?,
        inactive_binding_id,
        &connector,
    )
    .await?;
    revoke_agent_device(
        &store,
        tenant_id,
        inactive_installation_id,
        inactive_agent_device_id,
    )
    .await?;
    let mut inactive_fixture_session = store.begin_tenant(tenant_id).await?;
    let inactive_bindings = BindingSetRepository::new()
        .load(inactive_fixture_session.connection(), tenant_id)
        .await?;
    assert_eq!(
        inactive_bindings
            .binding(TenantRef::new(tenant_id, inactive_binding_id))?
            .state(),
        BindingState::Enabled
    );
    assert_eq!(
        AgentDeviceRepository::new()
            .load(
                inactive_fixture_session.connection(),
                tenant_id,
                inactive_agent_device_id,
            )
            .await?
            .expect("inactive Agent Device fixture must exist")
            .state(),
        AgentDeviceState::Revoked
    );
    inactive_fixture_session.rollback().await?;
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
        Some(private_conversation_profile_v1_digest()),
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

    // The AgentRoute is deliberately different from the source conversation.
    // It is the only conversation ID copied into the durable Router Run, while
    // the source remains in the owner/grant operation audit record.
    let route_id = ConversationId::new();
    let route_operation = RequestId::new();
    let route_event_id = EventId::try_from(*route_operation.as_uuid())?;
    let route_fence = [0x95; 32];
    let route_uri = format!("/v1/conversations/{conversation_id}/agent-routes/{route_id}/runs");
    let route_proof_expires_at = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )? + 3_000;
    let route_body = agent_route_run_body(
        tenant_id,
        conversation_id,
        route_id,
        installation_id,
        binding_id,
        agent_device_id,
        route_fence,
        route_event_id,
        route_operation,
        Revision::INITIAL,
        owner_id,
        owner_device_id,
        &owner_device_key,
        route_proof_expires_at,
    )?;
    // A Run cannot infer route availability from prior Runs or the enabled
    // binding.  Before an exact Installed RouteBootstrap head exists, it is
    // fail-closed even though the Owner grant is active.
    let no_head = owner_agent_route_run(
        router.clone(),
        &route_uri,
        &owner_authorization,
        route_operation,
        "\"g1\"",
        route_body.clone(),
    )
    .await?;
    assert_eq!(no_head.0, StatusCode::CONFLICT);
    install_agent_route_binding_head(
        &store,
        tenant_id,
        owner_id,
        owner_device_id,
        installation_id,
        binding_id,
        agent_device_id,
        &connector,
        route_id,
        route_fence,
    )
    .await?;
    let wrong_fence = owner_agent_route_run(
        router.clone(),
        &route_uri,
        &owner_authorization,
        route_operation,
        "\"g1\"",
        agent_route_run_body(
            tenant_id,
            conversation_id,
            route_id,
            installation_id,
            binding_id,
            agent_device_id,
            [0x96; 32],
            route_event_id,
            route_operation,
            Revision::INITIAL,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(wrong_fence.0, StatusCode::CONFLICT);
    let insufficient_tool_authority = owner_agent_route_run(
        router.clone(),
        &route_uri,
        &owner_authorization,
        route_operation,
        "\"g1\"",
        route_body.clone(),
    )
    .await?;
    assert_eq!(
        insufficient_tool_authority.0,
        StatusCode::FORBIDDEN,
        "an AgentRoute Run that can reach Connector tools must require InvokeTools"
    );
    let mut denied_session = store.begin_tenant(tenant_id).await?;
    let denied_run_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_runs
          WHERE tenant_id=$1 AND request_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(route_operation))
    .fetch_one(denied_session.connection())
    .await?;
    let denied_operation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_route_run_operations
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(route_operation))
    .fetch_one(denied_session.connection())
    .await?;
    assert_eq!((denied_run_count, denied_operation_count), (0, 0));

    let installation = AgentInstallationRepository::new()
        .load(denied_session.connection(), tenant_id, installation_id)
        .await?
        .expect("target installation persists");
    let grants = ConversationGrantRepository::new();
    let mut tool_grant = grants
        .load_for_share(
            denied_session.connection(),
            tenant_id,
            conversation_id,
            installation_id,
        )
        .await?
        .expect("chat grant persists");
    let prior = tool_grant.snapshot();
    tokio::time::sleep(Duration::from_millis(2)).await;
    let approved_at = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )?;
    tool_grant.apply(
        &installation,
        Revision::INITIAL,
        ConversationGrantCommand::Update {
            update: ConversationGrantUpdate::new(
                prior
                    .permissions
                    .with(AgentConversationPermission::InvokeTools),
                prior.trigger_policy,
                prior.privacy_policy_hash,
                owner_device_id,
                approved_at,
                Some(approved_at + 600_000),
            ),
            permission_expansion: Some(PermissionExpansionConfirmation::confirmed()),
            all_messages: None,
        },
    )?;
    assert_eq!(
        grants
            .save(denied_session.connection(), &tool_grant, approved_at)
            .await?,
        CurrentWrite::Advanced
    );
    denied_session.commit().await?;

    let tool_route_proof_expires_at = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )? + 3_000;
    let route_body = agent_route_run_body(
        tenant_id,
        conversation_id,
        route_id,
        installation_id,
        binding_id,
        agent_device_id,
        route_fence,
        route_event_id,
        route_operation,
        Revision::new(2)?,
        owner_id,
        owner_device_id,
        &owner_device_key,
        tool_route_proof_expires_at,
    )?;
    let route_first = owner_agent_route_run(
        router.clone(),
        &route_uri,
        &owner_authorization,
        route_operation,
        "\"g2\"",
        route_body.clone(),
    )
    .await?;
    assert_eq!(
        route_first.0,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&route_first.1)
    );
    let route_receipt = decode_deterministic_cbor(&route_first.1)?;
    let CanonicalValue::Map(route_receipt) = route_receipt else {
        panic!("AgentRoute receipt must be a canonical map");
    };
    assert_eq!(route_receipt[2].1, text(conversation_id));
    assert_eq!(route_receipt[3].1, text(route_id));
    assert_eq!(route_receipt[6].1, text(route_operation));

    // Replay still succeeds after the proof has expired, but a changed exact
    // body with the same operation never creates another Run.
    tokio::time::sleep(Duration::from_millis(3_100)).await;
    let route_replay = owner_agent_route_run(
        router.clone(),
        &route_uri,
        &owner_authorization,
        route_operation,
        "\"g2\"",
        route_body,
    )
    .await?;
    assert_eq!(route_replay.0, StatusCode::OK);
    assert_eq!(route_replay.1, route_first.1);
    let route_conflict = owner_agent_route_run(
        router.clone(),
        &route_uri,
        &owner_authorization,
        route_operation,
        "\"g2\"",
        agent_route_run_body(
            tenant_id,
            conversation_id,
            route_id,
            installation_id,
            binding_id,
            agent_device_id,
            route_fence,
            route_event_id,
            route_operation,
            Revision::new(2)?,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(route_conflict.0, StatusCode::CONFLICT);
    let mut route_session = store.begin_tenant(tenant_id).await?;
    let (route_run_conversation, route_run_capabilities): (Uuid, Vec<String>) = sqlx::query_as(
        "SELECT conversation_id, required_capability_codes
           FROM agent.agent_runs
          WHERE tenant_id=$1 AND request_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(route_operation))
    .fetch_one(route_session.connection())
    .await?;
    assert_eq!(route_run_conversation, Uuid::from(route_id));
    assert_eq!(
        route_run_capabilities,
        ["chat.streaming".to_owned(), "tool.invoke".to_owned()]
    );
    let operation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_route_run_operations
          WHERE tenant_id=$1 AND operation_id=$2
            AND source_conversation_id=$3 AND route_id=$4",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(route_operation))
    .bind(Uuid::from(conversation_id))
    .bind(Uuid::from(route_id))
    .fetch_one(route_session.connection())
    .await?;
    assert_eq!(operation_count, 1);
    route_session.rollback().await?;

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
        "\"g2\"",
        conversation_grant_body(
            2,
            revoke_operation,
            tenant_id,
            conversation_id,
            installation_id,
            Some(Revision::new(2)?),
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
    assert_eq!(grant.grant_version(), Revision::new(3)?);
    assert!(grant.snapshot().revoked_at_ms.is_some());
    assert!(!grant.authorizes_version_for(&installation, now(), Revision::INITIAL));
    session.rollback().await?;

    // Regrant is fail-closed once the installation no longer has an enabled
    // Binding backed by an active Agent Device.  Without this gate the same
    // valid owner signature and grant fence would restore the grant.
    set_binding_state(&store, tenant_id, binding_id, false).await?;
    let no_active_binding_operation = RequestId::new();
    let no_active_binding = owner_conversation_grant_mutation(
        router.clone(),
        Method::PUT,
        &uri,
        &owner_authorization,
        no_active_binding_operation,
        "\"g3\"",
        conversation_grant_body(
            1,
            no_active_binding_operation,
            tenant_id,
            conversation_id,
            installation_id,
            Some(Revision::new(3)?),
            owner_id,
            owner_device_id,
            &owner_device_key,
            Some(now() + 600_000),
            Some([0x94; 32]),
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(no_active_binding.0, StatusCode::CONFLICT);

    // A Binding that remains enabled is still insufficient when the dedicated
    // Agent Device has been revoked.  This uses a distinct installation and
    // `g0` fence so it proves the gate also protects a new grant, not only a
    // regrant whose existing Binding was disabled above.
    let inactive_device_operation = RequestId::new();
    let inactive_device_uri =
        format!("/v1/conversations/{conversation_id}/agent-grants/{inactive_installation_id}");
    let inactive_device_grant = owner_conversation_grant_mutation(
        router.clone(),
        Method::PUT,
        &inactive_device_uri,
        &owner_authorization,
        inactive_device_operation,
        "\"g0\"",
        conversation_grant_body(
            1,
            inactive_device_operation,
            tenant_id,
            conversation_id,
            inactive_installation_id,
            None,
            owner_id,
            owner_device_id,
            &owner_device_key,
            Some(now() + 600_000),
            Some([0x95; 32]),
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(inactive_device_grant.0, StatusCode::CONFLICT);

    drop(non_owner_credential);
    drop(owner_credential);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn route_bootstrap_v1_postgres_happy_path_gates_route_run_until_installed()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    init_test_clock();
    grant_agent_route_run_runtime_access(&harness).await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;

    let owner_root = key(110);
    let owner_device_key = key(111);
    let owner_device_id = DeviceId::new();
    let (owner_id, owner_head, _) = provision_identity(
        &harness,
        &owner_root,
        &owner_device_key,
        owner_device_id,
        112,
    )
    .await?;
    let (owner_credential, owner_authorization) =
        provision_owner_session(&harness, owner_id, owner_device_id, owner_head, [0x71; 32])
            .await?;

    let agent_root = key(113);
    let agent_device_key = key(114);
    let agent_identity_device_id = DeviceId::new();
    let (_, _, agent_certificate) = provision_identity(
        &harness,
        &agent_root,
        &agent_device_key,
        agent_identity_device_id,
        115,
    )
    .await?;
    let (host, connector) = provision_host_and_connector(&store, tenant_id, owner_id).await?;
    let installation_id = InstallationId::new();
    let agent_control_device_id = AgentDeviceId::new();
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
        agent_control_device_id,
        agent_identity_device_id,
        fingerprint,
        binding_id,
        &connector,
    )
    .await?;
    let source_conversation_id = ConversationId::new();
    provision_private_conversation_owner(&harness, tenant_id, source_conversation_id, owner_id)
        .await?;

    let (issuer, ca_der) = certificate_issuer(now())?;
    let index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let app = Arc::new(application(store.clone(), issuer, index.clone()));
    let enrollment = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            RequestId::new(),
            EnrollmentToken::from_bytes([0x72; 32]),
            None,
        )?)
        .await?;
    let enrollment_request = signed_enrollment_request(&enrollment, &[0x72; 32], 116, 117)?;
    let completion = app
        .enroll(ParsedEnrollment {
            token: EnrollmentToken::from_bytes([0x72; 32]),
            request: enrollment_request,
        })
        .await?;
    let route_auth_time_ms = current_store_timestamp()?;
    assert!(
        completion.credential.not_before_millis() <= route_auth_time_ms
            && route_auth_time_ms < completion.credential.not_after_millis(),
        "route connector authentication time must be inside the issued credential validity",
    );
    app.hydrate_connector_authorization(tenant_id, connector.connector_id())
        .await?;
    let opened = app
        .open_control(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            ParsedHello {
                tenant_id,
                connector_id: connector.connector_id(),
                host_id: host.host_id(),
                boot_id: BootId::new(),
                connector_generation: completion.credential.generation(),
                spec_revision: completion.credential.revision(),
                protocol: ParsedProtocolRange {
                    minimum_major: 1,
                    minimum_minor: 6,
                    maximum_major: 1,
                    maximum_minor: 6,
                },
                runtime_claims: claims()?,
                capacity: capacity(),
                last_applied_command_sequence: 0,
                required_server_capabilities: vec![
                    "agent-route-health.v1".into(),
                    "opaque-agent-provisioning".into(),
                ],
            },
        )
        .await?;
    assert_eq!(opened.protocol_minor, 6);
    let fence = opened.lease.fence();
    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app.clone()),
    ));

    // An ordinary ACK is reserved for closing one exact Prepare command only
    // after its bootstrap expires. It must atomically retire the command and
    // outbox so a successor Begin for the same live target can make progress.
    let expired_bootstrap_id = AgentRouteBootstrapId::new();
    let expired_at = current_store_timestamp()? + 5_000;
    let expired_begin = owner_post(
        router.clone(),
        "/v1/agent-route-bootstraps",
        &owner_authorization,
        "route_bootstrap_expired_prepare",
        "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor",
        agent_route_bootstrap_begin_body(
            expired_bootstrap_id,
            tenant_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            owner_id,
            owner_device_id,
            expired_at,
            vec![0x70; 128],
            &owner_device_key,
        )?,
    )
    .await?;
    assert_eq!(expired_begin.0, StatusCode::CREATED);
    let expired_commands = app
        .poll_commands(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            fence,
            0,
        )
        .await
        .expect("polling the new expired-case Prepare command must remain available");
    let expired_prepare = expired_commands
        .iter()
        .find(|command| {
            matches!(
                command.payload(),
                ServerCommandPayload::PrepareAgentRouteRecipient(prepare)
                    if prepare.bootstrap_id == expired_bootstrap_id
            )
        })
        .expect("expired bootstrap has one durable Prepare command");
    let expired_ack = ParsedCommandAcknowledgement {
        fence: parsed_fence(fence),
        command_sequence: expired_prepare.sequence(),
        payload_digest: expired_prepare.payload_digest(),
        encoded_command_digest: expired_prepare.encoded_command_digest(),
    };
    assert_eq!(
        app.acknowledge_command_on_session(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            expired_ack,
            5,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "a nonexpired Prepare must not be retired by an ordinary ACK",
    );

    let wrong_sequence = ParsedCommandAcknowledgement {
        command_sequence: expired_ack.command_sequence + 1,
        ..expired_ack
    };
    assert_eq!(
        app.acknowledge_command_on_session(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            wrong_sequence,
            5,
        )
        .await,
        Err(ConnectorControlApplicationError::StaleFence),
        "an ACK for a different sequence must not retire the expired Prepare",
    );
    let wrong_digest = ParsedCommandAcknowledgement {
        encoded_command_digest: ControlDigest::from_bytes([0x6f; 32]),
        ..expired_ack
    };
    assert_eq!(
        app.acknowledge_command_on_session(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            wrong_digest,
            5,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "an inexact digest must not retire the expired Prepare",
    );
    let mut before_expired_ack = store.begin_tenant(tenant_id).await?;
    let (before_state, before_outbox_state, before_cursor): (String, String, i64) = sqlx::query_as(
        "SELECT b.state, o.state, h.acknowledged_command_sequence
               FROM agent.agent_route_bootstraps AS b
               JOIN agent.agent_route_bootstrap_outbox AS o
                 ON o.tenant_id=b.tenant_id AND o.bootstrap_id=b.bootstrap_id
               JOIN agent.connector_control_stream_heads AS h
                 ON h.tenant_id=b.tenant_id AND h.connector_id=b.connector_id
              WHERE b.tenant_id=$1 AND b.bootstrap_id=$2
                AND o.command_kind='prepare_recipient'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(expired_bootstrap_id))
    .fetch_one(before_expired_ack.connection())
    .await?;
    assert_eq!(before_state, "pending_recipient");
    assert_eq!(before_outbox_state, "dispatched");
    assert_eq!(before_cursor, 0);
    before_expired_ack.rollback().await?;

    let wait_until_expired = expired_at
        .saturating_sub(current_store_timestamp()?)
        .max(0)
        .saturating_add(2);
    tokio::time::sleep(Duration::from_millis(u64::try_from(wait_until_expired)?)).await;
    assert_eq!(
        app.acknowledge_command_on_session(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            expired_ack,
            4,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "an Agent Control 1.4 session cannot invoke the 1.5 expired-Prepare transition",
    );
    let mut before_minor_five_ack = store.begin_tenant(tenant_id).await?;
    let (before_minor_five_state, before_minor_five_outbox, before_minor_five_cursor): (
        String,
        String,
        i64,
    ) = sqlx::query_as(
        "SELECT b.state, o.state, h.acknowledged_command_sequence
           FROM agent.agent_route_bootstraps AS b
           JOIN agent.agent_route_bootstrap_outbox AS o
             ON o.tenant_id=b.tenant_id AND o.bootstrap_id=b.bootstrap_id
           JOIN agent.connector_control_stream_heads AS h
             ON h.tenant_id=b.tenant_id AND h.connector_id=b.connector_id
          WHERE b.tenant_id=$1 AND b.bootstrap_id=$2
            AND o.command_kind='prepare_recipient'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(expired_bootstrap_id))
    .fetch_one(before_minor_five_ack.connection())
    .await?;
    assert_eq!(before_minor_five_state, "pending_recipient");
    assert_eq!(before_minor_five_outbox, "dispatched");
    assert_eq!(before_minor_five_cursor, 0);
    before_minor_five_ack.rollback().await?;

    app.acknowledge_command_on_session(
        authenticate_at(
            index.clone(),
            &ca_der,
            &completion.credential,
            route_auth_time_ms,
        )?,
        expired_ack,
        5,
    )
    .await
    .expect("the exact expired Prepare ACK must close its command, bootstrap, and outbox");
    assert_eq!(
        app.acknowledge_command_on_session(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            expired_ack,
            5,
        )
        .await,
        Ok(()),
        "the exact completed expiry transition must replay idempotently",
    );

    let expired_uri = format!("/v1/agent-route-bootstraps/{expired_bootstrap_id}");
    let expired_status = owner_get(router.clone(), &expired_uri, &owner_authorization).await?;
    assert_eq!(expired_status.0, StatusCode::OK);
    let CanonicalValue::Map(expired_receipt) = decode_deterministic_cbor(&expired_status.1)? else {
        panic!("expired RouteBootstrap receipt must be a canonical map");
    };
    assert_eq!(expired_receipt.len(), 11);
    assert_eq!(expired_receipt[2].1, text(expired_bootstrap_id));
    assert_eq!(expired_receipt[3].1, u(6));
    assert_eq!(expired_receipt[4].1, CanonicalValue::Null);
    assert_eq!(expired_receipt[5].1, CanonicalValue::Null);
    assert_eq!(expired_receipt[6].1, CanonicalValue::Null);
    assert_eq!(expired_receipt[7].1, CanonicalValue::Null);
    assert_eq!(expired_receipt[10].1, CanonicalValue::Null);

    let mut expired_session = store.begin_tenant(tenant_id).await?;
    let (expired_state, cancelled_state, acknowledged_cursor): (String, String, i64) =
        sqlx::query_as(
            "SELECT b.state, o.state, h.acknowledged_command_sequence
               FROM agent.agent_route_bootstraps AS b
               JOIN agent.agent_route_bootstrap_outbox AS o
                 ON o.tenant_id=b.tenant_id AND o.bootstrap_id=b.bootstrap_id
               JOIN agent.connector_control_stream_heads AS h
                 ON h.tenant_id=b.tenant_id AND h.connector_id=b.connector_id
              WHERE b.tenant_id=$1 AND b.bootstrap_id=$2
                AND o.command_kind='prepare_recipient'",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(expired_bootstrap_id))
        .fetch_one(expired_session.connection())
        .await?;
    assert_eq!(expired_state, "expired");
    assert_eq!(cancelled_state, "cancelled");
    assert_eq!(
        acknowledged_cursor,
        i64::try_from(expired_prepare.sequence())?
    );
    expired_session.rollback().await?;

    let bootstrap_id = AgentRouteBootstrapId::new();
    let bootstrap_expires_at = now() + 300_000;
    let owner_signed_intent = vec![0x75; 128];
    let begin_body = agent_route_bootstrap_begin_body(
        bootstrap_id,
        tenant_id,
        installation_id,
        binding_id,
        agent_control_device_id,
        owner_id,
        owner_device_id,
        bootstrap_expires_at,
        owner_signed_intent,
        &owner_device_key,
    )?;
    let begin = owner_post(
        router.clone(),
        "/v1/agent-route-bootstraps",
        &owner_authorization,
        "route_bootstrap_begin_1",
        "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor",
        begin_body.clone(),
    )
    .await?;
    assert_eq!(begin.0, StatusCode::CREATED);
    let begin_replay = owner_post(
        router.clone(),
        "/v1/agent-route-bootstraps",
        &owner_authorization,
        "route_bootstrap_begin_1",
        "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor",
        begin_body,
    )
    .await?;
    assert_eq!(begin_replay.0, StatusCode::OK);
    assert_eq!(begin_replay.1, begin.1);

    let grant_operation = RequestId::new();
    let grant_uri =
        format!("/v1/conversations/{source_conversation_id}/agent-grants/{installation_id}");
    let grant = owner_conversation_grant_mutation(
        router.clone(),
        Method::PUT,
        &grant_uri,
        &owner_authorization,
        grant_operation,
        "\"g0\"",
        conversation_grant_body(
            1,
            grant_operation,
            tenant_id,
            source_conversation_id,
            installation_id,
            None,
            owner_id,
            owner_device_id,
            &owner_device_key,
            Some(now() + 600_000),
            Some(private_conversation_tools_profile_v1_digest()),
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(grant.0, StatusCode::CREATED);

    let route_id = ConversationId::new();
    let route_fence = [0x74; 32];
    let before_install_operation = RequestId::new();
    let before_install_event = EventId::try_from(*before_install_operation.as_uuid())?;
    let run_uri =
        format!("/v1/conversations/{source_conversation_id}/agent-routes/{route_id}/runs");
    let before_install = owner_agent_route_run(
        router.clone(),
        &run_uri,
        &owner_authorization,
        before_install_operation,
        "\"g1\"",
        agent_route_run_body(
            tenant_id,
            source_conversation_id,
            route_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            route_fence,
            before_install_event,
            before_install_operation,
            Revision::INITIAL,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(before_install.0, StatusCode::CONFLICT);

    let blocked_commands = app
        .poll_commands_for_protocol(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            fence,
            expired_prepare.sequence(),
            3,
        )
        .await
        .expect("v1.3 must retain the RouteBootstrap durable head");
    assert!(
        blocked_commands.is_empty(),
        "v1.3 cannot receive the RouteBootstrap Prepare command",
    );
    let mut blocked_verify_session = store.begin_tenant(tenant_id).await?;
    let blocked_outbox_state: String = sqlx::query_scalar(
        "SELECT state FROM agent.agent_route_bootstrap_outbox
          WHERE tenant_id=$1 AND bootstrap_id=$2 AND command_kind='prepare_recipient'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .fetch_one(blocked_verify_session.connection())
    .await?;
    assert_eq!(
        blocked_outbox_state, "pending",
        "polling a v1.3 suffix must not dispatch the blocked durable RouteBootstrap row",
    );
    blocked_verify_session.rollback().await?;

    let commands = app
        .poll_commands(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            fence,
            expired_prepare.sequence(),
        )
        .await
        .expect("polling the successor Prepare must continue from the expired ACK cursor");
    let prepare_commands = commands
        .iter()
        .filter(|command| {
            matches!(
                command.payload(),
                ServerCommandPayload::PrepareAgentRouteRecipient(_)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(prepare_commands.len(), 1);
    let prepare_command = prepare_commands[0];
    let mut verify_session = store.begin_tenant(tenant_id).await?;
    let prepare_outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_route_bootstrap_outbox
          WHERE tenant_id=$1 AND bootstrap_id=$2 AND command_kind='prepare_recipient'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .fetch_one(verify_session.connection())
    .await?;
    assert_eq!(prepare_outbox_count, 1);
    verify_session.rollback().await?;

    let recipient_id = AgentRouteRecipientId::new();
    let opaque_recipient_capsule = vec![0x76; 256];
    let recipient_capsule_digest = ControlDigest::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-route-recipient-capsule.v1\0",
            &opaque_recipient_capsule,
        )
        .as_bytes(),
    );
    let recipient_result_digest = route_bootstrap_recipient_ready_result_digest(
        bootstrap_id,
        tenant_id,
        installation_id,
        binding_id,
        agent_control_device_id,
        recipient_id,
        prepare_command.sequence(),
        recipient_capsule_digest,
        bootstrap_expires_at,
    );
    let health_signing_key = key(75);
    let route_health_key_id = RouteHealthKeyId::new();
    let route_health_public_key =
        Ed25519PublicKey::try_from(health_signing_key.verifying_key().to_bytes())?;
    let ready = ParsedAgentRouteRecipientReady {
        connector_fence: parsed_fence(fence),
        bootstrap_id,
        command_sequence: prepare_command.sequence(),
        command_payload_digest: prepare_command.payload_digest(),
        encoded_command_digest: prepare_command.encoded_command_digest(),
        installation_id,
        binding_id,
        agent_control_device_id,
        recipient_id,
        recipient_capsule_digest,
        opaque_recipient_capsule,
        expires_at_millis: bootstrap_expires_at,
        result_digest: recipient_result_digest,
        route_health_key_id: Some(route_health_key_id),
        route_health_public_key: Some(route_health_public_key),
        server_receipt_key_id: None,
        server_receipt_public_key: None,
    };
    let competing_recipient_id = AgentRouteRecipientId::new();
    let competing_capsule = vec![0x79; 256];
    let competing_capsule_digest = ControlDigest::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-route-recipient-capsule.v1\0",
            &competing_capsule,
        )
        .as_bytes(),
    );
    let competing_ready = ParsedAgentRouteRecipientReady {
        recipient_id: competing_recipient_id,
        recipient_capsule_digest: competing_capsule_digest,
        opaque_recipient_capsule: competing_capsule,
        result_digest: route_bootstrap_recipient_ready_result_digest(
            bootstrap_id,
            tenant_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            competing_recipient_id,
            prepare_command.sequence(),
            competing_capsule_digest,
            bootstrap_expires_at,
        ),
        route_health_key_id: Some(RouteHealthKeyId::new()),
        route_health_public_key: Some(Ed25519PublicKey::try_from(
            key(76).verifying_key().to_bytes(),
        )?),
        ..ready.clone()
    };
    let (first_ready, second_ready) = tokio::join!(
        app.record_agent_route_recipient_ready(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            ready.clone(),
        ),
        app.record_agent_route_recipient_ready(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            competing_ready.clone(),
        )
    );
    assert_eq!(first_ready.is_ok(), second_ready.is_err());
    assert_eq!(first_ready.is_err(), second_ready.is_ok());
    let ready = if first_ready.is_ok() {
        ready
    } else {
        competing_ready
    };
    let winner_health_key_id = ready.route_health_key_id.expect("health key ID");
    let winner_health_public_key = ready.route_health_public_key.expect("health public key");
    let route_health_public_key_digest = ControlDigest::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-route-health-public-key.v1\0",
            winner_health_public_key.as_bytes(),
        )
        .as_bytes(),
    );
    let mut changed_ready = ready.clone();
    changed_ready.result_digest = ControlDigest::from_bytes([0x77; 32]);
    assert!(
        app.record_agent_route_recipient_ready(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            changed_ready,
        )
        .await
        .is_err()
    );
    app.record_agent_route_recipient_ready(
        authenticate_at(
            index.clone(),
            &ca_der,
            &completion.credential,
            route_auth_time_ms,
        )?,
        ready.clone(),
    )
    .await?;
    let mut changed_health_ready = ready.clone();
    changed_health_ready.route_health_key_id = Some(RouteHealthKeyId::new());
    assert_eq!(
        app.record_agent_route_recipient_ready(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            changed_health_ready,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict),
    );

    let mut ready_session = store.begin_tenant(tenant_id).await?;
    let (bootstrap_state, prepare_state): (String, String) = sqlx::query_as(
        "SELECT b.state, o.state
           FROM agent.agent_route_bootstraps AS b
           JOIN agent.agent_route_bootstrap_outbox AS o
             ON o.tenant_id=b.tenant_id AND o.bootstrap_id=b.bootstrap_id
          WHERE b.tenant_id=$1 AND b.bootstrap_id=$2
            AND o.command_kind='prepare_recipient'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .fetch_one(ready_session.connection())
    .await?;
    assert_eq!(bootstrap_state, "recipient_ready");
    assert_eq!(prepare_state, "acknowledged");
    let acknowledged_after_ready: i64 = sqlx::query_scalar(
        "SELECT acknowledged_command_sequence
           FROM agent.connector_control_stream_heads
          WHERE tenant_id=$1 AND connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector.connector_id()))
    .fetch_one(ready_session.connection())
    .await?;
    assert_eq!(
        acknowledged_after_ready,
        i64::try_from(prepare_command.sequence())?
    );
    ready_session.rollback().await?;

    let delivery_id = AgentRouteDeliveryId::new();
    let opaque_sealed_bootstrap = vec![0x78; 512];
    let bootstrap_capsule_digest = Sha256Digest::hash_domain(
        b"dirextalk.agent-route-bootstrap-capsule.v1\0",
        &opaque_sealed_bootstrap,
    );
    let delivery_body = agent_route_bootstrap_delivery_body(
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
        bootstrap_capsule_digest,
        opaque_sealed_bootstrap,
        bootstrap_expires_at,
        &owner_device_key,
    )?;
    let delivery_uri =
        format!("/v1/agent-route-bootstraps/{bootstrap_id}/deliveries/{delivery_id}");
    let delivery = owner_agent_route_bootstrap_delivery(
        router.clone(),
        &delivery_uri,
        &owner_authorization,
        delivery_body,
    )
    .await?;
    assert_eq!(delivery.0, StatusCode::CREATED);
    let delivery_commands = app
        .poll_commands(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            fence,
            prepare_command.sequence(),
        )
        .await?;
    let delivery_commands = delivery_commands
        .iter()
        .filter(|command| {
            matches!(
                command.payload(),
                ServerCommandPayload::DeliverAgentRouteBootstrap(_)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(delivery_commands.len(), 1);
    let delivery_command = delivery_commands[0];
    let ServerCommandPayload::DeliverAgentRouteBootstrap(delivery_payload) =
        delivery_command.payload()
    else {
        panic!("expected DeliverAgentRouteBootstrap command");
    };
    assert_eq!(
        delivery_payload.route_health_key_id,
        Some(winner_health_key_id)
    );
    assert_eq!(
        delivery_payload.route_health_public_key_digest,
        Some(route_health_public_key_digest),
    );

    assert_eq!(
        app.acknowledge_command(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            ParsedCommandAcknowledgement {
                fence: parsed_fence(fence),
                command_sequence: delivery_command.sequence(),
                payload_digest: delivery_command.payload_digest(),
                encoded_command_digest: delivery_command.encoded_command_digest(),
            },
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict),
        "a delivery command requires its typed terminal result, never an ordinary ACK",
    );

    let mut delivery_session = store.begin_tenant(tenant_id).await?;
    let delivery_outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_route_bootstrap_outbox
          WHERE tenant_id=$1 AND delivery_id=$2 AND command_kind='deliver_bootstrap'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(delivery_id))
    .fetch_one(delivery_session.connection())
    .await?;
    assert_eq!(delivery_outbox_count, 1);
    delivery_session.rollback().await?;

    let installed_at = now();
    let installed_capsule_digest = ControlDigest::from_bytes(*bootstrap_capsule_digest.as_bytes());
    let installed = ParsedAgentRouteBootstrapInstalled {
        connector_fence: parsed_fence(fence),
        bootstrap_id,
        delivery_id,
        route_id,
        command_sequence: delivery_command.sequence(),
        command_payload_digest: delivery_command.payload_digest(),
        encoded_command_digest: delivery_command.encoded_command_digest(),
        installation_id,
        binding_id,
        agent_control_device_id,
        recipient_id,
        capsule_digest: installed_capsule_digest,
        route_fence,
        installed_at_millis: installed_at,
        result_digest: route_bootstrap_installed_result_digest(
            bootstrap_id,
            delivery_id,
            route_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            recipient_id,
            delivery_command.sequence(),
            installed_capsule_digest,
            route_fence,
            installed_at,
        ),
        route_health_key_id: ready.route_health_key_id,
        route_health_public_key_digest: Some(route_health_public_key_digest),
        server_receipt_key_id: None,
        server_receipt_public_key_digest: None,
    };
    let mut changed_installed = installed.clone();
    changed_installed.route_health_public_key_digest = Some(ControlDigest::from_bytes([0x7a; 32]));
    assert_eq!(
        app.complete_agent_route_bootstrap(
            authenticate_at(
                index.clone(),
                &ca_der,
                &completion.credential,
                route_auth_time_ms,
            )?,
            changed_installed,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict),
    );
    app.complete_agent_route_bootstrap(
        authenticate_at(
            index.clone(),
            &ca_der,
            &completion.credential,
            route_auth_time_ms,
        )?,
        installed.clone(),
    )
    .await?;

    let mut replay_before = store.begin_tenant(tenant_id).await?;
    let before_bootstrap: (i64, Vec<u8>) = sqlx::query_as(
        "SELECT updated_at_ms, delivery_receipt_digest FROM agent.agent_route_bootstraps WHERE tenant_id=$1 AND bootstrap_id=$2",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(bootstrap_id)).fetch_one(replay_before.connection()).await?;
    let before_outbox: (String, Vec<u8>, Option<i64>) = sqlx::query_as(
        "SELECT state, result_digest, resolved_at_ms FROM agent.agent_route_bootstrap_outbox WHERE tenant_id=$1 AND bootstrap_id=$2 AND command_kind='deliver_bootstrap'",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(bootstrap_id)).fetch_one(replay_before.connection()).await?;
    let before_head: (Uuid, Uuid, Uuid, Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
        "SELECT bootstrap_id, delivery_id, route_id, route_fence, capsule_digest, installed_at_ms FROM agent.agent_route_binding_heads WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3 AND installation_id=$4 AND binding_id=$5 AND agent_control_device_id=$6",
    ).bind(Uuid::from(tenant_id)).bind(owner_id.to_string()).bind(Uuid::from(owner_device_id)).bind(Uuid::from(installation_id)).bind(Uuid::from(binding_id)).bind(Uuid::from(agent_control_device_id)).fetch_one(replay_before.connection()).await?;
    let before_cursor: i64 = sqlx::query_scalar("SELECT acknowledged_command_sequence FROM agent.connector_control_stream_heads WHERE tenant_id=$1 AND connector_id=$2").bind(Uuid::from(tenant_id)).bind(Uuid::from(connector.connector_id())).fetch_one(replay_before.connection()).await?;
    replay_before.rollback().await?;
    app.complete_agent_route_bootstrap(
        authenticate_at(
            index.clone(),
            &ca_der,
            &completion.credential,
            route_auth_time_ms,
        )?,
        installed.clone(),
    )
    .await?;
    let mut replay_after = store.begin_tenant(tenant_id).await?;
    let after_bootstrap: (i64, Vec<u8>) = sqlx::query_as("SELECT updated_at_ms, delivery_receipt_digest FROM agent.agent_route_bootstraps WHERE tenant_id=$1 AND bootstrap_id=$2").bind(Uuid::from(tenant_id)).bind(Uuid::from(bootstrap_id)).fetch_one(replay_after.connection()).await?;
    let after_outbox: (String, Vec<u8>, Option<i64>) = sqlx::query_as("SELECT state, result_digest, resolved_at_ms FROM agent.agent_route_bootstrap_outbox WHERE tenant_id=$1 AND bootstrap_id=$2 AND command_kind='deliver_bootstrap'").bind(Uuid::from(tenant_id)).bind(Uuid::from(bootstrap_id)).fetch_one(replay_after.connection()).await?;
    let after_head: (Uuid, Uuid, Uuid, Vec<u8>, Vec<u8>, i64) = sqlx::query_as("SELECT bootstrap_id, delivery_id, route_id, route_fence, capsule_digest, installed_at_ms FROM agent.agent_route_binding_heads WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3 AND installation_id=$4 AND binding_id=$5 AND agent_control_device_id=$6").bind(Uuid::from(tenant_id)).bind(owner_id.to_string()).bind(Uuid::from(owner_device_id)).bind(Uuid::from(installation_id)).bind(Uuid::from(binding_id)).bind(Uuid::from(agent_control_device_id)).fetch_one(replay_after.connection()).await?;
    let after_cursor: i64 = sqlx::query_scalar("SELECT acknowledged_command_sequence FROM agent.connector_control_stream_heads WHERE tenant_id=$1 AND connector_id=$2").bind(Uuid::from(tenant_id)).bind(Uuid::from(connector.connector_id())).fetch_one(replay_after.connection()).await?;
    assert_eq!(after_bootstrap, before_bootstrap);
    assert_eq!(after_outbox, before_outbox);
    assert_eq!(after_head, before_head);
    assert_eq!(after_cursor, before_cursor);
    replay_after.rollback().await?;

    let mut installed_session = store.begin_tenant(tenant_id).await?;
    let installed_state: String = sqlx::query_scalar(
        "SELECT state FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND bootstrap_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .fetch_one(installed_session.connection())
    .await?;
    assert_eq!(installed_state, "installed");
    let (head_route_id, head_route_fence): (Uuid, Vec<u8>) = sqlx::query_as(
        "SELECT route_id, route_fence FROM agent.agent_route_binding_heads
          WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3
            AND installation_id=$4 AND binding_id=$5 AND agent_control_device_id=$6",
    )
    .bind(Uuid::from(tenant_id))
    .bind(owner_id.to_string())
    .bind(Uuid::from(owner_device_id))
    .bind(Uuid::from(installation_id))
    .bind(Uuid::from(binding_id))
    .bind(Uuid::from(agent_control_device_id))
    .fetch_one(installed_session.connection())
    .await?;
    assert_eq!(head_route_id, Uuid::from(route_id));
    assert_eq!(head_route_fence, route_fence);
    let (stored_health_key_id, stored_health_public_key): (Uuid, Vec<u8>) = sqlx::query_as(
        "SELECT route_health_key_id, route_health_public_key
           FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND bootstrap_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .fetch_one(installed_session.connection())
    .await?;
    assert_eq!(stored_health_key_id, Uuid::from(winner_health_key_id));
    assert_eq!(
        stored_health_public_key,
        winner_health_public_key.as_bytes()
    );
    let current_health_key_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND route_health_key_id=$2
            AND state IN ('recipient_ready','pending_delivery','installed')",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(winner_health_key_id))
    .fetch_one(installed_session.connection())
    .await?;
    assert_eq!(current_health_key_count, 1);
    let owner_receipt = owner_get(
        router.clone(),
        &format!("/v1/agent-route-bootstraps/{bootstrap_id}"),
        &owner_authorization,
    )
    .await?;
    assert_eq!(owner_receipt.0, StatusCode::OK);
    assert!(
        !owner_receipt
            .1
            .windows(winner_health_key_id.to_string().len())
            .any(|window| window == winner_health_key_id.to_string().as_bytes())
    );
    assert!(
        !owner_receipt
            .1
            .windows(winner_health_public_key.as_bytes().len())
            .any(|window| window == winner_health_public_key.as_bytes())
    );
    let acknowledged_after_installed: i64 = sqlx::query_scalar(
        "SELECT acknowledged_command_sequence
           FROM agent.connector_control_stream_heads
          WHERE tenant_id=$1 AND connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector.connector_id()))
    .fetch_one(installed_session.connection())
    .await?;
    assert_eq!(
        acknowledged_after_installed,
        i64::try_from(delivery_command.sequence())?
    );
    installed_session.rollback().await?;
    let admitted_operation = RequestId::new();
    let admitted_event = EventId::try_from(*admitted_operation.as_uuid())?;
    let admitted = owner_agent_route_run(
        router,
        &run_uri,
        &owner_authorization,
        admitted_operation,
        "\"g1\"",
        agent_route_run_body(
            tenant_id,
            source_conversation_id,
            route_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            route_fence,
            admitted_event,
            admitted_operation,
            Revision::INITIAL,
            owner_id,
            owner_device_id,
            &owner_device_key,
            now() + 300_000,
        )?,
    )
    .await?;
    assert_eq!(admitted.0, StatusCode::CREATED);
    let mut admitted_session = store.begin_tenant(tenant_id).await?;
    let admitted_binding: Uuid = sqlx::query_scalar(
        "SELECT candidate.binding_id
           FROM agent.agent_runs AS run
           JOIN agent.agent_run_candidates AS candidate
             ON candidate.tenant_id=run.tenant_id AND candidate.run_id=run.run_id
          WHERE run.tenant_id=$1 AND run.request_id=$2 AND candidate.candidate_ordinal=0",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(admitted_operation))
    .fetch_one(admitted_session.connection())
    .await?;
    assert_eq!(admitted_binding, Uuid::from(binding_id));
    admitted_session.rollback().await?;

    let reopened = app
        .open_control(
            authenticate(index.clone(), &ca_der, &completion.credential)?,
            ParsedHello {
                tenant_id,
                connector_id: connector.connector_id(),
                host_id: host.host_id(),
                boot_id: BootId::new(),
                connector_generation: completion.credential.generation(),
                spec_revision: completion.credential.revision(),
                protocol: ParsedProtocolRange {
                    minimum_major: 1,
                    minimum_minor: 6,
                    maximum_major: 1,
                    maximum_minor: 6,
                },
                runtime_claims: claims()?,
                capacity: capacity(),
                last_applied_command_sequence: delivery_command.sequence(),
                required_server_capabilities: vec!["agent-route-health.v1".into()],
            },
        )
        .await?;
    assert!(
        reopened
            .server_capabilities
            .windows(2)
            .all(|window| window[0] <= window[1])
    );
    assert!(
        reopened
            .server_capabilities
            .iter()
            .any(|capability| capability == "agent-route-health.v1")
    );

    let legacy = app
        .open_control(
            authenticate(index.clone(), &ca_der, &completion.credential)?,
            ParsedHello {
                tenant_id,
                connector_id: connector.connector_id(),
                host_id: host.host_id(),
                boot_id: BootId::new(),
                connector_generation: completion.credential.generation(),
                spec_revision: completion.credential.revision(),
                protocol: ParsedProtocolRange {
                    minimum_major: 1,
                    minimum_minor: 5,
                    maximum_major: 1,
                    maximum_minor: 5,
                },
                runtime_claims: claims()?,
                capacity: capacity(),
                last_applied_command_sequence: delivery_command.sequence(),
                required_server_capabilities: Vec::new(),
            },
        )
        .await?;
    assert!(legacy.server_capabilities.is_empty());

    drop(owner_credential);
    Ok(())
}

#[tokio::test]
async fn route_bootstrap_v1_postgres_rejected_health_lifecycle() -> Result<(), Box<dyn Error>> {
    init_test_clock();
    let harness = PostgresHarness::start().await?;
    grant_agent_route_run_runtime_access(&harness).await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    let owner_root = key(130);
    let owner_device_key = key(131);
    let owner_device_id = DeviceId::new();
    let (owner_id, owner_head, _) = provision_identity(
        &harness,
        &owner_root,
        &owner_device_key,
        owner_device_id,
        132,
    )
    .await?;
    let (_, owner_authorization) =
        provision_owner_session(&harness, owner_id, owner_device_id, owner_head, [0x91; 32])
            .await?;
    let agent_identity_device_id = DeviceId::new();
    let (_, _, agent_certificate) = provision_identity(
        &harness,
        &key(133),
        &key(134),
        agent_identity_device_id,
        135,
    )
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
        agent_identity_device_id,
        fingerprint,
        binding_id,
        &connector,
    )
    .await?;
    let (issuer, ca_der) = certificate_issuer(now())?;
    let index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let server_pin_a = RouteHealthKeyId::new();
    let server_public_a = [0x3a; 32];
    let server_digest_a = ControlDigest::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-route-health-public-key.v1\0",
            &server_public_a,
        )
        .as_bytes(),
    );
    let app = Arc::new(
        application(store.clone(), issuer.clone(), index.clone())
            .with_route_health_receipt_pin(server_pin_a, server_public_a),
    );
    let enrollment = app
        .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
            tenant_id,
            connector.connector_id(),
            RequestId::new(),
            EnrollmentToken::from_bytes([0x92; 32]),
            None,
        )?)
        .await?;
    let completion = app
        .enroll(ParsedEnrollment {
            token: EnrollmentToken::from_bytes([0x92; 32]),
            request: signed_enrollment_request(&enrollment, &[0x92; 32], 136, 137)?,
        })
        .await?;
    app.hydrate_connector_authorization(tenant_id, connector.connector_id())
        .await?;
    let auth_time = current_store_timestamp()?;
    let opened = app
        .open_control(
            authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
            ParsedHello {
                tenant_id,
                connector_id: connector.connector_id(),
                host_id: host.host_id(),
                boot_id: BootId::new(),
                connector_generation: completion.credential.generation(),
                spec_revision: completion.credential.revision(),
                protocol: ParsedProtocolRange {
                    minimum_major: 1,
                    minimum_minor: 6,
                    maximum_major: 1,
                    maximum_minor: 6,
                },
                runtime_claims: claims()?,
                capacity: capacity(),
                last_applied_command_sequence: 0,
                required_server_capabilities: vec!["agent-route-health.v1".into()],
            },
        )
        .await?;
    let fence = opened.lease.fence();
    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app.clone()),
    ));
    let bootstrap_id = AgentRouteBootstrapId::new();
    assert_eq!(
        owner_post(
            router.clone(),
            "/v1/agent-route-bootstraps",
            &owner_authorization,
            "route_rejected_begin",
            "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor",
            agent_route_bootstrap_begin_body(
                bootstrap_id,
                tenant_id,
                installation_id,
                binding_id,
                agent_device_id,
                owner_id,
                owner_device_id,
                now() + 300_000,
                vec![0xa1; 128],
                &owner_device_key,
            )?,
        )
        .await?
        .0,
        StatusCode::CREATED
    );
    let prepare = app.poll_commands(
        authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?, fence, 0,
    ).await?.into_iter().find(|c| matches!(c.payload(),
        ServerCommandPayload::PrepareAgentRouteRecipient(v) if v.bootstrap_id == bootstrap_id
    )).expect("Prepare #1");
    let recipient_id = AgentRouteRecipientId::new();
    let recipient_capsule = vec![0xa2; 256];
    let recipient_digest = ControlDigest::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-route-recipient-capsule.v1\0",
            &recipient_capsule,
        )
        .as_bytes(),
    );
    let key_id = RouteHealthKeyId::new();
    let public_key = Ed25519PublicKey::try_from(key(138).verifying_key().to_bytes())?;
    let ready = ParsedAgentRouteRecipientReady {
        connector_fence: parsed_fence(fence),
        bootstrap_id,
        command_sequence: prepare.sequence(),
        command_payload_digest: prepare.payload_digest(),
        encoded_command_digest: prepare.encoded_command_digest(),
        installation_id,
        binding_id,
        agent_control_device_id: agent_device_id,
        recipient_id,
        recipient_capsule_digest: recipient_digest,
        opaque_recipient_capsule: recipient_capsule,
        expires_at_millis: now() + 300_000,
        result_digest: route_bootstrap_recipient_ready_result_digest(
            bootstrap_id,
            tenant_id,
            installation_id,
            binding_id,
            agent_device_id,
            recipient_id,
            prepare.sequence(),
            recipient_digest,
            now() + 300_000,
        ),
        route_health_key_id: Some(key_id),
        route_health_public_key: Some(public_key),
        server_receipt_key_id: Some(server_pin_a),
        server_receipt_public_key: Some(Ed25519PublicKey::try_from(server_public_a)?),
    };
    let mut conflicting_ready = ready.clone();
    conflicting_ready.route_health_public_key = conflicting_ready.server_receipt_public_key;
    assert!(matches!(
        app.record_agent_route_recipient_ready(
            authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
            conflicting_ready,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict)
    ));
    app.record_agent_route_recipient_ready(
        authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
        ready,
    )
    .await?;
    let delivery_id = AgentRouteDeliveryId::new();
    let route_id = ConversationId::new();
    let sealed = vec![0xa3; 256];
    let sealed_digest =
        Sha256Digest::hash_domain(b"dirextalk.agent-route-bootstrap-capsule.v1\0", &sealed);
    let delivery_request_body = agent_route_bootstrap_delivery_body_v2(
        bootstrap_id,
        delivery_id,
        tenant_id,
        installation_id,
        binding_id,
        agent_device_id,
        owner_id,
        owner_device_id,
        recipient_id,
        route_id,
        sealed_digest,
        sealed.clone(),
        now() + 300_000,
        &owner_device_key,
        server_pin_a,
        Sha256Digest::from_bytes(server_digest_a.as_bytes()),
    )?;
    let delivery_response = owner_agent_route_bootstrap_delivery(
        router.clone(),
        &format!("/v1/agent-route-bootstraps/{bootstrap_id}/deliveries/{delivery_id}"),
        &owner_authorization,
        delivery_request_body,
    )
    .await?;
    assert_eq!(delivery_response.0, StatusCode::CREATED);
    let deliver = app.poll_commands(
        authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
        fence, prepare.sequence(),
    ).await?.into_iter().find(|c| matches!(c.payload(),
        ServerCommandPayload::DeliverAgentRouteBootstrap(v) if v.bootstrap_id == bootstrap_id
    )).expect("Deliver #2");
    let health_digest = ControlDigest::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-route-health-public-key.v1\0",
            public_key.as_bytes(),
        )
        .as_bytes(),
    );
    let rejected_at = now();
    let code = "INVALID_CAPSULE".to_owned();
    let rejected = ParsedAgentRouteBootstrapRejected {
        connector_fence: parsed_fence(fence),
        bootstrap_id,
        delivery_id,
        route_id,
        command_sequence: deliver.sequence(),
        command_payload_digest: deliver.payload_digest(),
        encoded_command_digest: deliver.encoded_command_digest(),
        installation_id,
        binding_id,
        agent_control_device_id: agent_device_id,
        recipient_id,
        capsule_digest: ControlDigest::from_bytes(*sealed_digest.as_bytes()),
        stable_error_code: code.clone(),
        rejected_at_millis: rejected_at,
        result_digest: route_bootstrap_rejected_result_digest(
            bootstrap_id,
            delivery_id,
            route_id,
            installation_id,
            binding_id,
            agent_device_id,
            recipient_id,
            deliver.sequence(),
            ControlDigest::from_bytes(*sealed_digest.as_bytes()),
            &code,
            rejected_at,
        ),
        route_health_key_id: Some(key_id),
        route_health_public_key_digest: Some(health_digest),
        server_receipt_key_id: Some(server_pin_a),
        server_receipt_public_key_digest: Some(server_digest_a),
    };
    app.reject_agent_route_bootstrap(
        authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
        rejected.clone(),
    )
    .await?;
    let mut session = store.begin_tenant(tenant_id).await?;
    let row: (String, Uuid, Vec<u8>, i64) = sqlx::query_as(
        "SELECT state, route_health_key_id, route_health_public_key, updated_at_ms FROM agent.agent_route_bootstraps WHERE tenant_id=$1 AND bootstrap_id=$2",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(bootstrap_id)).fetch_one(session.connection()).await?;
    assert_eq!(row.0, "rejected");
    assert_eq!(row.1, Uuid::from(key_id));
    assert_eq!(row.2, public_key.as_bytes());
    let updated_at_before_replay = row.3;
    session.rollback().await?;
    let mut head_before = store.begin_tenant(tenant_id).await?;
    let head_count_before: i64 = sqlx::query_scalar("SELECT count(*) FROM agent.agent_route_binding_heads WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3 AND installation_id=$4 AND binding_id=$5 AND agent_control_device_id=$6")
        .bind(Uuid::from(tenant_id)).bind(owner_id.to_string()).bind(Uuid::from(owner_device_id)).bind(Uuid::from(installation_id)).bind(Uuid::from(binding_id)).bind(Uuid::from(agent_device_id)).fetch_one(head_before.connection()).await?;
    assert_eq!(head_count_before, 0);
    head_before.rollback().await?;
    assert!(
        app.reject_agent_route_bootstrap(
            authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
            rejected.clone(),
        )
        .await
        .is_ok()
    );
    let mut replay_session = store.begin_tenant(tenant_id).await?;
    let updated_at_after_replay: i64 = sqlx::query_scalar(
        "SELECT updated_at_ms FROM agent.agent_route_bootstraps WHERE tenant_id=$1 AND bootstrap_id=$2",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(bootstrap_id))
    .fetch_one(replay_session.connection()).await?;
    assert_eq!(updated_at_after_replay, updated_at_before_replay);
    replay_session.rollback().await?;
    let mut head_after = store.begin_tenant(tenant_id).await?;
    let head_count_after: i64 = sqlx::query_scalar("SELECT count(*) FROM agent.agent_route_binding_heads WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3 AND installation_id=$4 AND binding_id=$5 AND agent_control_device_id=$6")
        .bind(Uuid::from(tenant_id)).bind(owner_id.to_string()).bind(Uuid::from(owner_device_id)).bind(Uuid::from(installation_id)).bind(Uuid::from(binding_id)).bind(Uuid::from(agent_device_id)).fetch_one(head_after.connection()).await?;
    assert_eq!(head_count_after, 0);
    head_after.rollback().await?;
    let mut mismatch = rejected.clone();
    mismatch.route_health_public_key_digest = Some(ControlDigest::from_bytes([0xa4; 32]));
    assert_eq!(
        app.reject_agent_route_bootstrap(
            authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
            mismatch,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict)
    );

    let mut pin_session = store.begin_tenant(tenant_id).await?;
    let stored_pin: (Uuid, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT server_receipt_key_id, server_receipt_public_key,
                server_receipt_public_key_digest
           FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND bootstrap_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .fetch_one(pin_session.connection())
    .await?;
    assert_eq!(stored_pin.0, Uuid::from(server_pin_a));
    assert_eq!(stored_pin.1, server_public_a);
    assert_eq!(stored_pin.2, server_digest_a.as_bytes());
    pin_session.rollback().await?;

    let old_receipt = owner_get(
        router.clone(),
        &format!("/v1/agent-route-bootstraps/{bootstrap_id}"),
        &owner_authorization,
    )
    .await?;
    assert_eq!(old_receipt.0, StatusCode::OK);
    assert!(
        old_receipt
            .1
            .windows(server_pin_a.to_string().len())
            .any(|window| { window == server_pin_a.to_string().as_bytes() })
    );
    let target_uri = format!(
        "/v1/agent-installations/{installation_id}/agent-route-target?binding_id={binding_id}"
    );
    let target_a = owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(target_a.0, StatusCode::OK);
    assert!(
        target_a
            .1
            .windows(server_pin_a.to_string().len())
            .any(|window| window == server_pin_a.to_string().as_bytes())
    );

    let server_pin_b = RouteHealthKeyId::new();
    let server_public_b = [0x3b; 32];
    let server_digest_b = ControlDigest::from_bytes(
        *Sha256Digest::hash_domain(
            b"dirextalk.agent-route-health-public-key.v1\0",
            &server_public_b,
        )
        .as_bytes(),
    );
    let mut wrong_pin = rejected.clone();
    wrong_pin.server_receipt_key_id = Some(server_pin_b);
    wrong_pin.server_receipt_public_key_digest = Some(server_digest_b);
    assert_eq!(
        app.reject_agent_route_bootstrap(
            authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
            wrong_pin,
        )
        .await,
        Err(ConnectorControlApplicationError::Conflict)
    );
    let rotated_app = Arc::new(
        application(store.clone(), issuer.clone(), index.clone())
            .with_route_health_receipt_pin(server_pin_b, server_public_b),
    );
    let rotation_request = RotateConnectorCredentialRequest {
        fence: ConnectorCommandFence {
            tenant_id,
            connector_id: connector.connector_id(),
            generation: completion.credential.generation(),
            spec_revision: completion.credential.revision(),
        },
        operation_id: RequestId::new(),
        deadline_millis: now() + 300_000,
    };
    let rotation_command = rotated_app
        .enqueue_credential_rotation(rotation_request)
        .await?;
    let ServerCommandPayload::RotateCredential(rotation) = rotation_command.payload() else {
        return Err("expected credential rotation command".into());
    };
    let successor_control = key(139);
    let successor_public_key =
        Ed25519PublicKey::try_from(successor_control.verifying_key().to_bytes())?;
    let transcript = CredentialRotationTranscript::new(
        tenant_id,
        connector.connector_id(),
        rotation_request.operation_id,
        completion.credential.credential_id(),
        completion.credential.generation(),
        rotation_command.sequence(),
        rotation_command.payload_digest(),
        rotation.successor_revision(),
        rotation.nonce(),
        successor_public_key,
    )?;
    let signing_bytes = transcript.signing_bytes();
    let current_refresh = key(137);
    let rotation_proof = parse_credential_rotation_proof(v1::CredentialRotationProof {
        fence: Some(build_lease_fence(fence)),
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
    let rotation_completion = rotated_app
        .rotate_credential(
            authenticate_at(index.clone(), &ca_der, &completion.credential, auth_time)?,
            rotation_proof,
        )
        .await?;
    let pending_target = owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(pending_target.0, StatusCode::OK);
    assert!(
        pending_target
            .1
            .windows(server_pin_a.to_string().len())
            .any(|window| window == server_pin_a.to_string().as_bytes())
    );
    assert!(
        !pending_target
            .1
            .windows(server_pin_b.to_string().len())
            .any(|window| window == server_pin_b.to_string().as_bytes())
    );
    let successor_peer = authenticate_at(
        index.clone(),
        &ca_der,
        &rotation_completion.credential,
        auth_time,
    )?;
    let promoted = rotated_app
        .open_control(
            successor_peer,
            ParsedHello {
                tenant_id,
                connector_id: connector.connector_id(),
                host_id: host.host_id(),
                boot_id: BootId::new(),
                connector_generation: rotation_completion.credential.generation(),
                spec_revision: rotation_completion.credential.revision(),
                protocol: ParsedProtocolRange {
                    minimum_major: 1,
                    minimum_minor: 6,
                    maximum_major: 1,
                    maximum_minor: 6,
                },
                runtime_claims: claims()?,
                capacity: capacity(),
                last_applied_command_sequence: rotation_command.sequence(),
                required_server_capabilities: vec!["agent-route-health.v1".into()],
            },
        )
        .await?;
    assert_eq!(
        promoted.lease.fence().generation().get(),
        rotation_completion.credential.generation()
    );
    let promoted_target = owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(promoted_target.0, StatusCode::OK);
    assert!(
        promoted_target
            .1
            .windows(server_pin_b.to_string().len())
            .any(|window| window == server_pin_b.to_string().as_bytes())
    );

    let old_receipt_after_rotation = owner_get(
        router.clone(),
        &format!("/v1/agent-route-bootstraps/{bootstrap_id}"),
        &owner_authorization,
    )
    .await?;
    assert_eq!(old_receipt_after_rotation.0, StatusCode::OK);
    assert_eq!(old_receipt_after_rotation.1, old_receipt.1);

    let (restart_issuer, _) = certificate_issuer(now())?;
    let restarted_app = Arc::new(
        application(store.clone(), restart_issuer, index.clone())
            .with_route_health_receipt_pin(server_pin_b, server_public_b),
    );
    let restarted_router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, restarted_app),
    ));
    let old_receipt_after_restart = owner_get(
        restarted_router.clone(),
        &format!("/v1/agent-route-bootstraps/{bootstrap_id}"),
        &owner_authorization,
    )
    .await?;
    assert_eq!(old_receipt_after_restart.0, StatusCode::OK);
    assert_eq!(old_receipt_after_restart.1, old_receipt.1);
    let restart_target = owner_get(restarted_router, &target_uri, &owner_authorization).await?;
    assert_eq!(restart_target.0, StatusCode::OK);
    assert!(
        restart_target
            .1
            .windows(server_pin_b.to_string().len())
            .any(|window| window == server_pin_b.to_string().as_bytes())
    );

    let successor_id = AgentRouteBootstrapId::new();
    let successor = owner_post(
        router.clone(),
        "/v1/agent-route-bootstraps",
        &owner_authorization,
        "route_successor_begin",
        "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor",
        agent_route_bootstrap_begin_body(
            successor_id,
            tenant_id,
            installation_id,
            binding_id,
            agent_device_id,
            owner_id,
            owner_device_id,
            now() + 300_000,
            vec![0xa5; 128],
            &owner_device_key,
        )?,
    )
    .await?;
    assert_eq!(successor.0, StatusCode::CREATED);
    assert!(
        successor
            .1
            .windows(server_pin_b.to_string().len())
            .any(|window| window == server_pin_b.to_string().as_bytes())
    );

    Ok(())
}

#[tokio::test]
async fn owner_agent_route_target_resolves_only_one_active_owned_binding()
-> Result<(), Box<dyn Error>> {
    init_test_clock();
    let harness = PostgresHarness::start().await?;
    grant_agent_route_run_runtime_access(&harness).await?;
    let store = harness.runtime_store(12).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;

    let owner_root = key(120);
    let owner_device_key = key(121);
    let owner_device_id = DeviceId::new();
    let (owner_id, owner_head, _) = provision_identity(
        &harness,
        &owner_root,
        &owner_device_key,
        owner_device_id,
        122,
    )
    .await?;
    let (_owner_credential, owner_authorization) =
        provision_owner_session(&harness, owner_id, owner_device_id, owner_head, [0x79; 32])
            .await?;

    let non_owner_root = key(123);
    let non_owner_device_key = key(124);
    let non_owner_device_id = DeviceId::new();
    let (non_owner_id, non_owner_head, _) = provision_identity(
        &harness,
        &non_owner_root,
        &non_owner_device_key,
        non_owner_device_id,
        125,
    )
    .await?;
    let (_non_owner_credential, non_owner_authorization) = provision_owner_session(
        &harness,
        non_owner_id,
        non_owner_device_id,
        non_owner_head,
        [0x7a; 32],
    )
    .await?;

    let agent_root = key(126);
    let agent_device_key = key(127);
    let agent_identity_device_id = DeviceId::new();
    let (_, _, agent_certificate) = provision_identity(
        &harness,
        &agent_root,
        &agent_device_key,
        agent_identity_device_id,
        128,
    )
    .await?;
    let (_, connector) = provision_host_and_connector(&store, tenant_id, owner_id).await?;
    let installation_id = InstallationId::new();
    let agent_control_device_id = AgentDeviceId::new();
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
        agent_control_device_id,
        agent_identity_device_id,
        fingerprint,
        binding_id,
        &connector,
    )
    .await?;

    let (issuer, _) = certificate_issuer(now())?;
    let app = Arc::new(application(
        store.clone(),
        issuer,
        Arc::new(ConnectorCredentialAuthorizationIndex::new()),
    ));
    let router = agent_provisioning_owner_router(Arc::new(
        PostgresAgentProvisioningOwnerBackend::new(store.clone(), tenant_id, app),
    ));
    let target_uri = format!(
        "/v1/agent-installations/{installation_id}/agent-route-target?binding_id={binding_id}"
    );

    let response = router
        .clone()
        .oneshot(
            Request::get(&target_uri)
                .header(header::AUTHORIZATION, &owner_authorization)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.dirextalk.agent-route-target.v1+cbor")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let target_body = to_bytes(response.into_body(), 16 * 1024).await?.to_vec();
    let expected_target = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(agent_control_device_id.to_string()),
        ),
    ]))?;
    assert_eq!(target_body, expected_target);

    let unauthenticated = owner_get(router.clone(), &target_uri, "").await?;
    assert_eq!(unauthenticated.0, StatusCode::UNAUTHORIZED);
    let non_owner = owner_get(router.clone(), &target_uri, &non_owner_authorization).await?;
    assert_eq!(non_owner.0, StatusCode::NOT_FOUND);
    let mismatched = owner_get(
        router.clone(),
        &format!(
            "/v1/agent-installations/{installation_id}/agent-route-target?binding_id={}",
            BindingId::new()
        ),
        &owner_authorization,
    )
    .await?;
    assert_eq!(mismatched.0, StatusCode::NOT_FOUND);

    let mut session = store.begin_tenant(tenant_id).await?;
    let repository = BindingSetRepository::new();
    let mut bindings = repository.load(session.connection(), tenant_id).await?;
    let binding_ref = TenantRef::new(tenant_id, binding_id);
    let revision = bindings.binding(binding_ref)?.revision();
    bindings.disable(binding_ref, revision)?;
    repository
        .save(session.connection(), &bindings, now())
        .await?;
    session.commit().await?;
    let disabled_binding = owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(disabled_binding.0, StatusCode::NOT_FOUND);

    let mut session = store.begin_tenant(tenant_id).await?;
    let installation = AgentInstallationRepository::new()
        .load(session.connection(), tenant_id, installation_id)
        .await?
        .expect("installation remains");
    let device = AgentDeviceRepository::new()
        .load(session.connection(), tenant_id, agent_control_device_id)
        .await?
        .expect("device remains");
    let repository = BindingSetRepository::new();
    let mut bindings = repository.load(session.connection(), tenant_id).await?;
    let revision = bindings.binding(binding_ref)?.revision();
    bindings.enable(binding_ref, revision, &installation, &device)?;
    repository
        .save(session.connection(), &bindings, now())
        .await?;
    session.commit().await?;
    let restored = owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(restored.0, StatusCode::OK);

    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query(
        "UPDATE agent.agent_devices
            SET state='provisioning', aggregate_revision=aggregate_revision+1,
                updated_at_ms=$3
          WHERE tenant_id=$1 AND agent_device_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(agent_control_device_id))
    .bind(now())
    .execute(session.connection())
    .await?;
    session.commit().await?;
    let provisioning = owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(provisioning.0, StatusCode::NOT_FOUND);

    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query(
        "UPDATE agent.agent_devices
            SET state='active', aggregate_revision=aggregate_revision+1,
                updated_at_ms=$3
          WHERE tenant_id=$1 AND agent_device_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(agent_control_device_id))
    .bind(now())
    .execute(session.connection())
    .await?;
    session.commit().await?;
    let active = owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(active.0, StatusCode::OK);

    let mut session = store.begin_tenant(tenant_id).await?;
    let repository = AgentInstallationRepository::new();
    let mut installation = repository
        .load(session.connection(), tenant_id, installation_id)
        .await?
        .expect("installation remains");
    installation.apply(installation.revision(), InstallationCommand::Disable)?;
    assert_eq!(
        repository
            .save(session.connection(), &installation, now())
            .await?,
        CurrentWrite::Advanced
    );
    session.commit().await?;
    let disabled_installation =
        owner_get(router.clone(), &target_uri, &owner_authorization).await?;
    assert_eq!(disabled_installation.0, StatusCode::NOT_FOUND);
    let rejected_begin = owner_post(
        router,
        "/v1/agent-route-bootstraps",
        &owner_authorization,
        "target_begin_1",
        "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor",
        agent_route_bootstrap_begin_body(
            AgentRouteBootstrapId::new(),
            tenant_id,
            installation_id,
            binding_id,
            agent_control_device_id,
            owner_id,
            owner_device_id,
            now() + 300_000,
            vec![0x7b; 128],
            &owner_device_key,
        )?,
    )
    .await?;
    assert_eq!(rejected_begin.0, StatusCode::CONFLICT);
    let mut session = store.begin_tenant(tenant_id).await?;
    let bootstrap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND installation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(installation_id))
    .fetch_one(session.connection())
    .await?;
    assert_eq!(bootstrap_count, 0);
    session.rollback().await?;

    Ok(())
}
