//! Shared Route Health HTTP fixture support.

use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use axum::{body::Body, http::Request};
use dtx_agent_control::EnrollmentToken;
use dtx_agent_control_server::{
    ConnectorControlApplication, ConnectorCredentialAuthorizationIndex,
    CreateConnectorEnrollmentRequest, ParsedEnrollment, ParsedHello, ParsedProtocolRange,
    RouteHealthConnectInfo,
};
use dtx_domain::{
    AgentDeviceId, BindingId, BootId, ConnectorId, ConversationId, DeviceId, IdentityId,
    InstallationId, RequestId, Revision, RouteHealthKeyId, TenantId,
};
use dtx_security::AuthenticatedConnectorPeer;
use dtx_storage::PgStore;
use dtx_wire::{CanonicalEncode, CanonicalValue, Sha256Digest, encode_deterministic_cbor};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::Executor;
use tower::ServiceExt;
use uuid::Uuid;

use super::{PostgresHarness, agent_provisioning as fixture};

// Keep fixture signing seeds disjoint from the fixed receipt-signing seeds in
// the HTTP matrix so domain-separation tests do not depend on parallel order.
static FIXTURE_SEED: AtomicU8 = AtomicU8::new(1);

/// All durable facts needed to exercise the Route Health HTTP boundary.
pub struct RouteHealthFixture {
    pub store: PgStore,
    pub tenant_id: TenantId,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub connector_id: ConnectorId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_device_id: AgentDeviceId,
    pub bootstrap_id: dtx_domain::AgentRouteBootstrapId,
    pub delivery_id: dtx_domain::AgentRouteDeliveryId,
    pub route_id: ConversationId,
    pub route_fence: [u8; 32],
    pub route_health_key_id: RouteHealthKeyId,
    pub route_health_key: SigningKey,
    pub connector_generation: u64,
    pub lease_id: dtx_domain::LeaseId,
    pub lease_epoch: u64,
    pub connector_credential: dtx_agent_control::ConnectorCredential,
    pub peer: AuthenticatedConnectorPeer,
}

pub struct RouteHealthFixtureBuilder<'a> {
    harness: &'a PostgresHarness,
}

impl<'a> RouteHealthFixtureBuilder<'a> {
    pub fn new(harness: &'a PostgresHarness) -> Self {
        Self { harness }
    }

    pub async fn establish(self) -> Result<RouteHealthFixture, Box<dyn Error>> {
        fixture::init_test_clock();
        fixture::grant_agent_route_run_runtime_access(self.harness).await?;
        sqlx::raw_sql(
            "GRANT SELECT, INSERT ON agent.agent_route_health_receipts TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.agent_route_health_heads TO dtx_runtime_test;",
        )
        .execute(self.harness.admin_pool())
        .await?;
        let store = self.harness.runtime_store(12).await?;
        let tenant_id = TenantId::new();
        fixture::provision_tenant(&store, tenant_id).await?;
        let seed = FIXTURE_SEED.fetch_add(10, Ordering::Relaxed);

        let owner_root = fixture::key(seed);
        let owner_device_key = fixture::key(seed.wrapping_add(1));
        let owner_device_id = DeviceId::new();
        let (owner_identity_id, owner_head, _) = fixture::provision_identity(
            self.harness,
            &owner_root,
            &owner_device_key,
            owner_device_id,
            203,
        )
        .await?;
        let (_owner_credential, owner_authorization) = fixture::provision_owner_session(
            self.harness,
            owner_identity_id,
            owner_device_id,
            owner_head,
            [0xD1; 32],
        )
        .await?;
        let (agent_root, agent_device_key) = (
            fixture::key(seed.wrapping_add(3)),
            fixture::key(seed.wrapping_add(4)),
        );
        let identity_device_id = DeviceId::new();
        let (agent_identity_id, agent_head, agent_certificate) = fixture::provision_identity(
            self.harness,
            &agent_root,
            &agent_device_key,
            identity_device_id,
            206,
        )
        .await?;
        let (host, connector) =
            fixture::provision_host_and_connector(&store, tenant_id, owner_identity_id).await?;
        let installation_id = InstallationId::new();
        let agent_device_id = AgentDeviceId::new();
        let binding_id = BindingId::new();
        let fingerprint = dtx_agent_registry::DeviceCredentialFingerprint::from_bytes(
            *Sha256Digest::hash_domain(
                b"dirextalk.agent-device-credential-fingerprint.v1\0",
                &agent_certificate.to_deterministic_cbor()?,
            )
            .as_bytes(),
        );
        fixture::provision_installation_binding(
            &store,
            tenant_id,
            owner_identity_id,
            installation_id,
            agent_device_id,
            identity_device_id,
            fingerprint,
            binding_id,
            &connector,
        )
        .await?;

        let (issuer, ca_der) = fixture::certificate_issuer(fixture::now())?;
        let index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
        let app = Arc::new(fixture::application(store.clone(), issuer, index.clone()));
        let enrollment = app
            .create_enrollment_intent(CreateConnectorEnrollmentRequest::new(
                tenant_id,
                connector.connector_id(),
                RequestId::new(),
                EnrollmentToken::from_bytes([seed.wrapping_add(6); 32]),
                None,
            )?)
            .await?;
        let enrollment_request = fixture::signed_enrollment_request(
            &enrollment,
            &[seed.wrapping_add(6); 32],
            seed.wrapping_add(7),
            seed.wrapping_add(8),
        )?;
        let completion = app
            .enroll(ParsedEnrollment {
                token: EnrollmentToken::from_bytes([seed.wrapping_add(6); 32]),
                request: enrollment_request,
            })
            .await?;
        app.hydrate_connector_authorization(tenant_id, connector.connector_id())
            .await?;
        let auth_time = fixture::current_store_timestamp()?;
        let peer = fixture::authenticate_at(index, &ca_der, &completion.credential, auth_time)?;
        let opened = app
            .open_control(
                peer,
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
                    runtime_claims: fixture::claims()?,
                    capacity: fixture::capacity(),
                    last_applied_command_sequence: 0,
                    required_server_capabilities: vec!["agent-route-health.v1".into()],
                },
            )
            .await?;
        let fence = opened.lease.fence();

        let router = dtx_agent_control_server::agent_provisioning_owner_router(Arc::new(
            dtx_agent_control_server::PostgresAgentProvisioningOwnerBackend::new(
                store.clone(),
                tenant_id,
                app,
            ),
        ));
        let approval_id = dtx_domain::ApprovalId::new();
        let approval = fixture::owner_post(
            router,
            &format!("/v1/agent-installations/{installation_id}/identity-approvals"),
            &owner_authorization,
            "route_health_fixture_approval",
            "application/vnd.dirextalk.agent-identity-approval.v1+cbor",
            fixture::approval_body(
                approval_id,
                tenant_id,
                installation_id,
                binding_id,
                agent_device_id,
                agent_identity_id,
                identity_device_id,
                agent_head,
                fingerprint,
                owner_identity_id,
                owner_device_id,
                &owner_device_key,
            )?,
        )
        .await?;
        if approval.0 != axum::http::StatusCode::CREATED {
            return Err(format!(
                "fixture approval failed: {:?}: {}",
                approval.0,
                String::from_utf8_lossy(&approval.1)
            )
            .into());
        }

        let route_id = ConversationId::new();
        let route_fence = [0xD3; 32];
        fixture::install_agent_route_binding_head(
            &store,
            tenant_id,
            owner_identity_id,
            owner_device_id,
            installation_id,
            binding_id,
            agent_device_id,
            &connector,
            route_id,
            route_fence,
        )
        .await?;
        let (bootstrap_id, delivery_id): (Uuid, Uuid) = sqlx::query_as(
            "SELECT bootstrap_id, delivery_id FROM agent.agent_route_bootstraps
              WHERE tenant_id=$1 AND route_id=$2 AND state='installed'",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(route_id))
        .fetch_one(self.harness.admin_pool())
        .await?;
        let bootstrap_id = dtx_domain::AgentRouteBootstrapId::try_from(bootstrap_id)?;
        let delivery_id = dtx_domain::AgentRouteDeliveryId::try_from(delivery_id)?;
        let route_health_key_id = RouteHealthKeyId::new();
        let route_health_key = fixture::key(seed.wrapping_add(9));
        let mut route_session = store.begin_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE agent.agent_route_bootstraps
                SET route_health_key_id=$3, route_health_public_key=$4,
                    route_health_key_purpose='agent-route-health'
              WHERE tenant_id=$1 AND route_id=$2 AND state='installed'",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(route_id))
        .bind(Uuid::from(route_health_key_id))
        .bind(route_health_key.verifying_key().to_bytes().to_vec())
        .execute(route_session.connection())
        .await?;
        route_session.commit().await?;

        Ok(RouteHealthFixture {
            store,
            tenant_id,
            owner_identity_id,
            owner_device_id,
            connector_id: connector.connector_id(),
            installation_id,
            binding_id,
            agent_device_id,
            bootstrap_id,
            delivery_id,
            route_id,
            route_fence,
            route_health_key_id,
            route_health_key,
            connector_generation: fence.generation().get(),
            lease_id: fence.lease_id(),
            lease_epoch: fence.lease_epoch().get(),
            connector_credential: completion.credential,
            peer,
        })
    }
}

impl RouteHealthFixture {
    pub fn signed_request(&self, request_id: RequestId, status_revision: Revision) -> Vec<u8> {
        self.signed_request_with_nonce(request_id, status_revision, [0xD4; 32])
    }

    pub fn signed_request_with_nonce(
        &self,
        request_id: RequestId,
        status_revision: Revision,
        nonce: [u8; 32],
    ) -> Vec<u8> {
        self.signed_request_with_key(&self.route_health_key, request_id, status_revision, nonce)
    }

    pub fn signed_request_with_key(
        &self,
        signing_key: &SigningKey,
        request_id: RequestId,
        status_revision: Revision,
        nonce: [u8; 32],
    ) -> Vec<u8> {
        let now = fixture::now();
        let mut fields = vec![
            (fixture::u(1), fixture::u(1)),
            (fixture::u(2), fixture::text(request_id)),
            (fixture::u(3), fixture::text(self.tenant_id)),
            (fixture::u(4), fixture::text(self.connector_id)),
            (fixture::u(5), fixture::text(self.installation_id)),
            (fixture::u(6), fixture::text(self.binding_id)),
            (fixture::u(7), fixture::text(self.agent_device_id)),
            (fixture::u(8), fixture::text(self.bootstrap_id)),
            (fixture::u(9), fixture::text(self.delivery_id)),
            (fixture::u(10), fixture::text(self.route_id)),
            (fixture::u(11), fixture::u(self.connector_generation)),
            (fixture::u(12), fixture::text(self.lease_id)),
            (fixture::u(13), fixture::u(self.lease_epoch)),
            (fixture::u(14), fixture::bytes(&self.route_fence)),
            (fixture::u(15), fixture::text(self.route_health_key_id)),
            (fixture::u(16), fixture::u(status_revision.get())),
            (fixture::u(17), CanonicalValue::Bool(true)),
            (fixture::u(18), fixture::bytes(&[0xD5; 32])),
            (fixture::u(19), fixture::u(u64::try_from(now).unwrap())),
            (fixture::u(20), fixture::u(u64::try_from(now).unwrap())),
            (
                fixture::u(21),
                fixture::u(u64::try_from(now + 300_000).unwrap()),
            ),
            (fixture::u(22), fixture::bytes(&nonce)),
        ];
        let signed = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone())).unwrap();
        let signature = signing_key.sign(
            Sha256Digest::hash_domain(
                dtx_agent_control_server::ROUTE_HEALTH_SIGNATURE_DOMAIN,
                &signed,
            )
            .as_bytes(),
        );
        fields.push((fixture::u(23), fixture::bytes(&signature.to_bytes())));
        encode_deterministic_cbor(&CanonicalValue::Map(fields)).unwrap()
    }

    pub fn resign_request<F>(&self, bytes: &[u8], mutate: F) -> Vec<u8>
    where
        F: FnOnce(&mut Vec<(CanonicalValue, CanonicalValue)>),
    {
        let CanonicalValue::Map(mut fields) =
            dtx_wire::decode_deterministic_cbor(bytes).expect("fixture request cbor")
        else {
            panic!("fixture request map")
        };
        fields.retain(|(key, _)| *key != fixture::u(23));
        mutate(&mut fields);
        let signed = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone())).unwrap();
        let signature = self.route_health_key.sign(
            Sha256Digest::hash_domain(
                dtx_agent_control_server::ROUTE_HEALTH_SIGNATURE_DOMAIN,
                &signed,
            )
            .as_bytes(),
        );
        fields.push((fixture::u(23), fixture::bytes(&signature.to_bytes())));
        encode_deterministic_cbor(&CanonicalValue::Map(fields)).unwrap()
    }

    pub fn connect_info(&self) -> RouteHealthConnectInfo {
        RouteHealthConnectInfo(self.peer)
    }

    pub async fn post(
        &self,
        request_id: RequestId,
        status_revision: Revision,
        receipt_key_id: RouteHealthKeyId,
        receipt_seed: [u8; 32],
    ) -> Result<axum::response::Response, Box<dyn Error>> {
        let body = self.signed_request(request_id, status_revision);
        self.post_body(body, receipt_key_id, receipt_seed).await
    }

    pub async fn post_body(
        &self,
        body: Vec<u8>,
        receipt_key_id: RouteHealthKeyId,
        receipt_seed: [u8; 32],
    ) -> Result<axum::response::Response, Box<dyn Error>> {
        self.post_body_as_peer(body, receipt_key_id, receipt_seed, self.peer)
            .await
    }

    pub async fn post_body_as_peer(
        &self,
        body: Vec<u8>,
        receipt_key_id: RouteHealthKeyId,
        receipt_seed: [u8; 32],
        peer: AuthenticatedConnectorPeer,
    ) -> Result<axum::response::Response, Box<dyn Error>> {
        let mut request = Request::post("/agent-route/health").body(Body::from(body))?;
        request
            .extensions_mut()
            .insert(axum::extract::connect_info::ConnectInfo(
                RouteHealthConnectInfo(peer),
            ));
        Ok(dtx_agent_control_server::route_health_router_with_state(
            dtx_agent_control_server::RouteHealthHttpState {
                store: self.store.clone(),
                receipt_key_id,
                receipt_seed,
                receipt_keyring: None,
            },
        )
        .oneshot(request)
        .await?)
    }
}
