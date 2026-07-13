use std::{
    fmt::Write as _,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dtx_agent_control::{
    CloseStreamCommand, CommandLog, ConnectorCredential, ConnectorCredentialAuthorization,
    ExactCommandBytes, ServerCommandPayload, Sha256Digest, command_payload_digest,
};
use dtx_agent_control_proto::v1;
use dtx_agent_control_server::{
    ApplicationFuture, ConnectorControlApplication, ConnectorControlApplicationError,
    ConnectorCredentialAuthorizationIndex, CredentialRotationCompletion, EnrollmentCompletion,
    HeartbeatCompletion, OpenControlCompletion, ParsedCommandAcknowledgement,
    ParsedCredentialRotationProof, ParsedEnrollment, ParsedHeartbeat, ParsedHello,
    ParsedLeaseFence, ParsedReady, connector_control_service, connector_tls_incoming,
};
use dtx_connect_registry::{
    AdapterKind, Connector, ConnectorDesiredState, ConnectorFence, ConnectorObservedState,
    ConnectorRevisionSnapshot, ConnectorSnapshot, LeaseStatus,
};
use dtx_domain::{
    BootId, ConnectorCredentialId, ConnectorId, Ed25519PublicKey, HostId, LeaseId, RequestId,
    Revision, TenantId,
};
use dtx_security::{
    AuthenticatedConnectorPeer, ConnectorCredentialAuthorizer, ConnectorMtlsClientVerifier,
    ConnectorWorkloadIdentity, SecretBytes, build_connector_mtls_server_config,
};
use dtx_testkit::{CertificatePurpose, TestCertificateAuthority, WorkloadIdentity};
use ed25519_dalek::SigningKey;
use prost::Message as _;
use rustls::{RootCertStore, pki_types::CertificateDer};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Code, Streaming,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

const HEARTBEAT_INTERVAL_MILLIS: u32 = 5_000;
const HEARTBEAT_TTL_MILLIS: u32 = 90_000;

struct FakeState {
    connector: Connector,
    command_log: CommandLog,
}

struct FakeApplication {
    now_millis: i64,
    identity: ConnectorWorkloadIdentity,
    host_id: HostId,
    expected_fingerprint: dtx_security::CertificateFingerprint,
    authoritative_credential_current: AtomicBool,
    state: Mutex<FakeState>,
    heartbeat_calls: AtomicUsize,
    command_poll_calls: AtomicUsize,
    command_page_size: usize,
}

impl FakeApplication {
    fn new(
        now_millis: i64,
        identity: ConnectorWorkloadIdentity,
        host_id: HostId,
        expected_fingerprint: dtx_security::CertificateFingerprint,
        operation_id: RequestId,
        exact_command_bytes: Vec<u8>,
        payload_digest: Sha256Digest,
    ) -> Self {
        let connector = Connector::try_from_snapshot(ConnectorSnapshot {
            tenant_id: identity.tenant_id(),
            connector_id: identity.connector_id(),
            host_id,
            adapter_kind: AdapterKind::Codex,
            generation: 1,
            desired_state: ConnectorDesiredState::Running,
            observed_state: ConnectorObservedState::Enrolling,
            max_concurrency: 2,
            boots: Vec::new(),
            current_boot_id: None,
            leases: Vec::new(),
            active_lease_index: None,
            highest_lease_epoch: None,
            server_time_high_water_millis: None,
            spec_revision: Revision::INITIAL,
            revisions: vec![ConnectorRevisionSnapshot {
                tenant_id: identity.tenant_id(),
                connector_id: identity.connector_id(),
                revision: Revision::INITIAL,
                generation: 1,
                adapter_kind: AdapterKind::Codex,
                desired_state: ConnectorDesiredState::Running,
                max_concurrency: 2,
            }],
        })
        .expect("fixture Connector snapshot is coherent");
        let mut command_log = CommandLog::new(
            identity.tenant_id(),
            identity.connector_id(),
            1,
            Revision::INITIAL,
        )
        .expect("fixture command log is coherent");
        command_log
            .append(
                1,
                Revision::INITIAL,
                operation_id,
                ServerCommandPayload::CloseStream(CloseStreamCommand::reconnect()),
                payload_digest,
                ExactCommandBytes::new(exact_command_bytes)
                    .expect("fixture command bytes are bounded"),
            )
            .expect("fixture command appends");
        Self {
            now_millis,
            identity,
            host_id,
            expected_fingerprint,
            authoritative_credential_current: AtomicBool::new(true),
            state: Mutex::new(FakeState {
                connector,
                command_log,
            }),
            heartbeat_calls: AtomicUsize::new(0),
            command_poll_calls: AtomicUsize::new(0),
            command_page_size: 64,
        }
    }

    fn validate_peer(
        &self,
        peer: AuthenticatedConnectorPeer,
    ) -> Result<(), ConnectorControlApplicationError> {
        if peer.identity() != self.identity
            || peer.certificate_fingerprint() != self.expected_fingerprint
            || !self.authoritative_credential_current.load(Ordering::SeqCst)
        {
            Err(ConnectorControlApplicationError::AuthenticationFailed)
        } else {
            Ok(())
        }
    }

    fn acknowledged_sequence(&self) -> u64 {
        self.state
            .lock()
            .expect("fixture state is available")
            .command_log
            .acknowledged_sequence()
    }

    fn revoke_authoritative_credential(&self) {
        self.authoritative_credential_current
            .store(false, Ordering::SeqCst);
    }

    fn append_reconnect_commands(&self, count: usize) {
        let mut state = self.state.lock().expect("fixture state is available");
        for _ in 0..count {
            let sequence = state
                .command_log
                .next_sequence()
                .expect("fixture command sequence is bounded");
            let operation_id = RequestId::new();
            let payload = v1::CloseStream {
                reason: v1::CloseStreamReason::Reconnect as i32,
                stable_code: "RECONNECT".to_owned(),
                redacted_detail: String::new(),
            };
            let payload_digest = command_payload_digest(&payload.encode_to_vec())
                .expect("fixture payload digest is valid");
            let command = v1::DurableCommand {
                command_sequence: sequence,
                operation_id: operation_id.to_string(),
                connector_generation: 1,
                spec_revision: Revision::INITIAL.get(),
                payload_digest: payload_digest.as_bytes().to_vec(),
                command: Some(v1::durable_command::Command::CloseStream(payload)),
            }
            .encode_to_vec();
            state
                .command_log
                .append(
                    1,
                    Revision::INITIAL,
                    operation_id,
                    ServerCommandPayload::CloseStream(CloseStreamCommand::reconnect()),
                    payload_digest,
                    ExactCommandBytes::new(command).expect("fixture bytes are bounded"),
                )
                .expect("fixture command appends");
        }
    }
}

impl ConnectorControlApplication for FakeApplication {
    fn now_utc_millis(&self) -> Result<i64, ConnectorControlApplicationError> {
        Ok(self.now_millis)
    }

    fn enroll(&self, _request: ParsedEnrollment) -> ApplicationFuture<'_, EnrollmentCompletion> {
        application_result(Err(ConnectorControlApplicationError::PermissionDenied))
    }

    fn open_control(
        &self,
        peer: AuthenticatedConnectorPeer,
        hello: ParsedHello,
    ) -> ApplicationFuture<'_, OpenControlCompletion> {
        let result = (|| {
            self.validate_peer(peer)?;
            if hello.tenant_id != self.identity.tenant_id()
                || hello.connector_id != self.identity.connector_id()
                || hello.host_id != self.host_id
                || hello.connector_generation != 1
                || hello.spec_revision != Revision::INITIAL
                || !hello.protocol.supports(1, 0)
                || hello.capacity.maximum_concurrent_runs != 2
            {
                return Err(ConnectorControlApplicationError::InvalidRequest);
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            state
                .connector
                .begin_boot(hello.boot_id, self.now_millis)
                .map_err(|_| ConnectorControlApplicationError::Conflict)?;
            let fence = state
                .connector
                .issue_lease(
                    LeaseId::new(),
                    hello.boot_id,
                    self.now_millis,
                    self.now_millis + i64::from(HEARTBEAT_TTL_MILLIS),
                )
                .map_err(|_| ConnectorControlApplicationError::Conflict)?;
            let lease = *state
                .connector
                .leases()
                .iter()
                .find(|lease| lease.fence() == fence)
                .ok_or(ConnectorControlApplicationError::Internal)?;
            let replay_commands = state
                .command_log
                .resume(
                    hello.last_applied_command_sequence,
                    hello.connector_generation,
                    hello.spec_revision,
                )
                .map_err(|_| ConnectorControlApplicationError::Conflict)?
                .iter()
                .take(self.command_page_size)
                .cloned()
                .collect();
            Ok(OpenControlCompletion {
                lease,
                protocol_minor: 0,
                heartbeat_interval_millis: HEARTBEAT_INTERVAL_MILLIS,
                heartbeat_ttl_millis: HEARTBEAT_TTL_MILLIS,
                acknowledged_command_sequence: state.command_log.acknowledged_sequence(),
                replay_commands,
            })
        })();
        application_result(result)
    }

    fn ready(
        &self,
        peer: AuthenticatedConnectorPeer,
        ready: ParsedReady,
    ) -> ApplicationFuture<'_, ()> {
        let result = self.validate_peer(peer).and_then(|()| {
            let state = self
                .state
                .lock()
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            matching_fence(&state.connector, ready.fence).map(|_| ())
        });
        application_result(result)
    }

    fn heartbeat(
        &self,
        peer: AuthenticatedConnectorPeer,
        heartbeat: ParsedHeartbeat,
    ) -> ApplicationFuture<'_, HeartbeatCompletion> {
        let result = (|| {
            self.validate_peer(peer)?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            let fence = matching_fence(&state.connector, heartbeat.fence)?;
            let acknowledgement = state
                .connector
                .record_heartbeat(
                    &fence,
                    heartbeat.heartbeat_sequence,
                    self.now_millis,
                    ConnectorObservedState::Ready,
                    heartbeat.capacity.available_concurrent_runs,
                    1,
                )
                .map_err(|_| ConnectorControlApplicationError::StaleFence)?;
            self.heartbeat_calls.fetch_add(1, Ordering::SeqCst);
            Ok(HeartbeatCompletion {
                acknowledgement,
                observed_at_millis: self.now_millis,
            })
        })();
        application_result(result)
    }

    fn acknowledge_command(
        &self,
        peer: AuthenticatedConnectorPeer,
        acknowledgement: ParsedCommandAcknowledgement,
    ) -> ApplicationFuture<'_, ()> {
        let result = (|| {
            self.validate_peer(peer)?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            matching_fence(&state.connector, acknowledgement.fence)?;
            let spec_revision = state.command_log.spec_revision();
            state
                .command_log
                .acknowledge(acknowledgement.command_ack(spec_revision))
                .map_err(|_| ConnectorControlApplicationError::Conflict)
        })();
        application_result(result)
    }

    fn rotate_credential(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _proof: ParsedCredentialRotationProof,
    ) -> ApplicationFuture<'_, CredentialRotationCompletion> {
        application_result(Err(ConnectorControlApplicationError::PermissionDenied))
    }

    fn poll_commands(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
    ) -> ApplicationFuture<'_, Vec<dtx_agent_control::DurableServerCommand>> {
        let result = self.validate_peer(peer).and_then(|()| {
            let state = self
                .state
                .lock()
                .map_err(|_| ConnectorControlApplicationError::Unavailable)?;
            let _ = matching_fence(
                &state.connector,
                ParsedLeaseFence {
                    tenant_id: fence.tenant_id(),
                    connector_id: fence.connector_id(),
                    boot_id: fence.boot_id(),
                    connector_generation: fence.generation().get(),
                    lease_id: fence.lease_id(),
                    lease_epoch: fence.lease_epoch().get(),
                },
            )?;
            if after_sequence < state.command_log.acknowledged_sequence()
                || after_sequence > state.command_log.commands().len() as u64
            {
                return Err(ConnectorControlApplicationError::StaleFence);
            }
            self.command_poll_calls.fetch_add(1, Ordering::SeqCst);
            Ok(state
                .command_log
                .commands()
                .iter()
                .skip(
                    usize::try_from(after_sequence)
                        .map_err(|_| ConnectorControlApplicationError::StaleFence)?,
                )
                .take(self.command_page_size)
                .cloned()
                .collect())
        });
        application_result(result)
    }
}

fn application_result<T: Send + 'static>(
    result: Result<T, ConnectorControlApplicationError>,
) -> ApplicationFuture<'static, T> {
    Box::pin(async move { result })
}

fn matching_fence(
    connector: &Connector,
    presented: ParsedLeaseFence,
) -> Result<ConnectorFence, ConnectorControlApplicationError> {
    let fence = connector
        .leases()
        .last()
        .filter(|lease| lease.status() == LeaseStatus::Active)
        .map(dtx_connect_registry::ConnectorLease::fence)
        .ok_or(ConnectorControlApplicationError::StaleFence)?;
    if fence.tenant_id() == presented.tenant_id
        && fence.connector_id() == presented.connector_id
        && fence.boot_id() == presented.boot_id
        && fence.generation().get() == presented.connector_generation
        && fence.lease_id() == presented.lease_id
        && fence.lease_epoch().get() == presented.lease_epoch
    {
        Ok(fence)
    } else {
        Err(ConnectorControlApplicationError::StaleFence)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn real_mtls_control_uses_application_authority_not_the_local_tls_index() {
    let now_millis = current_time_millis();
    let ca = TestCertificateAuthority::new(now_millis).expect("test CA created");
    let identity = ConnectorWorkloadIdentity::new(TenantId::new(), ConnectorId::new());
    let host_id = HostId::new();
    let client_certificate = ca
        .issue(
            &WorkloadIdentity::from(identity),
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("Connector client certificate issued");
    let unknown_client_certificate = ca
        .issue(
            &WorkloadIdentity::from(identity),
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("same-identity unknown client certificate issued");
    let server_certificate = ca
        .issue(
            &WorkloadIdentity::ControlServer {
                dns_name: "localhost".to_owned(),
            },
            CertificatePurpose::ServerAuth,
            now_millis,
            300,
        )
        .expect("control server certificate issued");

    let control_key = public_key(7);
    let refresh_key = public_key(11);
    let credential = ConnectorCredential::new(
        ConnectorCredentialId::new(),
        identity.tenant_id(),
        identity.connector_id(),
        1,
        Revision::INITIAL,
        control_key,
        refresh_key,
        Sha256Digest::from_bytes(*client_certificate.certificate_fingerprint().as_bytes()),
        vec![client_certificate.certificate_der().to_vec()],
        client_certificate.not_before_millis(),
        client_certificate.not_after_millis(),
    )
    .expect("public credential matches the client leaf");
    let mut credential_authorization =
        ConnectorCredentialAuthorization::new(credential).expect("credential head created");
    let current_authorization_snapshot = credential_authorization.snapshot();
    let authorization_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());

    let roots = test_roots(&ca);
    let verifier = ConnectorMtlsClientVerifier::new(
        Arc::clone(&roots),
        Arc::clone(&authorization_index) as Arc<dyn ConnectorCredentialAuthorizer>,
    )
    .expect("Connector verifier builds");
    let verifier = Arc::new(verifier);
    let server_config = server_config(&server_certificate, verifier.as_ref().clone());
    let client_tls = client_tls_config(&ca, &client_certificate);
    let unknown_client_tls = client_tls_config(&ca, &unknown_client_certificate);

    let (operation_id, expected_command, expected_payload_digest, expected_encoded_digest) =
        exact_command();
    let application = Arc::new(FakeApplication::new(
        now_millis,
        identity,
        host_id,
        client_certificate.certificate_fingerprint(),
        operation_id,
        expected_command.clone(),
        expected_payload_digest,
    ));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener.local_addr().expect("loopback address available");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server_application: Arc<dyn ConnectorControlApplication> = application.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .serve_with_incoming_shutdown(
                connector_control_service(server_application, verifier),
                connector_tls_incoming(listener, Arc::new(server_config)),
                async {
                    let _ = shutdown_receiver.await;
                },
            )
            .await
    });

    let first_boot = BootId::new();
    let (first_sender, mut first_responses) = open_control(
        address,
        client_tls.clone(),
        hello(identity, host_id, first_boot, 0),
    )
    .await;
    let first_lease = expect_lease(&mut first_responses).await;
    let first_command = expect_command(&mut first_responses).await;
    assert_eq!(first_command.encoded_command, expected_command);
    assert_eq!(
        first_command.encoded_command_digest,
        expected_encoded_digest.as_bytes()
    );
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(
        application.command_poll_calls.load(Ordering::SeqCst),
        1,
        "an idle stream performs only subscribe-then-replay, not fixed one-hertz polling",
    );
    send_heartbeat(&first_sender, first_lease.clone(), 1).await;
    expect_heartbeat_ack(&mut first_responses, 1).await;
    drop(first_sender);
    drop(first_responses);

    let second_boot = BootId::new();
    let (second_sender, mut second_responses) = open_control(
        address,
        client_tls.clone(),
        hello(identity, host_id, second_boot, 0),
    )
    .await;
    let second_lease = expect_lease(&mut second_responses).await;
    let replayed_command = expect_command(&mut second_responses).await;
    assert_eq!(
        replayed_command, first_command,
        "a lost ACK must replay the exact retained frame bytes and digest"
    );
    second_sender
        .send(v1::ClientFrame {
            kind: Some(v1::client_frame::Kind::CommandAcknowledgement(
                v1::CommandAcknowledgement {
                    fence: Some(second_lease.clone()),
                    command_sequence: 1,
                    payload_digest: expected_payload_digest.as_bytes().to_vec(),
                    encoded_command_digest: expected_encoded_digest.as_bytes().to_vec(),
                },
            )),
        })
        .await
        .expect("command ACK sent");
    send_heartbeat(&second_sender, second_lease, 1).await;
    expect_heartbeat_ack(&mut second_responses, 1).await;
    assert_eq!(application.acknowledged_sequence(), 1);
    drop(second_sender);
    drop(second_responses);

    application.append_reconnect_commands(130);
    let (paged_sender, mut paged_responses) = open_control(
        address,
        client_tls.clone(),
        hello(identity, host_id, BootId::new(), 1),
    )
    .await;
    let paged_lease = expect_lease(&mut paged_responses).await;
    for expected_sequence in 2..=131 {
        let command_frame = expect_command(&mut paged_responses).await;
        let command = v1::DurableCommand::decode(command_frame.encoded_command.as_slice())
            .expect("paged command uses the reviewed durable encoding");
        assert_eq!(command.command_sequence, expected_sequence);
        paged_sender
            .send(v1::ClientFrame {
                kind: Some(v1::client_frame::Kind::CommandAcknowledgement(
                    v1::CommandAcknowledgement {
                        fence: Some(paged_lease.clone()),
                        command_sequence: command.command_sequence,
                        payload_digest: command.payload_digest,
                        encoded_command_digest: command_frame.encoded_command_digest,
                    },
                )),
            })
            .await
            .expect("paged command ACK sent");
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while application.acknowledged_sequence() != 131 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every paged command ACK is durably observed");
    assert!(
        application.command_poll_calls.load(Ordering::SeqCst) >= 5,
        "reconnect must immediately drain every bounded page without another notification",
    );
    drop(paged_sender);
    drop(paged_responses);

    let (unknown_sender, mut unknown_responses) = open_control(
        address,
        unknown_client_tls,
        hello(identity, host_id, BootId::new(), 1),
    )
    .await;
    let unknown_status = unknown_responses
        .message()
        .await
        .expect_err("the application rejects a DB-unknown certificate fingerprint");
    assert_eq!(unknown_status.code(), Code::Unauthenticated);
    assert_eq!(unknown_status.message(), "AUTHENTICATION_FAILED");
    drop(unknown_sender);

    // Refill the independent per-identity rate bucket so the next assertion
    // isolates permit lifetime rather than intentionally bounded connect rate.
    tokio::time::sleep(Duration::from_millis(4_100)).await;
    let third_boot = BootId::new();
    let (third_sender, mut third_responses) = open_control(
        address,
        client_tls.clone(),
        hello(identity, host_id, third_boot, 131),
    )
    .await;
    let third_lease = expect_lease(&mut third_responses).await;
    credential_authorization
        .revoke()
        .expect("credential head revokes");
    authorization_index
        .replace(&credential_authorization.snapshot())
        .expect("local authorization cache is stale-revoked");
    send_heartbeat(&third_sender, third_lease, 1).await;
    expect_heartbeat_ack(&mut third_responses, 1).await;
    assert_eq!(
        application.heartbeat_calls.load(Ordering::SeqCst),
        3,
        "stale local revocation cannot block the authoritative application method"
    );

    authorization_index
        .replace(&current_authorization_snapshot)
        .expect("local authorization cache is stale-current");

    let (fourth_sender, mut fourth_responses) = open_control(
        address,
        client_tls.clone(),
        hello(identity, host_id, BootId::new(), 131),
    )
    .await;
    let _fourth_lease = expect_lease(&mut fourth_responses).await;
    let (fifth_sender, mut fifth_responses) = open_control(
        address,
        client_tls,
        hello(identity, host_id, BootId::new(), 131),
    )
    .await;
    let fifth_lease = expect_lease(&mut fifth_responses).await;

    application.revoke_authoritative_credential();
    send_heartbeat(&fifth_sender, fifth_lease, 1).await;
    let status = fifth_responses
        .message()
        .await
        .expect_err("the application rejects its authoritative credential revocation");
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(status.message(), "AUTHENTICATION_FAILED");
    assert_eq!(
        application.heartbeat_calls.load(Ordering::SeqCst),
        3,
        "application revocation fails closed before the heartbeat mutation"
    );

    drop(third_sender);
    drop(fourth_sender);
    drop(fifth_sender);
    shutdown_sender.send(()).expect("server shutdown sent");
    server
        .await
        .expect("control server task joins")
        .expect("control server exits cleanly");
}

fn exact_command() -> (RequestId, Vec<u8>, Sha256Digest, Sha256Digest) {
    let payload = v1::CloseStream {
        reason: v1::CloseStreamReason::Reconnect as i32,
        stable_code: "RECONNECT".to_owned(),
        redacted_detail: String::new(),
    };
    let payload_digest =
        command_payload_digest(&payload.encode_to_vec()).expect("payload digest created");
    let operation_id = RequestId::new();
    let command = v1::DurableCommand {
        command_sequence: 1,
        operation_id: operation_id.to_string(),
        connector_generation: 1,
        spec_revision: Revision::INITIAL.get(),
        payload_digest: payload_digest.as_bytes().to_vec(),
        command: Some(v1::durable_command::Command::CloseStream(payload)),
    }
    .encode_to_vec();
    let exact = ExactCommandBytes::new(command.clone()).expect("exact command is bounded");
    (
        operation_id,
        command,
        payload_digest,
        exact.encoded_command_digest(),
    )
}

fn public_key(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::try_from(
        *SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
    .expect("fixture verification key is canonical and non-weak")
}

fn test_roots(ca: &TestCertificateAuthority) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.ca_certificate_der().to_vec()))
        .expect("test CA root is valid");
    Arc::new(roots)
}

fn server_config(
    certificate: &dtx_testkit::IssuedTestCertificate,
    verifier: ConnectorMtlsClientVerifier,
) -> rustls::ServerConfig {
    let mut config = None;
    certificate.expose_private_key(|key| {
        config = Some(
            build_connector_mtls_server_config(
                verifier,
                vec![certificate.certificate_der().to_vec()],
                SecretBytes::new(key.to_vec()).expect("fixture key is bounded"),
            )
            .expect("mTLS server config builds"),
        );
    });
    config.expect("private-key callback ran")
}

fn client_tls_config(
    ca: &TestCertificateAuthority,
    certificate: &dtx_testkit::IssuedTestCertificate,
) -> ClientTlsConfig {
    let certificate_pem = pem("CERTIFICATE", certificate.certificate_der());
    let mut identity = None;
    certificate.expose_private_key(|key| {
        identity = Some(Identity::from_pem(
            &certificate_pem,
            pem("PRIVATE KEY", key),
        ));
    });
    ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(pem(
            "CERTIFICATE",
            ca.ca_certificate_der(),
        )))
        .identity(identity.expect("private-key callback ran"))
        .assume_http2(true)
}

async fn open_control(
    address: SocketAddr,
    tls: ClientTlsConfig,
    hello: v1::Hello,
) -> (mpsc::Sender<v1::ClientFrame>, Streaming<v1::ServerFrame>) {
    let channel = Endpoint::from_shared(format!("https://{address}"))
        .expect("loopback endpoint is valid")
        .connect_timeout(Duration::from_secs(5))
        .tls_config(tls)
        .expect("client TLS config is valid")
        .connect()
        .await
        .expect("real mTLS channel connects");
    open_control_on_channel(channel, hello).await
}

async fn open_control_on_channel(
    channel: Channel,
    hello: v1::Hello,
) -> (mpsc::Sender<v1::ClientFrame>, Streaming<v1::ServerFrame>) {
    let mut client = v1::connector_control_client::ConnectorControlClient::new(channel);
    let (sender, receiver) = mpsc::channel(8);
    sender
        .send(v1::ClientFrame {
            kind: Some(v1::client_frame::Kind::Hello(hello)),
        })
        .await
        .expect("Hello queued");
    let response = client
        .control(ReceiverStream::new(receiver))
        .await
        .expect("control stream opens")
        .into_inner();
    (sender, response)
}

fn hello(
    identity: ConnectorWorkloadIdentity,
    host_id: HostId,
    boot_id: BootId,
    last_applied_command_sequence: u64,
) -> v1::Hello {
    v1::Hello {
        tenant_id: identity.tenant_id().to_string(),
        connector_id: identity.connector_id().to_string(),
        host_id: host_id.to_string(),
        boot_id: boot_id.to_string(),
        connector_generation: 1,
        spec_revision: Revision::INITIAL.get(),
        protocol: Some(v1::ProtocolRange {
            minimum_major: 1,
            minimum_minor: 0,
            maximum_major: 1,
            maximum_minor: 0,
        }),
        runtime_claims: Some(runtime_claims()),
        capacity: Some(capacity()),
        last_applied_command_sequence,
        required_server_capabilities: Vec::new(),
    }
}

fn runtime_claims() -> v1::RuntimeClaims {
    v1::RuntimeClaims {
        runtime_kind: "codex".to_owned(),
        runtime_version: "fixture-1".to_owned(),
        adapter_build_digest: vec![23; 32],
        capabilities: vec!["agent.control".to_owned()],
        queue_depth: 0,
        active_run_ids: Vec::new(),
        stable_error_code: String::new(),
    }
}

const fn capacity() -> v1::Capacity {
    v1::Capacity {
        maximum_concurrent_runs: 2,
        available_concurrent_runs: 2,
        maximum_queue_depth: 16,
    }
}

async fn send_heartbeat(
    sender: &mpsc::Sender<v1::ClientFrame>,
    fence: v1::LeaseFence,
    sequence: u64,
) {
    sender
        .send(v1::ClientFrame {
            kind: Some(v1::client_frame::Kind::Heartbeat(v1::Heartbeat {
                fence: Some(fence),
                heartbeat_sequence: sequence,
                applied_config_revision: Revision::INITIAL.get(),
                applied_command_sequence: 0,
                runtime_claims: Some(runtime_claims()),
                capacity: Some(capacity()),
            })),
        })
        .await
        .expect("heartbeat sent");
}

async fn expect_lease(responses: &mut Streaming<v1::ServerFrame>) -> v1::LeaseFence {
    match responses
        .message()
        .await
        .expect("lease response is valid")
        .and_then(|frame| frame.kind)
    {
        Some(v1::server_frame::Kind::ConnectLease(lease)) => {
            lease.fence.expect("lease includes a fence")
        }
        other => panic!("expected ConnectLease, received {other:?}"),
    }
}

async fn expect_command(responses: &mut Streaming<v1::ServerFrame>) -> v1::DurableCommandFrame {
    match responses
        .message()
        .await
        .expect("command response is valid")
        .and_then(|frame| frame.kind)
    {
        Some(v1::server_frame::Kind::DurableCommand(command)) => command,
        other => panic!("expected DurableCommand, received {other:?}"),
    }
}

async fn expect_heartbeat_ack(responses: &mut Streaming<v1::ServerFrame>, sequence: u64) {
    match responses
        .message()
        .await
        .expect("heartbeat response is valid")
        .and_then(|frame| frame.kind)
    {
        Some(v1::server_frame::Kind::HeartbeatAcknowledgement(acknowledgement)) => {
            assert_eq!(acknowledgement.heartbeat_sequence, sequence);
        }
        other => panic!("expected HeartbeatAcknowledgement, received {other:?}"),
    }
}

fn current_time_millis() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after Unix epoch")
            .as_millis(),
    )
    .expect("current time fits in i64")
}

fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        encoded.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        encoded.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }

    let mut result = format!("-----BEGIN {label}-----\n");
    for (index, character) in encoded.chars().enumerate() {
        result.push(character);
        if (index + 1).is_multiple_of(64) {
            result.push('\n');
        }
    }
    if !encoded.len().is_multiple_of(64) {
        result.push('\n');
    }
    writeln!(&mut result, "-----END {label}-----").expect("writing to a String cannot fail");
    result
}
