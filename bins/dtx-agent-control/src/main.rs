#![forbid(unsafe_code)]

mod config;

use std::{
    env, fmt, fs,
    io::{self, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    routing::get,
};
use config::BootstrapConfig;
use dtx_agent_control_server::{
    AgentRunIngressApplication, ConnectorCertificateAuthority, ConnectorControlApplication,
    ConnectorCredentialAuthorizationIndex, PostgresAgentProvisioningOwnerBackend,
    PostgresConnectorControlApplication, ProtobufDurableCommandDecoder,
    agent_provisioning_owner_router, agent_run_ingress_service, connector_control_service,
    connector_enrollment_service, connector_tls_incoming, tls_incoming,
};
use dtx_security::{
    ConnectorCredentialAuthorizer, ConnectorMtlsClientVerifier, InternalServiceKind,
    InternalServiceMtlsClientVerifier, SecretBytes, build_connector_mtls_server_config,
    build_internal_service_mtls_server_config,
};
use dtx_storage::PgStore;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
    server::NoServerSessionStorage,
};
use sqlx::postgres::PgConnectOptions;
use tokio::{net::TcpListener, sync::oneshot};
use tonic::transport::Server;
use zeroize::{Zeroize as _, Zeroizing};

const MAX_PEM_BUNDLE_BYTES: u64 = 1_048_576;
const MAX_DATABASE_URL_BYTES: u64 = 8_192;
const READINESS_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const REQUIRED_FUNCTION_PRIVILEGES: &[(&str, &str)] = &[
    ("system.current_tenant_id()", "EXECUTE"),
    ("system.is_uuid_v7(uuid)", "EXECUTE"),
    ("system.is_stable_code(text,integer)", "EXECUTE"),
    ("agent.is_public_id(text,text)", "EXECUTE"),
    (
        "agent.connector_certificate_chain_valid(bytea[])",
        "EXECUTE",
    ),
    (
        "agent.connector_runtime_name_valid(text,integer)",
        "EXECUTE",
    ),
    ("agent.connector_claim_codes_valid(text[])", "EXECUTE"),
    ("agent.connector_run_ids_valid(uuid[])", "EXECUTE"),
    ("agent.connector_runtime_error_code_valid(text)", "EXECUTE"),
    (
        "agent.prune_connector_runtime_claim_history(uuid,uuid,integer)",
        "EXECUTE",
    ),
    ("agent.router_stable_names(text[])", "EXECUTE"),
    ("identity.identity_agent_reader_authorized()", "EXECUTE"),
];
const REQUIRED_TABLE_PRIVILEGES: &[(&str, &str)] = &[
    ("agent.hosts", "SELECT"),
    ("agent.installations", "SELECT"),
    ("agent.agent_devices", "SELECT"),
    ("identity.device_sessions", "SELECT"),
    ("identity.log_heads", "SELECT"),
    ("identity.log_entries", "SELECT"),
    ("agent.agent_identity_approvals", "SELECT"),
    ("agent.agent_identity_approvals", "INSERT"),
    ("agent.agent_provisioning_recipients", "SELECT"),
    ("agent.agent_provisioning_recipients", "INSERT"),
    ("agent.agent_provisioning_recipients", "UPDATE"),
    ("agent.agent_provisioning_deliveries", "SELECT"),
    ("agent.agent_provisioning_deliveries", "INSERT"),
    ("agent.agent_provisioning_deliveries", "UPDATE"),
    ("agent.agent_provisioning_outbox", "INSERT"),
    ("agent.agent_installation_revocations", "SELECT"),
    ("agent.agent_installation_revocations", "INSERT"),
    ("agent.connector_conformance", "SELECT"),
    ("agent.binding_set_heads", "SELECT"),
    ("agent.installation_routing_policies", "SELECT"),
    ("agent.connector_bindings", "SELECT"),
    ("agent.conversation_grant_ids", "SELECT"),
    ("agent.conversation_grant_versions", "SELECT"),
    ("agent.conversation_grant_heads", "SELECT"),
    ("agent.conversation_grant_permissions", "SELECT"),
    ("agent.conversation_grant_cloud_connections", "SELECT"),
    ("agent.connector_instances", "SELECT"),
    ("agent.connector_instances", "INSERT"),
    ("agent.connector_instances", "UPDATE"),
    ("agent.connector_revisions", "SELECT"),
    ("agent.connector_revisions", "INSERT"),
    ("agent.connector_boots", "SELECT"),
    ("agent.connector_boots", "INSERT"),
    ("agent.connector_boots", "UPDATE"),
    ("agent.connector_leases", "SELECT"),
    ("agent.connector_leases", "INSERT"),
    ("agent.connector_leases", "UPDATE"),
    ("agent.connector_enrollment_intents", "SELECT"),
    ("agent.connector_enrollment_intents", "INSERT"),
    ("agent.connector_enrollment_intents", "UPDATE"),
    ("agent.connector_control_operations", "SELECT"),
    ("agent.connector_control_operations", "INSERT"),
    ("agent.connector_control_credentials", "SELECT"),
    ("agent.connector_control_credentials", "INSERT"),
    ("agent.connector_control_credential_revisions", "SELECT"),
    ("agent.connector_control_credential_revisions", "INSERT"),
    ("agent.connector_control_credential_rotations", "SELECT"),
    ("agent.connector_control_credential_rotations", "INSERT"),
    ("agent.connector_control_credential_heads", "SELECT"),
    ("agent.connector_control_credential_heads", "INSERT"),
    ("agent.connector_control_credential_heads", "UPDATE"),
    ("agent.connector_runtime_claims", "SELECT"),
    ("agent.connector_runtime_claims", "INSERT"),
    ("agent.connector_runtime_claim_heads", "SELECT"),
    ("agent.connector_runtime_claim_heads", "INSERT"),
    ("agent.connector_runtime_claim_heads", "UPDATE"),
    ("agent.connector_control_stream_heads", "SELECT"),
    ("agent.connector_control_stream_heads", "INSERT"),
    ("agent.connector_control_stream_heads", "UPDATE"),
    ("agent.connector_control_commands", "SELECT"),
    ("agent.connector_control_commands", "INSERT"),
    ("agent.agent_runs", "SELECT"),
    ("agent.agent_runs", "INSERT"),
    ("agent.agent_runs", "UPDATE"),
    ("agent.agent_run_candidates", "SELECT"),
    ("agent.agent_run_candidates", "INSERT"),
    ("agent.connector_run_capacity_heads", "SELECT"),
    ("agent.connector_run_capacity_heads", "INSERT"),
    ("agent.connector_run_capacity_heads", "UPDATE"),
    ("agent.binding_run_capacity_heads", "SELECT"),
    ("agent.binding_run_capacity_heads", "INSERT"),
    ("agent.binding_run_capacity_heads", "UPDATE"),
    ("agent.agent_run_offers", "SELECT"),
    ("agent.agent_run_offers", "INSERT"),
    ("agent.agent_run_offers", "UPDATE"),
    ("agent.agent_run_leases", "SELECT"),
    ("agent.agent_run_leases", "INSERT"),
    ("agent.agent_run_leases", "UPDATE"),
];

#[tokio::main]
async fn main() -> ExitCode {
    match Box::pin(run()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dtx-agent-control: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)] // One fail-closed bootstrap boundary owns every listener.
async fn run() -> Result<(), BootstrapError> {
    let config = BootstrapConfig::load(&config_path()?).map_err(|_| BootstrapError::Config)?;
    let enrollment_listener = TcpListener::bind(config.enrollment.listen)
        .await
        .map_err(|_| BootstrapError::Bind)?;
    let control_listener = TcpListener::bind(config.control.listen)
        .await
        .map_err(|_| BootstrapError::Bind)?;
    let legacy_gateway_listener = TcpListener::bind(config.legacy_gateway.listen)
        .await
        .map_err(|_| BootstrapError::Bind)?;
    let health_listener = TcpListener::bind(config.health.listen)
        .await
        .map_err(|_| BootstrapError::Bind)?;
    let owner_api_listener = TcpListener::bind(config.owner_api.listen)
        .await
        .map_err(|_| BootstrapError::Bind)?;

    let database_options = load_database_options(&config.database_url_file)?;
    let store = PgStore::connect(database_options, config.max_database_connections)
        .await
        .map_err(|_| BootstrapError::Database)?;
    let health_store = store.clone();
    let owner_api_store = store.clone();
    let accepting_requests = Arc::new(AtomicBool::new(false));

    let authorization_index = Arc::new(ConnectorCredentialAuthorizationIndex::new());
    let authorizer: Arc<dyn ConnectorCredentialAuthorizer> = authorization_index.clone();
    let connector_roots = Arc::new(load_root_store(&config.control.client_ca_bundle_pem)?);
    let verifier = ConnectorMtlsClientVerifier::new(connector_roots, authorizer)
        .map_err(|_| BootstrapError::Tls)?;
    let control_server_config = build_connector_mtls_server_config(
        verifier.clone(),
        load_certificate_chain(&config.control.certificate_chain_pem)?,
        load_private_key(&config.control.private_key_pkcs8_pem)?,
    )
    .map_err(|_| BootstrapError::Tls)?;
    let gateway_roots = Arc::new(load_root_store(
        &config.legacy_gateway.client_ca_bundle_pem,
    )?);
    let gateway_verifier = InternalServiceMtlsClientVerifier::new(
        gateway_roots,
        InternalServiceKind::LegacyMatrixGateway,
    )
    .map_err(|_| BootstrapError::Tls)?;
    let legacy_gateway_server_config = build_internal_service_mtls_server_config(
        gateway_verifier.clone(),
        load_certificate_chain(&config.legacy_gateway.certificate_chain_pem)?,
        load_private_key(&config.legacy_gateway.private_key_pkcs8_pem)?,
    )
    .map_err(|_| BootstrapError::Tls)?;
    let enrollment_server_config = build_server_auth_tls_config(
        load_certificate_chain(&config.enrollment.certificate_chain_pem)?,
        load_private_key(&config.enrollment.private_key_pkcs8_pem)?,
    )?;
    let verifier = Arc::new(verifier);
    let gateway_verifier = Arc::new(gateway_verifier);

    let issuer_certificate = load_single_certificate(&config.connector_issuer.certificate)?;
    let issuer_intermediates = config
        .connector_issuer
        .response_intermediates
        .as_deref()
        .map(load_certificate_chain)
        .transpose()?
        .unwrap_or_default();
    let issuer = Arc::new(
        ConnectorCertificateAuthority::from_ed25519_pkcs8(
            issuer_certificate,
            load_private_key(&config.connector_issuer.private_key)?,
            issuer_intermediates,
        )
        .map_err(|_| BootstrapError::Tls)?,
    );
    let application = Arc::new(PostgresConnectorControlApplication::new(
        store,
        issuer,
        authorization_index,
        Arc::new(ProtobufDurableCommandDecoder),
    ));
    let enrollment_application: Arc<dyn ConnectorControlApplication> = application.clone();
    let control_application: Arc<dyn ConnectorControlApplication> = application.clone();
    let gateway_application: Arc<dyn AgentRunIngressApplication> = application;

    let (enrollment_shutdown_tx, enrollment_shutdown_rx) = oneshot::channel();
    let (control_shutdown_tx, control_shutdown_rx) = oneshot::channel();
    let (legacy_gateway_shutdown_tx, legacy_gateway_shutdown_rx) = oneshot::channel();
    let (health_shutdown_tx, health_shutdown_rx) = oneshot::channel();
    let (owner_api_shutdown_tx, owner_api_shutdown_rx) = oneshot::channel();
    let enrollment_server = Server::builder().serve_with_incoming_shutdown(
        connector_enrollment_service(enrollment_application),
        tls_incoming(enrollment_listener, Arc::new(enrollment_server_config)),
        async {
            let _ = enrollment_shutdown_rx.await;
        },
    );
    let control_server = Server::builder().serve_with_incoming_shutdown(
        connector_control_service(control_application, verifier),
        connector_tls_incoming(control_listener, Arc::new(control_server_config)),
        async {
            let _ = control_shutdown_rx.await;
        },
    );
    let legacy_gateway_server = Server::builder().serve_with_incoming_shutdown(
        agent_run_ingress_service(gateway_application, gateway_verifier),
        tls_incoming(
            legacy_gateway_listener,
            Arc::new(legacy_gateway_server_config),
        ),
        async {
            let _ = legacy_gateway_shutdown_rx.await;
        },
    );
    let health_state = HealthState {
        store: health_store,
        accepting_requests: Arc::clone(&accepting_requests),
    };
    let health_server = async move {
        axum::serve(health_listener, health_router(health_state))
            .with_graceful_shutdown(async {
                let _ = health_shutdown_rx.await;
            })
            .await
    };
    let owner_backend = Arc::new(PostgresAgentProvisioningOwnerBackend::new(
        owner_api_store,
        config.owner_api.tenant_id,
    ));
    let owner_api_server = async move {
        axum::serve(
            owner_api_listener,
            agent_provisioning_owner_router(owner_backend),
        )
        .with_graceful_shutdown(async {
            let _ = owner_api_shutdown_rx.await;
        })
        .await
    };
    tokio::pin!(enrollment_server);
    tokio::pin!(control_server);
    tokio::pin!(legacy_gateway_server);
    let mut health_server = tokio::spawn(health_server);
    let mut owner_api_server = tokio::spawn(owner_api_server);

    accepting_requests.store(true, Ordering::Release);
    report_ready(
        config.enrollment.listen,
        config.control.listen,
        config.legacy_gateway.listen,
        config.health.listen,
        config.owner_api.listen,
    )?;
    tokio::select! {
        result = &mut enrollment_server => {
            accepting_requests.store(false, Ordering::Release);
            let _ = control_shutdown_tx.send(());
            let _ = legacy_gateway_shutdown_tx.send(());
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
                let _ = tokio::join!(control_server.as_mut(), legacy_gateway_server.as_mut());
                let _ = health_shutdown_tx.send(());
                let _ = owner_api_shutdown_tx.send(());
                let _ = tokio::join!(&mut health_server, &mut owner_api_server);
            }).await;
            endpoint_result(&result)
        }
        result = &mut control_server => {
            accepting_requests.store(false, Ordering::Release);
            let _ = enrollment_shutdown_tx.send(());
            let _ = legacy_gateway_shutdown_tx.send(());
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
                let _ = tokio::join!(enrollment_server.as_mut(), legacy_gateway_server.as_mut());
                let _ = health_shutdown_tx.send(());
                let _ = owner_api_shutdown_tx.send(());
                let _ = tokio::join!(&mut health_server, &mut owner_api_server);
            }).await;
            endpoint_result(&result)
        }
        result = &mut legacy_gateway_server => {
            accepting_requests.store(false, Ordering::Release);
            let _ = enrollment_shutdown_tx.send(());
            let _ = control_shutdown_tx.send(());
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
                let _ = tokio::join!(enrollment_server.as_mut(), control_server.as_mut());
                let _ = health_shutdown_tx.send(());
                let _ = owner_api_shutdown_tx.send(());
                let _ = tokio::join!(&mut health_server, &mut owner_api_server);
            }).await;
            endpoint_result(&result)
        }
        result = &mut health_server => {
            accepting_requests.store(false, Ordering::Release);
            let _ = enrollment_shutdown_tx.send(());
            let _ = control_shutdown_tx.send(());
            let _ = legacy_gateway_shutdown_tx.send(());
            let _ = owner_api_shutdown_tx.send(());
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
                let _ = tokio::join!(
                    enrollment_server.as_mut(),
                    control_server.as_mut(),
                    legacy_gateway_server.as_mut(),
                );
                let _ = (&mut owner_api_server).await;
            }).await;
            health_task_result(&result)
        }
        result = &mut owner_api_server => {
            accepting_requests.store(false, Ordering::Release);
            let _ = enrollment_shutdown_tx.send(());
            let _ = control_shutdown_tx.send(());
            let _ = legacy_gateway_shutdown_tx.send(());
            let _ = health_shutdown_tx.send(());
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
                let _ = tokio::join!(
                    enrollment_server.as_mut(),
                    control_server.as_mut(),
                    legacy_gateway_server.as_mut(),
                );
                let _ = (&mut health_server).await;
            }).await;
            health_task_result(&result)
        }
        signal = shutdown_signal() => {
            signal?;
            accepting_requests.store(false, Ordering::Release);
            let _ = enrollment_shutdown_tx.send(());
            let _ = control_shutdown_tx.send(());
            let _ = legacy_gateway_shutdown_tx.send(());
            let _ = owner_api_shutdown_tx.send(());
            tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
                let (enrollment, control, legacy_gateway) = tokio::join!(
                    enrollment_server.as_mut(),
                    control_server.as_mut(),
                    legacy_gateway_server.as_mut(),
                );
                enrollment.map_err(|_| BootstrapError::Server)?;
                control.map_err(|_| BootstrapError::Server)?;
                legacy_gateway.map_err(|_| BootstrapError::Server)?;
                let _ = health_shutdown_tx.send(());
                let health = (&mut health_server)
                    .await
                    .map_err(|_| BootstrapError::Server)?;
                health.map_err(|_| BootstrapError::Server)?;
                let owner_api = (&mut owner_api_server)
                    .await
                    .map_err(|_| BootstrapError::Server)?;
                owner_api.map_err(|_| BootstrapError::Server)?;
                Ok::<(), BootstrapError>(())
            })
            .await
            .map_err(|_| BootstrapError::ShutdownTimeout)??;
            Ok(())
        }
    }
}

#[derive(Clone)]
struct HealthState {
    store: PgStore,
    accepting_requests: Arc<AtomicBool>,
}

type ProbeResponse = (
    StatusCode,
    [(header::HeaderName, &'static str); 1],
    &'static str,
);

fn health_router(state: HealthState) -> Router {
    Router::new()
        .route("/live", get(live_probe))
        .route("/ready", get(ready_probe))
        .with_state(state)
}

#[allow(clippy::unused_async)] // Axum handlers are asynchronous by contract.
async fn live_probe() -> ProbeResponse {
    probe_response(StatusCode::OK, "live\n")
}

async fn ready_probe(State(state): State<HealthState>) -> ProbeResponse {
    if !state.accepting_requests.load(Ordering::Acquire) {
        return probe_response(StatusCode::SERVICE_UNAVAILABLE, "not ready\n");
    }
    let database_ready = matches!(
        tokio::time::timeout(
            READINESS_TIMEOUT,
            state
                .store
                .readiness_check(REQUIRED_TABLE_PRIVILEGES, REQUIRED_FUNCTION_PRIVILEGES,),
        )
        .await,
        Ok(Ok(true))
    );
    if database_ready && state.accepting_requests.load(Ordering::Acquire) {
        probe_response(StatusCode::OK, "ready\n")
    } else {
        probe_response(StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

fn probe_response(status: StatusCode, body: &'static str) -> ProbeResponse {
    (status, [(header::CACHE_CONTROL, "no-store")], body)
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<(), BootstrapError> {
    let mut termination = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| BootstrapError::Signal)?;
    tokio::select! {
        interrupt = tokio::signal::ctrl_c() => interrupt.map_err(|_| BootstrapError::Signal),
        received = termination.recv() => received.map_or(Err(BootstrapError::Signal), |_| Ok(())),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<(), BootstrapError> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|_| BootstrapError::Signal)
}

fn endpoint_result(result: &Result<(), tonic::transport::Error>) -> Result<(), BootstrapError> {
    match result {
        Ok(()) => Err(BootstrapError::EndpointExited),
        Err(_) => Err(BootstrapError::Server),
    }
}

fn health_task_result(
    result: &Result<io::Result<()>, tokio::task::JoinError>,
) -> Result<(), BootstrapError> {
    match result {
        Ok(Ok(())) => Err(BootstrapError::EndpointExited),
        Ok(Err(_)) | Err(_) => Err(BootstrapError::Server),
    }
}

fn config_path() -> Result<PathBuf, BootstrapError> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(BootstrapError::Usage);
    }
    let path = arguments.next().ok_or(BootstrapError::Usage)?;
    if arguments.next().is_some() {
        return Err(BootstrapError::Usage);
    }
    Ok(PathBuf::from(path))
}

fn load_database_options(path: &Path) -> Result<PgConnectOptions, BootstrapError> {
    let bytes = Zeroizing::new(read_bounded(path, MAX_DATABASE_URL_BYTES)?);
    std::str::from_utf8(&bytes)
        .map_err(|_| BootstrapError::DatabaseConfig)?
        .trim()
        .parse::<PgConnectOptions>()
        .map_err(|_| BootstrapError::DatabaseConfig)
}

fn load_root_store(path: &Path) -> Result<RootCertStore, BootstrapError> {
    let bundle = read_bounded(path, MAX_PEM_BUNDLE_BYTES)?;
    let certificates = CertificateDer::pem_slice_iter(&bundle)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BootstrapError::Tls)?;
    if certificates.is_empty() {
        return Err(BootstrapError::Tls);
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|_| BootstrapError::Tls)?;
    }
    Ok(roots)
}

fn load_certificate_chain(path: &Path) -> Result<Vec<Vec<u8>>, BootstrapError> {
    let bundle = read_bounded(path, MAX_PEM_BUNDLE_BYTES)?;
    let certificates = CertificateDer::pem_slice_iter(&bundle)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BootstrapError::Tls)?;
    if certificates.is_empty() {
        return Err(BootstrapError::Tls);
    }
    Ok(certificates
        .into_iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect())
}

fn load_single_certificate(path: &Path) -> Result<Vec<u8>, BootstrapError> {
    let mut certificates = load_certificate_chain(path)?;
    if certificates.len() != 1 {
        return Err(BootstrapError::Tls);
    }
    certificates.pop().ok_or(BootstrapError::Tls)
}

fn load_private_key(path: &Path) -> Result<SecretBytes, BootstrapError> {
    let pem = Zeroizing::new(read_bounded(path, MAX_PEM_BUNDLE_BYTES)?);
    let mut key = decode_single_private_key(&pem)?;
    let secret = SecretBytes::new(key.secret_pkcs8_der().to_vec()).map_err(|_| BootstrapError::Tls);
    key.zeroize();
    secret
}

fn build_server_auth_tls_config(
    certificate_chain_der: Vec<Vec<u8>>,
    private_key: SecretBytes,
) -> Result<ServerConfig, BootstrapError> {
    let certificate_chain = certificate_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let mut configured = Err(BootstrapError::Tls);
    private_key.expose(|private_key_der| {
        configured = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                certificate_chain,
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der.to_vec())),
            )
            .map_err(|_| BootstrapError::Tls);
    });
    drop(private_key);
    let mut configured = configured?;
    configured.session_storage = Arc::new(NoServerSessionStorage {});
    configured.send_tls13_tickets = 0;
    configured.max_early_data_size = 0;
    configured.send_half_rtt_data = false;
    configured.alpn_protocols = vec![b"h2".to_vec()];
    Ok(configured)
}

fn decode_single_private_key(pem: &[u8]) -> Result<PrivatePkcs8KeyDer<'static>, BootstrapError> {
    let mut keys = PrivatePkcs8KeyDer::pem_slice_iter(pem);
    let Some(mut key) = keys.next().transpose().map_err(|_| BootstrapError::Tls)? else {
        return Err(BootstrapError::Tls);
    };
    match keys.next().transpose() {
        Ok(None) => Ok(key),
        Ok(Some(mut extra)) => {
            key.zeroize();
            extra.zeroize();
            Err(BootstrapError::Tls)
        }
        Err(_) => {
            key.zeroize();
            Err(BootstrapError::Tls)
        }
    }
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BootstrapError> {
    let metadata = fs::metadata(path).map_err(|_| BootstrapError::SecretRead)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(BootstrapError::SecretRead);
    }
    let bytes = fs::read(path).map_err(|_| BootstrapError::SecretRead)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        Err(BootstrapError::SecretRead)
    } else {
        Ok(bytes)
    }
}

fn report_ready(
    enrollment: SocketAddr,
    control: SocketAddr,
    legacy_gateway: SocketAddr,
    health: SocketAddr,
    owner_api: SocketAddr,
) -> Result<(), BootstrapError> {
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "dtx-agent-control ready enrollment={enrollment} control={control} legacy_gateway={legacy_gateway} health={health} owner_api={owner_api}"
    )
    .map_err(|_| BootstrapError::Ready)?;
    output.flush().map_err(|_| BootstrapError::Ready)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapError {
    Usage,
    Config,
    SecretRead,
    DatabaseConfig,
    Database,
    Tls,
    Bind,
    Signal,
    Ready,
    Server,
    ShutdownTimeout,
    EndpointExited,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "usage: dtx-agent-control --config <path>",
            Self::Config => "bootstrap configuration is invalid",
            Self::SecretRead => "a required credential file could not be loaded",
            Self::DatabaseConfig => "database connection configuration is invalid",
            Self::Database => "database runtime boundary is unavailable",
            Self::Tls => "TLS identity or trust configuration is invalid",
            Self::Bind => "a configured listener could not be bound",
            Self::Signal => "shutdown signal handling failed",
            Self::Ready => "service readiness could not be reported",
            Self::Server => "a service listener failed",
            Self::ShutdownTimeout => "service shutdown timed out",
            Self::EndpointExited => "a service listener exited unexpectedly",
        })
    }
}

impl std::error::Error for BootstrapError {}
