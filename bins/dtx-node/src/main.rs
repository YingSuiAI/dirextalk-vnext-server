#![forbid(unsafe_code)]

use std::{
    env, fs, net::SocketAddr, path::PathBuf, process::ExitCode, str::FromStr, sync::Arc,
    time::Duration,
};

use axum::{http::StatusCode, routing::get};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use dtx_domain::{Clock, IndexerId, SystemClock, TenantId};
use dtx_group_node::{GroupNodeState, group_router_with_state, load_mls_sequencer_signing_key};
use dtx_group_persistence::GroupPgStore;
use dtx_identity_node::{IdentityBootstrapState, identity_bootstrap_router_with_state};
use dtx_identity_persistence::IdentityPgStore;
use dtx_indexer_node::{IndexerPgStore, PinnedHttpsBundleFetcher, indexer_router};
use dtx_mailbox::MailboxPgStore;
use dtx_mailbox_node::{MailboxNodeState, mailbox_router_with_state};
use dtx_public_feed_node::{PublicFeedPgStore, public_feed_router};
use ed25519_dalek::SigningKey;
use sqlx::postgres::PgConnectOptions;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const DEFAULT_LISTEN: &str = "127.0.0.1:9080";
const LISTEN_ENV: &str = "DTX_NODE_LISTEN";
const PUBLIC_ORIGIN_ENV: &str = "DTX_NODE_PUBLIC_ORIGIN";
const TENANT_ID_ENV: &str = "DTX_NODE_TENANT_ID";
const IDENTITY_DATABASE_URL_FILE_ENV: &str = "DTX_IDENTITY_DATABASE_URL_FILE";
const GROUP_DATABASE_URL_FILE_ENV: &str = "DTX_GROUP_DATABASE_URL_FILE";
const GROUP_MLS_SEQUENCER_KEY_FILE_ENV: &str = "DTX_GROUP_MLS_SEQUENCER_KEY_FILE";
const MAILBOX_DATABASE_URL_FILE_ENV: &str = "DTX_MAILBOX_DATABASE_URL_FILE";
const PUBLIC_FEED_DATABASE_URL_FILE_ENV: &str = "DTX_PUBLIC_FEED_DATABASE_URL_FILE";
const INDEXER_DATABASE_URL_FILE_ENV: &str = "DTX_INDEXER_DATABASE_URL_FILE";
const INDEXER_ID_ENV: &str = "DTX_NODE_INDEXER_ID";
const DEV_HTTP_IDENTITY_ORIGINS_ENV: &str = "DTX_GROUP_DEV_HTTP_IDENTITY_ORIGINS";
const TLS_CERTIFICATE_FILE_ENV: &str = "DTX_NODE_TLS_CERTIFICATE_FILE";
const TLS_PRIVATE_KEY_FILE_ENV: &str = "DTX_NODE_TLS_PRIVATE_KEY_FILE";
const GROUP_FEDERATED_IDENTITY_TRUST_ROOT_FILE_ENV: &str =
    "DTX_GROUP_FEDERATED_IDENTITY_TRUST_ROOT_FILE";
const MAX_DATABASE_URL_BYTES: usize = 8_192;
const MAX_TLS_PEM_BYTES: u64 = 1_048_576;
const MAX_FEDERATED_IDENTITY_TRUST_ROOT_PEM_BYTES: usize = 64 * 1024;
const TLS_GRACEFUL_SHUTDOWN: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dtx-node: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), NodeError> {
    let NodeConfig {
        listen,
        tls,
        public_origin,
        tenant_id,
        identity_database,
        group_database,
        group_mls_sequencer_key_file,
        mailbox_database,
        public_feed_database,
        indexer_database,
        indexer_id,
        allowed_http_identity_origins,
        additional_federated_identity_trust_root_pem,
    } = NodeConfig::load()?;
    let sequencer_signing_key = load_mls_sequencer_signing_key(&group_mls_sequencer_key_file)
        .map_err(|_| NodeError::Configuration)?;
    let identity_store = IdentityPgStore::connect(identity_database, 8)
        .await
        .map_err(|_| NodeError::Database("identity"))?;
    let group_store = GroupPgStore::connect(group_database, 8)
        .await
        .map_err(|_| NodeError::Database("group"))?;
    let mailbox_store = MailboxPgStore::connect(mailbox_database, 8)
        .await
        .map_err(|_| NodeError::Database("mailbox"))?;
    let public_feed_store = PublicFeedPgStore::connect(public_feed_database, 8)
        .await
        .map_err(|_| NodeError::Database("public feed"))?;
    let indexer_store = IndexerPgStore::connect(indexer_database, 8)
        .await
        .map_err(|_| NodeError::Database("indexer"))?;

    let clock = Arc::new(SystemClock);
    let identity_state = IdentityBootstrapState::with_clock_and_device_session_audience(
        identity_store,
        clock.clone(),
        public_origin.clone(),
    );
    let group_state = configured_group_state(
        group_store,
        tenant_id,
        clock.clone(),
        sequencer_signing_key,
        &public_origin,
        allowed_http_identity_origins,
        additional_federated_identity_trust_root_pem.as_deref(),
    )?;
    let mailbox_state = MailboxNodeState::with_clock(mailbox_store, clock);

    let router = identity_bootstrap_router_with_state(identity_state)
        .merge(group_router_with_state(group_state))
        .merge(mailbox_router_with_state(mailbox_state))
        .merge(public_feed_router(public_feed_store, tenant_id))
        .merge(indexer_router(
            indexer_store,
            tenant_id,
            indexer_id,
            Arc::new(PinnedHttpsBundleFetcher::default()),
        ))
        .route("/local-health", get(local_health));
    serve_node(router, listen, tls).await
}

async fn serve_node(
    router: axum::Router,
    listen: SocketAddr,
    tls: Option<NodeTlsConfig>,
) -> Result<(), NodeError> {
    let Some(tls) = tls else {
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|_| NodeError::Bind)?;
        return axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|_| NodeError::Serve);
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls_config = RustlsConfig::from_pem_file(tls.certificate_file, tls.private_key_file)
        .await
        .map_err(|_| NodeError::Configuration)?;
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(TLS_GRACEFUL_SHUTDOWN));
    });
    axum_server::bind_rustls(listen, tls_config)
        .handle(handle)
        .serve(router.into_make_service())
        .await
        .map_err(|_| NodeError::Serve)
}

fn configured_group_state(
    group_store: GroupPgStore,
    tenant_id: TenantId,
    clock: Arc<dyn Clock>,
    sequencer_signing_key: SigningKey,
    public_origin: &str,
    allowed_http_identity_origins: Vec<String>,
    additional_federated_identity_trust_root_pem: Option<&[u8]>,
) -> Result<GroupNodeState, NodeError> {
    GroupNodeState::with_clock(group_store, tenant_id, clock)
        .with_mls_sequencer_signing_key(sequencer_signing_key)
        .with_federated_identity_configuration(
            public_origin,
            allowed_http_identity_origins,
            additional_federated_identity_trust_root_pem,
        )
        .map_err(|_| NodeError::Configuration)
}

async fn local_health() -> StatusCode {
    StatusCode::NO_CONTENT
}

struct NodeConfig {
    listen: SocketAddr,
    tls: Option<NodeTlsConfig>,
    public_origin: String,
    tenant_id: TenantId,
    identity_database: PgConnectOptions,
    group_database: PgConnectOptions,
    group_mls_sequencer_key_file: PathBuf,
    mailbox_database: PgConnectOptions,
    public_feed_database: PgConnectOptions,
    indexer_database: PgConnectOptions,
    indexer_id: IndexerId,
    allowed_http_identity_origins: Vec<String>,
    additional_federated_identity_trust_root_pem: Option<Vec<u8>>,
}

struct NodeTlsConfig {
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl NodeTlsConfig {
    fn load() -> Result<Option<Self>, NodeError> {
        let certificate_file = env::var_os(TLS_CERTIFICATE_FILE_ENV);
        let private_key_file = env::var_os(TLS_PRIVATE_KEY_FILE_ENV);
        match (certificate_file, private_key_file) {
            (None, None) => Ok(None),
            (Some(certificate_file), Some(private_key_file)) => Ok(Some(Self {
                certificate_file: required_tls_pem_file(PathBuf::from(certificate_file))?,
                private_key_file: required_tls_pem_file(PathBuf::from(private_key_file))?,
            })),
            _ => Err(NodeError::Configuration),
        }
    }
}

impl NodeConfig {
    fn load() -> Result<Self, NodeError> {
        let listen = env::var(LISTEN_ENV)
            .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| NodeError::Configuration)?;
        let public_origin = required_graphic_env(PUBLIC_ORIGIN_ENV, 256)?;
        let tls = NodeTlsConfig::load()?;
        validate_public_transport(&public_origin, tls.is_some())?;
        validate_listen_scope(listen, tls.is_some())?;
        let tenant_id = env::var(TENANT_ID_ENV)
            .map_err(|_| NodeError::Configuration)?
            .parse::<TenantId>()
            .map_err(|_| NodeError::Configuration)?;
        let indexer_id = env::var(INDEXER_ID_ENV)
            .map_err(|_| NodeError::Configuration)?
            .parse::<IndexerId>()
            .map_err(|_| NodeError::Configuration)?;
        let allowed_http_identity_origins = env::var(DEV_HTTP_IDENTITY_ORIGINS_ENV)
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|origin| !origin.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let additional_federated_identity_trust_root_pem =
            load_optional_federated_identity_trust_root_pem()?;

        Ok(Self {
            listen,
            tls,
            public_origin,
            tenant_id,
            identity_database: load_database_options(IDENTITY_DATABASE_URL_FILE_ENV)?,
            group_database: load_database_options(GROUP_DATABASE_URL_FILE_ENV)?,
            group_mls_sequencer_key_file: env::var_os(GROUP_MLS_SEQUENCER_KEY_FILE_ENV)
                .map(PathBuf::from)
                .ok_or(NodeError::Configuration)?,
            mailbox_database: load_database_options(MAILBOX_DATABASE_URL_FILE_ENV)?,
            public_feed_database: load_database_options(PUBLIC_FEED_DATABASE_URL_FILE_ENV)?,
            indexer_database: load_database_options(INDEXER_DATABASE_URL_FILE_ENV)?,
            indexer_id,
            allowed_http_identity_origins,
            additional_federated_identity_trust_root_pem,
        })
    }
}

fn validate_public_transport(public_origin: &str, tls_enabled: bool) -> Result<(), NodeError> {
    let declares_https = public_origin.starts_with("https://");
    let declares_http = public_origin.starts_with("http://");
    if !declares_https && !declares_http || declares_https != tls_enabled {
        return Err(NodeError::Configuration);
    }
    Ok(())
}

fn validate_listen_scope(listen: SocketAddr, tls_enabled: bool) -> Result<(), NodeError> {
    if !listen.ip().is_loopback() && !tls_enabled {
        return Err(NodeError::Configuration);
    }
    Ok(())
}

fn required_tls_pem_file(path: PathBuf) -> Result<PathBuf, NodeError> {
    let metadata = fs::symlink_metadata(&path).map_err(|_| NodeError::Configuration)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_TLS_PEM_BYTES
    {
        return Err(NodeError::Configuration);
    }
    Ok(path)
}

fn load_optional_federated_identity_trust_root_pem() -> Result<Option<Vec<u8>>, NodeError> {
    let Some(path) = env::var_os(GROUP_FEDERATED_IDENTITY_TRUST_ROOT_FILE_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let metadata = fs::symlink_metadata(&path).map_err(|_| NodeError::Configuration)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_FEDERATED_IDENTITY_TRUST_ROOT_PEM_BYTES as u64
    {
        return Err(NodeError::Configuration);
    }
    let pem = fs::read(path).map_err(|_| NodeError::Configuration)?;
    if pem.is_empty() || pem.len() > MAX_FEDERATED_IDENTITY_TRUST_ROOT_PEM_BYTES {
        return Err(NodeError::Configuration);
    }
    Ok(Some(pem))
}

fn required_graphic_env(name: &str, max_len: usize) -> Result<String, NodeError> {
    let value = env::var(name).map_err(|_| NodeError::Configuration)?;
    if !is_graphic_value(&value, max_len) {
        return Err(NodeError::Configuration);
    }
    Ok(value)
}

fn is_graphic_value(value: &str, max_len: usize) -> bool {
    (1..=max_len).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn load_database_options(name: &str) -> Result<PgConnectOptions, NodeError> {
    let path = env::var_os(name)
        .map(PathBuf::from)
        .ok_or(NodeError::Configuration)?;
    let metadata = fs::metadata(&path).map_err(|_| NodeError::Configuration)?;
    if !metadata.is_file() || metadata.len() > MAX_DATABASE_URL_BYTES as u64 {
        return Err(NodeError::Configuration);
    }
    let raw = Zeroizing::new(fs::read(path).map_err(|_| NodeError::Configuration)?);
    if raw.is_empty() || raw.len() > MAX_DATABASE_URL_BYTES {
        return Err(NodeError::Configuration);
    }
    let raw =
        Zeroizing::new(String::from_utf8(raw.to_vec()).map_err(|_| NodeError::Configuration)?);
    PgConnectOptions::from_str(raw.trim()).map_err(|_| NodeError::Configuration)
}

#[cfg(unix)]
async fn shutdown_signal() {
    let mut termination =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(_) => return,
        };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = termination.recv() => {},
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Debug)]
enum NodeError {
    Configuration,
    Database(&'static str),
    Bind,
    Serve,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration => formatter.write_str("invalid node configuration"),
            Self::Database(service) => {
                write!(formatter, "{service} database initialization failed")
            }
            Self::Bind => formatter.write_str("node loopback listener could not bind"),
            Self::Serve => formatter.write_str("node HTTP(S) server failed"),
        }
    }
}

impl std::error::Error for NodeError {}

#[cfg(test)]
#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod test_support;

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use axum::{body::Body, http::Request};
    use dtx_domain::SystemClock;
    use dtx_group_node::{
        GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE, GROUP_SERVICE_DESCRIPTOR_PATH,
        group_router_with_state,
    };
    use ed25519_dalek::SigningKey;
    use tower::ServiceExt;

    use super::{
        GroupPgStore, StatusCode, TenantId, configured_group_state, is_graphic_value,
        test_support as support, validate_listen_scope, validate_public_transport,
    };

    #[test]
    fn graphic_config_values_reject_whitespace_and_bounds() {
        assert!(is_graphic_value("https://node.example", 256));
        assert!(!is_graphic_value("https://node.example/ invalid", 256));
        assert!(!is_graphic_value("", 256));
        assert!(!is_graphic_value("toolong", 3));
    }

    #[test]
    fn public_transport_cannot_claim_https_without_a_tls_listener() {
        assert!(validate_public_transport("https://node.example", true).is_ok());
        assert!(validate_public_transport("http://node.example", false).is_ok());
        assert!(validate_public_transport("https://node.example", false).is_err());
        assert!(validate_public_transport("http://node.example", true).is_err());
        assert!(validate_public_transport("ftp://node.example", false).is_err());
    }

    #[test]
    fn non_loopback_listener_requires_tls() {
        let external = "0.0.0.0:8443".parse().expect("socket address");
        let loopback = "127.0.0.1:9080".parse().expect("socket address");
        assert!(validate_listen_scope(external, true).is_ok());
        assert!(validate_listen_scope(external, false).is_err());
        assert!(validate_listen_scope(loopback, false).is_ok());
    }

    #[tokio::test]
    async fn configured_unified_group_route_serves_descriptor() -> Result<(), Box<dyn Error>> {
        let harness = support::PostgresHarness::start().await?;
        let store = GroupPgStore::connect(harness.group_runtime_options(), 1).await?;
        let state = configured_group_state(
            store,
            TenantId::new(),
            Arc::new(SystemClock),
            SigningKey::from_bytes(&[73; 32]),
            "https://node.example",
            Vec::new(),
            None,
        )?;
        let response = group_router_with_state(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(GROUP_SERVICE_DESCRIPTOR_PATH)
                    .header("host", "attacker.invalid")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some(GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE)
        );
        Ok(())
    }
}
