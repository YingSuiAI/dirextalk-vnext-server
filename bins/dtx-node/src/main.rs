#![forbid(unsafe_code)]

use std::{env, fs, net::SocketAddr, path::PathBuf, process::ExitCode, str::FromStr, sync::Arc};

use axum::{http::StatusCode, routing::get};
use dtx_domain::{IndexerId, SystemClock, TenantId};
use dtx_group_node::{GroupNodeState, group_router_with_state};
use dtx_group_persistence::GroupPgStore;
use dtx_identity_node::{IdentityBootstrapState, identity_bootstrap_router_with_state};
use dtx_identity_persistence::IdentityPgStore;
use dtx_indexer_node::{IndexerPgStore, PinnedHttpsBundleFetcher, indexer_router};
use dtx_mailbox::MailboxPgStore;
use dtx_mailbox_node::{MailboxNodeState, mailbox_router_with_state};
use dtx_public_feed_node::{PublicFeedPgStore, public_feed_router};
use sqlx::postgres::PgConnectOptions;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const DEFAULT_LISTEN: &str = "127.0.0.1:9080";
const LISTEN_ENV: &str = "DTX_NODE_LISTEN";
const PUBLIC_ORIGIN_ENV: &str = "DTX_NODE_PUBLIC_ORIGIN";
const TENANT_ID_ENV: &str = "DTX_NODE_TENANT_ID";
const IDENTITY_DATABASE_URL_FILE_ENV: &str = "DTX_IDENTITY_DATABASE_URL_FILE";
const GROUP_DATABASE_URL_FILE_ENV: &str = "DTX_GROUP_DATABASE_URL_FILE";
const MAILBOX_DATABASE_URL_FILE_ENV: &str = "DTX_MAILBOX_DATABASE_URL_FILE";
const PUBLIC_FEED_DATABASE_URL_FILE_ENV: &str = "DTX_PUBLIC_FEED_DATABASE_URL_FILE";
const INDEXER_DATABASE_URL_FILE_ENV: &str = "DTX_INDEXER_DATABASE_URL_FILE";
const INDEXER_ID_ENV: &str = "DTX_NODE_INDEXER_ID";
const DEV_HTTP_IDENTITY_ORIGINS_ENV: &str = "DTX_GROUP_DEV_HTTP_IDENTITY_ORIGINS";
const MAX_DATABASE_URL_BYTES: usize = 8_192;

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
    let config = NodeConfig::load()?;
    let identity_store = IdentityPgStore::connect(config.identity_database, 8)
        .await
        .map_err(|_| NodeError::Database("identity"))?;
    let group_store = GroupPgStore::connect(config.group_database, 8)
        .await
        .map_err(|_| NodeError::Database("group"))?;
    let mailbox_store = MailboxPgStore::connect(config.mailbox_database, 8)
        .await
        .map_err(|_| NodeError::Database("mailbox"))?;
    let public_feed_store = PublicFeedPgStore::connect(config.public_feed_database, 8)
        .await
        .map_err(|_| NodeError::Database("public feed"))?;
    let indexer_store = IndexerPgStore::connect(config.indexer_database, 8)
        .await
        .map_err(|_| NodeError::Database("indexer"))?;

    let clock = Arc::new(SystemClock);
    let identity_state = IdentityBootstrapState::with_clock_and_device_session_audience(
        identity_store,
        clock.clone(),
        config.public_origin,
    );
    let group_state = GroupNodeState::with_clock(group_store, config.tenant_id, clock.clone())
        .with_allowed_http_identity_origins(config.allowed_http_identity_origins)
        .map_err(|_| NodeError::Configuration)?;
    let mailbox_state = MailboxNodeState::with_clock(mailbox_store, clock);

    let router = identity_bootstrap_router_with_state(identity_state)
        .merge(group_router_with_state(group_state))
        .merge(mailbox_router_with_state(mailbox_state))
        .merge(public_feed_router(public_feed_store, config.tenant_id))
        .merge(indexer_router(
            indexer_store,
            config.tenant_id,
            config.indexer_id,
            Arc::new(PinnedHttpsBundleFetcher::default()),
        ))
        .route("/local-health", get(local_health));
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|_| NodeError::Bind)?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|_| NodeError::Serve)
}

async fn local_health() -> StatusCode {
    StatusCode::NO_CONTENT
}

struct NodeConfig {
    listen: SocketAddr,
    public_origin: String,
    tenant_id: TenantId,
    identity_database: PgConnectOptions,
    group_database: PgConnectOptions,
    mailbox_database: PgConnectOptions,
    public_feed_database: PgConnectOptions,
    indexer_database: PgConnectOptions,
    indexer_id: IndexerId,
    allowed_http_identity_origins: Vec<String>,
}

impl NodeConfig {
    fn load() -> Result<Self, NodeError> {
        let listen = env::var(LISTEN_ENV)
            .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| NodeError::Configuration)?;
        if !listen.ip().is_loopback() {
            return Err(NodeError::Configuration);
        }

        let public_origin = required_graphic_env(PUBLIC_ORIGIN_ENV, 256)?;
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

        Ok(Self {
            listen,
            public_origin,
            tenant_id,
            identity_database: load_database_options(IDENTITY_DATABASE_URL_FILE_ENV)?,
            group_database: load_database_options(GROUP_DATABASE_URL_FILE_ENV)?,
            mailbox_database: load_database_options(MAILBOX_DATABASE_URL_FILE_ENV)?,
            public_feed_database: load_database_options(PUBLIC_FEED_DATABASE_URL_FILE_ENV)?,
            indexer_database: load_database_options(INDEXER_DATABASE_URL_FILE_ENV)?,
            indexer_id,
            allowed_http_identity_origins,
        })
    }
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
            Self::Serve => formatter.write_str("node HTTP server failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_graphic_value;

    #[test]
    fn graphic_config_values_reject_whitespace_and_bounds() {
        assert!(is_graphic_value("https://node.example", 256));
        assert!(!is_graphic_value("https://node.example/ invalid", 256));
        assert!(!is_graphic_value("", 256));
        assert!(!is_graphic_value("toolong", 3));
    }
}
