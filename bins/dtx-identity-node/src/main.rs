#![forbid(unsafe_code)]

use std::{env, fs, net::SocketAddr, path::PathBuf, process::ExitCode, str::FromStr};

use dtx_identity_node::{
    CompletionSignerConfig, IdentityBootstrapState, identity_bootstrap_router_with_state,
    load_completion_signing_key,
};
use dtx_identity_persistence::IdentityPgStore;
use dtx_wire::{Sha256Digest, UtcMillis};
use sqlx::postgres::PgConnectOptions;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DATABASE_URL_FILE_ENV: &str = "DTX_IDENTITY_DATABASE_URL_FILE";
const LISTEN_ENV: &str = "DTX_IDENTITY_LISTEN";
const DEVICE_SESSION_AUDIENCE_ENV: &str = "DTX_IDENTITY_DEVICE_SESSION_AUDIENCE";
const MAX_DATABASE_URL_BYTES: usize = 8_192;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dtx-identity-node: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), NodeError> {
    let listen = load_loopback_listen()?;
    let device_session_audience = load_device_session_audience(listen)?;
    let database_options = load_database_options()?;
    let store = IdentityPgStore::connect(database_options, 8)
        .await
        .map_err(|_| NodeError::Database)?;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|_| NodeError::Bind)?;
    let mut state = IdentityBootstrapState::with_clock_and_device_session_audience(
        store,
        std::sync::Arc::new(dtx_domain::SystemClock),
        device_session_audience,
    );
    if let Some(config) = load_completion_signer_config()? {
        state = state
            .with_completion_signer_config(config)
            .map_err(|_| NodeError::Configuration)?;
    }
    axum::serve(listener, identity_bootstrap_router_with_state(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|_| NodeError::Serve)
}

fn load_completion_signer_config() -> Result<Option<CompletionSignerConfig>, NodeError> {
    let Some(path) = env::var_os("DTX_IDENTITY_COMPLETION_KEY_FILE") else {
        let any = [
            "DTX_IDENTITY_COMPLETION_KEY_ID",
            "DTX_IDENTITY_COMPLETION_EPOCH",
            "DTX_IDENTITY_COMPLETION_ROLLBACK_FLOOR",
            "DTX_IDENTITY_COMPLETION_ISSUED_AT_MS",
            "DTX_IDENTITY_COMPLETION_EXPIRES_AT_MS",
            "DTX_IDENTITY_COMPLETION_PREVIOUS_DIGEST",
        ]
        .iter()
        .any(|name| env::var_os(name).is_some());
        if any {
            return Err(NodeError::Configuration);
        }
        return Ok(None);
    };
    let key_id = env::var("DTX_IDENTITY_COMPLETION_KEY_ID")
        .map_err(|_| NodeError::Configuration)?
        .parse()
        .map_err(|_| NodeError::Configuration)?;
    let epoch = env::var("DTX_IDENTITY_COMPLETION_EPOCH")
        .map_err(|_| NodeError::Configuration)?
        .parse()
        .map_err(|_| NodeError::Configuration)?;
    let rollback_floor_epoch = env::var("DTX_IDENTITY_COMPLETION_ROLLBACK_FLOOR")
        .map_err(|_| NodeError::Configuration)?
        .parse()
        .map_err(|_| NodeError::Configuration)?;
    let issued_at = UtcMillis::new(
        env::var("DTX_IDENTITY_COMPLETION_ISSUED_AT_MS")
            .map_err(|_| NodeError::Configuration)?
            .parse()
            .map_err(|_| NodeError::Configuration)?,
    )
    .map_err(|_| NodeError::Configuration)?;
    let expires_at = UtcMillis::new(
        env::var("DTX_IDENTITY_COMPLETION_EXPIRES_AT_MS")
            .map_err(|_| NodeError::Configuration)?
            .parse()
            .map_err(|_| NodeError::Configuration)?,
    )
    .map_err(|_| NodeError::Configuration)?;
    let previous_descriptor_digest = env::var("DTX_IDENTITY_COMPLETION_PREVIOUS_DIGEST")
        .ok()
        .map(|value| parse_hex_digest(&value))
        .transpose()
        .map_err(|_| NodeError::Configuration)?;
    let signing_key =
        load_completion_signing_key(&PathBuf::from(path)).map_err(|_| NodeError::Configuration)?;
    Ok(Some(CompletionSignerConfig {
        key_id,
        epoch,
        rollback_floor_epoch,
        issued_at,
        expires_at,
        previous_descriptor_digest,
        signing_key,
    }))
}

fn parse_hex_digest(value: &str) -> Result<Sha256Digest, ()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(Sha256Digest::from_bytes(out))
}

fn load_device_session_audience(listen: SocketAddr) -> Result<String, NodeError> {
    let audience =
        env::var(DEVICE_SESSION_AUDIENCE_ENV).unwrap_or_else(|_| format!("http://{listen}"));
    if !(1..=256).contains(&audience.len()) || !audience.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(NodeError::Configuration);
    }
    Ok(audience)
}

fn load_loopback_listen() -> Result<SocketAddr, NodeError> {
    let value = env::var(LISTEN_ENV).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let address: SocketAddr = value.parse().map_err(|_| NodeError::Configuration)?;
    if !address.ip().is_loopback() {
        return Err(NodeError::Configuration);
    }
    Ok(address)
}

fn load_database_options() -> Result<PgConnectOptions, NodeError> {
    let path = env::var_os(DATABASE_URL_FILE_ENV)
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
    let raw = String::from_utf8(raw.to_vec()).map_err(|_| NodeError::Configuration)?;
    let raw = Zeroizing::new(raw);
    let value = raw.trim();
    if value.is_empty() {
        return Err(NodeError::Configuration);
    }
    PgConnectOptions::from_str(value).map_err(|_| NodeError::Configuration)
}

#[cfg(unix)]
async fn shutdown_signal() {
    let Ok(mut termination) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return;
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

#[derive(Clone, Copy)]
enum NodeError {
    Configuration,
    Database,
    Bind,
    Serve,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid local identity node configuration",
            Self::Database => "identity database initialization failed",
            Self::Bind => "identity loopback listener could not bind",
            Self::Serve => "identity HTTP server failed",
        })
    }
}
