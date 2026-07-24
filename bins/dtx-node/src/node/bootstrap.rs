
use std::{
    env, fs, net::SocketAddr, path::PathBuf, process::ExitCode, str::FromStr, sync::Arc,
    time::Duration,
};

use axum::{extract::State, http::StatusCode, routing::get};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use dtx_domain::{Clock, SystemClock, TenantId};
use dtx_group_node::{GroupNodeState, group_router_with_state, load_mls_sequencer_signing_key};
use dtx_group_persistence::GroupPgStore;
use dtx_identity_node::{IdentityBootstrapState, identity_bootstrap_router_with_state};
use dtx_identity_persistence::IdentityPgStore;
use dtx_mailbox::MailboxPgStore;
use dtx_mailbox_node::{MailboxNodeState, mailbox_router_with_state};
use ed25519_dalek::SigningKey;
use sqlx::postgres::PgConnectOptions;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

#[cfg(feature = "public-content")]
use dtx_domain::IndexerId;
#[cfg(feature = "public-content")]
use dtx_federated_identity::FederatedIdentityVerifier;
#[cfg(feature = "public-content")]
use dtx_indexer_node::{IndexerPgStore, PinnedHttpsBundleFetcher, indexer_router};
#[cfg(feature = "public-content")]
use dtx_public_feed_node::{
    FederatedDeviceAuthority, PublicDiscussionRouterConfig, PublicFeedPgStore,
    public_feed_router_with_discussion,
};

const DEFAULT_LISTEN: &str = "127.0.0.1:9080";
const LISTEN_ENV: &str = "DTX_NODE_LISTEN";
const PUBLIC_ORIGIN_ENV: &str = "DTX_NODE_PUBLIC_ORIGIN";
const TENANT_ID_ENV: &str = "DTX_NODE_TENANT_ID";
const IDENTITY_DATABASE_URL_FILE_ENV: &str = "DTX_IDENTITY_DATABASE_URL_FILE";
const GROUP_DATABASE_URL_FILE_ENV: &str = "DTX_GROUP_DATABASE_URL_FILE";
const GROUP_MLS_SEQUENCER_KEY_FILE_ENV: &str = "DTX_GROUP_MLS_SEQUENCER_KEY_FILE";
const MAILBOX_DATABASE_URL_FILE_ENV: &str = "DTX_MAILBOX_DATABASE_URL_FILE";
#[cfg(feature = "public-content")]
const PUBLIC_FEED_DATABASE_URL_FILE_ENV: &str = "DTX_PUBLIC_FEED_DATABASE_URL_FILE";
#[cfg(feature = "public-content")]
const INDEXER_DATABASE_URL_FILE_ENV: &str = "DTX_INDEXER_DATABASE_URL_FILE";
#[cfg(feature = "public-content")]
const INDEXER_ID_ENV: &str = "DTX_NODE_INDEXER_ID";
const PUBLIC_CONTENT_ENABLED_ENV: &str = "DTX_NODE_PUBLIC_CONTENT_ENABLED";
const DB_MAX_CONNECTIONS_ENV: &str = "DTX_NODE_DB_MAX_CONNECTIONS";
const DEV_HTTP_IDENTITY_ORIGINS_ENV: &str = "DTX_GROUP_DEV_HTTP_IDENTITY_ORIGINS";
const TLS_CERTIFICATE_FILE_ENV: &str = "DTX_NODE_TLS_CERTIFICATE_FILE";
const TLS_PRIVATE_KEY_FILE_ENV: &str = "DTX_NODE_TLS_PRIVATE_KEY_FILE";
const GROUP_FEDERATED_IDENTITY_TRUST_ROOT_FILE_ENV: &str =
    "DTX_GROUP_FEDERATED_IDENTITY_TRUST_ROOT_FILE";
const MAX_DATABASE_URL_BYTES: usize = 8_192;
const MAX_TLS_PEM_BYTES: u64 = 1_048_576;
const MAX_FEDERATED_IDENTITY_TRUST_ROOT_PEM_BYTES: usize = 64 * 1024;
const TLS_GRACEFUL_SHUTDOWN: Duration = Duration::from_secs(30);
const READY_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 2;

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
        #[cfg(feature = "public-content")]
        public_content,
        db_max_connections,
        allowed_http_identity_origins,
        additional_federated_identity_trust_root_pem,
    } = NodeConfig::load()?;
    let sequencer_signing_key = load_mls_sequencer_signing_key(&group_mls_sequencer_key_file)
        .map_err(|_| NodeError::Configuration)?;
    let (identity_store, group_store, mailbox_store) = connect_product_stores(
        identity_database,
        group_database,
        mailbox_database,
        db_max_connections,
    )
    .await?;

    let clock = Arc::new(SystemClock);
    let identity_state = IdentityBootstrapState::with_clock_and_device_session_audience(
        identity_store.clone(),
        clock.clone(),
        public_origin.clone(),
    )
    .with_federated_identity_configuration(
        &public_origin,
        allowed_http_identity_origins.clone(),
        additional_federated_identity_trust_root_pem.as_deref(),
    )
    .map_err(|_| NodeError::Configuration)?;
    let group_state = configured_group_state(
        group_store.clone(),
        tenant_id,
        clock.clone(),
        sequencer_signing_key,
        &public_origin,
        allowed_http_identity_origins.clone(),
        additional_federated_identity_trust_root_pem.as_deref(),
    )?;
    let mailbox_state = MailboxNodeState::with_clock(mailbox_store.clone(), clock);

    let router = product_core_router(identity_state, group_state, mailbox_state);
    #[cfg(feature = "public-content")]
    let mut router = router;
    #[cfg(feature = "public-content")]
    let mut active_public_stores = None;
    #[cfg(feature = "public-content")]
    if let Some(public_content) = public_content {
        let public_feed_store =
            PublicFeedPgStore::connect(public_content.public_feed_database, db_max_connections)
                .await
                .map_err(|_| NodeError::Database("public feed"))?;
        let indexer_store =
            IndexerPgStore::connect(public_content.indexer_database, db_max_connections)
                .await
                .map_err(|_| NodeError::Database("indexer"))?;
        active_public_stores = Some((public_feed_store.clone(), indexer_store.clone()));
        let (discussion_identity, _) =
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                &public_origin,
                allowed_http_identity_origins,
                additional_federated_identity_trust_root_pem.as_deref(),
            )
            .map_err(|_| NodeError::Configuration)?;
        router = router
            .merge(public_feed_router_with_discussion(
                public_feed_store,
                tenant_id,
                PublicDiscussionRouterConfig::new(Arc::new(FederatedDeviceAuthority::new(
                    discussion_identity,
                ))),
            ))
            .merge(indexer_router(
                indexer_store,
                tenant_id,
                public_content.indexer_id,
                Arc::new(PinnedHttpsBundleFetcher::default()),
            ));
    }
    let readiness = NodeReadiness {
        identity: identity_store.clone(),
        group: group_store.clone(),
        mailbox: mailbox_store.clone(),
        #[cfg(feature = "public-content")]
        public_content: active_public_stores,
        mls_key_loaded: true,
    };
    let local_router = axum::Router::new()
        .route("/local/live", get(local_live))
        .route("/local/ready", get(local_ready))
        .with_state(readiness);
    let router = router.merge(local_router);
    serve_node(router, listen, tls).await
}

async fn connect_product_stores(
    identity_database: PgConnectOptions,
    group_database: PgConnectOptions,
    mailbox_database: PgConnectOptions,
    max_connections: u32,
) -> Result<(IdentityPgStore, GroupPgStore, MailboxPgStore), NodeError> {
    let identity = IdentityPgStore::connect(identity_database, max_connections)
        .await
        .map_err(|_| NodeError::Database("identity"))?;
    let group = GroupPgStore::connect(group_database, max_connections)
        .await
        .map_err(|_| NodeError::Database("group"))?;
    let mailbox = MailboxPgStore::connect(mailbox_database, max_connections)
        .await
        .map_err(|_| NodeError::Database("mailbox"))?;
    Ok((identity, group, mailbox))
}

fn product_core_router(
    identity: IdentityBootstrapState,
    group: GroupNodeState,
    mailbox: MailboxNodeState,
) -> axum::Router {
    identity_bootstrap_router_with_state(identity)
        .merge(group_router_with_state(group))
        .merge(mailbox_router_with_state(mailbox))
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

async fn local_live() -> StatusCode {
    StatusCode::NO_CONTENT
}
