
struct NodeConfig {
    listen: SocketAddr,
    tls: Option<NodeTlsConfig>,
    public_origin: String,
    tenant_id: TenantId,
    identity_database: PgConnectOptions,
    group_database: PgConnectOptions,
    group_mls_sequencer_key_file: PathBuf,
    mailbox_database: PgConnectOptions,
    #[cfg(feature = "public-content")]
    public_content: Option<PublicContentConfig>,
    db_max_connections: u32,
    allowed_http_identity_origins: Vec<String>,
    additional_federated_identity_trust_root_pem: Option<Vec<u8>>,
}

#[cfg(feature = "public-content")]
struct PublicContentConfig {
    public_feed_database: PgConnectOptions,
    indexer_database: PgConnectOptions,
    indexer_id: IndexerId,
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
        #[cfg(feature = "public-content")]
        let public_content = match public_content_enabled(env::var(PUBLIC_CONTENT_ENABLED_ENV).ok())? {
                false => None,
                true => Some(PublicContentConfig {
                    public_feed_database: load_database_options(PUBLIC_FEED_DATABASE_URL_FILE_ENV)?,
                    indexer_database: load_database_options(INDEXER_DATABASE_URL_FILE_ENV)?,
                    indexer_id: env::var(INDEXER_ID_ENV)
                        .map_err(|_| NodeError::Configuration)?
                        .parse::<IndexerId>()
                        .map_err(|_| NodeError::Configuration)?,
                }),
            };
        #[cfg(not(feature = "public-content"))]
        if public_content_enabled(env::var(PUBLIC_CONTENT_ENABLED_ENV).ok())? {
            return Err(NodeError::Configuration);
        }
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
            #[cfg(feature = "public-content")]
            public_content,
            db_max_connections: parse_pool_size(
                DB_MAX_CONNECTIONS_ENV,
                DEFAULT_DB_MAX_CONNECTIONS,
                64,
            )?,
            allowed_http_identity_origins,
            additional_federated_identity_trust_root_pem,
        })
    }
}

fn parse_pool_size(name: &str, default: u32, maximum: u32) -> Result<u32, NodeError> {
    match env::var(name) {
        Err(env::VarError::NotPresent) => Ok(default),
        Ok(value) => match value.parse::<u32>() {
            Ok(size) if (1..=maximum).contains(&size) => Ok(size),
            _ => Err(NodeError::Configuration),
        },
        Err(_) => Err(NodeError::Configuration),
    }
}

fn public_content_enabled(value: Option<String>) -> Result<bool, NodeError> {
    match value.as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(NodeError::Configuration),
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
