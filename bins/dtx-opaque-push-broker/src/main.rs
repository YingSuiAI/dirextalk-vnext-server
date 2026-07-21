#![forbid(unsafe_code)]

use axum_server::tls_rustls::RustlsConfig;
use dtx_domain::TenantId;
use dtx_opaque_push::ProductionBroker;
use dtx_opaque_push_broker::{
    Cancellation, PushRouterState, Readiness, StartupStep, StartupTrace, ready_listener, router,
    run_broker_loop, run_prune_loop,
};
use dtx_opaque_push_fcm::{FcmPushProvider, ServiceAccountCredentials};
use dtx_opaque_push_postgres::{
    BrokerPool, IdentityAuthPool, PostgresPushPersistence, PushRegistrationService,
    RegistrationPool,
};
use dtx_security::LocalRootKeyFileKms;
use rustls::pki_types::pem::PemObject;
use serde::Deserialize;
use sqlx::postgres::PgConnectOptions;
use std::{
    env,
    fs::{self, OpenOptions},
    io::Read,
    net::SocketAddr,
    os::unix::fs::MetadataExt,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct ServiceAccountFile {
    project_id: String,
    client_email: String,
    private_key: String,
}

fn main() {
    if run().is_err() {
        eprintln!("opaque push broker startup failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut trace = StartupTrace::default();
    let tenant_id = env::var("DTX_PUSH_TENANT_ID")?.parse::<TenantId>()?;
    let identity_database_url =
        load_secret_file_only("DTX_PUSH_IDENTITY_DATABASE_URL_FILE", 8_192)?;
    let registration_database_url =
        load_secret_file_only("DTX_PUSH_REGISTRATION_DATABASE_URL_FILE", 8_192)?;
    let broker_database_url = load_secret_file_only("DTX_PUSH_BROKER_DATABASE_URL_FILE", 8_192)?;
    let root_key_path = absolute_path(env::var("DTX_PUSH_ROOT_KEY_FILE")?)?;
    let service_account_path = absolute_path(env::var("DTX_PUSH_FCM_SERVICE_ACCOUNT_FILE")?)?;
    let tls_certificate = absolute_path(env::var("DTX_PUSH_TLS_CERTIFICATE_FILE")?)?;
    let tls_private_key = absolute_path(env::var("DTX_PUSH_TLS_PRIVATE_KEY_FILE")?)?;
    // All secret/configuration files are opened and validated before any pool,
    // provider, or listener can perform external work.
    let service_account: ServiceAccountFile =
        serde_json::from_slice(&load_secure_file(&service_account_path, 128 * 1024)?)?;
    let certificate_bytes = load_secure_file(&tls_certificate, 128 * 1024)?;
    let private_key_bytes = load_secure_file(&tls_private_key, 128 * 1024)?;
    let _ = rustls::pki_types::PrivateKeyDer::from_pem_slice(&private_key_bytes)
        .map_err(|_| "TLS private key rejected")?;
    let registration_kms = LocalRootKeyFileKms::from_root_key_file(&root_key_path)?;
    let broker_kms = LocalRootKeyFileKms::from_root_key_file(&root_key_path)?;
    trace
        .record(StartupStep::SecureLoads)
        .map_err(|_| "startup order")?;
    if parse_id("DTX_PUSH_UID", 10_001)? == 0 || parse_id("DTX_PUSH_GID", 10_001)? == 0 {
        return Err("root uid/gid is forbidden".into());
    }
    drop_privileges(
        parse_id("DTX_PUSH_UID", 10_001)?,
        parse_id("DTX_PUSH_GID", 10_001)?,
    )?;
    trace
        .record(StartupStep::PrivilegeDrop)
        .map_err(|_| "startup order")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main(
        tenant_id,
        identity_database_url,
        registration_database_url,
        broker_database_url,
        service_account,
        certificate_bytes.to_vec(),
        private_key_bytes.to_vec(),
        registration_kms,
        broker_kms,
        trace,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn async_main(
    tenant_id: TenantId,
    identity_database_url: Zeroizing<String>,
    registration_database_url: Zeroizing<String>,
    broker_database_url: Zeroizing<String>,
    mut service_account: ServiceAccountFile,
    certificate_bytes: Vec<u8>,
    private_key_bytes: Vec<u8>,
    registration_kms: LocalRootKeyFileKms,
    broker_kms: LocalRootKeyFileKms,
    mut trace: StartupTrace,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls = RustlsConfig::from_pem(certificate_bytes, private_key_bytes).await?;
    let login_identity =
        env::var("DTX_PUSH_IDENTITY_LOGIN").unwrap_or_else(|_| "dtx_push_identity_auth".to_owned());
    let login_registration = env::var("DTX_PUSH_REGISTRATION_LOGIN")
        .unwrap_or_else(|_| "dtx_push_registration".to_owned());
    let login_broker =
        env::var("DTX_PUSH_BROKER_LOGIN").unwrap_or_else(|_| "dtx_push_broker".to_owned());
    let identity_pool = IdentityAuthPool::connect(
        PgConnectOptions::from_str(&identity_database_url)?,
        8,
        login_identity,
    )
    .await?;
    let registration_pool = RegistrationPool::connect(
        PgConnectOptions::from_str(&registration_database_url)?,
        8,
        login_registration,
    )
    .await?;
    let broker_pool = BrokerPool::connect(
        PgConnectOptions::from_str(&broker_database_url)?,
        8,
        login_broker,
    )
    .await?;
    trace
        .record(StartupStep::Pools)
        .map_err(|_| "startup order")?;
    let registration =
        PushRegistrationService::new(identity_pool, registration_pool, registration_kms);
    let persistence = PostgresPushPersistence::new(broker_pool, tenant_id);
    let prune_persistence = persistence.clone();
    let credentials = ServiceAccountCredentials::new(
        std::mem::take(&mut service_account.project_id),
        std::mem::take(&mut service_account.client_email),
        std::mem::take(&mut service_account.private_key),
    )?;
    let provider = FcmPushProvider::from_service_account(credentials)?;
    trace
        .record(StartupStep::Provider)
        .map_err(|_| "startup order")?;
    let broker = ProductionBroker::new(persistence, broker_kms, provider).into_inner();
    let state = PushRouterState::new(Arc::new(registration), tenant_id);
    let readiness = Arc::new(Readiness::default());
    readiness.mark_pools_ready();
    readiness.mark_broker_ready();
    let cancellation = Cancellation::new();
    let broker_cancel = Arc::clone(&cancellation);
    tokio::spawn(run_broker_loop(
        broker,
        broker_cancel,
        Duration::from_secs(1),
    ));
    tokio::spawn(run_prune_loop(prune_persistence, Arc::clone(&cancellation)));

    let public_bind = env::var("DTX_PUSH_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9448".to_owned())
        .parse::<SocketAddr>()?;
    let ready_bind = env::var("DTX_PUSH_READY_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9488".to_owned())
        .parse::<SocketAddr>()?;
    if !ready_bind.ip().is_loopback() {
        return Err("readiness listener must be loopback-only".into());
    }
    let public_listener = std::net::TcpListener::bind(public_bind)?;
    public_listener.set_nonblocking(true)?;
    let public = axum_server::from_tcp_rustls(public_listener, tls)?
        .serve(router(state.clone()).into_make_service());
    let ready = TcpListener::bind(ready_bind).await?;
    trace
        .record(StartupStep::Listeners)
        .map_err(|_| "startup order")?;
    readiness.mark_router_ready();
    let ready_router = ready_listener(Arc::clone(&readiness));
    tokio::select! {
        result = public => { result?; }
        result = axum::serve(ready, ready_router) => { result?; }
        _ = tokio::signal::ctrl_c() => { cancellation.cancel(); }
    }
    Ok(())
}

fn absolute_path(value: String) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("path must be absolute".into());
    }
    Ok(path)
}

fn load_secret_file_only(
    file_name: &str,
    max: u64,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let path = env::var_os(file_name).ok_or("secure database URL file is required")?;
    let bytes = load_secure_file(Path::new(&path), max)?;
    let value = std::str::from_utf8(&bytes)?.trim_end();
    if value.is_empty() {
        return Err("secure database URL file is empty".into());
    }
    Ok(Zeroizing::new(value.to_owned()))
}

fn load_secure_file(
    path: &Path,
    max: u64,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > max
    {
        return Err("secure file policy rejected".into());
    }
    let expected_dev = metadata.dev();
    let expected_ino = metadata.ino();
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let handle = file.metadata()?;
    if !handle.file_type().is_file()
        || handle.file_type().is_symlink()
        || handle.uid() != 0
        || handle.mode() & 0o077 != 0
        || handle.len() == 0
        || handle.len() > max
        || handle.dev() != expected_dev
        || handle.ino() != expected_ino
    {
        return Err("secure file policy rejected".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(handle.len()).unwrap_or_default());
    let mut limited = (&mut file).take(max.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != handle.len() {
        return Err("secure file changed during read".into());
    }
    Ok(Zeroizing::new(bytes))
}

fn parse_id(name: &str, default: u32) -> Result<u32, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse().map_err(|_| "invalid uid/gid")?),
        Err(_) => Ok(default),
    }
}

#[cfg(unix)]
fn drop_privileges(uid: u32, gid: u32) -> Result<(), Box<dyn std::error::Error>> {
    use rustix::{
        process,
        thread::{self, Gid, Uid},
    };
    thread::set_thread_groups(&[])?;
    thread::set_thread_res_gid(
        Some(Gid::from_raw(gid)),
        Some(Gid::from_raw(gid)),
        Some(Gid::from_raw(gid)),
    )?;
    thread::set_thread_res_uid(
        Some(Uid::from_raw(uid)),
        Some(Uid::from_raw(uid)),
        Some(Uid::from_raw(uid)),
    )?;
    if process::getuid().as_raw() != uid
        || process::geteuid().as_raw() != uid
        || process::getgid().as_raw() != gid
        || process::getegid().as_raw() != gid
        || !process::getgroups()?.is_empty()
    {
        return Err("privilege drop verification failed".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn drop_privileges(_uid: u32, _gid: u32) -> Result<(), Box<dyn std::error::Error>> {
    Err("privilege drop unsupported".into())
}
