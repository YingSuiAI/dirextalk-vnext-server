#![forbid(unsafe_code)]

use std::{
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use dtx_domain::TenantId;
use dtx_group_node::load_mls_sequencer_signing_key;
use dtx_group_persistence::GroupPgStore;
use sqlx::postgres::PgConnectOptions;

const MAX_FEDERATED_IDENTITY_TRUST_ROOT_PEM_BYTES: u64 = 64 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = env::var("DTX_DATABASE_URL")?;
    let tenant_id = env::var("DTX_GROUP_TENANT_ID")?.parse::<TenantId>()?;
    let bind_address = env::var("DTX_GROUP_BIND")
        .unwrap_or_else(|_| "127.0.0.1:4814".to_owned())
        .parse::<SocketAddr>()?;
    let options = PgConnectOptions::from_str(&database_url)?;
    let store = GroupPgStore::connect(options, 8).await?;
    let sequencer_signing_key =
        load_mls_sequencer_signing_key(Path::new(&env::var("DTX_GROUP_MLS_SEQUENCER_KEY_FILE")?))?;
    let public_origin =
        env::var("DTX_GROUP_PUBLIC_ORIGIN").or_else(|_| env::var("DTX_NODE_PUBLIC_ORIGIN"))?;
    let allowed_http_identity_origins = env::var("DTX_GROUP_DEV_HTTP_IDENTITY_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let additional_federated_identity_trust_root_pem =
        load_optional_federated_identity_trust_root_pem()?;
    let state = dtx_group_node::GroupNodeState::new(store, tenant_id)
        .with_mls_sequencer_signing_key(sequencer_signing_key)
        .with_federated_identity_configuration(
            public_origin,
            allowed_http_identity_origins,
            additional_federated_identity_trust_root_pem.as_deref(),
        )?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    axum::serve(listener, dtx_group_node::group_router_with_state(state)).await?;
    Ok(())
}

fn load_optional_federated_identity_trust_root_pem() -> Result<Option<Vec<u8>>, io::Error> {
    let Some(path) = env::var_os("DTX_GROUP_FEDERATED_IDENTITY_TRUST_ROOT_FILE") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_FEDERATED_IDENTITY_TRUST_ROOT_PEM_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "federated identity trust root must be a non-empty regular PEM file within 64 KiB",
        ));
    }
    let pem = fs::read(path)?;
    if pem.is_empty()
        || u64::try_from(pem.len()).unwrap_or(u64::MAX)
            > MAX_FEDERATED_IDENTITY_TRUST_ROOT_PEM_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "federated identity trust root must be a non-empty regular PEM file within 64 KiB",
        ));
    }
    Ok(Some(pem))
}
