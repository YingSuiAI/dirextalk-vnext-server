#![forbid(unsafe_code)]

use std::{env, fs, io, net::SocketAddr, path::Path, str::FromStr};

use dtx_domain::TenantId;
use dtx_group_persistence::GroupPgStore;
use ed25519_dalek::SigningKey;
use sqlx::postgres::PgConnectOptions;

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
        load_sequencer_signing_key(Path::new(&env::var("DTX_GROUP_MLS_SEQUENCER_KEY_FILE")?))?;
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
    let state = dtx_group_node::GroupNodeState::new(store, tenant_id)
        .with_mls_sequencer_signing_key(sequencer_signing_key)
        .with_allowed_http_identity_origins(allowed_http_identity_origins)?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    axum::serve(listener, dtx_group_node::group_router_with_state(state)).await?;
    Ok(())
}

fn load_sequencer_signing_key(path: &Path) -> Result<SigningKey, io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MLS sequencer key must be an exact 32-byte regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "MLS sequencer key file must not be group/world accessible",
            ));
        }
    }
    let mut seed: [u8; 32] = fs::read(path)?
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid MLS key length"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(signing_key)
}
