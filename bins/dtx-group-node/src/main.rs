#![forbid(unsafe_code)]

use std::{env, net::SocketAddr, str::FromStr};

use dtx_domain::TenantId;
use dtx_group_persistence::GroupPgStore;
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
        .with_allowed_http_identity_origins(allowed_http_identity_origins)?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    axum::serve(listener, dtx_group_node::group_router_with_state(state)).await?;
    Ok(())
}
