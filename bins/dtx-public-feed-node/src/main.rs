#![forbid(unsafe_code)]

use std::{env, net::SocketAddr, str::FromStr};

use dtx_domain::TenantId;
use dtx_public_feed_node::{PublicFeedPgStore, public_feed_router};
use sqlx::postgres::PgConnectOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = PgConnectOptions::from_str(&env::var("DTX_DATABASE_URL")?)?;
    let tenant_id = env::var("DTX_PUBLIC_FEED_TENANT_ID")?.parse::<TenantId>()?;
    let bind = env::var("DTX_PUBLIC_FEED_BIND")
        .unwrap_or_else(|_| "127.0.0.1:4813".to_owned())
        .parse::<SocketAddr>()?;
    let store = PublicFeedPgStore::connect(options, 8).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, public_feed_router(store, tenant_id)).await?;
    Ok(())
}
