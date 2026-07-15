#![forbid(unsafe_code)]

use dtx_domain::{IndexerId, TenantId};
use dtx_indexer_node::{IndexerPgStore, PinnedHttpsBundleFetcher, indexer_router};
use sqlx::postgres::PgConnectOptions;
use std::{env, net::SocketAddr, str::FromStr, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = PgConnectOptions::from_str(&env::var("DTX_DATABASE_URL")?)?;
    let tenant = env::var("DTX_INDEXER_TENANT_ID")?.parse::<TenantId>()?;
    let indexer_id = env::var("DTX_INDEXER_ID")?.parse::<IndexerId>()?;
    let bind = env::var("DTX_INDEXER_BIND")
        .unwrap_or_else(|_| "127.0.0.1:4814".to_owned())
        .parse::<SocketAddr>()?;
    let store = IndexerPgStore::connect(options, 8).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        indexer_router(
            store,
            tenant,
            indexer_id,
            Arc::new(PinnedHttpsBundleFetcher::default()),
        ),
    )
    .await?;
    Ok(())
}
