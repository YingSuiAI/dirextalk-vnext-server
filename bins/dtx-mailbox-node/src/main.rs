#![forbid(unsafe_code)]

use std::{env, net::SocketAddr, str::FromStr};

use dtx_mailbox::MailboxPgStore;
use sqlx::postgres::PgConnectOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = env::var("DTX_DATABASE_URL")?;
    let bind_address = env::var("DTX_MAILBOX_BIND")
        .unwrap_or_else(|_| "127.0.0.1:4812".to_owned())
        .parse::<SocketAddr>()?;
    let options = PgConnectOptions::from_str(&database_url)?;
    let store = MailboxPgStore::connect(options, 8).await?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    axum::serve(listener, dtx_mailbox_node::mailbox_router(store)).await?;
    Ok(())
}
