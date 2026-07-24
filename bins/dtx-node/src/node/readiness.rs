#[derive(Clone)]
struct NodeReadiness {
    identity: IdentityPgStore,
    group: GroupPgStore,
    mailbox: MailboxPgStore,
    #[cfg(feature = "public-content")]
    public_content: Option<(PublicFeedPgStore, IndexerPgStore)>,
    mls_key_loaded: bool,
}

async fn local_ready(State(state): State<NodeReadiness>) -> StatusCode {
    if !state.mls_key_loaded {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let checks = async {
        let (identity, group, mailbox) = tokio::join!(
            state.identity.readiness_check(),
            state.group.readiness_check(),
            state.mailbox.readiness_check(),
        );
        let core_ready = identity.is_ok_and(|ready| ready)
            && group.is_ok_and(|ready| ready)
            && mailbox.is_ok_and(|ready| ready);
        #[cfg(feature = "public-content")]
        let public_ready = match &state.public_content {
            None => true,
            Some((feed, indexer)) => {
                let (feed, indexer) =
                    tokio::join!(feed.readiness_check(), indexer.readiness_check());
                feed.is_ok_and(|ready| ready) && indexer.is_ok_and(|ready| ready)
            }
        };
        #[cfg(not(feature = "public-content"))]
        let public_ready = true;
        core_ready && public_ready
    };
    if tokio::time::timeout(READY_TIMEOUT, checks).await == Ok(true) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
