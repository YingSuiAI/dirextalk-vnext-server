/// Builds the production router for one tenant-affine Group Node.
pub fn group_router(store: GroupPgStore, tenant_id: TenantId) -> Router {
    group_router_with_state(GroupNodeState::new(store, tenant_id))
}

/// Builds the Group Node router with explicit state for deterministic tests.
pub fn group_router_with_state(state: GroupNodeState) -> Router {
    Router::new()
        .route(GROUP_SCOPE_PATH_TEMPLATE, put(create_group))
        .route(GROUP_ADMIN_PATH_TEMPLATE, put(grant_admin))
        .route(GROUP_ADMIN_REVOKE_PATH_TEMPLATE, post(revoke_admin))
        .route(GROUP_INVITE_PATH_TEMPLATE, put(issue_invite))
        .route(GROUP_INVITE_REVOKE_PATH_TEMPLATE, post(revoke_invite))
        .route(GROUP_JOIN_REQUEST_PATH_TEMPLATE, put(request_join))
        .route(
            GROUP_JOIN_REQUEST_COLLECTION_PATH_TEMPLATE,
            get(list_join_requests),
        )
        .route(GROUP_JOIN_APPROVAL_PATH_TEMPLATE, post(approve_join))
        .route(
            GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE,
            get(get_membership_receipt),
        )
        .route(
            MLS_COMMIT_PATH_TEMPLATE,
            post(submit_mls_commit).get(get_mls_commit_receipt),
        )
        .route(MLS_COMMIT_FEED_PATH_TEMPLATE, get(get_mls_commit_feed))
        .route(
            MLS_CONFIRMATION_PATH_TEMPLATE,
            post(confirm_mls_device_join),
        )
        .route(
            MLS_SEQUENCER_DESCRIPTOR_PATH,
            get(get_mls_sequencer_descriptor),
        )
        .route(
            GROUP_SERVICE_DESCRIPTOR_PATH,
            get(get_group_service_descriptor),
        )
        .with_state(state)
}
