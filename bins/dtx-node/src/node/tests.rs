#[cfg(test)]
#[path = "../../../../crates/dtx-storage/tests/support/mod.rs"]
mod test_support;

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use axum::{body::Body, http::Request};
    use dtx_domain::SystemClock;
    use dtx_group_node::{
        GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE, GROUP_SERVICE_DESCRIPTOR_PATH,
        group_router_with_state,
    };
    use ed25519_dalek::SigningKey;
    use tower::ServiceExt;

    use super::{
        GroupPgStore, StatusCode, TenantId, configured_group_state, is_graphic_value,
        test_support as support, validate_listen_scope, validate_public_transport,
    };

    #[test]
    fn graphic_config_values_reject_whitespace_and_bounds() {
        assert!(is_graphic_value("https://node.example", 256));
        assert!(!is_graphic_value("https://node.example/ invalid", 256));
        assert!(!is_graphic_value("", 256));
        assert!(!is_graphic_value("toolong", 3));
    }

    #[test]
    fn public_transport_cannot_claim_https_without_a_tls_listener() {
        assert!(validate_public_transport("https://node.example", true).is_ok());
        assert!(validate_public_transport("http://node.example", false).is_ok());
        assert!(validate_public_transport("https://node.example", false).is_err());
        assert!(validate_public_transport("http://node.example", true).is_err());
        assert!(validate_public_transport("ftp://node.example", false).is_err());
    }

    #[test]
    fn non_loopback_listener_requires_tls() {
        let external = "0.0.0.0:8443".parse().expect("socket address");
        let loopback = "127.0.0.1:9080".parse().expect("socket address");
        assert!(validate_listen_scope(external, true).is_ok());
        assert!(validate_listen_scope(external, false).is_err());
        assert!(validate_listen_scope(loopback, false).is_ok());
    }

    #[test]
    fn public_opt_in_and_pool_bounds_fail_closed() {
        assert!(!super::public_content_enabled(None).expect("default disabled"));
        assert!(super::public_content_enabled(Some("true")).expect("explicit opt in"));
        assert!(super::public_content_enabled(Some("1")).is_err());
        assert!(super::parse_pool_size("DTX_NODE_TEST_MISSING", 2, 64).is_ok());
    }

    #[tokio::test]
    async fn configured_unified_group_route_serves_descriptor() -> Result<(), Box<dyn Error>> {
        let harness = support::PostgresHarness::start().await?;
        let store = GroupPgStore::connect(harness.group_runtime_options(), 1).await?;
        let state = configured_group_state(
            store,
            TenantId::new(),
            Arc::new(SystemClock),
            SigningKey::from_bytes(&[73; 32]),
            "https://node.example",
            Vec::new(),
            None,
        )?;
        let response = group_router_with_state(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(GROUP_SERVICE_DESCRIPTOR_PATH)
                    .header("host", "attacker.invalid")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some(GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE)
        );
        Ok(())
    }
}
