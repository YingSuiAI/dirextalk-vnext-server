use dtx_indexer::{IndexerError, PinnedOriginV1};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn resolution_is_fail_closed_and_connection_target_is_pinned() {
    let public: IpAddr = "93.184.216.34".parse().expect("public IP");
    let pinned = PinnedOriginV1::new("https://feed.example", vec![public]).expect("safe origin");
    assert_eq!(pinned.pinned_socket().ip(), public);
    for forbidden in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "10.0.0.1".parse().expect("private"),
        "169.254.169.254".parse().expect("metadata"),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "fe80::1".parse().expect("link-local"),
        "2001:db8::1".parse().expect("documentation"),
        "64:ff9b::a9fe:a9fe".parse().expect("NAT64 metadata"),
        "64:ff9b:1::7f00:1".parse().expect("local translation"),
        "2002:7f00:1::".parse().expect("6to4 loopback"),
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2"
            .parse()
            .expect("Teredo"),
    ] {
        assert_eq!(
            PinnedOriginV1::new("https://feed.example", vec![public, forbidden]),
            Err(IndexerError::UnsafeAddress)
        );
    }
    assert_eq!(
        PinnedOriginV1::new("https://127.0.0.1", vec![public]),
        Err(IndexerError::InvalidOrigin)
    );
}
