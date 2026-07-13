use std::{io, sync::Arc, time::Duration};

use futures_core::Stream;
use futures_util::StreamExt as _;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_stream::wrappers::TcpListenerStream;

use crate::transport_admission::{SourceTransportAdmission, SourceTransportAdmissionConfig};

/// Limits work spent on unauthenticated concurrent TLS handshakes per listener.
pub const MAX_CONCURRENT_TLS_HANDSHAKES: usize = 128;
/// Maximum time an unauthenticated peer may occupy one TLS handshake slot.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Converts an already-bound control listener into concurrently authenticated
/// rustls connections suitable for `tonic::transport::Server::serve_with_incoming`.
///
/// The caller must pass a configuration produced by
/// `dtx_security::build_connector_mtls_server_config`; this function never
/// weakens or replaces its custom Connector identity verifier. Live credential
/// authorization remains in the `PostgreSQL` application boundary.
pub fn connector_tls_incoming(
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
) -> impl Stream<Item = Result<TlsStream<TcpStream>, io::Error>> + Send + 'static {
    connector_tls_incoming_with_timeout(listener, server_config, TLS_HANDSHAKE_TIMEOUT)
}

fn connector_tls_incoming_with_timeout(
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
    handshake_timeout: Duration,
) -> impl Stream<Item = Result<TlsStream<TcpStream>, io::Error>> + Send + 'static {
    let acceptor = TlsAcceptor::from(server_config);
    let admission = SourceTransportAdmission::new(SourceTransportAdmissionConfig::default());
    TcpListenerStream::new(listener)
        .map(move |accepted| {
            let acceptor = acceptor.clone();
            let admission = admission.clone();
            async move {
                let stream = accepted?;
                let source_ip = stream.peer_addr().ok().map(|address| address.ip());
                let _handshake_permit = admission.try_acquire(source_ip).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Connector TLS admission is temporarily unavailable",
                    )
                })?;
                match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                    Ok(result) => {
                        result.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    }
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Connector TLS handshake timed out",
                    )),
                }
            }
        })
        .buffer_unordered(MAX_CONCURRENT_TLS_HANDSHAKES)
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use futures_util::StreamExt as _;
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    };
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use super::{MAX_CONCURRENT_TLS_HANDSHAKES, connector_tls_incoming_with_timeout};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_handshakes_release_capacity_for_the_next_valid_client() {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("test key generated");
        let certificate = CertificateParams::new(vec!["localhost".to_owned()])
            .expect("certificate parameters are valid")
            .self_signed(&key)
            .expect("test certificate is signed");
        let certificate_der = certificate.der().clone();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate_der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .expect("server TLS config is valid");
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate_der)
            .expect("test certificate is a valid root");
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let address = listener.local_addr().expect("listener has an address");
        let incoming = connector_tls_incoming_with_timeout(
            listener,
            Arc::new(server_config),
            Duration::from_millis(100),
        );
        let server = tokio::spawn(async move {
            let mut incoming = Box::pin(incoming);
            let mut timed_out = 0_usize;
            let mut rejected = 0_usize;
            loop {
                match incoming.next().await.expect("incoming stream remains open") {
                    Ok(_) => return (timed_out, rejected),
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => timed_out += 1,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => rejected += 1,
                    Err(error) => panic!("unexpected TLS accept error: {error}"),
                }
            }
        });

        let mut slow_clients = Vec::with_capacity(MAX_CONCURRENT_TLS_HANDSHAKES);
        for _ in 0..MAX_CONCURRENT_TLS_HANDSHAKES {
            slow_clients.push(
                TcpStream::connect(address)
                    .await
                    .expect("slow client connects"),
            );
        }
        tokio::time::sleep(Duration::from_millis(150)).await;

        let valid_tcp = TcpStream::connect(address)
            .await
            .expect("valid client reaches the accept queue");
        let valid_tls = TlsConnector::from(Arc::new(client_config)).connect(
            ServerName::try_from("localhost")
                .expect("test DNS name is valid")
                .to_owned(),
            valid_tcp,
        );
        tokio::time::timeout(Duration::from_secs(2), valid_tls)
            .await
            .expect("valid client is admitted after slow handshakes time out")
            .expect("valid TLS handshake succeeds");
        let (timed_out, rejected) = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server observes the valid connection")
            .expect("server task succeeds");
        assert!(timed_out > 0, "at least one saturated slot must time out");
        assert!(
            rejected > 0,
            "one direct source must not occupy every global handshake slot"
        );
        drop(slow_clients);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_handshakes_release_pending_source_capacity() {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("test key generated");
        let certificate = CertificateParams::new(vec!["localhost".to_owned()])
            .expect("certificate parameters are valid")
            .self_signed(&key)
            .expect("test certificate is signed");
        let certificate_der = certificate.der().clone();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate_der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .expect("server TLS config is valid");
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate_der)
            .expect("test certificate is a valid root");
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let address = listener.local_addr().expect("listener has an address");
        let incoming = connector_tls_incoming_with_timeout(
            listener,
            Arc::new(server_config),
            Duration::from_secs(2),
        );
        let server = tokio::spawn(async move {
            let mut incoming = Box::pin(incoming);
            let mut established = Vec::new();
            while established.len() < 9 {
                established.push(
                    incoming
                        .next()
                        .await
                        .expect("incoming stream remains open")
                        .expect("completed handshake is not rejected by pending limits"),
                );
            }
            established
        });

        let mut clients = Vec::new();
        for _ in 0..9 {
            let tcp = TcpStream::connect(address)
                .await
                .expect("client reaches the accept queue");
            let tls = TlsConnector::from(Arc::clone(&client_config)).connect(
                ServerName::try_from("localhost")
                    .expect("test DNS name is valid")
                    .to_owned(),
                tcp,
            );
            clients.push(
                tokio::time::timeout(Duration::from_secs(2), tls)
                    .await
                    .expect("completed handshakes do not consume pending capacity")
                    .expect("TLS handshake succeeds"),
            );
        }
        let established = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server accepts every completed connection")
            .expect("server task succeeds");
        assert_eq!(established.len(), 9);
        assert_eq!(clients.len(), 9);
    }
}
