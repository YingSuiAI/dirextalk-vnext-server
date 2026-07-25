use crate::unix_time_from_millis;
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use dtx_security::{AuthenticatedConnectorPeer, ConnectorMtlsClientVerifier};
use rustls::ServerConfig;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

#[derive(Clone, Copy)]
pub struct RouteHealthConnectInfo(pub AuthenticatedConnectorPeer);

pub struct RouteHealthTlsIo {
    pub tls_stream: TlsStream<TcpStream>,
    pub peer: AuthenticatedConnectorPeer,
}
impl AsyncRead for RouteHealthTlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for RouteHealthTlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tls_stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_shutdown(cx)
    }
}

pub struct RouteHealthTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    verifier: Arc<ConnectorMtlsClientVerifier>,
}
impl RouteHealthTlsListener {
    pub fn new(
        listener: TcpListener,
        config: Arc<ServerConfig>,
        verifier: Arc<ConnectorMtlsClientVerifier>,
    ) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            verifier,
        }
    }
}
impl Listener for RouteHealthTlsListener {
    type Io = RouteHealthTlsIo;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = loop {
                if let Ok(value) = self.listener.accept().await {
                    break value;
                }
            };
            let Ok(stream) = self.acceptor.accept(stream).await else {
                continue;
            };
            let Some(certs) = stream.get_ref().1.peer_certificates() else {
                continue;
            };
            let Some((leaf, intermediates)) = certs.split_first() else {
                continue;
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_millis()).ok())
                .unwrap_or(0);
            let Ok(now) = unix_time_from_millis(now) else {
                continue;
            };
            let Ok(peer) = self
                .verifier
                .authenticate_peer_certificate(leaf, intermediates, now)
            else {
                continue;
            };
            return (
                RouteHealthTlsIo {
                    tls_stream: stream,
                    peer,
                },
                address,
            );
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}
impl Connected<IncomingStream<'_, RouteHealthTlsListener>> for RouteHealthConnectInfo {
    fn connect_info(stream: IncomingStream<'_, RouteHealthTlsListener>) -> Self {
        Self(stream.io().peer)
    }
}
