use std::{error::Error, fmt, time::Duration};

use dtx_security::{AuthenticatedConnectorPeer, ConnectorMtlsClientVerifier};
use rustls::pki_types::UnixTime;
use tonic::Request;

/// Re-authenticates the exact certificate chain attached by tonic to a control RPC.
///
/// The custom rustls verifier already ran during the handshake. Repeating the
/// cryptographic check here binds the concrete RPC to a typed identity and leaf
/// fingerprint. Credential authorization is intentionally deferred to the
/// PostgreSQL-backed application operation.
///
/// # Errors
///
/// Fails closed when tonic did not attach an mTLS chain or the live verifier
/// rejects its leaf, chain, certificate time, or strict identity shape.
pub fn authenticate_control_request<T>(
    request: &Request<T>,
    verifier: &ConnectorMtlsClientVerifier,
    now: UnixTime,
) -> Result<AuthenticatedConnectorPeer, ControlRequestAuthenticationError> {
    let certificates = request
        .peer_certs()
        .ok_or(ControlRequestAuthenticationError::MissingPeerCertificate)?;
    let (leaf, intermediates) = certificates
        .split_first()
        .ok_or(ControlRequestAuthenticationError::MissingPeerCertificate)?;
    verifier
        .authenticate_peer_certificate(leaf, intermediates, now)
        .map_err(|_| ControlRequestAuthenticationError::PeerRejected)
}

/// Converts a non-negative Unix millisecond value without rounding into rustls time.
///
/// # Errors
///
/// Rejects negative timestamps rather than wrapping them into a future time.
pub fn unix_time_from_millis(
    unix_millis: i64,
) -> Result<UnixTime, ControlRequestAuthenticationError> {
    let millis = u64::try_from(unix_millis)
        .map_err(|_| ControlRequestAuthenticationError::InvalidServerTime)?;
    Ok(UnixTime::since_unix_epoch(Duration::from_millis(millis)))
}

/// Sanitized control transport authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRequestAuthenticationError {
    MissingPeerCertificate,
    PeerRejected,
    InvalidServerTime,
}

impl fmt::Display for ControlRequestAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPeerCertificate => "Connector control RPC has no authenticated peer",
            Self::PeerRejected => "Connector control RPC peer was rejected",
            Self::InvalidServerTime => "Connector control server time is invalid",
        })
    }
}

impl Error for ControlRequestAuthenticationError {}
