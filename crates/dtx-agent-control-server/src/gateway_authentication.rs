use std::{error::Error, fmt};

use dtx_security::{AuthenticatedInternalServicePeer, InternalServiceMtlsClientVerifier};
use rustls::pki_types::UnixTime;
use tonic::Request;

/// Re-authenticates the exact internal-service certificate chain attached to a Gateway RPC.
///
/// The TLS verifier already checked this chain during the handshake. Repeating
/// the check here binds the unary request to the typed service identity and its
/// certificate-derived tenant before parsing any caller-controlled fields.
///
/// # Errors
///
/// Fails closed when tonic did not attach a peer chain or the live verifier
/// rejects its trust, time, EKU, URI shape, or service kind.
pub fn authenticate_agent_gateway_request<T>(
    request: &Request<T>,
    verifier: &InternalServiceMtlsClientVerifier,
    now: UnixTime,
) -> Result<AuthenticatedInternalServicePeer, GatewayRequestAuthenticationError> {
    let certificates = request
        .peer_certs()
        .ok_or(GatewayRequestAuthenticationError::MissingPeerCertificate)?;
    let (leaf, intermediates) = certificates
        .split_first()
        .ok_or(GatewayRequestAuthenticationError::MissingPeerCertificate)?;
    verifier
        .authenticate_peer_certificate(leaf, intermediates, now)
        .map_err(|_| GatewayRequestAuthenticationError::PeerRejected)
}

/// Sanitized internal Gateway transport authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayRequestAuthenticationError {
    MissingPeerCertificate,
    PeerRejected,
}

impl fmt::Display for GatewayRequestAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPeerCertificate => "Agent Gateway RPC has no authenticated peer",
            Self::PeerRejected => "Agent Gateway RPC peer was rejected",
        })
    }
}

impl Error for GatewayRequestAuthenticationError {}
