use std::{error::Error, fmt, sync::Arc};

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use crate::SecretBytes;

/// Client certificate chain paired with a non-cloneable PKCS#8 private key.
///
/// This type deliberately implements neither `Clone` nor `Debug`. The key can
/// only cross into rustls while held by [`SecretBytes::expose`].
pub struct TlsClientIdentity {
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: SecretBytes,
}

impl TlsClientIdentity {
    /// Creates a client identity from leaf-first certificate DER and one PKCS#8 key.
    ///
    /// # Errors
    ///
    /// Returns an error when the certificate chain is empty or contains an
    /// empty certificate.
    pub fn new_pkcs8(
        certificate_chain_der: Vec<Vec<u8>>,
        private_key: SecretBytes,
    ) -> Result<Self, TlsClientIdentityError> {
        if certificate_chain_der.is_empty() {
            return Err(TlsClientIdentityError::EmptyCertificateChain);
        }
        if certificate_chain_der.iter().any(Vec::is_empty) {
            return Err(TlsClientIdentityError::EmptyCertificate);
        }
        Ok(Self {
            certificate_chain: certificate_chain_der
                .into_iter()
                .map(CertificateDer::from)
                .collect(),
            private_key,
        })
    }

    /// Consumes this boundary and installs its key into a rustls client configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when rustls rejects the PKCS#8 private key or its
    /// association with the certificate chain.
    pub fn into_client_config(
        self,
        roots: Arc<RootCertStore>,
    ) -> Result<ClientConfig, TlsClientIdentityError> {
        let Self {
            certificate_chain,
            private_key,
        } = self;
        let mut result = Err(TlsClientIdentityError::InvalidPrivateKey);
        private_key.expose(|private_key_der| {
            let private_key =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der.to_vec()));
            result = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(certificate_chain, private_key)
                .map_err(|_| TlsClientIdentityError::InvalidPrivateKey);
        });
        result
    }
}

/// Stable TLS identity construction failure with no certificate or key payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsClientIdentityError {
    EmptyCertificateChain,
    EmptyCertificate,
    InvalidPrivateKey,
}

impl fmt::Display for TlsClientIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyCertificateChain => "TLS client certificate chain is empty",
            Self::EmptyCertificate => "TLS client certificate is empty",
            Self::InvalidPrivateKey => "TLS client private key is invalid",
        })
    }
}

impl Error for TlsClientIdentityError {}
