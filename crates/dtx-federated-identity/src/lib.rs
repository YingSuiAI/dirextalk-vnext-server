#![forbid(unsafe_code)]

//! Hardened remote identity-log resolution shared by federated services.

use std::{collections::BTreeSet, fmt, time::Duration};

use dtx_domain::{DeviceId, IdentityId};
use dtx_identity_log::{
    DeviceStatusV1, IdentityLogEventV1, IdentityLogPageV1, IdentityLogV1,
    MAX_IDENTITY_LOG_PAGE_BYTES, MAX_IDENTITY_LOG_PAGE_EVENTS,
};
use dtx_wire::SigningPublicKey;
use reqwest::{Certificate, Client, StatusCode, Url, header};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use x509_parser::parse_x509_certificate;

const IDENTITY_LOG_PAGE_CONTENT_TYPE: &str = "application/vnd.dirextalk.identity-log-page.v1+cbor";
const MAX_IDENTITY_LOG_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_IDENTITY_LOG_PAGES: usize = 256;

#[derive(Clone)]
pub struct FederatedIdentityVerifier {
    client: Client,
    allowed_http_origins: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedIdentityError {
    InvalidOrigin,
    InvalidTrustRoot,
    InvalidIdentityLog,
    DeviceUnavailable,
    TemporarilyUnavailable,
}

impl fmt::Display for FederatedIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOrigin => "federated identity origin is invalid",
            Self::InvalidTrustRoot => "federated identity trust root is invalid",
            Self::InvalidIdentityLog => "federated identity log is invalid",
            Self::DeviceUnavailable => "federated identity device is unavailable",
            Self::TemporarilyUnavailable => "federated identity service is unavailable",
        })
    }
}

impl std::error::Error for FederatedIdentityError {}

impl FederatedIdentityVerifier {
    /// Builds a verifier that permits HTTPS origins and the explicitly listed
    /// development-only HTTP origins.
    ///
    /// # Errors
    ///
    /// Returns an error when an HTTP origin is invalid or the hardened HTTP
    /// client cannot be constructed.
    pub fn new(
        allowed_http_origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, FederatedIdentityError> {
        let mut canonical_http_origins = BTreeSet::new();
        for origin in allowed_http_origins {
            let canonical = canonical_origin(&origin, true)?;
            if canonical.scheme() != "http" {
                return Err(FederatedIdentityError::InvalidOrigin);
            }
            canonical_http_origins.insert(canonical.origin().ascii_serialization());
        }
        let client = build_client(None)?;
        Ok(Self {
            client,
            allowed_http_origins: canonical_http_origins,
        })
    }

    /// Builds a verifier and canonicalizes the local node's public origin.
    ///
    /// An optional CA certificate extends the platform trust store without
    /// replacing normal hostname and certificate-chain validation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid public or allowed origin, an invalid CA
    /// certificate, or a failure to construct the hardened HTTP client.
    pub fn new_with_public_origin_and_additional_trust_root_pem(
        public_origin: &str,
        allowed_http_origins: impl IntoIterator<Item = String>,
        additional_trust_root_pem: Option<&[u8]>,
    ) -> Result<(Self, String), FederatedIdentityError> {
        let verifier = Self::new(allowed_http_origins)?;
        let verifier = match additional_trust_root_pem {
            Some(trust_root_pem) => verifier.with_additional_trust_root_pem(trust_root_pem)?,
            None => verifier,
        };
        let public_origin = canonical_origin(public_origin, true)?;
        let canonical_public_origin = public_origin.origin().ascii_serialization();
        if public_origin.scheme() == "http"
            && !verifier
                .allowed_http_origins
                .contains(&canonical_public_origin)
        {
            return Err(FederatedIdentityError::InvalidOrigin);
        }
        Ok((verifier, canonical_public_origin))
    }

    /// Extends the normal platform trust store with one explicitly configured CA root.
    ///
    /// The root is deliberately merged with the normal verifier instead of replacing it;
    /// Rustls therefore continues to enforce normal certificate-chain and hostname checks.
    fn with_additional_trust_root_pem(
        mut self,
        trust_root_pem: &[u8],
    ) -> Result<Self, FederatedIdentityError> {
        self.client = build_client(Some(parse_additional_trust_root_pem(trust_root_pem)?))?;
        Ok(self)
    }

    /// Resolves the current active signing key for one remote device from its
    /// origin's canonical identity log.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not allowed, the remote service is
    /// unavailable, the identity log is invalid, or the requested device is
    /// absent or no longer active.
    pub async fn active_device_signing_key(
        &self,
        origin: &str,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<SigningPublicKey, FederatedIdentityError> {
        let origin = self.parse_allowed_origin(origin)?;
        let mut after = 0_u64;
        let mut advertised_head = None;
        let mut projection = None;
        let mut total_bytes = 0_usize;

        for _ in 0..MAX_IDENTITY_LOG_PAGES {
            let page_url = identity_log_page_url(&origin, identity_id, after)?;
            let response = self
                .client
                .get(page_url)
                .header(header::ACCEPT, IDENTITY_LOG_PAGE_CONTENT_TYPE)
                .header(header::CACHE_CONTROL, "no-store")
                .send()
                .await
                .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?;
            if response.status() != StatusCode::OK {
                return Err(if response.status().is_server_error() {
                    FederatedIdentityError::TemporarilyUnavailable
                } else {
                    FederatedIdentityError::DeviceUnavailable
                });
            }
            require_single_header(
                response.headers(),
                header::CONTENT_TYPE,
                IDENTITY_LOG_PAGE_CONTENT_TYPE,
            )?;
            require_single_header(response.headers(), header::CACHE_CONTROL, "no-store")?;
            require_single_header(
                response.headers(),
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff",
            )?;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_IDENTITY_LOG_PAGE_BYTES as u64)
            {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            let mut response = response;
            let mut exact_page = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?
            {
                total_bytes = total_bytes
                    .checked_add(chunk.len())
                    .ok_or(FederatedIdentityError::InvalidIdentityLog)?;
                if exact_page.len() + chunk.len() > MAX_IDENTITY_LOG_PAGE_BYTES
                    || total_bytes > MAX_IDENTITY_LOG_TOTAL_BYTES
                {
                    return Err(FederatedIdentityError::InvalidIdentityLog);
                }
                exact_page.extend_from_slice(&chunk);
            }
            let page = IdentityLogPageV1::decode_and_verify(&exact_page)
                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?;
            if page.identity_id() != identity_id || page.requested_after_sequence() != after {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            let page_head = (page.advertised_head_sequence(), page.advertised_head_hash());
            if advertised_head.is_some_and(|head| head != page_head) {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            advertised_head = Some(page_head);
            for exact_event in page.exact_events() {
                let event = IdentityLogEventV1::decode_and_verify(exact_event)
                    .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?;
                match projection.as_mut() {
                    None => {
                        projection = Some(
                            IdentityLogV1::bootstrap(&event)
                                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?,
                        );
                    }
                    Some(log) => log
                        .append(&event)
                        .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?,
                }
            }
            after = page.next_after_sequence();
            if !page.has_more() {
                let log = projection.ok_or(FederatedIdentityError::InvalidIdentityLog)?;
                if advertised_head != Some((log.head_sequence(), log.head_hash())) {
                    return Err(FederatedIdentityError::InvalidIdentityLog);
                }
                return active_signing_key(&log, device_id);
            }
            if page.exact_events().len() != MAX_IDENTITY_LOG_PAGE_EVENTS {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
        }
        Err(FederatedIdentityError::InvalidIdentityLog)
    }

    fn parse_allowed_origin(&self, origin: &str) -> Result<Url, FederatedIdentityError> {
        let parsed = canonical_origin(origin, true)?;
        if parsed.scheme() == "https"
            || self
                .allowed_http_origins
                .contains(&parsed.origin().ascii_serialization())
        {
            Ok(parsed)
        } else {
            Err(FederatedIdentityError::InvalidOrigin)
        }
    }
}

fn build_client(
    additional_trust_root: Option<Certificate>,
) -> Result<Client, FederatedIdentityError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = Client::builder()
        .https_only(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .referer(false);
    // `tls_certs_merge` retains the platform/WebPKI verifier and only appends this
    // explicitly configured root. In particular, it does not disable hostname or
    // certificate-chain validation.
    let builder = match additional_trust_root {
        Some(trust_root) => builder.tls_certs_merge([trust_root]),
        None => builder,
    };
    builder
        .build()
        .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)
}

fn parse_additional_trust_root_pem(
    trust_root_pem: &[u8],
) -> Result<Certificate, FederatedIdentityError> {
    let certificates = CertificateDer::pem_slice_iter(trust_root_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)?;
    let [certificate] = certificates.as_slice() else {
        return Err(FederatedIdentityError::InvalidTrustRoot);
    };
    let (remaining, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)?;
    if !remaining.is_empty() || !parsed.is_ca() {
        return Err(FederatedIdentityError::InvalidTrustRoot);
    }
    Certificate::from_der(certificate.as_ref())
        .map_err(|_| FederatedIdentityError::InvalidTrustRoot)
}

fn active_signing_key(
    log: &IdentityLogV1,
    device_id: DeviceId,
) -> Result<SigningPublicKey, FederatedIdentityError> {
    if log.device_status(device_id) != Some(DeviceStatusV1::Active) {
        return Err(FederatedIdentityError::DeviceUnavailable);
    }
    log.device_certificate(device_id)
        .map(dtx_identity_log::DeviceCertificateV1::device_signing_key)
        .ok_or(FederatedIdentityError::DeviceUnavailable)
}

fn canonical_origin(value: &str, allow_http: bool) -> Result<Url, FederatedIdentityError> {
    if !(10..=512).contains(&value.len()) || !value.is_ascii() {
        return Err(FederatedIdentityError::InvalidOrigin);
    }
    let parsed = Url::parse(value).map_err(|_| FederatedIdentityError::InvalidOrigin)?;
    if !matches!(parsed.scheme(), "https" | "http")
        || (!allow_http && parsed.scheme() != "https")
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || parsed.host_str().is_none()
        || parsed.origin().ascii_serialization() != value
    {
        return Err(FederatedIdentityError::InvalidOrigin);
    }
    Ok(parsed)
}

fn identity_log_page_url(
    origin: &Url,
    identity_id: IdentityId,
    after: u64,
) -> Result<Url, FederatedIdentityError> {
    origin
        .join(&format!(
            "v1/identities/{identity_id}/log?after={after}&limit={MAX_IDENTITY_LOG_PAGE_EVENTS}"
        ))
        .map_err(|_| FederatedIdentityError::InvalidOrigin)
}

fn require_single_header(
    headers: &header::HeaderMap,
    name: header::HeaderName,
    expected: &'static str,
) -> Result<(), FederatedIdentityError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(FederatedIdentityError::InvalidIdentityLog)?;
    if first != expected || values.next().is_some() {
        return Err(FederatedIdentityError::InvalidIdentityLog);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use base64ct::{Base64, Encoding as _};
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };

    use super::{FederatedIdentityError, FederatedIdentityVerifier};

    #[test]
    fn additional_trust_root_requires_one_ca_pem() -> Result<(), Box<dyn Error>> {
        let ca_pem = ca_certificate_pem()?;
        let (_, public_origin) =
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(ca_pem.as_bytes()),
            )?;
        assert_eq!(public_origin, "https://group.test");

        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)?;
        let leaf = CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&leaf_key)?;
        let leaf_pem = pem_from_der(leaf.der().as_ref());
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(leaf_pem.as_bytes()),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );

        let duplicate_ca_pem = format!("{ca_pem}{ca_pem}");
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(duplicate_ca_pem.as_bytes()),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(b"not a PEM certificate"),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );
        Ok(())
    }

    fn ca_certificate_pem() -> Result<String, Box<dyn Error>> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = parameters.self_signed(&key)?;
        Ok(pem_from_der(certificate.der().as_ref()))
    }

    fn pem_from_der(der: &[u8]) -> String {
        let encoded = Base64::encode_string(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 output is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}
