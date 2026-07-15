use std::{collections::BTreeSet, fmt, time::Duration};

use dtx_domain::{DeviceId, IdentityId};
use dtx_identity_log::{
    DeviceStatusV1, IdentityLogEventV1, IdentityLogPageV1, IdentityLogV1,
    MAX_IDENTITY_LOG_PAGE_BYTES, MAX_IDENTITY_LOG_PAGE_EVENTS,
};
use dtx_wire::SigningPublicKey;
use reqwest::{Client, StatusCode, Url, header};

const IDENTITY_LOG_PAGE_CONTENT_TYPE: &str = "application/vnd.dirextalk.identity-log-page.v1+cbor";
const MAX_IDENTITY_LOG_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_IDENTITY_LOG_PAGES: usize = 256;

#[derive(Clone)]
pub(crate) struct FederatedIdentityVerifier {
    client: Client,
    allowed_http_origins: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FederatedIdentityError {
    InvalidOrigin,
    InvalidIdentityLog,
    DeviceUnavailable,
    TemporarilyUnavailable,
}

impl fmt::Display for FederatedIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOrigin => "federated identity origin is invalid",
            Self::InvalidIdentityLog => "federated identity log is invalid",
            Self::DeviceUnavailable => "federated identity device is unavailable",
            Self::TemporarilyUnavailable => "federated identity service is unavailable",
        })
    }
}

impl std::error::Error for FederatedIdentityError {}

impl FederatedIdentityVerifier {
    pub(crate) fn new(
        allowed_http_origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, FederatedIdentityError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut canonical_http_origins = BTreeSet::new();
        for origin in allowed_http_origins {
            let canonical = canonical_origin(&origin, true)?;
            if canonical.scheme() != "http" {
                return Err(FederatedIdentityError::InvalidOrigin);
            }
            canonical_http_origins.insert(canonical.origin().ascii_serialization());
        }
        let client = Client::builder()
            .https_only(false)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .referer(false)
            .build()
            .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?;
        Ok(Self {
            client,
            allowed_http_origins: canonical_http_origins,
        })
    }

    pub(crate) async fn active_device_signing_key(
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
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
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
