#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

//! Production Firebase Cloud Messaging adapter for opaque wake hints.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use dtx_opaque_push::{
    Provider, ProviderOutcome, PushProvider, RetryDelay, SecretToken, TransportPolicy, WakePayload,
};
use futures_core::Stream;
use futures_util::StreamExt;
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fmt::Write as _,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_URL_PREFIX: &str = "https://fcm.googleapis.com/v1/projects/";
const OAUTH_URL: &str = "https://oauth2.googleapis.com/token";
const MAX_PROJECT_ID: usize = 30;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 32 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct AccessToken(Zeroizing<String>);

impl AccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() || value.len() > MAX_TOKEN_BYTES || !value.is_ascii() {
            return Err(TokenError::Malformed);
        }
        Ok(Self(value))
    }
    fn expose<T>(&self, f: impl FnOnce(&str) -> T) -> T {
        f(self.0.as_str())
    }
}
impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken(REDACTED)")
    }
}
impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    Temporary,
    Permanent,
    Malformed,
}

pub trait AccessTokenSource: Send + Sync {
    fn access_token<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, TokenError>> + Send + 'a>>;
}

struct HttpResponse {
    status: u16,
    retry_after: Option<String>,
    body: Zeroizing<Vec<u8>>,
}

struct HttpRequest {
    url: String,
    bearer: Option<AccessToken>,
    content_type: &'static str,
    body: Zeroizing<Vec<u8>>,
}

type ResponseChunks =
    Pin<Box<dyn Stream<Item = Result<bytes::Bytes, HttpFailure>> + Send + 'static>>;

struct RawHttpResponse {
    status: u16,
    retry_after: Option<String>,
    content_length: Option<u64>,
    chunks: ResponseChunks,
}

trait HttpPort: Send + Sync {
    fn post(
        &self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<RawHttpResponse, HttpFailure>> + Send + '_>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpFailure {
    Transport,
    ResponseTooLarge,
}

struct ReqwestPort {
    client: reqwest::Client,
}

impl ReqwestPort {
    fn new() -> Result<Self, ConfigError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .referer(false)
            .build()
            .map_err(|_| ConfigError::HttpClient)?;
        Ok(Self { client })
    }
}

impl HttpPort for ReqwestPort {
    fn post(
        &self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<RawHttpResponse, HttpFailure>> + Send + '_>> {
        Box::pin(async move {
            let HttpRequest {
                url,
                bearer,
                content_type,
                body,
            } = request;
            let mut request = self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, content_type);
            if let Some(token) = bearer {
                // `HeaderValue` and the TLS stack necessarily retain their own
                // short-lived copies; reqwest exposes no zeroize-on-drop header
                // storage. Adapter-owned copies remain redacted and zeroizing.
                request = token.expose(|value| request.bearer_auth(value));
            }
            // `Bytes::from_owner` keeps the zeroizing owner alive until reqwest
            // drops the request body instead of converting it to a plain `Vec`.
            let body = bytes::Bytes::from_owner(body);
            let response = request
                .body(body)
                .send()
                .await
                .map_err(|_| HttpFailure::Transport)?;
            let status = response.status().as_u16();
            let content_length = response.content_length();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let chunks = response.bytes_stream().map(|chunk| {
                // Hyper/reqwest owns this received `Bytes` allocation and
                // exposes no wipe hook. The bounded reader checks its length
                // before copying into adapter-owned zeroizing storage.
                chunk.map_err(|_| HttpFailure::Transport)
            });
            Ok(RawHttpResponse {
                status,
                retry_after,
                content_length,
                chunks: Box::pin(chunks),
            })
        })
    }
}

async fn post_bounded(
    http: &dyn HttpPort,
    request: HttpRequest,
) -> Result<HttpResponse, HttpFailure> {
    let RawHttpResponse {
        status,
        retry_after,
        content_length,
        mut chunks,
    } = http.post(request).await?;
    if content_length.is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
        return Err(HttpFailure::ResponseTooLarge);
    }
    let mut body = Zeroizing::new(Vec::with_capacity(
        content_length
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(MAX_RESPONSE_BYTES),
    ));
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(HttpFailure::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        status,
        retry_after,
        body,
    })
}

pub struct ServiceAccountCredentials {
    project_id: String,
    client_email: String,
    private_key_pem: Zeroizing<String>,
}

impl ServiceAccountCredentials {
    pub fn new(
        project_id: impl Into<String>,
        client_email: impl Into<String>,
        private_key_pem: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        let project_id = project_id.into();
        validate_project_id(&project_id)?;
        let client_email = client_email.into();
        validate_service_account_email(&project_id, &client_email)?;
        let private_key_pem = Zeroizing::new(private_key_pem.into());
        if private_key_pem.is_empty() || private_key_pem.len() > MAX_PRIVATE_KEY_BYTES {
            return Err(ConfigError::CredentialKey);
        }
        parse_private_key(&private_key_pem).map_err(|()| ConfigError::CredentialKey)?;
        Ok(Self {
            project_id,
            client_email,
            private_key_pem,
        })
    }
}
impl fmt::Debug for ServiceAccountCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountCredentials")
            .field("project_id", &self.project_id)
            .field("client_email", &"[REDACTED]")
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

pub struct ServiceAccountTokenSource {
    credentials: Arc<ServiceAccountCredentials>,
    http: Arc<dyn HttpPort>,
    cache: Mutex<Option<CachedToken>>,
}
struct CachedToken {
    token: AccessToken,
    expires_at: Instant,
}

impl ServiceAccountTokenSource {
    pub fn new(credentials: ServiceAccountCredentials) -> Result<Self, ConfigError> {
        Ok(Self {
            credentials: Arc::new(credentials),
            http: Arc::new(ReqwestPort::new()?),
            cache: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn with_http(credentials: ServiceAccountCredentials, http: Arc<dyn HttpPort>) -> Self {
        Self {
            credentials: Arc::new(credentials),
            http,
            cache: Mutex::new(None),
        }
    }

    #[cfg(test)]
    async fn expire_cache(&self) {
        if let Some(cached) = self.cache.lock().await.as_mut() {
            cached.expires_at = Instant::now();
        }
    }
}

impl AccessTokenSource for ServiceAccountTokenSource {
    fn access_token<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, TokenError>> + Send + 'a>> {
        Box::pin(async move {
            // Hold the refresh gate across the exchange: callers arriving on an
            // empty/expired cache share exactly one OAuth request.
            let mut cache = self.cache.lock().await;
            let now = Instant::now();
            if let Some(cached) = cache.as_ref()
                && cached.expires_at > now + Duration::from_mins(1)
            {
                return Ok(cached.token.clone());
            }
            let jwt = build_jwt(&self.credentials).map_err(|()| TokenError::Temporary)?;
            let assertion = form_encode(jwt.as_str());
            let mut body = Zeroizing::new(Vec::with_capacity(assertion.len() + 96));
            body.extend_from_slice(
                b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
            );
            body.extend_from_slice(assertion.as_bytes());
            let response = post_bounded(
                self.http.as_ref(),
                HttpRequest {
                    url: OAUTH_URL.to_owned(),
                    bearer: None,
                    content_type: "application/x-www-form-urlencoded",
                    body,
                },
            )
            .await
            .map_err(|_| TokenError::Temporary)?;
            if !(200..300).contains(&response.status) {
                return Err(TokenError::Temporary);
            }
            let parsed: OAuthResponse =
                serde_json::from_slice(&response.body).map_err(|_| TokenError::Temporary)?;
            let token = AccessToken::new(parsed.access_token).map_err(|_| TokenError::Temporary)?;
            let expires = parsed
                .expires_in
                .filter(|v| *v > 0 && *v <= 86_400)
                .ok_or(TokenError::Temporary)?;
            cache.replace(CachedToken {
                token: token.clone(),
                expires_at: Instant::now() + Duration::from_secs(expires),
            });
            Ok(token)
        })
    }
}

#[derive(Deserialize)]
struct OAuthResponse {
    access_token: String,
    expires_in: Option<u64>,
}

pub struct FcmPushProvider {
    project_id: String,
    source: Arc<dyn AccessTokenSource>,
    http: Arc<dyn HttpPort>,
}

impl FcmPushProvider {
    pub fn new(
        project_id: impl Into<String>,
        source: Arc<dyn AccessTokenSource>,
    ) -> Result<Self, ConfigError> {
        let project_id = project_id.into();
        validate_project_id(&project_id)?;
        Ok(Self {
            project_id,
            source,
            http: Arc::new(ReqwestPort::new()?),
        })
    }
    pub fn from_service_account(
        credentials: ServiceAccountCredentials,
    ) -> Result<Self, ConfigError> {
        let project_id = credentials.project_id.clone();
        Self::from_service_account_for_project(project_id, credentials)
    }
    pub fn from_service_account_for_project(
        project_id: impl Into<String>,
        credentials: ServiceAccountCredentials,
    ) -> Result<Self, ConfigError> {
        let project_id = project_id.into();
        validate_project_id(&project_id)?;
        if project_id != credentials.project_id {
            return Err(ConfigError::ProjectIdentityMismatch);
        }
        let source = Arc::new(ServiceAccountTokenSource::new(credentials)?);
        Self::new(project_id, source)
    }
    #[cfg(test)]
    fn with_http(
        project_id: String,
        source: Arc<dyn AccessTokenSource>,
        http: Arc<dyn HttpPort>,
    ) -> Result<Self, ConfigError> {
        validate_project_id(&project_id)?;
        Ok(Self {
            project_id,
            source,
            http,
        })
    }
}

impl PushProvider for FcmPushProvider {
    fn send<'a>(
        &'a self,
        provider: Provider,
        token: &'a SecretToken,
        payload: &'a WakePayload,
        _policy: TransportPolicy,
    ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>> {
        Box::pin(async move {
            if provider != Provider::Fcm {
                return ProviderOutcome::PermanentFailure {
                    redacted_class: dtx_opaque_push::RedactedFailureClass::InvalidRequest,
                };
            }
            let token_text =
                match token.expose(|bytes| str::from_utf8(bytes).ok().map(str::to_owned)) {
                    Some(value) => Zeroizing::new(value),
                    None => {
                        return ProviderOutcome::PermanentFailure {
                            redacted_class: dtx_opaque_push::RedactedFailureClass::InvalidRequest,
                        };
                    }
                };
            let Ok(access) = self.source.access_token().await else {
                return transient(1, dtx_opaque_push::RedactedFailureClass::Unavailable);
            };
            let body = match serde_json::to_vec(&FcmRequest::new(&token_text, payload)) {
                Ok(value) => Zeroizing::new(value),
                Err(_) => {
                    return ProviderOutcome::PermanentFailure {
                        redacted_class: dtx_opaque_push::RedactedFailureClass::InvalidRequest,
                    };
                }
            };
            let url = format!("{FCM_URL_PREFIX}{}/messages:send", self.project_id);
            let response = match post_bounded(
                self.http.as_ref(),
                HttpRequest {
                    url,
                    bearer: Some(access),
                    content_type: "application/json",
                    body,
                },
            )
            .await
            {
                Ok(value) => value,
                Err(HttpFailure::Transport) => {
                    return transient(1, dtx_opaque_push::RedactedFailureClass::Unavailable);
                }
                Err(HttpFailure::ResponseTooLarge) => {
                    return ProviderOutcome::PermanentFailure {
                        redacted_class: dtx_opaque_push::RedactedFailureClass::Rejected,
                    };
                }
            };
            classify_fcm(&response)
        })
    }
}

#[derive(serde::Serialize)]
struct FcmRequest<'a> {
    message: FcmMessage<'a>,
}
#[derive(serde::Serialize)]
struct FcmMessage<'a> {
    token: &'a str,
    data: std::collections::BTreeMap<&'static str, String>,
    android: AndroidConfig,
}
#[derive(serde::Serialize)]
struct AndroidConfig {
    priority: &'static str,
    ttl: &'static str,
}
impl<'a> FcmRequest<'a> {
    fn new(token: &'a str, payload: &'a WakePayload) -> Self {
        let mut data = std::collections::BTreeMap::new();
        data.insert("version", "1".to_owned());
        data.insert("wake_delivery_id", payload.wake_delivery_id.to_string());
        Self {
            message: FcmMessage {
                token,
                data,
                android: AndroidConfig {
                    priority: "HIGH",
                    ttl: "60s",
                },
            },
        }
    }
}

fn classify_fcm(response: &HttpResponse) -> ProviderOutcome {
    if response.status == 200 {
        let ok = serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .is_some_and(|v| {
                v.get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| !name.is_empty())
            });
        return if ok {
            ProviderOutcome::Accepted
        } else {
            ProviderOutcome::PermanentFailure {
                redacted_class: dtx_opaque_push::RedactedFailureClass::Rejected,
            }
        };
    }
    if response.status == 429 || response.status >= 500 {
        return transient(
            retry_after(response.retry_after.as_deref()),
            dtx_opaque_push::RedactedFailureClass::Unavailable,
        );
    }
    let error = serde_json::from_slice::<FcmError>(&response.body).ok();
    if error.as_ref().is_some_and(FcmError::transient) {
        transient(
            retry_after(response.retry_after.as_deref()),
            dtx_opaque_push::RedactedFailureClass::Unavailable,
        )
    } else if error.as_ref().is_some_and(FcmError::token_invalid) {
        ProviderOutcome::PermanentTokenInvalid
    } else {
        ProviderOutcome::PermanentFailure {
            redacted_class: dtx_opaque_push::RedactedFailureClass::Rejected,
        }
    }
}

#[derive(Deserialize)]
struct FcmError {
    error: Option<FcmErrorDetail>,
}
#[derive(Deserialize)]
struct FcmErrorDetail {
    status: Option<String>,
    details: Option<Vec<FcmErrorItem>>,
}
#[derive(Deserialize)]
struct FcmErrorItem {
    #[serde(rename = "@type")]
    kind: Option<String>,
    #[serde(rename = "errorCode")]
    code: Option<String>,
}
impl FcmError {
    fn transient(&self) -> bool {
        self.error.as_ref().is_some_and(|error| {
            matches!(
                error.status.as_deref(),
                Some("QUOTA_EXCEEDED" | "UNAVAILABLE")
            )
        })
    }

    fn token_invalid(&self) -> bool {
        self.error.as_ref().is_some_and(|e| {
            e.status.as_deref() == Some("UNREGISTERED")
                || e.details.as_ref().is_some_and(|d| {
                    d.iter().any(|i| {
                        i.kind.as_deref()
                            == Some("type.googleapis.com/google.firebase.fcm.v1.FcmError")
                            && matches!(
                                i.code.as_deref(),
                                Some("UNREGISTERED" | "INVALID_ARGUMENT")
                            )
                    })
                })
        })
    }
}

fn retry_after(value: Option<&str>) -> u64 {
    let Some(value) = value.map(str::trim) else {
        return 1;
    };
    if let Ok(seconds) = value.parse::<u64>() {
        return seconds.clamp(1, 60);
    }
    httpdate::parse_http_date(value)
        .ok()
        .and_then(|when| when.duration_since(SystemTime::now()).ok())
        .map_or(1, |d| d.as_secs().clamp(1, 60))
}
fn transient(seconds: u64, class: dtx_opaque_push::RedactedFailureClass) -> ProviderOutcome {
    ProviderOutcome::Transient {
        retry_after: RetryDelay::new(seconds)
            .unwrap_or_else(|| RetryDelay::new(1).expect("one second")),
        redacted_class: class,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidProjectId,
    ProjectIdentityMismatch,
    CredentialIdentity,
    CredentialKey,
    HttpClient,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidProjectId => "project id is invalid",
            Self::ProjectIdentityMismatch => "credential and project identities differ",
            Self::CredentialIdentity => "credential identity is invalid",
            Self::CredentialKey => "credential key is invalid",
            Self::HttpClient => "HTTP client unavailable",
        })
    }
}
impl std::error::Error for ConfigError {}

fn validate_project_id(value: &str) -> Result<(), ConfigError> {
    if !(6..=MAX_PROJECT_ID).contains(&value.len())
        || !value.is_ascii()
        || value
            .as_bytes()
            .first()
            .is_none_or(|b| !b.is_ascii_lowercase())
        || value
            .as_bytes()
            .last()
            .is_none_or(|b| !b.is_ascii_lowercase() && !b.is_ascii_digit())
        || value
            .bytes()
            .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    {
        return Err(ConfigError::InvalidProjectId);
    }
    Ok(())
}

fn validate_service_account_email(project_id: &str, value: &str) -> Result<(), ConfigError> {
    if value.len() > 320 || !value.is_ascii() {
        return Err(ConfigError::CredentialIdentity);
    }
    let Some((local, domain)) = value.split_once('@') else {
        return Err(ConfigError::CredentialIdentity);
    };
    let expected_domain = format!("{project_id}.iam.gserviceaccount.com");
    if domain != expected_domain
        || !(6..=30).contains(&local.len())
        || local
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        || local
            .as_bytes()
            .first()
            .is_none_or(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit())
        || local
            .as_bytes()
            .last()
            .is_none_or(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit())
    {
        return Err(ConfigError::CredentialIdentity);
    }
    Ok(())
}

fn parse_private_key(pem: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
    let begin = "-----BEGIN PRIVATE KEY-----";
    let end = "-----END PRIVATE KEY-----";
    let trimmed = pem.trim_matches(|character: char| character.is_ascii_whitespace());
    let body = trimmed
        .strip_prefix(begin)
        .and_then(|v| v.strip_suffix(end))
        .ok_or(())?;
    let encoded = Zeroizing::new(
        body.chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>(),
    );
    let decoded_capacity = base64::decoded_len_estimate(encoded.len());
    if decoded_capacity == 0 || decoded_capacity > MAX_PRIVATE_KEY_BYTES {
        return Err(());
    }
    let mut der = Zeroizing::new(vec![0_u8; decoded_capacity]);
    let decoded_len = STANDARD
        .decode_slice(encoded.as_bytes(), der.as_mut_slice())
        .map_err(|_| ())?;
    der.truncate(decoded_len);
    // Ring's parsed RSA key object has no zeroize hook; the source PEM and DER
    // remain zeroizing, but ring may retain internal key limbs until drop.
    RsaKeyPair::from_pkcs8(&der).map_err(|_| ())?;
    Ok(der)
}

#[derive(Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'static str,
    iat: u64,
    exp: u64,
}

fn build_jwt(credentials: &ServiceAccountCredentials) -> Result<Zeroizing<String>, ()> {
    let der = parse_private_key(&credentials.private_key_pem)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    let header_json = Zeroizing::new(
        serde_json::to_vec(&JwtHeader {
            alg: "RS256",
            typ: "JWT",
        })
        .map_err(|_| ())?,
    );
    let claims_json = Zeroizing::new(
        serde_json::to_vec(&JwtClaims {
            iss: &credentials.client_email,
            scope: FCM_SCOPE,
            aud: OAUTH_URL,
            iat: now,
            exp: now.saturating_add(3600),
        })
        .map_err(|_| ())?,
    );
    let header = Zeroizing::new(URL_SAFE_NO_PAD.encode(header_json.as_slice()));
    let claims = Zeroizing::new(URL_SAFE_NO_PAD.encode(claims_json.as_slice()));
    let mut signing = Zeroizing::new(String::with_capacity(header.len() + claims.len() + 1));
    signing.push_str(header.as_str());
    signing.push('.');
    signing.push_str(claims.as_str());
    let key = RsaKeyPair::from_pkcs8(&der).map_err(|_| ())?;
    let mut signature = Zeroizing::new(vec![0_u8; key.public().modulus_len()]);
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing.as_bytes(),
        &mut signature,
    )
    .map_err(|_| ())?;
    let encoded_signature = Zeroizing::new(URL_SAFE_NO_PAD.encode(signature.as_slice()));
    let mut jwt = Zeroizing::new(String::with_capacity(
        signing.len() + encoded_signature.len() + 1,
    ));
    jwt.push_str(signing.as_str());
    jwt.push('.');
    jwt.push_str(encoded_signature.as_str());
    Ok(jwt)
}

fn form_encode(value: &str) -> Zeroizing<String> {
    let mut encoded = Zeroizing::new(String::with_capacity(value.len()));
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            let _ = write!(encoded, "{byte:02X}");
        }
    }
    encoded
}

impl Drop for ServiceAccountCredentials {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

#[cfg(test)]
mod tests;
