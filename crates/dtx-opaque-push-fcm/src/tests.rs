#![allow(clippy::type_complexity)]
use super::*;
use dtx_opaque_push::{PushProvider, WakeDeliveryId};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use std::{
    fmt,
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Semaphore;

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDE+rxqMIhDqpdDvBDC1tSpFRwyKGY4XAewlTW20244ZUDfrjAfA+SOx0Cd1tKwu8vmhNpBpc3oJG DohW/KzMytoPsG0H8Tys5gVkSDedipMm8k3Vxa6qUIJmYCMF8EWXcTM2c9vgVR2nDkMwC+4mzdwy32HER2VeEt+kcUYpjir2TrYqgpB8/smr8TXaLQezlEN+cFQG4VLHqk3Da2khVy5HyoqBetI+BmqUJwyrPTTFVJDgNx6nUrCqo7PaptCTnP2GUjHItgzLyl0PTO2nqv6nNTaJtpHnCE0q2i3yWQGlXn9WGGwR7gcHWUC4KapF8gYXwRXoyrfvMYj6q7xDqnAgMBAAECggEAAZXhEVu9pQnI+OcZHXBcOtYsKW0w0XBQMYgp7ARMpVCPUp2UzpMZ8lpBN2QEwx5n2D2mghPDEgTE8OouCaxXU2hxzM69zxt5SMY4+/PtngMFaP8NIMA1vtiMRqU8Bo1vy2xE/va6FTwUX4nXjjHFXY2WH55/oJI1Y0jZ7JyUjXKHVAx0SwzAoo7sVft6V/Oj++h+CvqNHuiOfixNkNgLlYU+5aHyPivinAlxpkOVIYYp0TdQbxJv56Dj7rQSsfYMneGCRzaD3NO0ZDn5l4Gf1I1vka/XPkW/Ymd2sZWis8+qcl9uEItReIAj/dw3Vnovr4AzhBVfvlmAymEIGPLwnQKBgQD3q04ChQEUnkGn3TTZmNA/UI5D5yOv59tzKGXWJQhNc8RywUNMHnrqOz66w1jBqRbC8Akt06+DGht5gf68RLOo12oHQwh1bO6eUTxZlWUmNllrTJ+YzFOdNWqziIAL5ssrnUNqZt9Yj5j+9dGi/X78w6jKnt4ITZ0vfEvGqAkCywKBgQDLmvBTYQgZD/UrJ7DBurVxEj+fAa0S4gH40MMuwM1GJQ/SJwuPFEzcADKhDibGMViXQmNlkTCFz4RkmydxLJVYtWXL7rzvsJ6uA9dspNlh+kljsK/O30ivzx2tZqXQ5BhxXuUyGh1117QKJr1LvmDBZEx2GfyY4kBUxlSlPTUAFQKBgQCMh1TSNSmxy0Ixv2A3f2/aHRk8CjDDpOlt5CQ0Z/rYB7IV8vb+f+T6dvdW/XSlHg5eOdjbeduCphOk1E/3/3t5eBEfYbew+UhD6JA3vH8SOZBvQ6DjEDz5XM/YYsFU/3WUn70a6JgeJgyHzm9O7ktZnKNvpMkTKQbhZMOSStIiFQKBgFkR2NzA8Af2wSw12s+FXGawswBefVZrZK1ytlA3rBVplTg8OIRJPy5nL77hL/k4ESdqtYzzLST8mVBhx6ls9ZCvGm9Sa3j37RL3P0CaBTclhQGFhAOeDnBKzRLUeumdP0wpVV7LqeOpj2t5cwo1qKIxvHlV+Pjw0W/Eq7b1xb/ZAoGBAIUEkoG5ujOkIgCjVw4XqxtODFMawxC8j4LFPYXEPq8xuoD2eaPiu0kkRve4vuzZhhwWCjv+CZTLjlOxHLfhMwbCt5QueYa69yP4B9MoBfu5ftJWl1sBJdncv86AhRidZ4ftdK+hVmDIikVmUkfKTh/KTpCDwm7Rr5nas4X16JI6\n-----END PRIVATE KEY-----";

struct RequestRecord {
    url: String,
    bearer: Option<AccessToken>,
    content_type: &'static str,
    body: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for RequestRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestRecord")
            .field("url", &self.url)
            .field("bearer", &"[REDACTED]")
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .finish()
    }
}

struct RecordedResponse {
    status: u16,
    retry_after: Option<String>,
    content_length: Option<u64>,
    chunks: Vec<Result<bytes::Bytes, HttpFailure>>,
}

struct Recording {
    requests: StdMutex<Vec<RequestRecord>>,
    responses: StdMutex<Vec<Result<RecordedResponse, HttpFailure>>>,
}
impl Recording {
    fn one(response: RecordedResponse) -> Arc<Self> {
        Arc::new(Self {
            requests: StdMutex::new(Vec::new()),
            responses: StdMutex::new(vec![Ok(response)]),
        })
    }
    fn many(responses: Vec<Result<RecordedResponse, HttpFailure>>) -> Arc<Self> {
        Arc::new(Self {
            requests: StdMutex::new(Vec::new()),
            responses: StdMutex::new(responses),
        })
    }
}
impl HttpPort for Recording {
    fn post(
        &self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<RawHttpResponse, HttpFailure>> + Send + '_>> {
        let HttpRequest {
            url,
            bearer,
            content_type,
            body,
        } = request;
        self.requests.lock().unwrap().push(RequestRecord {
            url,
            bearer,
            content_type,
            body,
        });
        let response = self.responses.lock().unwrap().remove(0);
        Box::pin(async move {
            response.map(|recorded| RawHttpResponse {
                status: recorded.status,
                retry_after: recorded.retry_after,
                content_length: recorded.content_length,
                chunks: Box::pin(futures_util::stream::iter(recorded.chunks)),
            })
        })
    }
}

struct GatedRecording {
    calls: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}

impl GatedRecording {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }
}

impl HttpPort for GatedRecording {
    fn post(
        &self,
        _request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<RawHttpResponse, HttpFailure>> + Send + '_>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.add_permits(1);
            self.release
                .acquire()
                .await
                .expect("test gate open")
                .forget();
            let recorded = oauth_ok("shared-token", 120);
            Ok(RawHttpResponse {
                status: recorded.status,
                retry_after: recorded.retry_after,
                content_length: recorded.content_length,
                chunks: Box::pin(futures_util::stream::iter(recorded.chunks)),
            })
        })
    }
}

fn credentials() -> ServiceAccountCredentials {
    ServiceAccountCredentials::new(
        "project-123",
        "push-agent@project-123.iam.gserviceaccount.com",
        TEST_PRIVATE_KEY,
    )
    .unwrap()
}

fn oauth_ok(token: &str, expires_in: u64) -> RecordedResponse {
    let body = Zeroizing::new(
        serde_json::json!({"access_token": token, "expires_in": expires_in}).to_string(),
    );
    response(200, &body)
}

struct StaticToken;
impl AccessTokenSource for StaticToken {
    fn access_token<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, TokenError>> + Send + 'a>> {
        Box::pin(async { AccessToken::new("bearer-token").map_err(|_| TokenError::Malformed) })
    }
}

struct FailingToken(TokenError);
impl AccessTokenSource for FailingToken {
    fn access_token<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, TokenError>> + Send + 'a>> {
        let error = self.0;
        Box::pin(async move { Err(error) })
    }
}

fn payload() -> WakePayload {
    WakePayload::new(WakeDeliveryId::parse("0190f2a5-7b1c-7abc-8def-0123456789ab").unwrap())
}
fn provider(recording: Arc<Recording>) -> FcmPushProvider {
    FcmPushProvider::with_http("project-123".to_owned(), Arc::new(StaticToken), recording).unwrap()
}
fn response(status: u16, body: &str) -> RecordedResponse {
    RecordedResponse {
        status,
        retry_after: None,
        content_length: Some(body.len() as u64),
        chunks: vec![Ok(bytes::Bytes::from_owner(Zeroizing::new(
            body.as_bytes().to_vec(),
        )))],
    }
}

#[tokio::test]
async fn exact_fcm_request_shape_and_fixed_endpoint() {
    let recording = Recording::one(response(
        200,
        r#"{"name":"projects/project-123/messages/abc"}"#,
    ));
    let provider = provider(recording.clone());
    let token = SecretToken::new(b"device-token".to_vec()).unwrap();
    assert_eq!(
        provider
            .send(
                Provider::Fcm,
                &token,
                &payload(),
                TransportPolicy {
                    ttl_seconds: 1,
                    android_priority: dtx_opaque_push::AndroidPriority::High
                }
            )
            .await,
        ProviderOutcome::Accepted
    );
    let requests = recording.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url,
        "https://fcm.googleapis.com/v1/projects/project-123/messages:send"
    );
    assert!(
        requests[0]
            .bearer
            .as_ref()
            .is_some_and(|token| token.expose(|value| value == "bearer-token"))
    );
    assert_eq!(requests[0].content_type, "application/json");
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["message"]["token"], "device-token");
    assert_eq!(
        body["message"]["data"],
        serde_json::json!({"version":"1","wake_delivery_id":"0190f2a5-7b1c-7abc-8def-0123456789ab"})
    );
    assert_eq!(
        body["message"]["android"],
        serde_json::json!({"priority":"HIGH","ttl":"60s"})
    );
    assert!(body["message"].get("notification").is_none());
}

#[tokio::test]
async fn invalid_utf8_never_reaches_http() {
    let recording = Recording::one(response(200, r#"{"name":"ok"}"#));
    let provider = provider(recording.clone());
    let token = SecretToken::new(vec![0xff]).unwrap();
    assert!(matches!(
        provider
            .send(
                Provider::Fcm,
                &token,
                &payload(),
                TransportPolicy::default()
            )
            .await,
        ProviderOutcome::PermanentFailure {
            redacted_class: dtx_opaque_push::RedactedFailureClass::InvalidRequest
        }
    ));
    assert!(recording.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn every_access_token_source_error_is_transient() {
    for error in [
        TokenError::Temporary,
        TokenError::Permanent,
        TokenError::Malformed,
    ] {
        let recording = Recording::one(response(200, r#"{"name":"unused"}"#));
        let provider = FcmPushProvider::with_http(
            "project-123".to_owned(),
            Arc::new(FailingToken(error)),
            recording.clone(),
        )
        .unwrap();
        assert!(matches!(
            provider
                .send(
                    Provider::Fcm,
                    &SecretToken::new(b"device-token".to_vec()).unwrap(),
                    &payload(),
                    TransportPolicy::default()
                )
                .await,
            ProviderOutcome::Transient { retry_after, .. } if retry_after.seconds() == 1
        ));
        assert!(recording.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn response_mappings_are_redacted_and_bounded() {
    let recording = Recording::one(response(400, r#"{"error":{"status":"UNREGISTERED"}}"#));
    assert_eq!(
        provider(recording)
            .send(
                Provider::Fcm,
                &SecretToken::new(b"token".to_vec()).unwrap(),
                &payload(),
                TransportPolicy::default()
            )
            .await,
        ProviderOutcome::PermanentTokenInvalid
    );
    let recording = Recording::one(RecordedResponse {
        status: 429,
        retry_after: Some("120".to_owned()),
        content_length: None,
        chunks: Vec::new(),
    });
    assert!(
        matches!(provider(recording).send(Provider::Fcm, &SecretToken::new(b"token".to_vec()).unwrap(), &payload(), TransportPolicy::default()).await, ProviderOutcome::Transient { retry_after, .. } if retry_after.seconds() == 60)
    );
    for status in ["QUOTA_EXCEEDED", "UNAVAILABLE"] {
        let recording = Recording::one(response(
            400,
            &serde_json::json!({"error":{"status":status}}).to_string(),
        ));
        assert!(matches!(
            provider(recording)
                .send(
                    Provider::Fcm,
                    &SecretToken::new(b"token".to_vec()).unwrap(),
                    &payload(),
                    TransportPolicy::default()
                )
                .await,
            ProviderOutcome::Transient { .. }
        ));
    }
    let recording = Recording::one(response(200, "not-json"));
    assert!(matches!(
        provider(recording)
            .send(
                Provider::Fcm,
                &SecretToken::new(b"token".to_vec()).unwrap(),
                &payload(),
                TransportPolicy::default()
            )
            .await,
        ProviderOutcome::PermanentFailure { .. }
    ));
}

#[tokio::test]
async fn invalid_argument_only_revokes_with_exact_fcm_token_detail() {
    let cases = [
        (r#"{"error":{"status":"INVALID_ARGUMENT"}}"#, false),
        (
            r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"}]}}"#,
            true,
        ),
        (
            r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","errorCode":"INVALID_ARGUMENT"}]}}"#,
            false,
        ),
        (
            r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"QUOTA_EXCEEDED"}]}}"#,
            false,
        ),
    ];
    for (body, token_invalid) in cases {
        let outcome = provider(Recording::one(response(400, body)))
            .send(
                Provider::Fcm,
                &SecretToken::new(b"device-token".to_vec()).unwrap(),
                &payload(),
                TransportPolicy::default(),
            )
            .await;
        if token_invalid {
            assert_eq!(outcome, ProviderOutcome::PermanentTokenInvalid);
        } else {
            assert_eq!(
                outcome,
                ProviderOutcome::PermanentFailure {
                    redacted_class: dtx_opaque_push::RedactedFailureClass::Rejected,
                }
            );
        }
    }
}

#[test]
fn project_and_credential_validation_redacts_debug() {
    assert!(matches!(
        ServiceAccountCredentials::new("Bad_Project", "x@x.iam.gserviceaccount.com", "secret"),
        Err(ConfigError::InvalidProjectId)
    ));
    let error = ConfigError::CredentialKey;
    assert!(!format!("{error:?}").contains("secret"));
    let token = AccessToken::new("secret").unwrap();
    assert!(!format!("{token:?}").contains("secret"));
}

#[tokio::test]
async fn oauth_jwt_has_fixed_claims_and_valid_signature() {
    let recording = Recording::many(vec![Ok(oauth_ok("oauth-secret", 120))]);
    let source = ServiceAccountTokenSource::with_http(credentials(), recording.clone());
    assert_eq!(
        source.access_token().await.unwrap().to_string(),
        "[REDACTED]"
    );
    let request = &recording.requests.lock().unwrap()[0];
    let debug = format!("{request:?}");
    assert!(!debug.contains("oauth-secret"));
    assert!(!debug.contains("assertion"));
    assert_eq!(request.url, OAUTH_URL);
    assert_eq!(request.content_type, "application/x-www-form-urlencoded");
    let form = str::from_utf8(&request.body).unwrap();
    assert!(form.starts_with(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
    ));
    let jwt = form.split_once("assertion=").unwrap().1;
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header, serde_json::json!({"alg":"RS256","typ":"JWT"}));
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(
        claims["iss"],
        "push-agent@project-123.iam.gserviceaccount.com"
    );
    assert_eq!(claims["scope"], FCM_SCOPE);
    assert_eq!(claims["aud"], OAUTH_URL);
    let der = parse_private_key(TEST_PRIVATE_KEY).unwrap();
    let key = RsaKeyPair::from_pkcs8(&der).unwrap();
    let verifier = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public().as_ref());
    verifier
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .unwrap();
}

#[tokio::test]
async fn oauth_cache_reuses_valid_token_and_refreshes_expired_token() {
    let recording = Recording::many(vec![Ok(oauth_ok("first", 120)), Ok(oauth_ok("second", 1))]);
    let source = ServiceAccountTokenSource::with_http(credentials(), recording.clone());
    assert!(
        source
            .access_token()
            .await
            .unwrap()
            .expose(|value| value == "first")
    );
    assert!(
        source
            .access_token()
            .await
            .unwrap()
            .expose(|value| value == "first")
    );
    assert_eq!(recording.requests.lock().unwrap().len(), 1);
    source.expire_cache().await;
    let refreshed = source.access_token().await.unwrap();
    assert!(refreshed.expose(|value| value == "second"));
    assert_eq!(recording.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn concurrent_oauth_refresh_is_single_flight() {
    let recording = GatedRecording::new();
    let source = Arc::new(ServiceAccountTokenSource::with_http(
        credentials(),
        recording.clone(),
    ));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let source = source.clone();
        tasks.push(tokio::spawn(async move { source.access_token().await }));
    }
    recording
        .entered
        .acquire()
        .await
        .expect("first exchange entered")
        .forget();
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(recording.calls.load(Ordering::SeqCst), 1);
    recording.release.add_permits(16);
    for task in tasks {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(recording.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn every_runtime_oauth_failure_is_transient() {
    let cases = vec![
        Ok(response(400, r#"{"error":"invalid_grant"}"#)),
        Ok(response(200, "malformed")),
        Ok(response(429, r#"{"error":"quota"}"#)),
        Ok(response(500, r#"{"error":"unavailable"}"#)),
        Err(HttpFailure::Transport),
        Err(HttpFailure::ResponseTooLarge),
    ];
    for oauth_response in cases {
        let recording = Recording::many(vec![oauth_response]);
        let source = Arc::new(ServiceAccountTokenSource::with_http(
            credentials(),
            recording.clone(),
        ));
        let provider =
            FcmPushProvider::with_http("project-123".to_owned(), source, recording.clone())
                .unwrap();
        let outcome = provider
            .send(
                Provider::Fcm,
                &SecretToken::new(b"device-token".to_vec()).unwrap(),
                &payload(),
                TransportPolicy::default(),
            )
            .await;
        assert!(
            matches!(outcome, ProviderOutcome::Transient { retry_after, .. } if (1..=60).contains(&retry_after.seconds()))
        );
        assert!(!format!("{outcome:?}").contains("invalid_grant"));
        assert_eq!(recording.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn temporary_oauth_and_oversized_transport_are_redacted_failures() {
    let oauth_recording = Recording::many(vec![Ok(RecordedResponse {
        status: 503,
        retry_after: None,
        content_length: None,
        chunks: vec![Ok(bytes::Bytes::from_owner(Zeroizing::new(
            b"provider-secret-body".to_vec(),
        )))],
    })]);
    let source = Arc::new(ServiceAccountTokenSource::with_http(
        credentials(),
        oauth_recording.clone(),
    ));
    let temp_provider =
        FcmPushProvider::with_http("project-123".to_owned(), source, oauth_recording.clone())
            .unwrap();
    let outcome = temp_provider
        .send(
            Provider::Fcm,
            &SecretToken::new(b"token".to_vec()).unwrap(),
            &payload(),
            TransportPolicy::default(),
        )
        .await;
    assert!(matches!(outcome, ProviderOutcome::Transient { .. }));
    assert_eq!(oauth_recording.requests.lock().unwrap().len(), 1);
    let oversized = RecordedResponse {
        status: 200,
        retry_after: None,
        content_length: None,
        chunks: vec![
            Ok(bytes::Bytes::from_owner(Zeroizing::new(vec![
                b'a';
                MAX_RESPONSE_BYTES
            ]))),
            Ok(bytes::Bytes::from_owner(Zeroizing::new(vec![b'b']))),
        ],
    };
    let oversized_provider = FcmPushProvider::with_http(
        "project-123".to_owned(),
        Arc::new(StaticToken),
        Recording::many(vec![Ok(oversized)]),
    )
    .unwrap();
    let outcome = oversized_provider
        .send(
            Provider::Fcm,
            &SecretToken::new(b"token".to_vec()).unwrap(),
            &payload(),
            TransportPolicy::default(),
        )
        .await;
    assert!(matches!(outcome, ProviderOutcome::PermanentFailure { .. }));
    let capture = Recording::one(response(200, r#"{"name":"ok"}"#));
    let _ = provider(capture.clone())
        .send(
            Provider::Fcm,
            &SecretToken::new(b"token".to_vec()).unwrap(),
            &payload(),
            TransportPolicy::default(),
        )
        .await;
    let debug = format!("{:?}", capture.requests.lock().unwrap()[0]);
    assert!(!debug.contains("bearer-token"));
    assert!(!debug.contains("token"));
}

#[test]
fn credential_project_identity_is_checked() {
    let credentials = credentials();
    assert!(matches!(
        FcmPushProvider::from_service_account_for_project("other-123", credentials),
        Err(ConfigError::ProjectIdentityMismatch)
    ));
}

#[test]
fn pem_whitespace_and_email_grammar_are_strict() {
    let padded = format!(" \r\n\t{TEST_PRIVATE_KEY}\n \t");
    assert!(
        ServiceAccountCredentials::new(
            "project-123",
            "push-agent@project-123.iam.gserviceaccount.com",
            padded,
        )
        .is_ok()
    );
    assert!(matches!(
        ServiceAccountCredentials::new(
            "project-123",
            "push-agent@project-123.iam.gserviceaccount.com",
            "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQ!\n-----END PRIVATE KEY-----",
        ),
        Err(ConfigError::CredentialKey)
    ));
    for invalid in [
        "Push-agent@project-123.iam.gserviceaccount.com",
        "-push-agent@project-123.iam.gserviceaccount.com",
        "push-agent-@project-123.iam.gserviceaccount.com",
        "push-agent\"@project-123.iam.gserviceaccount.com",
        "push-agent\\@project-123.iam.gserviceaccount.com",
        "push-agent\n@project-123.iam.gserviceaccount.com",
        "push-agent@other-123.iam.gserviceaccount.com",
    ] {
        assert!(matches!(
            ServiceAccountCredentials::new("project-123", invalid, TEST_PRIVATE_KEY),
            Err(ConfigError::CredentialIdentity)
        ));
    }
}
