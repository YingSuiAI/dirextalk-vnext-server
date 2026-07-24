fn map_federated_identity_error(error: FederatedIdentityError) -> GroupFailure {
    match error {
        FederatedIdentityError::TemporarilyUnavailable => GroupFailure::TemporarilyUnavailable,
        FederatedIdentityError::InvalidOrigin
        | FederatedIdentityError::InvalidTrustRoot
        | FederatedIdentityError::InvalidIdentityLog
        | FederatedIdentityError::InvalidRecoveryAuthorization
        | FederatedIdentityError::RecoveryAuthorizationUnavailable
        | FederatedIdentityError::DeviceUnavailable => GroupFailure::AuthenticationRejected,
    }
}

fn map_control_rejection(rejection: GroupControlRejection) -> GroupFailure {
    match rejection {
        GroupControlRejection::PolicyDenied => GroupFailure::AccessDenied,
        GroupControlRejection::RevisionConflict
        | GroupControlRejection::AdminLimitReached
        | GroupControlRejection::GroupExists => GroupFailure::ActionConflict,
        GroupControlRejection::InvalidOperation => GroupFailure::InvalidRequest,
    }
}

fn map_persistence_error(error: &GroupPersistenceError) -> GroupFailure {
    use dtx_membership_command::MembershipCommandError;

    match error {
        GroupPersistenceError::DeviceAuthenticationRejected => GroupFailure::AuthenticationRejected,
        GroupPersistenceError::MembershipReceiptAccessDenied
        | GroupPersistenceError::MembershipDiscoveryAccessDenied => GroupFailure::AccessDenied,
        GroupPersistenceError::GroupNotFound
        | GroupPersistenceError::MembershipCommand(
            MembershipCommandError::CommandNotFound | MembershipCommandError::JoinRequestNotFound,
        ) => GroupFailure::Unavailable,
        GroupPersistenceError::ActionProofRejected
        | GroupPersistenceError::MlsAuthorizationRejected => GroupFailure::ActionProofInvalid,
        GroupPersistenceError::ControlCommandConflict
        | GroupPersistenceError::MlsCommitConflict => GroupFailure::IdempotencyConflict,
        GroupPersistenceError::MembershipCommand(MembershipCommandError::IdempotencyConflict) => {
            GroupFailure::IdempotencyConflict
        }
        GroupPersistenceError::MembershipCommand(
            MembershipCommandError::ActorCandidateMismatch
            | MembershipCommandError::JoinRequestMismatch,
        ) => GroupFailure::InvalidRequest,
        GroupPersistenceError::MembershipCommand(_)
        | GroupPersistenceError::GroupBootstrapConflict
        | GroupPersistenceError::StaleMlsHead
        | GroupPersistenceError::MlsDeviceConfirmationRejected => GroupFailure::ActionConflict,
        GroupPersistenceError::GroupPolicy(_)
        | GroupPersistenceError::Database(_)
        | GroupPersistenceError::UnsafeRuntimeRole
        | GroupPersistenceError::RuntimeRoleUnauthorized
        | GroupPersistenceError::RuntimeRoleOverprivileged
        | GroupPersistenceError::TenantContextLeak
        | GroupPersistenceError::GroupSnapshot(_)
        | GroupPersistenceError::CorruptData(_)
        | GroupPersistenceError::CandidateIdentityOriginUnavailable
        | GroupPersistenceError::LeaseLost
        | GroupPersistenceError::ScopeMismatch => GroupFailure::TemporarilyUnavailable,
    }
}

fn group_failure_response(failure: GroupFailure, request_id: RequestId) -> Response {
    let (status, code, retryable) = match failure {
        GroupFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            GroupErrorCode::RequestInvalid,
            false,
        ),
        GroupFailure::ActionProofInvalid => (
            StatusCode::UNPROCESSABLE_ENTITY,
            GroupErrorCode::ActionProofInvalid,
            false,
        ),
        GroupFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            GroupErrorCode::DeviceAuthenticationFailed,
            false,
        ),
        GroupFailure::AccessDenied => (StatusCode::FORBIDDEN, GroupErrorCode::AccessDenied, false),
        GroupFailure::Unavailable => (
            StatusCode::NOT_FOUND,
            GroupErrorCode::ResourceUnavailable,
            false,
        ),
        GroupFailure::ActionConflict => {
            (StatusCode::CONFLICT, GroupErrorCode::ActionConflict, false)
        }
        GroupFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            GroupErrorCode::IdempotencyConflict,
            false,
        ),
        GroupFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            GroupErrorCode::ServiceUnavailable,
            true,
        ),
    };
    let body = serde_json::to_vec(&SafeErrorEnvelope {
        error: SafeErrorBody {
            code,
            request_id,
            retryable,
        },
    })
    .expect("the fixed Group Node error envelope always serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    with_common_headers(response, request_id)
}

#[derive(Clone, Copy, Serialize)]
enum GroupErrorCode {
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    DeviceAuthenticationFailed,
    #[serde(rename = "GROUP_ACCESS_DENIED")]
    AccessDenied,
    #[serde(rename = "GROUP_RESOURCE_UNAVAILABLE")]
    ResourceUnavailable,
    #[serde(rename = "GROUP_ACTION_CONFLICT")]
    ActionConflict,
    #[serde(rename = "GROUP_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "GROUP_ACTION_PROOF_INVALID")]
    ActionProofInvalid,
    #[serde(rename = "GROUP_REQUEST_INVALID")]
    RequestInvalid,
    #[serde(rename = "GROUP_SERVICE_UNAVAILABLE")]
    ServiceUnavailable,
}

#[derive(Serialize)]
struct SafeErrorEnvelope {
    error: SafeErrorBody,
}

#[derive(Serialize)]
struct SafeErrorBody {
    code: GroupErrorCode,
    request_id: RequestId,
    retryable: bool,
}

fn with_common_headers(mut response: Response, request_id: RequestId) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let request_id = HeaderValue::from_str(&request_id.to_string())
        .expect("a canonical UUIDv7 request ID is a valid HTTP header value");
    response.headers_mut().insert(REQUEST_ID_HEADER, request_id);
    response
}
