use std::sync::Arc;

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
};
use dtx_domain::{Clock, SystemClock};
use dtx_mailbox::{
    IdentityMailboxAckCommand, MailboxAcknowledgementCommand, MailboxEnvelopeCommand,
    MailboxPgStore, MailboxRegistrationCommand, MailboxRepository,
};
use dtx_wire::UtcMillis;

use super::{
    ACCOUNT_READ_CURSOR_QUERY_RECEIPT_V1_CONTENT_TYPE, ACCOUNT_READ_CURSOR_QUERY_V1_CONTENT_TYPE,
    ACCOUNT_READ_CURSOR_WRITE_RECEIPT_V1_CONTENT_TYPE, ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
    DEVICE_HISTORY_GRANT_RECEIPT_V1_CONTENT_TYPE, DEVICE_HISTORY_GRANT_RECEIPT_V2_CONTENT_TYPE,
    DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE, DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
    HTTP_ACCOUNT_READ_CURSOR_IDEMPOTENCY_HASH_DOMAIN, HTTP_ACK_IDEMPOTENCY_HASH_DOMAIN,
    HTTP_ENQUEUE_IDEMPOTENCY_HASH_DOMAIN, HTTP_HISTORY_GRANT_V2_IDEMPOTENCY_HASH_DOMAIN,
    HTTP_IDENTITY_ACK_V2_IDEMPOTENCY_HASH_DOMAIN, HTTP_REGISTER_IDEMPOTENCY_HASH_DOMAIN,
    IDENTITY_MAILBOX_ACK_RECEIPT_V2_CONTENT_TYPE, IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
    IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE, IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
    MAILBOX_ACK_CONTENT_TYPE, MAILBOX_ACK_RECEIPT_CONTENT_TYPE, MAILBOX_ENVELOPE_CONTENT_TYPE,
    MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE, MAILBOX_PULL_CONTENT_TYPE,
    MAILBOX_PULL_RECEIPT_CONTENT_TYPE, MAILBOX_REGISTER_CONTENT_TYPE,
    MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE, MAX_ACK_BODY_BYTES, MAX_ENVELOPE_BODY_BYTES,
    MAX_HISTORY_RECOVERY_BODY_BYTES, MAX_PULL_BODY_BYTES, MAX_REGISTER_BODY_BYTES,
};
use crate::{
    auth::{
        has_exact_content_type, idempotency_key_hash, parse_device_session_authorization,
        parse_mailbox_capability_authorization, read_exact_body,
    },
    codec::{
        parse_account_read_cursor_query, parse_account_read_cursor_write,
        parse_acknowledgement_request, parse_device_history_grant, parse_device_history_grant_v2,
        parse_envelope_id, parse_envelope_request, parse_identity_ack_v2_request,
        parse_identity_pull_v3_request, parse_mailbox_id, parse_pull_request,
        parse_registration_request,
    },
    errors::{MailboxFailure, MailboxSuccess, map_persistence_error},
};

/// Shared state for the isolated public mailbox router.
#[derive(Clone)]
pub struct MailboxNodeState {
    pub(crate) store: MailboxPgStore,
    pub(crate) repository: MailboxRepository,
    pub(crate) clock: Arc<dyn Clock>,
}

impl MailboxNodeState {
    /// Creates production mailbox state using the system UTC clock.
    #[must_use]
    pub fn new(store: MailboxPgStore) -> Self {
        Self::with_clock(store, Arc::new(SystemClock))
    }

    /// Creates mailbox state with a deterministic clock for boundary tests.
    #[must_use]
    pub fn with_clock(store: MailboxPgStore, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            repository: MailboxRepository,
            clock,
        }
    }

    pub(crate) fn now(&self) -> Result<UtcMillis, MailboxFailure> {
        self.clock
            .now_utc_millis()
            .map_err(|_| MailboxFailure::TemporarilyUnavailable)
            .and_then(|value| {
                UtcMillis::new(value).map_err(|_| MailboxFailure::TemporarilyUnavailable)
            })
    }

    pub(crate) async fn register(
        &self,
        path_mailbox_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_REGISTER_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let credential = parse_device_session_authorization(headers)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_REGISTER_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_REGISTER_BODY_BYTES).await?;
        let request = parse_registration_request(&bytes)?;
        if request.mailbox_id != mailbox_id {
            return Err(MailboxFailure::InvalidRequest);
        }
        let command = MailboxRegistrationCommand::new(
            idempotency_key_hash,
            request.mailbox_id,
            request.owner_identity_id,
            request.owner_device_id,
            request.write_capability_hash,
            request.expires_at,
            bytes,
        )
        .map_err(|error| map_persistence_error(&error))?;
        let outcome = self
            .repository
            .register(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE,
        ))
    }

    pub(crate) async fn enqueue(
        &self,
        path_mailbox_id: &str,
        path_envelope_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_ENVELOPE_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let envelope_id = parse_envelope_id(path_envelope_id)?;
        let capability = parse_mailbox_capability_authorization(headers)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_ENQUEUE_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_ENVELOPE_BODY_BYTES).await?;
        let request = parse_envelope_request(&bytes)?;
        if request.envelope_id != envelope_id {
            return Err(MailboxFailure::InvalidRequest);
        }
        let command = MailboxEnvelopeCommand::new(
            idempotency_key_hash,
            mailbox_id,
            request.envelope_id,
            request.opaque_ciphertext,
            request.expires_at,
            bytes,
        )
        .map_err(|error| map_persistence_error(&error))?;
        let outcome = self
            .repository
            .enqueue(&self.store, &capability, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE,
        ))
    }

    pub(crate) async fn pull(
        &self,
        path_mailbox_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_PULL_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let credential = parse_device_session_authorization(headers)?;
        let bytes = read_exact_body(body, MAX_PULL_BODY_BYTES).await?;
        let request = parse_pull_request(&bytes)?;
        let outcome = self
            .repository
            .pull(&self.store, &credential, mailbox_id, request, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess {
            status: StatusCode::OK,
            exact_receipt_bytes: outcome.receipt_bytes().to_vec(),
            content_type: MAILBOX_PULL_RECEIPT_CONTENT_TYPE,
        })
    }

    pub(crate) async fn acknowledge(
        &self,
        path_mailbox_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, MAILBOX_ACK_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let mailbox_id = parse_mailbox_id(path_mailbox_id)?;
        let credential = parse_device_session_authorization(headers)?;
        let idempotency_key_hash = idempotency_key_hash(headers, HTTP_ACK_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_ACK_BODY_BYTES).await?;
        let request = parse_acknowledgement_request(&bytes)?;
        let command = MailboxAcknowledgementCommand::new(
            idempotency_key_hash,
            mailbox_id,
            request.envelope_ids,
            bytes,
        )
        .map_err(|error| map_persistence_error(&error))?;
        let outcome = self
            .repository
            .acknowledge(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            MAILBOX_ACK_RECEIPT_CONTENT_TYPE,
        ))
    }

    pub(crate) async fn pull_identity_v3(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)?;
        let bytes = read_exact_body(body, MAX_PULL_BODY_BYTES).await?;
        let request = parse_identity_pull_v3_request(&bytes)?;
        let outcome = self
            .repository
            .pull_identity_v3(&self.store, &credential, request, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess {
            status: StatusCode::OK,
            exact_receipt_bytes: outcome.receipt_bytes().to_vec(),
            content_type: IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE,
        })
    }

    pub(crate) async fn acknowledge_identity_v2(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_IDENTITY_ACK_V2_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_ACK_BODY_BYTES).await?;
        let sequence = parse_identity_ack_v2_request(&bytes)?;
        let command = IdentityMailboxAckCommand::new(idempotency_key_hash, sequence, bytes)
            .map_err(|error| map_persistence_error(&error))?;
        let outcome = self
            .repository
            .acknowledge_identity_v2(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            IDENTITY_MAILBOX_ACK_RECEIPT_V2_CONTENT_TYPE,
        ))
    }

    pub(crate) async fn grant_device_history(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)?;
        let bytes = read_exact_body(body, MAX_REGISTER_BODY_BYTES).await?;
        let command = parse_device_history_grant(&bytes)?;
        let outcome = self
            .repository
            .grant_device_history(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            DEVICE_HISTORY_GRANT_RECEIPT_V1_CONTENT_TYPE,
        ))
    }

    pub(crate) async fn grant_device_history_v2(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_HISTORY_GRANT_V2_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_HISTORY_RECOVERY_BODY_BYTES).await?;
        let command = parse_device_history_grant_v2(&bytes, idempotency_key_hash)?;
        let outcome = self
            .repository
            .grant_device_history_v2(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            DEVICE_HISTORY_GRANT_RECEIPT_V2_CONTENT_TYPE,
        ))
    }

    pub(crate) async fn write_account_read_cursor(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_ACCOUNT_READ_CURSOR_IDEMPOTENCY_HASH_DOMAIN)?;
        let bytes = read_exact_body(body, MAX_REGISTER_BODY_BYTES).await?;
        let command = parse_account_read_cursor_write(&bytes, idempotency_key_hash)?;
        let outcome = self
            .repository
            .write_account_read_cursor(&self.store, &credential, &command, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess::write(
            &outcome,
            ACCOUNT_READ_CURSOR_WRITE_RECEIPT_V1_CONTENT_TYPE,
        ))
    }

    pub(crate) async fn query_account_read_cursor(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MailboxSuccess, MailboxFailure> {
        if !has_exact_content_type(headers, ACCOUNT_READ_CURSOR_QUERY_V1_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)?;
        let bytes = read_exact_body(body, MAX_PULL_BODY_BYTES).await?;
        let conversation_digest = parse_account_read_cursor_query(&bytes)?;
        let outcome = self
            .repository
            .read_account_read_cursor(&self.store, &credential, conversation_digest, self.now()?)
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(MailboxSuccess {
            status: StatusCode::OK,
            exact_receipt_bytes: outcome.receipt_bytes().to_vec(),
            content_type: ACCOUNT_READ_CURSOR_QUERY_RECEIPT_V1_CONTENT_TYPE,
        })
    }
}
