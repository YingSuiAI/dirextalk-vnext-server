use dtx_wire::Sha256Digest;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    ClientBindingIssueCommand, ClientBindingRepository, ClientBindingWorkflowError,
    IdentityPersistenceError, IdentityPgStore, is_canonical_https_origin,
};

pub const DEPLOYMENT_BINDING_CAPABILITY_HASH_DOMAIN: &[u8] =
    b"dirextalk.deployment-binding-capability.v1\0";
pub const DEPLOYMENT_BINDING_STATUS_TOKEN_HASH_DOMAIN: &[u8] =
    b"dirextalk.deployment-binding-status-token.v1\0";
pub const DEPLOYMENT_BINDING_CLIENT_AUTHORIZATION_DOMAIN: &[u8] =
    b"dirextalk.deployment-binding-client-authorization.v1\0";

#[derive(Clone, Debug)]
pub struct DeploymentBindingTicketIssueCommand {
    pub ticket_id: Uuid,
    pub binding_id: Uuid,
    pub deployment_operation_id: Uuid,
    pub tenant_id: Uuid,
    pub server_origin: String,
    pub tls_root_ca_pem: String,
    pub tls_root_ca_sha256: Sha256Digest,
    pub capability_digest: Sha256Digest,
    pub status_token_digest: Sha256Digest,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct DeploymentBindingTicket {
    pub ticket_id: Uuid,
    pub binding_id: Uuid,
    pub deployment_operation_id: Uuid,
    pub tenant_id: Uuid,
    pub server_origin: String,
    pub tls_root_ca_pem: String,
    pub tls_root_ca_sha256: Sha256Digest,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub state: DeploymentBindingTicketState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentBindingTicketState {
    Issued,
    Redeemed,
    IdentityBound,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Debug)]
pub enum DeploymentBindingTicketError {
    Persistence(IdentityPersistenceError),
    Invalid,
    Unauthorized,
    Conflict,
    Expired,
    Corrupt,
}

impl From<IdentityPersistenceError> for DeploymentBindingTicketError {
    fn from(value: IdentityPersistenceError) -> Self {
        Self::Persistence(value)
    }
}

impl std::fmt::Display for DeploymentBindingTicketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("deployment binding ticket operation failed")
    }
}

impl std::error::Error for DeploymentBindingTicketError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct DeploymentBindingTicketRepository;

impl DeploymentBindingTicketRepository {
    pub async fn authorize_redeem(
        self,
        store: &IdentityPgStore,
        ticket_id: Uuid,
        capability_digest: Sha256Digest,
        now_ms: i64,
    ) -> Result<DeploymentBindingTicket, DeploymentBindingTicketError> {
        self.load_authorized(store, ticket_id, capability_digest, now_ms)
            .await
    }

    pub async fn issue(
        self,
        store: &IdentityPgStore,
        command: &DeploymentBindingTicketIssueCommand,
    ) -> Result<DeploymentBindingTicket, DeploymentBindingTicketError> {
        if command.ticket_id.get_version_num() != 7
            || command.binding_id.get_version_num() != 7
            || command.deployment_operation_id.get_version_num() != 7
            || command.tenant_id.get_version_num() != 7
            || command.tls_root_ca_pem.is_empty()
            || command.tls_root_ca_pem.len() > 12 * 1024
            || !command.tls_root_ca_pem.is_ascii()
            || !is_canonical_https_origin(&command.server_origin)
            || command.expires_at_ms <= command.issued_at_ms
            || command.expires_at_ms > command.issued_at_ms.saturating_add(900_000)
        {
            return Err(DeploymentBindingTicketError::Invalid);
        }
        let mut session = store
            .begin()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        let result = sqlx::query(
            "INSERT INTO identity.deployment_binding_tickets (
                 ticket_id,binding_id,deployment_operation_id,tenant_id,server_origin,
                 tls_root_ca_pem,tls_root_ca_sha256,capability_digest,status_token_digest,
                 issued_at_ms,expires_at_ms,state,revision
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'issued',1)
             ON CONFLICT (deployment_operation_id) DO NOTHING",
        )
        .bind(command.ticket_id)
        .bind(command.binding_id)
        .bind(command.deployment_operation_id)
        .bind(command.tenant_id)
        .bind(&command.server_origin)
        .bind(&command.tls_root_ca_pem)
        .bind(command.tls_root_ca_sha256.as_bytes().as_slice())
        .bind(command.capability_digest.as_bytes().as_slice())
        .bind(command.status_token_digest.as_bytes().as_slice())
        .bind(command.issued_at_ms)
        .bind(command.expires_at_ms)
        .execute(session.connection())
        .await
        .map_err(IdentityPersistenceError::from)?;
        let row = sqlx::query(
            "SELECT * FROM identity.deployment_binding_tickets
             WHERE deployment_operation_id=$1 FOR UPDATE",
        )
        .bind(command.deployment_operation_id)
        .fetch_one(session.connection())
        .await
        .map_err(IdentityPersistenceError::from)?;
        let ticket = ticket_from_row(&row, None)?;
        if ticket.ticket_id != command.ticket_id
            || ticket.binding_id != command.binding_id
            || ticket.tenant_id != command.tenant_id
            || ticket.server_origin != command.server_origin
            || ticket.tls_root_ca_pem != command.tls_root_ca_pem
            || ticket.tls_root_ca_sha256 != command.tls_root_ca_sha256
            || row
                .try_get::<Vec<u8>, _>("capability_digest")
                .ok()
                .as_deref()
                != Some(command.capability_digest.as_bytes())
            || row
                .try_get::<Vec<u8>, _>("status_token_digest")
                .ok()
                .as_deref()
                != Some(command.status_token_digest.as_bytes())
            || ticket.issued_at_ms != command.issued_at_ms
            || ticket.expires_at_ms != command.expires_at_ms
        {
            let _ = session.rollback().await;
            return Err(DeploymentBindingTicketError::Conflict);
        }
        let _ = result;
        session
            .commit()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        Ok(ticket)
    }

    pub async fn redeem(
        self,
        store: &IdentityPgStore,
        ticket_id: Uuid,
        capability_digest: Sha256Digest,
        binding: &ClientBindingIssueCommand,
        now_ms: i64,
    ) -> Result<DeploymentBindingTicket, DeploymentBindingTicketError> {
        let ticket = self
            .load_authorized(store, ticket_id, capability_digest, now_ms)
            .await?;
        if ticket.binding_id != binding.binding_id
            || ticket.deployment_operation_id != binding.deployment_operation_id
            || ticket.tenant_id != binding.tenant_id
            || ticket.server_origin != binding.server_origin
            || ticket.tls_root_ca_sha256 != binding.tls_root_ca_sha256
            || ticket.issued_at_ms != binding.issued_at_ms
            || ticket.expires_at_ms != binding.expires_at_ms
        {
            return Err(DeploymentBindingTicketError::Conflict);
        }
        ClientBindingRepository
            .issue(store, binding)
            .await
            .map_err(map_binding_error)?;
        let mut session = store
            .begin()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        sqlx::query(
            "UPDATE identity.deployment_binding_tickets
             SET state='redeemed', redeemed_at_ms=COALESCE(redeemed_at_ms,$2), revision=revision+1
             WHERE ticket_id=$1 AND state IN ('issued','redeemed')",
        )
        .bind(ticket_id)
        .bind(now_ms)
        .execute(session.connection())
        .await
        .map_err(IdentityPersistenceError::from)?;
        session
            .commit()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        Ok(DeploymentBindingTicket {
            state: DeploymentBindingTicketState::Redeemed,
            ..ticket
        })
    }

    pub async fn status(
        self,
        store: &IdentityPgStore,
        ticket_id: Uuid,
        status_token_digest: Sha256Digest,
        now_ms: i64,
    ) -> Result<DeploymentBindingTicketState, DeploymentBindingTicketError> {
        let mut session = store
            .begin()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        let row = sqlx::query(
            "SELECT ticket.*, binding.state AS binding_state
             FROM identity.deployment_binding_tickets ticket
             LEFT JOIN identity.client_bindings binding ON binding.binding_id=ticket.binding_id
             WHERE ticket.ticket_id=$1",
        )
        .bind(ticket_id)
        .fetch_optional(session.connection())
        .await
        .map_err(IdentityPersistenceError::from)?
        .ok_or(DeploymentBindingTicketError::Unauthorized)?;
        let ticket = ticket_from_row(
            &row,
            row.try_get::<Option<String>, _>("binding_state")
                .ok()
                .flatten()
                .as_deref(),
        )?;
        if row
            .try_get::<Vec<u8>, _>("status_token_digest")
            .ok()
            .as_deref()
            != Some(status_token_digest.as_bytes())
        {
            let _ = session.rollback().await;
            return Err(DeploymentBindingTicketError::Unauthorized);
        }
        session
            .rollback()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        if now_ms >= ticket.expires_at_ms && ticket.state == DeploymentBindingTicketState::Issued {
            Ok(DeploymentBindingTicketState::Expired)
        } else {
            Ok(ticket.state)
        }
    }

    async fn load_authorized(
        self,
        store: &IdentityPgStore,
        ticket_id: Uuid,
        capability_digest: Sha256Digest,
        now_ms: i64,
    ) -> Result<DeploymentBindingTicket, DeploymentBindingTicketError> {
        let mut session = store
            .begin()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        let row =
            sqlx::query("SELECT * FROM identity.deployment_binding_tickets WHERE ticket_id=$1")
                .bind(ticket_id)
                .fetch_optional(session.connection())
                .await
                .map_err(IdentityPersistenceError::from)?
                .ok_or(DeploymentBindingTicketError::Unauthorized)?;
        if row
            .try_get::<Vec<u8>, _>("capability_digest")
            .ok()
            .as_deref()
            != Some(capability_digest.as_bytes())
        {
            let _ = session.rollback().await;
            return Err(DeploymentBindingTicketError::Unauthorized);
        }
        let ticket = ticket_from_row(&row, None)?;
        session
            .rollback()
            .await
            .map_err(DeploymentBindingTicketError::from)?;
        if now_ms >= ticket.expires_at_ms {
            return Err(DeploymentBindingTicketError::Expired);
        }
        if !matches!(
            ticket.state,
            DeploymentBindingTicketState::Issued | DeploymentBindingTicketState::Redeemed
        ) {
            return Err(DeploymentBindingTicketError::Conflict);
        }
        Ok(ticket)
    }
}

fn map_binding_error(error: ClientBindingWorkflowError) -> DeploymentBindingTicketError {
    match error {
        ClientBindingWorkflowError::Persistence(error) => {
            DeploymentBindingTicketError::Persistence(error)
        }
        ClientBindingWorkflowError::Invalid => DeploymentBindingTicketError::Invalid,
        ClientBindingWorkflowError::Unauthorized => DeploymentBindingTicketError::Unauthorized,
        ClientBindingWorkflowError::Conflict => DeploymentBindingTicketError::Conflict,
        ClientBindingWorkflowError::Expired | ClientBindingWorkflowError::Revoked => {
            DeploymentBindingTicketError::Expired
        }
        ClientBindingWorkflowError::Corrupt => DeploymentBindingTicketError::Corrupt,
    }
}

fn digest(
    row: &sqlx::postgres::PgRow,
    name: &str,
) -> Result<Sha256Digest, DeploymentBindingTicketError> {
    let bytes = row
        .try_get::<Vec<u8>, _>(name)
        .map_err(|_| DeploymentBindingTicketError::Corrupt)?;
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeploymentBindingTicketError::Corrupt)?;
    Ok(Sha256Digest::from_bytes(value))
}

fn ticket_from_row(
    row: &sqlx::postgres::PgRow,
    binding_state: Option<&str>,
) -> Result<DeploymentBindingTicket, DeploymentBindingTicketError> {
    let state = match binding_state {
        Some("identity_bound") => DeploymentBindingTicketState::IdentityBound,
        Some("consumed") => DeploymentBindingTicketState::Consumed,
        Some("expired") => DeploymentBindingTicketState::Expired,
        Some("revoked") => DeploymentBindingTicketState::Revoked,
        Some("issued") | None => match row
            .try_get::<String, _>("state")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?
            .as_str()
        {
            "issued" => DeploymentBindingTicketState::Issued,
            "redeemed" => DeploymentBindingTicketState::Redeemed,
            "expired" => DeploymentBindingTicketState::Expired,
            "revoked" => DeploymentBindingTicketState::Revoked,
            _ => return Err(DeploymentBindingTicketError::Corrupt),
        },
        Some(_) => return Err(DeploymentBindingTicketError::Corrupt),
    };
    Ok(DeploymentBindingTicket {
        ticket_id: row
            .try_get("ticket_id")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        binding_id: row
            .try_get("binding_id")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        deployment_operation_id: row
            .try_get("deployment_operation_id")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        server_origin: row
            .try_get("server_origin")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        tls_root_ca_pem: row
            .try_get("tls_root_ca_pem")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        tls_root_ca_sha256: digest(row, "tls_root_ca_sha256")?,
        issued_at_ms: row
            .try_get("issued_at_ms")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        expires_at_ms: row
            .try_get("expires_at_ms")
            .map_err(|_| DeploymentBindingTicketError::Corrupt)?,
        state,
    })
}
