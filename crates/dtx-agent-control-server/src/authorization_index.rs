use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::RwLock,
};

use dtx_agent_control::{
    ConnectorCredentialAuthorizationSnapshot, ConnectorCredentialAuthorizationState,
    ConnectorCredentialStatus, Sha256Digest,
};
use dtx_domain::{ConnectorId, TenantId};
use dtx_security::{
    CertificateFingerprint, ConnectorAuthorizationError, ConnectorCredentialAdmission,
    ConnectorCredentialAuthorizer, ConnectorWorkloadIdentity,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ConnectorKey {
    tenant_id: TenantId,
    connector_id: ConnectorId,
}

impl From<ConnectorWorkloadIdentity> for ConnectorKey {
    fn from(identity: ConnectorWorkloadIdentity) -> Self {
        Self {
            tenant_id: identity.tenant_id(),
            connector_id: identity.connector_id(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndexedCredential {
    identity: ConnectorWorkloadIdentity,
    fingerprint: Sha256Digest,
    not_before_millis: i64,
    not_after_millis: i64,
    status: ConnectorCredentialStatus,
}

#[derive(Clone, Default)]
struct AuthorizationState {
    by_connector: BTreeMap<ConnectorKey, Vec<IndexedCredential>>,
    by_fingerprint: BTreeMap<[u8; 32], ConnectorWorkloadIdentity>,
}

/// Synchronous, atomically replaceable advisory credential view.
///
/// `PostgreSQL` remains the only authorization source. The application may refresh this
/// index after a credential transaction commits, but TLS, `Hello`, and control frames must
/// not depend on its contents. It exists only for diagnostics and safe best-effort hints.
#[derive(Default)]
pub struct ConnectorCredentialAuthorizationIndex {
    state: RwLock<AuthorizationState>,
}

impl ConnectorCredentialAuthorizationIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces one Connector's complete authorization history.
    ///
    /// # Errors
    ///
    /// Rejects a snapshot with a mismatched active head or a fingerprint already
    /// bound to a different Connector identity.
    pub fn replace(
        &self,
        snapshot: &ConnectorCredentialAuthorizationSnapshot,
    ) -> Result<(), ConnectorAuthorizationIndexError> {
        let identity = ConnectorWorkloadIdentity::new(snapshot.tenant_id, snapshot.connector_id);
        validate_head(snapshot)?;
        let credentials = snapshot
            .history
            .iter()
            .map(|entry| IndexedCredential {
                identity,
                fingerprint: entry.credential.certificate_fingerprint(),
                not_before_millis: entry.credential.not_before_millis(),
                not_after_millis: entry.credential.not_after_millis(),
                status: if snapshot.state == ConnectorCredentialAuthorizationState::Revoked {
                    ConnectorCredentialStatus::Revoked
                } else {
                    entry.status
                },
            })
            .collect::<Vec<_>>();

        let key = ConnectorKey::from(identity);
        let mut state = self
            .state
            .write()
            .map_err(|_| ConnectorAuthorizationIndexError::StateUnavailable)?;
        let mut next = state.clone();
        let previous = next.by_connector.remove(&key).unwrap_or_default();
        for credential in previous {
            next.by_fingerprint
                .remove(&credential.fingerprint.as_bytes());
        }
        let mut seen = BTreeSet::new();
        for credential in &credentials {
            let fingerprint = credential.fingerprint.as_bytes();
            if !seen.insert(fingerprint) {
                return Err(ConnectorAuthorizationIndexError::FingerprintReuse);
            }
            if next
                .by_fingerprint
                .get(&fingerprint)
                .is_some_and(|bound| *bound != identity)
            {
                return Err(ConnectorAuthorizationIndexError::FingerprintReuse);
            }
            next.by_fingerprint.insert(fingerprint, identity);
        }
        next.by_connector.insert(key, credentials);
        *state = next;
        Ok(())
    }

    /// Hydrates a complete startup view, publishing it only after every snapshot validates.
    ///
    /// # Errors
    ///
    /// Rejects duplicate Connector heads, invalid heads, or cross-identity fingerprint reuse.
    pub fn hydrate(
        &self,
        snapshots: impl IntoIterator<Item = ConnectorCredentialAuthorizationSnapshot>,
    ) -> Result<(), ConnectorAuthorizationIndexError> {
        let mut next = AuthorizationState::default();
        for snapshot in snapshots {
            validate_head(&snapshot)?;
            let identity =
                ConnectorWorkloadIdentity::new(snapshot.tenant_id, snapshot.connector_id);
            let key = ConnectorKey::from(identity);
            if next.by_connector.contains_key(&key) {
                return Err(ConnectorAuthorizationIndexError::DuplicateConnector);
            }
            let mut credentials = Vec::with_capacity(snapshot.history.len());
            for entry in snapshot.history {
                let fingerprint = entry.credential.certificate_fingerprint().as_bytes();
                if next.by_fingerprint.insert(fingerprint, identity).is_some() {
                    return Err(ConnectorAuthorizationIndexError::FingerprintReuse);
                }
                credentials.push(IndexedCredential {
                    identity,
                    fingerprint: entry.credential.certificate_fingerprint(),
                    not_before_millis: entry.credential.not_before_millis(),
                    not_after_millis: entry.credential.not_after_millis(),
                    status: if snapshot.state == ConnectorCredentialAuthorizationState::Revoked {
                        ConnectorCredentialStatus::Revoked
                    } else {
                        entry.status
                    },
                });
            }
            next.by_connector.insert(key, credentials);
        }
        *self
            .state
            .write()
            .map_err(|_| ConnectorAuthorizationIndexError::StateUnavailable)? = next;
        Ok(())
    }
}

impl ConnectorCredentialAuthorizer for ConnectorCredentialAuthorizationIndex {
    fn authorize(
        &self,
        identity: ConnectorWorkloadIdentity,
        certificate_fingerprint: CertificateFingerprint,
        now_unix_seconds: u64,
    ) -> Result<ConnectorCredentialAdmission, ConnectorAuthorizationError> {
        let state = self
            .state
            .read()
            .map_err(|_| ConnectorAuthorizationError::StateUnavailable)?;
        let fingerprint = *certificate_fingerprint.as_bytes();
        if state
            .by_fingerprint
            .get(&fingerprint)
            .is_some_and(|bound| *bound != identity)
        {
            return Err(ConnectorAuthorizationError::WrongIdentity);
        }
        let credential = state
            .by_connector
            .get(&ConnectorKey::from(identity))
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.fingerprint.as_bytes() == fingerprint)
            })
            .ok_or(ConnectorAuthorizationError::UnknownCredential)?;
        debug_assert_eq!(credential.identity, identity);
        let now_millis = now_unix_seconds
            .checked_mul(1_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(ConnectorAuthorizationError::StateUnavailable)?;
        if now_millis < credential.not_before_millis {
            return Err(ConnectorAuthorizationError::NotValidYet);
        }
        if now_millis >= credential.not_after_millis {
            return Err(ConnectorAuthorizationError::Expired);
        }
        match credential.status {
            ConnectorCredentialStatus::Current => Ok(ConnectorCredentialAdmission::Current),
            ConnectorCredentialStatus::Pending => {
                Ok(ConnectorCredentialAdmission::PendingSuccessor)
            }
            ConnectorCredentialStatus::Retired => Err(ConnectorAuthorizationError::Retired),
            ConnectorCredentialStatus::Revoked => Err(ConnectorAuthorizationError::Revoked),
        }
    }
}

fn validate_head(
    snapshot: &ConnectorCredentialAuthorizationSnapshot,
) -> Result<(), ConnectorAuthorizationIndexError> {
    let current_count = snapshot
        .history
        .iter()
        .filter(|entry| entry.status == ConnectorCredentialStatus::Current)
        .count();
    let pending_count = snapshot
        .history
        .iter()
        .filter(|entry| entry.status == ConnectorCredentialStatus::Pending)
        .count();
    let current_matches = snapshot.current_credential_id.is_some_and(|id| {
        snapshot.history.iter().any(|entry| {
            entry.status == ConnectorCredentialStatus::Current
                && entry.credential.credential_id() == id
        })
    });
    let pending_matches = match snapshot.pending_credential_id {
        Some(id) => snapshot.history.iter().any(|entry| {
            entry.status == ConnectorCredentialStatus::Pending
                && entry.credential.credential_id() == id
        }),
        None => pending_count == 0,
    };
    let valid = match snapshot.state {
        ConnectorCredentialAuthorizationState::Active => {
            current_count == 1 && current_matches && pending_count <= 1 && pending_matches
        }
        ConnectorCredentialAuthorizationState::Revoked => {
            snapshot.current_credential_id.is_none()
                && snapshot.pending_credential_id.is_none()
                && current_count == 0
                && pending_count == 0
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ConnectorAuthorizationIndexError::InvalidHead)
    }
}

/// Sanitized authorization-index update failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorAuthorizationIndexError {
    InvalidHead,
    DuplicateConnector,
    FingerprintReuse,
    StateUnavailable,
}

impl fmt::Display for ConnectorAuthorizationIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHead => "Connector credential authorization head is invalid",
            Self::DuplicateConnector => "Connector credential authorization head is duplicated",
            Self::FingerprintReuse => "Connector certificate fingerprint is already bound",
            Self::StateUnavailable => "Connector credential authorization index is unavailable",
        })
    }
}

impl Error for ConnectorAuthorizationIndexError {}
