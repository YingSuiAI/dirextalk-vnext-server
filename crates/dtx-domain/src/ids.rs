use std::{error::Error, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use uuid::{Uuid, Variant};

/// Parsing failed because an identifier was malformed or was not a canonical `UUIDv7`.
#[derive(Debug)]
pub enum IdParseError {
    /// The input was not a syntactically valid UUID.
    InvalidUuid {
        /// Domain identifier kind being parsed.
        kind: &'static str,
        /// UUID parser error.
        source: uuid::Error,
    },
    /// The UUID used a valid but non-canonical textual spelling.
    NonCanonicalText {
        /// Domain identifier kind being parsed.
        kind: &'static str,
    },
    /// The UUID was valid but used a version other than version 7.
    UnsupportedVersion {
        /// Domain identifier kind being parsed.
        kind: &'static str,
        /// Parsed UUID version number.
        actual: Option<usize>,
    },
    /// The UUID did not use the RFC 4122/9562 variant required by `UUIDv7`.
    UnsupportedVariant {
        /// Domain identifier kind being parsed.
        kind: &'static str,
        /// Parsed UUID variant.
        actual: Variant,
    },
}

impl fmt::Display for IdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid { kind, .. } => write!(formatter, "invalid {kind} UUID"),
            Self::NonCanonicalText { kind } => {
                write!(formatter, "{kind} must use lowercase hyphenated UUID text")
            }
            Self::UnsupportedVersion { kind, actual } => {
                write!(formatter, "{kind} must be UUIDv7, got version {actual:?}")
            }
            Self::UnsupportedVariant { kind, actual } => {
                write!(
                    formatter,
                    "{kind} must use the RFC UUID variant, got {actual:?}"
                )
            }
        }
    }
}

impl Error for IdParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidUuid { source, .. } => Some(source),
            Self::NonCanonicalText { .. }
            | Self::UnsupportedVersion { .. }
            | Self::UnsupportedVariant { .. } => None,
        }
    }
}

fn parse_uuid_v7(kind: &'static str, value: &str) -> Result<Uuid, IdParseError> {
    let uuid =
        Uuid::parse_str(value).map_err(|source| IdParseError::InvalidUuid { kind, source })?;
    if uuid.hyphenated().to_string() != value {
        return Err(IdParseError::NonCanonicalText { kind });
    }

    let actual_variant = uuid.get_variant();
    if actual_variant != Variant::RFC4122 {
        return Err(IdParseError::UnsupportedVariant {
            kind,
            actual: actual_variant,
        });
    }
    let actual = Some(uuid.get_version_num());
    if actual != Some(7) {
        return Err(IdParseError::UnsupportedVersion { kind, actual });
    }
    Ok(uuid)
}

macro_rules! define_uuid_v7_id {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("UUIDv7 identifier for a ", $kind, ".")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[doc = concat!("Generates a new ", $kind, " identifier.")]
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_uuid_v7($kind, value).map(Self)
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = IdParseError;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                value.hyphenated().to_string().parse()
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(de::Error::custom)
            }
        }
    };
}

define_uuid_v7_id!(TenantId, "tenant ID");
define_uuid_v7_id!(EventId, "event ID");
define_uuid_v7_id!(RequestId, "request ID");
define_uuid_v7_id!(AuditId, "audit event ID");
define_uuid_v7_id!(OutboxId, "outbox message ID");
define_uuid_v7_id!(SecretId, "secret ID");
define_uuid_v7_id!(AggregateId, "aggregate ID");
define_uuid_v7_id!(DeviceId, "device ID");
define_uuid_v7_id!(ConversationId, "conversation ID");
define_uuid_v7_id!(InstallationId, "agent installation ID");
define_uuid_v7_id!(AgentDeviceId, "agent device ID");
define_uuid_v7_id!(HostId, "agent host ID");
define_uuid_v7_id!(ConnectorId, "connector ID");
define_uuid_v7_id!(EnrollmentIntentId, "connector enrollment intent ID");
define_uuid_v7_id!(ConnectorCredentialId, "connector credential ID");
define_uuid_v7_id!(BootId, "connector boot ID");
define_uuid_v7_id!(LeaseId, "lease ID");
define_uuid_v7_id!(BindingId, "connector binding ID");
define_uuid_v7_id!(GrantId, "conversation agent grant ID");
define_uuid_v7_id!(HostCredentialId, "agent host credential ID");
define_uuid_v7_id!(ConsentId, "consent ID");
define_uuid_v7_id!(ApprovalId, "approval ID");
define_uuid_v7_id!(RunId, "agent run ID");
define_uuid_v7_id!(JobId, "job ID");
define_uuid_v7_id!(JobStepId, "job step ID");
define_uuid_v7_id!(JobEvidenceId, "job evidence ID");
define_uuid_v7_id!(WorkerId, "compute worker ID");
define_uuid_v7_id!(CloudConnectionId, "cloud connection ID");
define_uuid_v7_id!(JobResourceId, "job resource ID");
define_uuid_v7_id!(ManagedServiceId, "managed service ID");
define_uuid_v7_id!(ServiceOperationId, "managed service operation ID");
define_uuid_v7_id!(DirectoryRegistrationId, "directory registration ID");
define_uuid_v7_id!(IndexerId, "directory indexer ID");
