use std::{error::Error, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{CanonicalEncode, CanonicalValue};

/// A protocol version with a compatibility-breaking major and additive minor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Creates a protocol version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns the compatibility-breaking major component.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the additive minor component.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for ProtocolVersion {
    type Err = ProtocolVersionParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (major, minor) = value.split_once('.').ok_or(ProtocolVersionParseError)?;
        if major.is_empty()
            || minor.is_empty()
            || minor.contains('.')
            || (major.len() > 1 && major.starts_with('0'))
            || (minor.len() > 1 && minor.starts_with('0'))
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ProtocolVersionParseError);
        }
        Ok(Self::new(
            major.parse().map_err(|_| ProtocolVersionParseError)?,
            minor.parse().map_err(|_| ProtocolVersionParseError)?,
        ))
    }
}

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

impl CanonicalEncode for ProtocolVersion {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(u64::from(self.major)),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(u64::from(self.minor)),
            ),
        ])
    }
}

/// A protocol version string was not canonical `<major>.<minor>` text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolVersionParseError;

impl fmt::Display for ProtocolVersionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("protocol version must be canonical <major>.<minor> text")
    }
}

impl Error for ProtocolVersionParseError {}

/// Version metadata carried by every durable wire message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireVersion {
    /// Schema version used to write the message.
    pub protocol: ProtocolVersion,
    /// Oldest reader that can safely interpret the message.
    pub minimum_reader: ProtocolVersion,
}

impl WireVersion {
    /// Creates version metadata for a wire message.
    #[must_use]
    pub const fn new(protocol: ProtocolVersion, minimum_reader: ProtocolVersion) -> Self {
        Self {
            protocol,
            minimum_reader,
        }
    }
}

impl CanonicalEncode for WireVersion {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                self.protocol.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(2),
                self.minimum_reader.to_canonical_value(),
            ),
        ])
    }
}

/// A wire message cannot be safely interpreted by the current reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionError {
    /// The message's minimum reader is newer than its own schema version, or
    /// belongs to a different major line.
    InvalidVersionRange {
        /// Writer schema version.
        protocol: ProtocolVersion,
        /// Claimed minimum reader version.
        minimum: ProtocolVersion,
    },
    /// Reader and message use different compatibility-breaking major versions.
    UnsupportedMajor {
        /// Reader major version.
        reader_major: u16,
        /// Message major version.
        message_major: u16,
    },
    /// The reader predates a required additive change.
    ReaderTooOld {
        /// Current reader version.
        reader: ProtocolVersion,
        /// Oldest compatible reader version.
        minimum: ProtocolVersion,
    },
}

impl fmt::Display for VersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersionRange { protocol, minimum } => write!(
                formatter,
                "invalid wire version range: protocol {protocol}, minimum reader {minimum}"
            ),
            Self::UnsupportedMajor {
                reader_major,
                message_major,
            } => write!(
                formatter,
                "unsupported protocol major {message_major}; reader supports {reader_major}"
            ),
            Self::ReaderTooOld { reader, minimum } => {
                write!(
                    formatter,
                    "reader {reader} is older than required {minimum}"
                )
            }
        }
    }
}

impl Error for VersionError {}

/// Verifies that `reader` can safely interpret a message with `wire` metadata.
///
/// A writer may be newer than the reader within the same major line when it
/// explicitly declares that the reader is new enough for all required fields.
///
/// # Errors
///
/// Returns [`VersionError`] when the message declares an invalid range, uses a
/// different major protocol line, or requires a newer reader.
pub fn ensure_readable(reader: ProtocolVersion, wire: WireVersion) -> Result<(), VersionError> {
    if wire.protocol.major() != wire.minimum_reader.major() || wire.minimum_reader > wire.protocol {
        return Err(VersionError::InvalidVersionRange {
            protocol: wire.protocol,
            minimum: wire.minimum_reader,
        });
    }

    if reader.major() != wire.protocol.major() {
        return Err(VersionError::UnsupportedMajor {
            reader_major: reader.major(),
            message_major: wire.protocol.major(),
        });
    }

    if reader < wire.minimum_reader {
        return Err(VersionError::ReaderTooOld {
            reader,
            minimum: wire.minimum_reader,
        });
    }

    Ok(())
}
