use std::{error::Error, fmt, str::FromStr};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};

const PUBLIC_ID_LENGTH: usize = 57;
const ENCODED_DIGEST_LENGTH: usize = 52;
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A canonical, non-weak Ed25519 compressed verification key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Returns the canonical compressed key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<[u8; 32]> for Ed25519PublicKey {
    type Error = PublicKeyError;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        let key = VerifyingKey::from_bytes(&value)
            .map_err(|source| PublicKeyError::InvalidEncoding { source })?;
        if key.to_edwards().compress().to_bytes() != value {
            return Err(PublicKeyError::NonCanonicalEncoding);
        }
        if key.is_weak() {
            return Err(PublicKeyError::WeakKey);
        }
        Ok(Self(value))
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = PublicKeyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value
            .try_into()
            .map_err(|_| PublicKeyError::InvalidLength {
                actual: value.len(),
            })?;
        Self::try_from(bytes)
    }
}

/// A subject public key is invalid for stable-ID derivation.
#[derive(Debug)]
pub enum PublicKeyError {
    /// The compressed representation was not 32 bytes.
    InvalidLength {
        /// Supplied length.
        actual: usize,
    },
    /// Ed25519 rejected the compressed point.
    InvalidEncoding {
        /// Dalek validation error.
        source: ed25519_dalek::SignatureError,
    },
    /// Decompression and recompression changed the supplied bytes.
    NonCanonicalEncoding,
    /// The key is a weak/small-order point.
    WeakKey,
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual } => {
                write!(
                    formatter,
                    "Ed25519 public key must be 32 bytes, got {actual}"
                )
            }
            Self::InvalidEncoding { .. } => formatter.write_str("invalid Ed25519 public key"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("non-canonical Ed25519 public key encoding")
            }
            Self::WeakKey => formatter.write_str("weak Ed25519 public key is not allowed"),
        }
    }
}

impl Error for PublicKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEncoding { source } => Some(source),
            Self::InvalidLength { .. } | Self::NonCanonicalEncoding | Self::WeakKey => None,
        }
    }
}

/// A public stable identifier has invalid or non-canonical text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicIdParseError {
    /// The complete identifier did not have the fixed v1 length.
    InvalidLength {
        /// Supplied length.
        actual: usize,
    },
    /// The identifier did not begin with the expected kind prefix.
    InvalidPrefix {
        /// Expected prefix.
        expected: &'static str,
    },
    /// The digest contained a character outside lowercase RFC 4648 Base32.
    InvalidCharacter,
    /// The final Base32 character used non-zero padding bits.
    NonCanonicalTrailingBits,
}

impl fmt::Display for PublicIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual } => {
                write!(
                    formatter,
                    "public ID must be {PUBLIC_ID_LENGTH} bytes, got {actual}"
                )
            }
            Self::InvalidPrefix { expected } => {
                write!(formatter, "public ID must use prefix {expected}")
            }
            Self::InvalidCharacter => {
                formatter.write_str("public ID must use lowercase unpadded RFC 4648 Base32")
            }
            Self::NonCanonicalTrailingBits => {
                formatter.write_str("public ID has non-zero Base32 trailing bits")
            }
        }
    }
}

impl Error for PublicIdParseError {}

/// A stable public ID did not derive from the supplied subject key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicIdBindingError;

impl fmt::Display for PublicIdBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("public ID does not match the subject key")
    }
}

impl Error for PublicIdBindingError {}

fn encode_base32(digest: &[u8; 32]) -> [u8; ENCODED_DIGEST_LENGTH] {
    let mut output = [0_u8; ENCODED_DIGEST_LENGTH];
    let mut output_index = 0;
    let mut buffer = 0_u16;
    let mut bits = 0_u8;

    for byte in digest {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let alphabet_index = usize::from((buffer >> bits) & 0x1f);
            output[output_index] = BASE32_ALPHABET[alphabet_index];
            output_index += 1;
            buffer &= if bits == 0 { 0 } else { (1_u16 << bits) - 1 };
        }
    }

    if bits > 0 {
        let alphabet_index = usize::from((buffer << (5 - bits)) & 0x1f);
        output[output_index] = BASE32_ALPHABET[alphabet_index];
        output_index += 1;
    }

    debug_assert_eq!(output_index, ENCODED_DIGEST_LENGTH);
    output
}

fn decode_base32(value: &[u8]) -> Result<[u8; 32], PublicIdParseError> {
    debug_assert_eq!(value.len(), ENCODED_DIGEST_LENGTH);
    let mut output = [0_u8; 32];
    let mut output_index = 0;
    let mut buffer = 0_u16;
    let mut bits = 0_u8;

    for character in value {
        let alphabet_index = BASE32_ALPHABET
            .iter()
            .position(|candidate| candidate == character)
            .ok_or(PublicIdParseError::InvalidCharacter)?;
        buffer = (buffer << 5) | u16::try_from(alphabet_index).expect("Base32 index fits u16");
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if output_index < output.len() {
                output[output_index] = u8::try_from(buffer >> bits).expect("decoded byte fits u8");
                output_index += 1;
            }
            buffer &= if bits == 0 { 0 } else { (1_u16 << bits) - 1 };
        }
    }

    if output_index != output.len() || bits != 4 || buffer != 0 {
        return Err(PublicIdParseError::NonCanonicalTrailingBits);
    }
    Ok(output)
}

fn derive_digest(domain: &[u8], key: &Ed25519PublicKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

fn parse_public_id(prefix: &'static str, value: &str) -> Result<[u8; 32], PublicIdParseError> {
    if value.len() != PUBLIC_ID_LENGTH {
        return Err(PublicIdParseError::InvalidLength {
            actual: value.len(),
        });
    }
    let encoded = value
        .strip_prefix(prefix)
        .ok_or(PublicIdParseError::InvalidPrefix { expected: prefix })?;
    decode_base32(encoded.as_bytes())
}

macro_rules! define_public_id {
    ($name:ident, $prefix:literal, $domain:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Derives the stable ID from a validated subject genesis key.
            #[must_use]
            pub fn derive(key: &Ed25519PublicKey) -> Self {
                Self(derive_digest($domain, key))
            }

            /// Returns the domain-separated SHA-256 digest bytes.
            #[must_use]
            pub const fn digest_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Confirms that this ID is bound to the supplied validated key.
            ///
            /// # Errors
            ///
            /// Returns [`PublicIdBindingError`] when the key derives a different ID.
            pub fn verify_subject_key(
                &self,
                key: &Ed25519PublicKey,
            ) -> Result<(), PublicIdBindingError> {
                if *self == Self::derive(key) {
                    Ok(())
                } else {
                    Err(PublicIdBindingError)
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let encoded = encode_base32(&self.0);
                formatter.write_str($prefix)?;
                formatter.write_str(
                    std::str::from_utf8(&encoded).expect("Base32 alphabet is valid UTF-8"),
                )
            }
        }

        impl FromStr for $name {
            type Err = PublicIdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_public_id($prefix, value).map(Self)
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

define_public_id!(
    IdentityId,
    "dtxi1",
    b"dirextalk.identity.v1\0",
    "Stable public identity ID derived from its genesis signing key."
);
define_public_id!(
    ChannelId,
    "dtxc1",
    b"dirextalk.channel.v1\0",
    "Stable public channel ID derived from its subject genesis key."
);
define_public_id!(
    AgentId,
    "dtxa1",
    b"dirextalk.agent.v1\0",
    "Stable public Agent ID derived from its subject genesis key."
);

/// A validated public subject ID of any supported v1 kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PublicSubjectId {
    /// User or service identity subject.
    Identity(IdentityId),
    /// Public channel subject.
    Channel(ChannelId),
    /// Public Agent definition subject.
    Agent(AgentId),
}

impl fmt::Display for PublicSubjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(value) => value.fmt(formatter),
            Self::Channel(value) => value.fmt(formatter),
            Self::Agent(value) => value.fmt(formatter),
        }
    }
}

impl FromStr for PublicSubjectId {
    type Err = PublicIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.starts_with("dtxi1") {
            value.parse().map(Self::Identity)
        } else if value.starts_with("dtxc1") {
            value.parse().map(Self::Channel)
        } else if value.starts_with("dtxa1") {
            value.parse().map(Self::Agent)
        } else {
            Err(PublicIdParseError::InvalidPrefix {
                expected: "dtxi1, dtxc1, or dtxa1",
            })
        }
    }
}

impl Serialize for PublicSubjectId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PublicSubjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}
