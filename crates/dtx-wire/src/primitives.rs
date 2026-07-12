use std::{error::Error, fmt, str::FromStr};

use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::Ed25519PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};

use crate::{CanonicalEncode, CanonicalValue};

const MIN_UTC_MILLIS: i64 = -62_135_596_800_000;
const MAX_UTC_MILLIS: i64 = 253_402_300_799_999;
const SHA256_PREFIX: &str = "sha256:";
const ED25519_PREFIX: &str = "ed25519:";
const MAX_STABLE_CODE_BYTES: usize = 128;
const MAX_BOUNDED_STRING_BYTES: usize = 1024;

/// Largest unsigned integer represented exactly by JSON/Web number consumers.
pub const MAX_SAFE_UINT: u64 = (1_u64 << 53) - 1;

macro_rules! impl_string_serde {
    ($name:ty) => {
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

/// An unsigned integer that is exact across Rust, Dart VM, Dart Web, and JSON.
///
/// Registry fields use this wrapper instead of `u64` so their JSON number and
/// deterministic-CBOR unsigned integer representations always denote the same
/// value on every supported client platform.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SafeUint(u64);

impl SafeUint {
    /// Largest accepted value (`2^53 - 1`).
    pub const MAX: u64 = MAX_SAFE_UINT;

    /// Validates and creates a cross-platform exact unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns [`SafeUintError`] when `value` exceeds `2^53 - 1`.
    pub const fn new(value: u64) -> Result<Self, SafeUintError> {
        if value > Self::MAX {
            Err(SafeUintError { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the exact integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SafeUint {
    type Error = SafeUintError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SafeUint> for u64 {
    fn from(value: SafeUint) -> Self {
        value.get()
    }
}

impl Serialize for SafeUint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for SafeUint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalEncode for SafeUint {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Unsigned(self.0)
    }
}

/// An unsigned integer exceeds the cross-platform exact range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeUintError {
    actual: u64,
}

impl fmt::Display for SafeUintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "safe unsigned integer must be between 0 and {MAX_SAFE_UINT}, got {}",
            self.actual
        )
    }
}

impl Error for SafeUintError {}

/// A UTC Unix timestamp in milliseconds within the v1 cross-platform range.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UtcMillis(i64);

impl UtcMillis {
    /// Validates and creates a timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`UtcMillisError`] outside Gregorian years 1 through 9999.
    pub const fn new(value: i64) -> Result<Self, UtcMillisError> {
        if value < MIN_UTC_MILLIS || value > MAX_UTC_MILLIS {
            Err(UtcMillisError { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the Unix epoch-millisecond value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl Serialize for UtcMillis {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for UtcMillis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(i64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalEncode for UtcMillis {
    fn to_canonical_value(&self) -> CanonicalValue {
        if self.0 >= 0 {
            CanonicalValue::Unsigned(u64::try_from(self.0).expect("non-negative i64 fits u64"))
        } else {
            CanonicalValue::Negative(self.0)
        }
    }
}

/// A timestamp is outside the v1 wire range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcMillisError {
    actual: i64,
}

impl fmt::Display for UtcMillisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "UTC milliseconds must be between {MIN_UTC_MILLIS} and {MAX_UTC_MILLIS}, got {}",
            self.actual
        )
    }
}

impl Error for UtcMillisError {}

/// A bounded public string used by generated payloads.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedString(String);

impl BoundedString {
    /// Creates non-empty public text without control characters.
    ///
    /// # Errors
    ///
    /// Returns [`TextPrimitiveError`] when the value violates v1 bounds.
    pub fn new(value: impl Into<String>) -> Result<Self, TextPrimitiveError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_BOUNDED_STRING_BYTES
            || value.chars().any(char::is_control)
        {
            Err(TextPrimitiveError::InvalidBoundedString)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the public text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for BoundedString {
    type Err = TextPrimitiveError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl_string_serde!(BoundedString);

impl CanonicalEncode for BoundedString {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Text(self.0.clone())
    }
}

/// A bounded dotted lower-case stable code.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StableCode(String);

impl StableCode {
    /// Parses a code made from dotted lower-snake segments.
    ///
    /// # Errors
    ///
    /// Returns [`TextPrimitiveError`] for non-canonical or oversized text.
    pub fn parse(value: &str) -> Result<Self, TextPrimitiveError> {
        if value.is_empty()
            || value.len() > MAX_STABLE_CODE_BYTES
            || !value.split('.').all(is_lower_snake_segment)
        {
            Err(TextPrimitiveError::InvalidStableCode)
        } else {
            Ok(Self(value.to_owned()))
        }
    }

    /// Returns the exact stable code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StableCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for StableCode {
    type Err = TextPrimitiveError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl_string_serde!(StableCode);

impl CanonicalEncode for StableCode {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Text(self.0.clone())
    }
}

fn is_lower_snake_segment(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !value.ends_with('_')
        && !value.contains("__")
}

/// A bounded string or stable code was malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextPrimitiveError {
    /// Public text was empty, oversized, or contained a control character.
    InvalidBoundedString,
    /// A stable code was not bounded dotted lower-snake text.
    InvalidStableCode,
}

impl fmt::Display for TextPrimitiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBoundedString => {
                "bounded string is empty, too long, or contains control text"
            }
            Self::InvalidStableCode => "stable code must use bounded dotted lower_snake_case",
        })
    }
}

impl Error for TextPrimitiveError {}

/// A SHA-256 digest with an algorithm-tagged JSON representation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Creates a digest from its exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hashes the exact concatenation of `domain` and `message`.
    #[must_use]
    pub fn hash_domain(domain: &[u8], message: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(message);
        Self(hasher.finalize().into())
    }

    /// Returns the fixed digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SHA256_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Sha256Digest {
    type Err = EncodedPrimitiveError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .strip_prefix(SHA256_PREFIX)
            .ok_or(EncodedPrimitiveError::WrongAlgorithm)?;
        if encoded.len() != 64 {
            return Err(EncodedPrimitiveError::InvalidLength {
                expected: 64,
                actual: encoded.len(),
            });
        }
        if !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EncodedPrimitiveError::InvalidEncoding);
        }
        let mut bytes = [0_u8; 32];
        for (index, output) in bytes.iter_mut().enumerate() {
            *output = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .map_err(|_| EncodedPrimitiveError::InvalidEncoding)?;
        }
        Ok(Self(bytes))
    }
}

impl_string_serde!(Sha256Digest);

impl CanonicalEncode for Sha256Digest {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Bytes(self.0.to_vec())
    }
}

/// A validated Ed25519 public key with canonical wire text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SigningPublicKey(Ed25519PublicKey);

impl SigningPublicKey {
    /// Returns the compressed key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Returns the validated domain key.
    #[must_use]
    pub const fn as_domain_key(&self) -> &Ed25519PublicKey {
        &self.0
    }
}

impl TryFrom<[u8; 32]> for SigningPublicKey {
    type Error = EncodedPrimitiveError;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Ed25519PublicKey::try_from(value)
            .map(Self)
            .map_err(|_| EncodedPrimitiveError::InvalidPublicKey)
    }
}

impl fmt::Display for SigningPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(ED25519_PREFIX)?;
        formatter.write_str(&Base64UrlUnpadded::encode_string(self.as_bytes()))
    }
}

impl FromStr for SigningPublicKey {
    type Err = EncodedPrimitiveError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = decode_ed25519(value, 32)?;
        let bytes: [u8; 32] =
            bytes
                .try_into()
                .map_err(|_| EncodedPrimitiveError::InvalidLength {
                    expected: 32,
                    actual: 0,
                })?;
        Self::try_from(bytes)
    }
}

impl_string_serde!(SigningPublicKey);

impl CanonicalEncode for SigningPublicKey {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Bytes(self.as_bytes().to_vec())
    }
}

/// A fixed-size Ed25519 signature with canonical wire text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    /// Creates a signature wrapper from exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Display for Ed25519Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(ED25519_PREFIX)?;
        formatter.write_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl FromStr for Ed25519Signature {
    type Err = EncodedPrimitiveError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = decode_ed25519(value, 64)?;
        let bytes: [u8; 64] =
            bytes
                .try_into()
                .map_err(|_| EncodedPrimitiveError::InvalidLength {
                    expected: 64,
                    actual: 0,
                })?;
        Ok(Self(bytes))
    }
}

impl_string_serde!(Ed25519Signature);

impl CanonicalEncode for Ed25519Signature {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Bytes(self.0.to_vec())
    }
}

fn decode_ed25519(value: &str, expected: usize) -> Result<Vec<u8>, EncodedPrimitiveError> {
    let encoded = value
        .strip_prefix(ED25519_PREFIX)
        .ok_or(EncodedPrimitiveError::WrongAlgorithm)?;
    if encoded.contains('=') {
        return Err(EncodedPrimitiveError::InvalidEncoding);
    }
    let bytes = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|_| EncodedPrimitiveError::InvalidEncoding)?;
    if bytes.len() != expected {
        return Err(EncodedPrimitiveError::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// A tagged digest, key, or signature string is malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodedPrimitiveError {
    /// The algorithm prefix was absent or different.
    WrongAlgorithm,
    /// The decoded value had a different fixed size.
    InvalidLength {
        /// Required byte or character count.
        expected: usize,
        /// Supplied byte or character count.
        actual: usize,
    },
    /// Base64url or hexadecimal text was not canonical.
    InvalidEncoding,
    /// The Ed25519 point was invalid, non-canonical, or weak.
    InvalidPublicKey,
}

impl fmt::Display for EncodedPrimitiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongAlgorithm => formatter.write_str("wire primitive has the wrong algorithm"),
            Self::InvalidLength { expected, actual } => {
                write!(
                    formatter,
                    "wire primitive length must be {expected}, got {actual}"
                )
            }
            Self::InvalidEncoding => formatter.write_str("wire primitive is not canonical text"),
            Self::InvalidPublicKey => formatter.write_str("wire public key is invalid or weak"),
        }
    }
}

impl Error for EncodedPrimitiveError {}
