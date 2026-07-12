use std::{collections::BTreeMap, error::Error, fmt};

use dtx_domain::RequestId;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{CanonicalEncode, CanonicalValue, KnownApiErrorCode, MAX_SAFE_UINT};

const MAX_ERROR_MESSAGE_BYTES: usize = 512;
const MAX_DETAIL_ENTRIES: usize = 16;
const MAX_DETAIL_KEY_BYTES: usize = 64;
const MAX_DETAIL_TEXT_BYTES: usize = 256;
const MAX_DETAIL_LIST_ENTRIES: usize = 16;
const MAX_ERROR_CODE_BYTES: usize = 64;
const MAX_SAFE_INTEGER: i64 = MAX_SAFE_UINT.cast_signed();
const MIN_SAFE_INTEGER: i64 = -MAX_SAFE_INTEGER;

/// A stable known or syntactically valid future API error code.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApiErrorCode {
    raw: String,
    known: Option<KnownApiErrorCode>,
}

impl ApiErrorCode {
    fn from_known(code: KnownApiErrorCode) -> Self {
        Self {
            raw: code.as_str().to_owned(),
            known: Some(code),
        }
    }

    /// Parses a stable uppercase underscore-delimited code.
    ///
    /// Registered codes retain their typed variant; valid future codes retain
    /// their raw value so an older client can display a generic error.
    ///
    /// # Errors
    ///
    /// Returns [`ApiErrorCodeParseError`] for non-canonical code text.
    pub fn parse(value: &str) -> Result<Self, ApiErrorCodeParseError> {
        if value.len() < 3
            || value.len() > MAX_ERROR_CODE_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
            || value.ends_with('_')
            || value.contains("__")
        {
            return Err(ApiErrorCodeParseError);
        }
        Ok(Self {
            raw: value.to_owned(),
            known: KnownApiErrorCode::from_code(value),
        })
    }

    /// Returns the exact wire code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns the registered server code, or `None` for a future code.
    #[must_use]
    pub const fn known(&self) -> Option<KnownApiErrorCode> {
        self.known
    }
}

impl Serialize for ApiErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ApiErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalEncode for ApiErrorCode {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Text(self.raw.clone())
    }
}

/// An API error code was not canonical stable-code text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiErrorCodeParseError;

impl fmt::Display for ApiErrorCodeParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("API error code must use canonical UPPER_SNAKE_CASE")
    }
}

impl Error for ApiErrorCodeParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicErrorMessage(String);

impl PublicErrorMessage {
    fn new(value: impl Into<String>) -> Result<Self, PublicErrorMessageError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ERROR_MESSAGE_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(PublicErrorMessageError);
        }
        Ok(Self(value))
    }
}

impl Serialize for PublicErrorMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PublicErrorMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicErrorMessageError;

impl fmt::Display for PublicErrorMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("public error message is empty, too long, or contains control text")
    }
}

impl Error for PublicErrorMessageError {}

/// A structurally safe scalar or short scalar list for public error details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicDetailValue(PublicDetailKind);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum PublicDetailKind {
    Text(String),
    Integer(i64),
    Boolean(bool),
    TextList(Vec<String>),
    IntegerList(Vec<i64>),
}

impl PublicDetailValue {
    /// Creates bounded public text.
    ///
    /// # Errors
    ///
    /// Returns [`ApiErrorDetailsError`] for long or control-character text.
    pub fn text(value: impl Into<String>) -> Result<Self, ApiErrorDetailsError> {
        let value = Self(PublicDetailKind::Text(value.into()));
        value.validate()?;
        Ok(value)
    }

    /// Creates an exactly representable cross-platform integer detail.
    ///
    /// # Errors
    ///
    /// Returns [`ApiErrorDetailsError::IntegerOutOfRange`] outside the JSON-safe
    /// range shared by Rust, Dart VM, and Flutter Web.
    pub const fn integer(value: i64) -> Result<Self, ApiErrorDetailsError> {
        if value < MIN_SAFE_INTEGER || value > MAX_SAFE_INTEGER {
            Err(ApiErrorDetailsError::IntegerOutOfRange)
        } else {
            Ok(Self(PublicDetailKind::Integer(value)))
        }
    }

    /// Creates a public boolean detail.
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self(PublicDetailKind::Boolean(value))
    }

    /// Creates a bounded list of public strings.
    ///
    /// # Errors
    ///
    /// Returns [`ApiErrorDetailsError`] when the list or any item exceeds limits.
    pub fn text_list(values: Vec<String>) -> Result<Self, ApiErrorDetailsError> {
        let value = Self(PublicDetailKind::TextList(values));
        value.validate()?;
        Ok(value)
    }

    /// Creates a bounded list of exactly representable integers.
    ///
    /// # Errors
    ///
    /// Returns [`ApiErrorDetailsError`] when the list is too long or an item is
    /// outside the cross-platform JSON-safe range.
    pub fn integer_list(values: Vec<i64>) -> Result<Self, ApiErrorDetailsError> {
        let value = Self(PublicDetailKind::IntegerList(values));
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ApiErrorDetailsError> {
        match &self.0 {
            PublicDetailKind::Text(value) => validate_detail_text(value),
            PublicDetailKind::Integer(value) => validate_detail_integer(*value),
            PublicDetailKind::Boolean(_) => Ok(()),
            PublicDetailKind::TextList(values) => {
                if values.is_empty() {
                    return Err(ApiErrorDetailsError::EmptyList);
                }
                if values.len() > MAX_DETAIL_LIST_ENTRIES {
                    return Err(ApiErrorDetailsError::ListTooLong);
                }
                for value in values {
                    validate_detail_text(value)?;
                }
                Ok(())
            }
            PublicDetailKind::IntegerList(values) => {
                if values.is_empty() {
                    return Err(ApiErrorDetailsError::EmptyList);
                }
                if values.len() > MAX_DETAIL_LIST_ENTRIES {
                    return Err(ApiErrorDetailsError::ListTooLong);
                }
                for value in values {
                    validate_detail_integer(*value)?;
                }
                Ok(())
            }
        }
    }
}

impl Serialize for PublicDetailValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicDetailValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Self(PublicDetailKind::deserialize(deserializer)?);
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

impl CanonicalEncode for PublicDetailValue {
    fn to_canonical_value(&self) -> CanonicalValue {
        match &self.0 {
            PublicDetailKind::Text(value) => CanonicalValue::Text(value.clone()),
            PublicDetailKind::Integer(value) if *value >= 0 => {
                CanonicalValue::Unsigned(u64::try_from(*value).expect("non-negative i64 fits u64"))
            }
            PublicDetailKind::Integer(value) => CanonicalValue::Negative(*value),
            PublicDetailKind::Boolean(value) => CanonicalValue::Bool(*value),
            PublicDetailKind::TextList(values) => CanonicalValue::Array(
                values
                    .iter()
                    .map(|value| CanonicalValue::Text(value.clone()))
                    .collect(),
            ),
            PublicDetailKind::IntegerList(values) => CanonicalValue::Array(
                values
                    .iter()
                    .map(|value| {
                        if *value >= 0 {
                            CanonicalValue::Unsigned(
                                u64::try_from(*value).expect("non-negative i64 fits u64"),
                            )
                        } else {
                            CanonicalValue::Negative(*value)
                        }
                    })
                    .collect(),
            ),
        }
    }
}

fn validate_detail_integer(value: i64) -> Result<(), ApiErrorDetailsError> {
    if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        Ok(())
    } else {
        Err(ApiErrorDetailsError::IntegerOutOfRange)
    }
}

fn validate_detail_text(value: &str) -> Result<(), ApiErrorDetailsError> {
    if value.len() > MAX_DETAIL_TEXT_BYTES || value.chars().any(char::is_control) {
        Err(ApiErrorDetailsError::InvalidText)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct ApiErrorDetails(BTreeMap<String, PublicDetailValue>);

impl ApiErrorDetails {
    fn insert(
        &mut self,
        key: impl Into<String>,
        value: PublicDetailValue,
    ) -> Result<(), ApiErrorDetailsError> {
        let key = key.into();
        validate_detail_key(&key)?;
        value.validate()?;
        if !self.0.contains_key(&key) && self.0.len() >= MAX_DETAIL_ENTRIES {
            return Err(ApiErrorDetailsError::TooManyEntries);
        }
        self.0.insert(key, value);
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ApiErrorDetails {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = BTreeMap::<String, PublicDetailValue>::deserialize(deserializer)?;
        if entries.len() > MAX_DETAIL_ENTRIES {
            return Err(de::Error::custom(ApiErrorDetailsError::TooManyEntries));
        }
        for (key, value) in &entries {
            validate_detail_key(key).map_err(de::Error::custom)?;
            value.validate().map_err(de::Error::custom)?;
        }
        Ok(Self(entries))
    }
}

impl CanonicalEncode for ApiErrorDetails {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(
            self.0
                .iter()
                .map(|(key, value)| {
                    (
                        CanonicalValue::Text(key.clone()),
                        value.to_canonical_value(),
                    )
                })
                .collect(),
        )
    }
}

fn validate_detail_key(value: &str) -> Result<(), ApiErrorDetailsError> {
    if value.is_empty()
        || value.len() > MAX_DETAIL_KEY_BYTES
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || value.ends_with('_')
        || value.contains("__")
    {
        Err(ApiErrorDetailsError::InvalidKey)
    } else {
        Ok(())
    }
}

/// Public error details exceeded their structural bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiErrorDetailsError {
    /// The map contains too many entries.
    TooManyEntries,
    /// A detail key is not canonical lower snake case.
    InvalidKey,
    /// A text value is too long or contains control characters.
    InvalidText,
    /// A scalar list contains too many entries.
    ListTooLong,
    /// A scalar list is empty and would be ambiguous in JSON.
    EmptyList,
    /// An integer is not exactly representable by every supported JSON runtime.
    IntegerOutOfRange,
}

impl fmt::Display for ApiErrorDetailsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyEntries => "API error details contain too many entries",
            Self::InvalidKey => "API error detail key must use bounded lower_snake_case",
            Self::InvalidText => "API error detail text is too long or contains control text",
            Self::ListTooLong => "API error detail list contains too many entries",
            Self::EmptyList => "API error detail list cannot be empty",
            Self::IntegerOutOfRange => {
                "API error detail integer is outside the cross-platform safe range"
            }
        })
    }
}

impl Error for ApiErrorDetailsError {}

/// A bounded, public API error body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    code: ApiErrorCode,
    message: PublicErrorMessage,
    request_id: RequestId,
    retryable: bool,
    details: ApiErrorDetails,
}

impl ApiError {
    /// Creates an error from a registered server-owned code.
    #[must_use]
    pub fn new(code: KnownApiErrorCode, request_id: RequestId) -> Self {
        Self {
            code: ApiErrorCode::from_known(code),
            // The protocol generator rejects registry messages outside these bounds.
            message: PublicErrorMessage(code.default_message().to_owned()),
            request_id,
            retryable: code.default_retryable(),
            details: ApiErrorDetails::default(),
        }
    }

    /// Adds or replaces a structurally safe public detail.
    ///
    /// # Errors
    ///
    /// Returns [`ApiErrorDetailsError`] when key or value bounds are violated.
    pub fn with_detail(
        mut self,
        key: impl Into<String>,
        value: PublicDetailValue,
    ) -> Result<Self, ApiErrorDetailsError> {
        self.details.insert(key, value)?;
        Ok(self)
    }

    /// Returns the stable or preserved future code.
    #[must_use]
    pub const fn code(&self) -> &ApiErrorCode {
        &self.code
    }

    /// Returns the reviewed public message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message.0
    }

    /// Returns whether the identical idempotent command is safe to retry.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Returns the request correlation ID.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }
}

impl CanonicalEncode for ApiError {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), self.code.to_canonical_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.message.0.clone()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.request_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Bool(self.retryable),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.details.to_canonical_value(),
            ),
        ])
    }
}

/// The standard HTTP response envelope for [`ApiError`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorResponse {
    error: ApiError,
}

impl ApiErrorResponse {
    /// Wraps an API error for JSON transport.
    #[must_use]
    pub const fn new(error: ApiError) -> Self {
        Self { error }
    }

    /// Returns the contained API error.
    #[must_use]
    pub const fn error(&self) -> &ApiError {
        &self.error
    }
}

impl CanonicalEncode for ApiErrorResponse {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![(
            CanonicalValue::Unsigned(1),
            self.error.to_canonical_value(),
        )])
    }
}
