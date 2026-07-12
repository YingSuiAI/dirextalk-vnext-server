use std::{collections::HashSet, error::Error, fmt, fs, path::Path};

use serde::{Deserialize, Serialize};

const EVENT_FIELD_TYPES: &[&str] = &[
    "aggregate_id",
    "api_error_code",
    "approval_id",
    "binding_id",
    "bool",
    "boot_id",
    "bounded_string",
    "connector_id",
    "consent_id",
    "conversation_id",
    "device_id",
    "directory_registration_id",
    "host_id",
    "indexer_id",
    "installation_id",
    "job_evidence_id",
    "job_evidence_id_list",
    "job_id",
    "job_resource_id",
    "job_step_id",
    "managed_service_id",
    "optional_api_error_code",
    "optional_connector_id",
    "optional_sha256_digest",
    "optional_stable_code",
    "optional_utc_millis",
    "public_subject_id",
    "run_id",
    "service_operation_id",
    "sha256_digest",
    "stable_code",
    "u32",
    "u64",
    "utc_millis",
];

/// The event registry root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventRegistry {
    /// Registry schema version.
    pub version: u16,
    /// Durable event definitions in stable publication order.
    pub events: Vec<EventDefinition>,
}

/// One durable event and its policy metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventDefinition {
    /// Stable dotted wire type.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Generated Rust/Dart class name.
    pub rust_name: String,
    /// Payload schema version.
    pub schema_version: u16,
    /// Aggregate family.
    pub aggregate: String,
    /// Capability that makes this event required, or null for optional events.
    pub required_reader_capability: Option<String>,
    /// Stable authorization predicate name.
    pub authorization: String,
    /// Stable retention policy name.
    pub retention: String,
    /// Stable redaction policy name.
    pub redaction: String,
    /// Projection rebuilt by this event.
    pub snapshot_projection: String,
    /// Behavior when this payload version is unknown.
    pub unknown_version_policy: String,
    /// Ordered payload fields and numeric CBOR keys.
    pub fields: Vec<EventField>,
}

/// One generated event payload field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventField {
    /// Positive numeric CBOR map key.
    pub key: u16,
    /// Lower-snake field name.
    pub name: String,
    /// Type from the bounded generator vocabulary.
    #[serde(rename = "type")]
    pub field_type: String,
}

/// The API error registry root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorRegistry {
    /// Registry schema version.
    pub version: u16,
    /// Stable error definitions.
    pub errors: Vec<ErrorDefinition>,
}

/// One server-constructible API error.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDefinition {
    /// Upper-snake stable code.
    pub code: String,
    /// Generated enum variant.
    pub rust_name: String,
    /// Default HTTP status.
    pub http_status: u16,
    /// Whether replaying the same idempotent command is safe by default.
    pub default_retryable: bool,
    /// Reviewed public default message.
    pub message: String,
}

/// Contract parsing, validation, generation, or compatibility failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolToolError(String);

impl ProtocolToolError {
    /// Creates a non-sensitive protocol-tool diagnostic.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ProtocolToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ProtocolToolError {}

/// Loads and validates an event registry.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for I/O, YAML, or contract violations.
pub fn load_event_registry(path: &Path) -> Result<EventRegistry, ProtocolToolError> {
    let source = fs::read_to_string(path)
        .map_err(|error| ProtocolToolError::new(format!("read {}: {error}", path.display())))?;
    parse_event_registry(&source)
}

/// Parses and validates an event registry string.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for YAML or contract violations.
pub fn parse_event_registry(source: &str) -> Result<EventRegistry, ProtocolToolError> {
    let registry: EventRegistry = yaml_serde::from_str(source)
        .map_err(|error| ProtocolToolError::new(format!("parse event registry: {error}")))?;
    validate_event_registry(&registry)?;
    Ok(registry)
}

/// Loads and validates an API error registry.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for I/O, YAML, or contract violations.
pub fn load_error_registry(path: &Path) -> Result<ErrorRegistry, ProtocolToolError> {
    let source = fs::read_to_string(path)
        .map_err(|error| ProtocolToolError::new(format!("read {}: {error}", path.display())))?;
    parse_error_registry(&source)
}

/// Parses and validates an API error registry string.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for YAML or contract violations.
pub fn parse_error_registry(source: &str) -> Result<ErrorRegistry, ProtocolToolError> {
    let registry: ErrorRegistry = yaml_serde::from_str(source)
        .map_err(|error| ProtocolToolError::new(format!("parse error registry: {error}")))?;
    validate_error_registry(&registry)?;
    Ok(registry)
}

fn validate_event_registry(registry: &EventRegistry) -> Result<(), ProtocolToolError> {
    if registry.version != 1 {
        return Err(ProtocolToolError::new("event registry version must be 1"));
    }
    if registry.events.is_empty() {
        return Err(ProtocolToolError::new("event registry cannot be empty"));
    }
    let mut event_types = HashSet::new();
    let mut rust_names = HashSet::new();
    for event in &registry.events {
        if !event_types.insert(&event.event_type) {
            return Err(ProtocolToolError::new(format!(
                "duplicate event type {}",
                event.event_type
            )));
        }
        if !rust_names.insert(&event.rust_name) {
            return Err(ProtocolToolError::new(format!(
                "duplicate event Rust name {}",
                event.rust_name
            )));
        }
        validate_event(event)?;
    }
    Ok(())
}

fn validate_event(event: &EventDefinition) -> Result<(), ProtocolToolError> {
    if event.schema_version == 0
        || !is_event_type(&event.event_type)
        || !event
            .event_type
            .ends_with(&format!(".v{}", event.schema_version))
    {
        return Err(ProtocolToolError::new(format!(
            "invalid versioned event type {}",
            event.event_type
        )));
    }
    if !is_pascal_name(&event.rust_name) {
        return Err(ProtocolToolError::new(format!(
            "invalid event Rust name {}",
            event.rust_name
        )));
    }
    for value in [
        &event.aggregate,
        &event.authorization,
        &event.retention,
        &event.redaction,
        &event.snapshot_projection,
    ] {
        if !is_lower_snake(value) {
            return Err(ProtocolToolError::new(format!(
                "invalid event metadata code {value}"
            )));
        }
    }
    if let Some(capability) = &event.required_reader_capability
        && !is_stable_code(capability)
    {
        return Err(ProtocolToolError::new(format!(
            "invalid reader capability {capability}"
        )));
    }
    match event.unknown_version_policy.as_str() {
        "stop_cursor" => {}
        "preserve_and_skip" if event.required_reader_capability.is_none() => {}
        "preserve_and_skip" => {
            return Err(ProtocolToolError::new(format!(
                "required event {} cannot preserve-and-skip",
                event.event_type
            )));
        }
        _ => {
            return Err(ProtocolToolError::new(format!(
                "invalid unknown-version policy for {}",
                event.event_type
            )));
        }
    }
    validate_event_fields(event)
}

fn validate_event_fields(event: &EventDefinition) -> Result<(), ProtocolToolError> {
    if event.fields.is_empty() {
        return Err(ProtocolToolError::new(format!(
            "event {} has no payload fields",
            event.event_type
        )));
    }
    let mut names = HashSet::new();
    for (index, field) in event.fields.iter().enumerate() {
        let expected_key = u16::try_from(index + 1)
            .map_err(|_| ProtocolToolError::new("too many event fields"))?;
        if field.key != expected_key {
            return Err(ProtocolToolError::new(format!(
                "event {} field keys must be contiguous from 1",
                event.event_type
            )));
        }
        if !names.insert(&field.name) || !is_lower_snake(&field.name) {
            return Err(ProtocolToolError::new(format!(
                "invalid or duplicate field {} in {}",
                field.name, event.event_type
            )));
        }
        if !EVENT_FIELD_TYPES.contains(&field.field_type.as_str()) {
            return Err(ProtocolToolError::new(format!(
                "unsupported field type {} in {}",
                field.field_type, event.event_type
            )));
        }
    }
    Ok(())
}

fn validate_error_registry(registry: &ErrorRegistry) -> Result<(), ProtocolToolError> {
    if registry.version != 1 {
        return Err(ProtocolToolError::new("error registry version must be 1"));
    }
    if registry.errors.is_empty() {
        return Err(ProtocolToolError::new("error registry cannot be empty"));
    }
    let mut codes = HashSet::new();
    let mut rust_names = HashSet::new();
    for error in &registry.errors {
        if !codes.insert(&error.code)
            || !is_upper_snake(&error.code)
            || !(3..=64).contains(&error.code.len())
        {
            return Err(ProtocolToolError::new(format!(
                "invalid or duplicate API error code {}",
                error.code
            )));
        }
        if !rust_names.insert(&error.rust_name) || !is_pascal_name(&error.rust_name) {
            return Err(ProtocolToolError::new(format!(
                "invalid or duplicate error Rust name {}",
                error.rust_name
            )));
        }
        if !(400..=599).contains(&error.http_status) {
            return Err(ProtocolToolError::new(format!(
                "invalid HTTP status for {}",
                error.code
            )));
        }
        if error.message.is_empty()
            || error.message.len() > 512
            || error.message.chars().any(char::is_control)
        {
            return Err(ProtocolToolError::new(format!(
                "invalid public message for {}",
                error.code
            )));
        }
    }
    Ok(())
}

fn is_event_type(value: &str) -> bool {
    value.len() <= 128 && value.split('.').count() >= 3 && value.split('.').all(is_lower_snake)
}

fn is_stable_code(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.split('.').all(is_lower_snake)
}

fn is_lower_snake(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !value.ends_with('_')
        && !value.contains("__")
}

fn is_upper_snake(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && !value.ends_with('_')
        && !value.contains("__")
}

fn is_pascal_name(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
