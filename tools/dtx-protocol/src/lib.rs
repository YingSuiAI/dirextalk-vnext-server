#![forbid(unsafe_code)]

mod artifacts;
mod baseline;
mod compatibility;
mod generate;
mod history_recovery_v3;
mod key_package_v4;
mod mls_sequencer_v7;
mod opaque_push_v1;
mod recovery_scope_catalog_v2;
mod registry;

pub use baseline::{check_breaking, freeze_baseline};
pub use compatibility::{check_error_compatibility, check_event_compatibility};
pub use generate::{
    check_generated, generate, render_dart_errors, render_dart_events, render_rust_errors,
    render_rust_events,
};
pub use registry::{
    ErrorDefinition, ErrorRegistry, EventDefinition, EventField, EventRegistry, ProtocolToolError,
    load_error_registry, load_event_registry, parse_error_registry, parse_event_registry,
};

/// Validates every existing artifact plus the V42 and V43 versioned gates.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] when an artifact or cross-field invariant is invalid.
pub fn validate_artifacts(root: &std::path::Path) -> Result<(), ProtocolToolError> {
    artifacts::validate_artifacts(root)?;
    recovery_scope_catalog_v2::validate(root)?;
    history_recovery_v3::validate(root)?;
    key_package_v4::validate(root)?;
    mls_sequencer_v7::validate(root)?;
    opaque_push_v1::validate(root)
}
