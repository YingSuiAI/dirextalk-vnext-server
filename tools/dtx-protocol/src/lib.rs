#![forbid(unsafe_code)]

mod artifacts;
mod baseline;
mod compatibility;
mod generate;
mod registry;

pub use artifacts::validate_artifacts;
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
