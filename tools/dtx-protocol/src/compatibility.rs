use std::collections::HashMap;

use crate::{ErrorRegistry, EventRegistry, ProtocolToolError};

/// Ensures every frozen event remains byte-contract equivalent.
///
/// New event types are additive. An existing event must publish a new version
/// instead of changing its payload or policy metadata in place.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] when a baseline event is removed or changed.
pub fn check_event_compatibility(
    baseline: &EventRegistry,
    current: &EventRegistry,
) -> Result<(), ProtocolToolError> {
    if baseline.version != current.version {
        return Err(ProtocolToolError::new("event registry version changed"));
    }
    let current_by_type: HashMap<_, _> = current
        .events
        .iter()
        .map(|event| (event.event_type.as_str(), event))
        .collect();
    for baseline_event in &baseline.events {
        let Some(current_event) = current_by_type.get(baseline_event.event_type.as_str()) else {
            return Err(ProtocolToolError::new(format!(
                "frozen event {} was removed",
                baseline_event.event_type
            )));
        };
        if *current_event != baseline_event {
            return Err(ProtocolToolError::new(format!(
                "frozen event {} changed; publish a new version",
                baseline_event.event_type
            )));
        }
    }
    Ok(())
}

/// Ensures every frozen API error remains equivalent.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] when a baseline error is removed or changed.
pub fn check_error_compatibility(
    baseline: &ErrorRegistry,
    current: &ErrorRegistry,
) -> Result<(), ProtocolToolError> {
    if baseline.version != current.version {
        return Err(ProtocolToolError::new("error registry version changed"));
    }
    let current_by_code: HashMap<_, _> = current
        .errors
        .iter()
        .map(|error| (error.code.as_str(), error))
        .collect();
    for baseline_error in &baseline.errors {
        let Some(current_error) = current_by_code.get(baseline_error.code.as_str()) else {
            return Err(ProtocolToolError::new(format!(
                "frozen API error {} was removed",
                baseline_error.code
            )));
        };
        if *current_error != baseline_error {
            return Err(ProtocolToolError::new(format!(
                "frozen API error {} changed",
                baseline_error.code
            )));
        }
    }
    Ok(())
}
