use std::path::PathBuf;

use dtx_protocol::{
    check_generated, load_error_registry, load_event_registry, render_rust_errors,
    render_rust_events,
};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn canonical_registries_are_complete_unique_and_renderable() {
    let root = repository_root();
    let events = load_event_registry(&root.join("protocol/events/registry.yaml")).unwrap();
    let errors = load_error_registry(&root.join("protocol/errors/registry.yaml")).unwrap();

    assert_eq!(events.events.len(), 17);
    assert_eq!(errors.errors.len(), 25);

    let rendered_events = render_rust_events(&events).unwrap();
    for event in &events.events {
        assert!(rendered_events.contains(&format!("pub struct {}", event.rust_name)));
        assert!(rendered_events.contains(&event.event_type));
        assert!(rendered_events.contains(&format!(
            "impl crate::CanonicalDecode for {}",
            event.rust_name
        )));
        assert!(rendered_events.contains(&format!(
            "{}(crate::VerifiedEventEnvelope<{}>)",
            event.rust_name, event.rust_name
        )));
    }
    assert_eq!(rendered_events, render_rust_events(&events).unwrap());
    assert!(rendered_events.contains("pub policy_revision: crate::SafeUint"));
    assert!(rendered_events.contains("pub struct EventRegistryMetadata"));
    assert!(rendered_events.contains("pub aggregate_type: &'static str"));
    assert!(rendered_events.contains(
        "pub fn event_registry_metadata(event_type: &str) -> Option<EventRegistryMetadata>"
    ));
    assert!(
        rendered_events
            .contains("pub fn event_family_metadata(event_type: &str, schema_version: u16)")
    );
    assert!(rendered_events.contains("schema_version > *registered_schema_version"));
    assert!(rendered_events.contains("pub enum RegisteredEventEnvelope"));
    assert!(
        rendered_events.contains(
            "pub fn decode_registered_event(bytes: &[u8], reader: crate::ProtocolVersion)"
        )
    );
    assert!(rendered_events.contains("crate::peek_verified_event_dispatch_metadata"));

    let rendered_errors = render_rust_errors(&errors).unwrap();
    for error in &errors.errors {
        assert!(rendered_errors.contains(&error.code));
        assert!(rendered_errors.contains(&error.rust_name));
    }
}

#[test]
fn committed_rust_and_dart_sources_are_current() {
    check_generated(&repository_root()).expect("generated sources match their registries");
}
