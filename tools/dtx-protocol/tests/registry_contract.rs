use std::path::PathBuf;

use dtx_protocol::{
    check_event_compatibility, check_generated, load_error_registry, load_event_registry,
    parse_event_registry, render_rust_errors, render_rust_events,
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

#[test]
fn cross_version_registry_check_allows_addition_but_rejects_an_event_change() {
    let baseline = parse_event_registry(
        r"
version: 1
events:
  - type: example.changed.v1
    rust_name: ExampleChangedV1
    schema_version: 1
    aggregate: example
    required_reader_capability: example.v1
    authorization: owner
    retention: tenant_policy
    redaction: identifiers_only
    snapshot_projection: examples
    unknown_version_policy: stop_cursor
    fields:
      - { key: 1, name: example_id, type: aggregate_id }
",
    )
    .unwrap();
    let additive = parse_event_registry(
        r"
version: 1
events:
  - type: example.changed.v1
    rust_name: ExampleChangedV1
    schema_version: 1
    aggregate: example
    required_reader_capability: example.v1
    authorization: owner
    retention: tenant_policy
    redaction: identifiers_only
    snapshot_projection: examples
    unknown_version_policy: stop_cursor
    fields:
      - { key: 1, name: example_id, type: aggregate_id }
  - type: second.changed.v1
    rust_name: SecondChangedV1
    schema_version: 1
    aggregate: second
    required_reader_capability: null
    authorization: owner
    retention: tenant_policy
    redaction: identifiers_only
    snapshot_projection: seconds
    unknown_version_policy: preserve_and_skip
    fields:
      - { key: 1, name: second_id, type: aggregate_id }
",
    )
    .unwrap();
    let changed = parse_event_registry(
        r"
version: 1
events:
  - type: example.changed.v1
    rust_name: ExampleChangedV1
    schema_version: 1
    aggregate: different_aggregate
    required_reader_capability: example.v1
    authorization: owner
    retention: tenant_policy
    redaction: identifiers_only
    snapshot_projection: examples
    unknown_version_policy: stop_cursor
    fields:
      - { key: 1, name: example_id, type: aggregate_id }
",
    )
    .unwrap();

    check_event_compatibility(&baseline, &additive).expect("additive event is compatible");
    assert!(check_event_compatibility(&baseline, &changed).is_err());
}
